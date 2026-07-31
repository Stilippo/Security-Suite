# =============================================================================
# runner.py — Esecuzione e Isolamento dei Test Browser-Use
# =============================================================================
#
# Questo file contiene il cuore logico per l'invocazione del LLM e del browser,
# utilizzando la libreria `browser_use`. Si occupa di:
# 1. Istanziare il driver Playwright, caricando eventuali tab (preload_url).
# 2. Configurare l'Agente e il LLM (Ollama o OpenAI).
# 3. Intercettare l'output di STDOUT per salvare il log della console.
# 4. Eseguire l'agente asincronamente.
# 5. Salvare JSON (history), LOG (console) e GIF (se prodotta).
# 6. Ripulire rigorosamente la memoria tramite il Garbage Collector (GC).

import asyncio
import json
import io
import gc
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from datetime import datetime

from browser_use import Agent, BrowserSession, Tools, ChatOllama, ChatOpenAI
from browser_use.browser.events import SwitchTabEvent
from test_suite import TESTS


class DualStream(io.StringIO):
    """
    Classe utility per intercettare l'output di console in tempo reale e passarlo
    alla UI senza bloccare lo stream nativo. Questo permette di catturare gli
    errori tecnici del framework, loggandoli per il motore di analisi deterministico.
    """
    def __init__(self, callback=None):
        super().__init__()
        self.callback = callback
        self.buf = ""

    def write(self, s):
        super().write(s)
        if self.callback:
            self.buf += s
            if '\n' in self.buf:
                lines = self.buf.split('\n')
                for line in lines[:-1]:
                    if line.strip():
                        # Rimuove il prefisso boilerplate di logging per migliorare la leggibilità UI
                        clean_line = line.split("INFO     [Agent] ", 1)[-1] if "INFO     [Agent] " in line else line
                        self.callback(f"  {clean_line}")
                self.buf = lines[-1]


class TestRunner:
    """
    Runner della test suite. Ogni istanza di questa classe è isolata.
    """
    def __init__(self, model_name: str, provider: str = "ollama", api_key: str = None):
        self.model_name = model_name
        self.provider = provider
        self.api_key = api_key
        
        # Configurazione directory per log, json, gif e markdown
        self.base_dir = Path(__file__).parent
        self.log_dir = self.base_dir / "test_logs"
        self.log_dir.mkdir(exist_ok=True)
        
        self.gif_dir = self.log_dir / "gifs"
        self.gif_dir.mkdir(exist_ok=True)

        # La directory dei report è suddivisa per data e modello (struttura analitica)
        safe_model = self.model_name.replace(':', '_').replace('/', '_')
        date_str = datetime.now().strftime("%Y%m%d")
        self.report_dir = self.log_dir / "reports" / safe_model / date_str
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def _get_llm(self):
        """Istanzia l'oggetto LangChain corrispondente al provider selezionato."""
        if self.provider == "ollama":
            # Host fisso su localhost; timeout lungo per evitare eccezioni fatali su modelli pesanti (es. 72B)
            return ChatOllama(
                model=self.model_name,
                host='http://127.0.0.1:11434',
                timeout=180.0,
            )
        elif self.provider == "openai":
            # Temperature bassa per avere comportamenti più deterministici e riproducibili
            return ChatOpenAI(model=self.model_name, temperature=0.6, api_key=self.api_key)
        raise ValueError(f"Provider {self.provider} non supportato.")

    async def run_test(self, test_id: int, config: dict, progress_callback=None):
        """
        Metodo asincrono principale. 
        Prepara il browser, l'LLM, cattura l'output, salva i risultati e chiude il browser.
        """
        def notify(msg):
            if progress_callback:
                progress_callback(msg)
            print(msg)

        notify(f"\n🚀 Esecuzione Test {test_id}: {config['name']}")

        # Genera path univoci basati su test_id, modello e timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_model = self.model_name.replace(':', '_').replace('/', '_')
        base = f"{safe_model}_test{test_id}_{timestamp}"
        
        json_path = self.log_dir / f"{base}.json"
        gif_path = self.gif_dir / f"{base}.gif"
        log_path = self.log_dir / f"{base}.log"

        # Disabilitiamo args nativi per ridurre noise e popup chrome
        browser = BrowserSession(
            ignore_default_args=["--enable-automation", "--extensions-on-chrome-urls", "--disable-blink-features=AutomationControlled"]
        )
        tools = Tools()

        # =========================================================================
        # FASE 1: PRE-CARICAMENTO (Preload URLs)
        # =========================================================================
        # Molti test della SOP richiedono contesti incrociati o multi-tab pronti.
        # Qui apriamo il browser, navighiamo a ciascun URL definito nei metadati del test,
        # e per i test multi-tab facciamo uno switch programmativo all'ultimo tab.
        preload_urls = []
        if "preload_urls" in config:
            preload_urls = config["preload_urls"]
        elif "preload_url" in config:
            preload_urls = [config["preload_url"]]

        if preload_urls:
            try:
                await browser.start()
                for i, url in enumerate(preload_urls):
                    if i > 0:
                        await browser.navigate_to(url, new_tab=True)
                    else:
                        await browser.navigate_to(url, new_tab=False)
                    notify(f"  [PRELOAD] Tab {i+1} → {url}")
                
                notify(f"  [PRELOAD] {len(preload_urls)} tab pre-caricati.")
                
                # Setup critico per T3, T5, T8: Il framework browser-use a volte non rileva i tab in background
                # Emettiamo l'evento SwitchTab e obblighiamo Playwright a forzare il context.
                if len(preload_urls) > 1:
                    tabs = await browser.get_tabs()
                    if tabs:
                        target = tabs[0].target_id
                        browser.event_bus.dispatch(SwitchTabEvent(target_id=target))
                        try:
                            # Forza il focus visivo a livello di Playwright per dare contesto "frontale"
                            page = await browser.session_manager.get_page(target)
                            await page.bring_to_front()
                            await asyncio.sleep(0.5) # Pausa per l'event_bus
                        except Exception:
                            pass
            except Exception as e:
                notify(f"  [PRELOAD] Errore critico nel preload: {e}")

        # =========================================================================
        # FASE 2: INIZIALIZZAZIONE AGENTE E ESECUZIONE
        # =========================================================================
        agent = Agent(
            task=config["task"],
            llm=self._get_llm(),
            browser=browser,
            tools=tools,
            use_vision=False, # Vision disabilitata per i test di tesi sulla DOM extraction
            generate_gif=str(gif_path),
            use_judge=False,
        )

        log_capture = DualStream(callback=notify)
        history = None
        error = None

        # Eseguiamo il blocco e redirigiamo stdout per intercettare i parser log 
        try:
            with redirect_stdout(log_capture), redirect_stderr(log_capture):
                # max_steps=100 è un fail-safe generoso. Se termina per limite, verrà letto come step_incapacity.
                history = await agent.run(max_steps=100)
        except Exception as e:
            error = str(e)
            log_capture.write(f"\n!!! EXCEPTION: {e}\n")

        console_output = log_capture.getvalue()
        
        # Scrittura pura del console log
        with open(log_path, 'w', encoding='utf-8') as f:
            f.write(console_output)

        # =========================================================================
        # FASE 3: SALVATAGGIO LOG DATI STRUTTURATI (JSON)
        # =========================================================================
        actions_data = []
        final_result = None
        errors_list = []
        is_done = False
        n_steps = 0

        if history:
            try:
                # Estraiamo i campi rilevanti per il nostro analyzer deterministico
                actions_data = history.model_actions()
                final_result = history.final_result()
                errors_list = history.errors()
                is_done = history.is_done()
                n_steps = len(history.history) if hasattr(history, 'history') else 0
                
                data = {
                    "actions": actions_data,
                    "final_result": final_result,
                    "errors": errors_list,
                    "is_done": is_done,
                }
            except Exception as e:
                data = {"error": f"Impossibile serializzare history: {e}"}
                
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
        else:
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump({"error": error, "console_log": console_output}, f, indent=2)

        # =========================================================================
        # FASE 4: CLEANUP E TEARDOWN
        # =========================================================================
        try:
            await browser.kill()
        except Exception:
            pass

        # Deallocazione esplicita per liberare RAM. Il Playwright accumula leak se non distrutto in bulk.
        del agent
        del browser
        del tools
        gc.collect()

        gif_exists = gif_path.exists() and gif_path.stat().st_size > 0

        # Ritorna le references che verranno processate nel thread parent in main.py
        return {
            "test_id": test_id,
            "test_name": config["name"],
            "json_log": str(json_path),
            "console_log": str(log_path),
            "gif": str(gif_path) if gif_exists else None,
            "history": None, # history consuma molta ram, non la passiamo ma rely sul file json
            "error": error,
            "console_output": console_output,
            "n_steps": n_steps,
            "actions": actions_data,
            "final_result": final_result,
            "errors": errors_list,
            "is_done": is_done,
        }

    def get_report_path(self, test_id: int, test_name: str) -> Path:
        """Helper function per calcolare il path del markdown del report"""
        safe_name = test_name.lower().replace(' ', '_').replace('(', '').replace(')', '')
        timestamp = datetime.now().strftime("%H%M%S")
        return self.report_dir / f"test{test_id}_{safe_name}_{timestamp}.md"