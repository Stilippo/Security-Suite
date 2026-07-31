# =============================================================================
# main.py — Interfaccia Grafica e Entry Point dell'Applicazione
# =============================================================================
#
# Questo file contiene l'interfaccia utente (GUI) costruita con Tkinter.
# La UI permette all'utente di:
# 1. Selezionare il provider LLM (Ollama o OpenAI) e il relativo modello.
# 2. Selezionare quali test della security suite eseguire (Test 1-10).
# 3. Visualizzare l'output del console log in tempo reale.
# 4. Visualizzare la GIF prodotta dall'agente (se disponibile) e il report finale.
#
# Architettura:
# - L'interfaccia gira nel thread principale (Event Loop di Tkinter).
# - I server locali (ServerManager) vengono avviati all'inizio del run.
# - I test veri e propri vengono avviati in un thread separato (daemon thread)
#   per evitare di bloccare o "frizzare" la GUI. All'interno del thread
#   separato viene instanziato un loop `asyncio` per eseguire browser-use.

import tkinter as tk
from tkinter import ttk, scrolledtext
import subprocess
import threading
import asyncio
from pathlib import Path

from PIL import Image, ImageTk

from server_manager import ServerManager
from runner import TestRunner
from test_suite import TESTS
from analyzer import TestAnalyzer


# =============================================================================
# PALETTE COLORI E TIPOGRAFIA
# =============================================================================
COLORS = {
    "bg_primary":      "#0d1117",
    "bg_secondary":    "#161b22",
    "bg_tertiary":     "#1c2129",
    "bg_input":        "#0d1117",
    "border":          "#30363d",
    "border_focus":    "#58a6ff",
    "accent":          "#58a6ff",
    "accent_hover":    "#79b8ff",
    "success":         "#3fb950",
    "error":           "#f85149",
    "warning":         "#d29922",
    "text_primary":    "#e6edf3",
    "text_secondary":  "#8b949e",
    "text_muted":      "#484f58",
    "btn_green_bg":    "#238636",
    "btn_green_hover": "#2ea043",
    "btn_bg":          "#21262d",
    "btn_hover":       "#30363d",
    "btn_red_bg":      "#da3633",
    "btn_red_hover":   "#f85149",
    "purple":          "#d2a8ff",
    "accent_line":     "#1f6feb",
}

# Modelli OpenAI disponibili (i più comuni per uso con agenti)
OPENAI_MODELS = [
    "gpt-4o",
    "gpt-4o-mini",
    "gpt-4-turbo",
    "gpt-4",
    "gpt-3.5-turbo",
    "o4-mini",
    "o3",
    "o3-mini",
    "o1",
    "o1-mini",
]

FONT_TITLE       = ("Segoe UI Semibold", 15)
FONT_SUBTITLE    = ("Segoe UI", 9)
FONT_LABEL       = ("Segoe UI", 10)
FONT_LABEL_BOLD  = ("Segoe UI Semibold", 10)
FONT_BTN         = ("Segoe UI Semibold", 10)
FONT_BTN_SMALL   = ("Segoe UI", 9)
FONT_LOG         = ("Cascadia Code", 10)
FONT_LOG_HEADER  = ("Cascadia Code", 11, "bold")
FONT_STATUS      = ("Segoe UI", 9)
FONT_PLACEHOLDER = ("Segoe UI", 11)


class SecurityTestApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Browser-Use Security Test Suite")
        self.root.geometry("1200x850")
        self.root.minsize(1000, 700)
        self.root.configure(bg=COLORS["bg_primary"])

        # Variabili di stato per gestire l'animazione della GIF nel canvas
        self._gif_frames = []
        self._gif_index = 0
        self._gif_after_id = None

        # Stato della progress bar e stop
        self._total_tests = 0
        self._completed_tests = 0
        self._stop_requested = False
        self._emergency_stop = False
        self._server_mgr = None
        self._worker_loop = None  # Riferimento al loop asyncio del worker thread

        self._apply_dark_theme()
        self._build_ui()
        self._on_provider_change()  # Inizializza la vista corretta per il provider selezionato

    # =========================================================================
    # TEMA DARK — Configurazione stili ttk
    # =========================================================================
    def _apply_dark_theme(self):
        """Configura il tema dark professionale per tutti i widget ttk."""
        style = ttk.Style()
        style.theme_use("clam")

        # --- Frame ---
        style.configure("TFrame", background=COLORS["bg_primary"])
        style.configure("Card.TFrame", background=COLORS["bg_secondary"])

        # --- LabelFrame ---
        style.configure("TLabelframe",
                         background=COLORS["bg_secondary"],
                         bordercolor=COLORS["border"],
                         darkcolor=COLORS["bg_secondary"],
                         lightcolor=COLORS["bg_secondary"],
                         relief="solid",
                         borderwidth=1)
        style.configure("TLabelframe.Label",
                         background=COLORS["bg_secondary"],
                         foreground=COLORS["text_primary"],
                         font=FONT_LABEL_BOLD)

        # --- Label ---
        style.configure("TLabel",
                         background=COLORS["bg_primary"],
                         foreground=COLORS["text_primary"],
                         font=FONT_LABEL)
        style.configure("Card.TLabel",
                         background=COLORS["bg_secondary"],
                         foreground=COLORS["text_primary"],
                         font=FONT_LABEL)
        style.configure("Title.TLabel",
                         background=COLORS["bg_primary"],
                         foreground=COLORS["text_primary"],
                         font=FONT_TITLE)
        style.configure("Subtitle.TLabel",
                         background=COLORS["bg_primary"],
                         foreground=COLORS["text_secondary"],
                         font=FONT_SUBTITLE)
        style.configure("Status.TLabel",
                         background=COLORS["bg_primary"],
                         foreground=COLORS["text_secondary"],
                         font=FONT_STATUS)

        # --- Combobox ---
        style.configure("TCombobox",
                         fieldbackground=COLORS["bg_input"],
                         background=COLORS["btn_bg"],
                         foreground=COLORS["text_primary"],
                         bordercolor=COLORS["border"],
                         arrowcolor=COLORS["text_secondary"],
                         selectbackground=COLORS["accent"],
                         selectforeground="#ffffff",
                         padding=4)
        style.map("TCombobox",
                  fieldbackground=[("readonly", COLORS["bg_input"])],
                  foreground=[("readonly", COLORS["text_primary"])],
                  bordercolor=[("focus", COLORS["border_focus"])])
        # Stile dropdown list della combobox
        self.root.option_add("*TCombobox*Listbox.background", COLORS["bg_secondary"])
        self.root.option_add("*TCombobox*Listbox.foreground", COLORS["text_primary"])
        self.root.option_add("*TCombobox*Listbox.selectBackground", COLORS["accent"])
        self.root.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")
        self.root.option_add("*TCombobox*Listbox.font", FONT_LABEL)

        # --- Checkbutton ---
        style.configure("TCheckbutton",
                         background=COLORS["bg_secondary"],
                         foreground=COLORS["text_primary"],
                         font=FONT_LABEL,
                         indicatorbackground=COLORS["bg_input"],
                         indicatorforeground=COLORS["accent"],
                         indicatorrelief="flat")
        style.map("TCheckbutton",
                  background=[("active", COLORS["bg_secondary"])],
                  indicatorbackground=[("selected", COLORS["accent"]),
                                       ("!selected", COLORS["bg_input"])])

        # --- Button (default) ---
        style.configure("TButton",
                         background=COLORS["btn_bg"],
                         foreground=COLORS["text_primary"],
                         bordercolor=COLORS["border"],
                         font=FONT_BTN,
                         padding=(12, 5),
                         relief="flat")
        style.map("TButton",
                  background=[("active", COLORS["btn_hover"]),
                              ("disabled", COLORS["bg_tertiary"])],
                  foreground=[("disabled", COLORS["text_muted"])],
                  bordercolor=[("active", COLORS["border"])])

        # --- Button Small ---
        style.configure("Small.TButton",
                         background=COLORS["btn_bg"],
                         foreground=COLORS["text_secondary"],
                         bordercolor=COLORS["border"],
                         font=FONT_BTN_SMALL,
                         padding=(10, 3),
                         relief="flat")
        style.map("Small.TButton",
                  background=[("active", COLORS["btn_hover"])],
                  foreground=[("active", COLORS["text_primary"])])

        # --- Button Accent (Avvia) ---
        style.configure("Accent.TButton",
                         background=COLORS["btn_green_bg"],
                         foreground="#ffffff",
                         bordercolor=COLORS["btn_green_bg"],
                         font=FONT_BTN,
                         padding=(20, 7),
                         relief="flat")
        style.map("Accent.TButton",
                  background=[("active", COLORS["btn_green_hover"]),
                              ("disabled", COLORS["bg_tertiary"])],
                  foreground=[("disabled", COLORS["text_muted"])])

        # --- Button Stop (Rosso) ---
        style.configure("Stop.TButton",
                         background=COLORS["btn_red_bg"],
                         foreground="#ffffff",
                         bordercolor=COLORS["btn_red_bg"],
                         font=FONT_BTN,
                         padding=(20, 7),
                         relief="flat")
        style.map("Stop.TButton",
                  background=[("active", COLORS["btn_red_hover"]),
                              ("disabled", COLORS["bg_tertiary"])],
                  foreground=[("disabled", COLORS["text_muted"])])

        # --- Progressbar ---
        style.configure("Custom.Horizontal.TProgressbar",
                         troughcolor=COLORS["bg_tertiary"],
                         background=COLORS["accent"],
                         bordercolor=COLORS["border"],
                         lightcolor=COLORS["accent"],
                         darkcolor=COLORS["accent"],
                         thickness=6)

        # --- PanedWindow ---
        style.configure("TPanedwindow",
                         background=COLORS["bg_primary"])
        style.configure("Sash",
                         sashthickness=6,
                         gripcount=0,
                         background=COLORS["bg_primary"])

        # --- Scrollbar ---
        style.configure("Vertical.TScrollbar",
                         background=COLORS["bg_tertiary"],
                         troughcolor=COLORS["bg_primary"],
                         bordercolor=COLORS["bg_primary"],
                         arrowcolor=COLORS["text_muted"],
                         gripcount=0)
        style.map("Vertical.TScrollbar",
                  background=[("active", COLORS["text_muted"])])

    # =========================================================================
    # COSTRUZIONE UI
    # =========================================================================
    def _build_ui(self):
        """
        Costruisce l'intera interfaccia dividendo la finestra in aree principali:
        - HEADER: Titolo e branding
        - CONFIG: Selettori Provider e Modello (con switching Ollama/OpenAI)
        - TEST SELECTOR: Checkbox per i test + bottoni selezione rapida
        - ACTION BAR: Bottone avvio + stop + status + progress bar
        - MAIN PANE: Log a sinistra, preview GIF a destra
        """
        # =====================================================================
        # HEADER: Titolo + Sottotitolo
        # =====================================================================
        header = ttk.Frame(self.root, style="TFrame")
        header.pack(fill='x', padx=20, pady=(16, 0))

        ttk.Label(header,
                  text="🛡️  Browser-Use Security Test Suite",
                  style="Title.TLabel").pack(anchor='w')
        ttk.Label(header,
                  text="Test automatizzati per la sicurezza degli agenti browser  •  SOP · Prompt Injection · Data Leakage",
                  style="Subtitle.TLabel").pack(anchor='w', pady=(2, 0))

        # Linea accent sotto il titolo
        accent_line = tk.Frame(self.root, height=2, bg=COLORS["accent_line"])
        accent_line.pack(fill='x', padx=20, pady=(10, 12))

        # =====================================================================
        # CONFIGURAZIONE: Provider + Modello (Card con switching dinamico)
        # =====================================================================
        config_card = ttk.LabelFrame(self.root, text="  ⚙️  Configurazione  ")
        config_card.pack(fill='x', padx=20, pady=(0, 8))

        # --- Riga 1: Provider ---
        provider_row = ttk.Frame(config_card, style="Card.TFrame")
        provider_row.pack(fill='x', padx=12, pady=(10, 6))

        ttk.Label(provider_row, text="Provider:", style="Card.TLabel").pack(side='left', padx=(4, 6))
        self.provider_var = tk.StringVar(value="ollama")
        provider_combo = ttk.Combobox(provider_row, textvariable=self.provider_var,
                                       values=["ollama", "openai"], state="readonly", width=12)
        provider_combo.pack(side='left', padx=(0, 12))
        # Bind il cambio provider per aggiornare la UI dinamicamente
        provider_combo.bind("<<ComboboxSelected>>", lambda e: self._on_provider_change())

        # --- Riga 2: Configurazione Ollama (modello + refresh) ---
        self._ollama_frame = ttk.Frame(config_card, style="Card.TFrame")
        self._ollama_frame.pack(fill='x', padx=12, pady=(0, 10))

        ttk.Label(self._ollama_frame, text="Modello:", style="Card.TLabel").pack(side='left', padx=(4, 6))
        self.model_var = tk.StringVar()
        self.model_combo = ttk.Combobox(self._ollama_frame, textvariable=self.model_var,
                                         state="readonly", width=28)
        self.model_combo.pack(side='left', padx=(0, 10))
        ttk.Button(self._ollama_frame, text="🔄  Aggiorna modelli",
                   command=self.refresh_models).pack(side='left')

        # --- Riga 2 alt: Configurazione OpenAI (API key + modello) ---
        self._openai_frame = ttk.Frame(config_card, style="Card.TFrame")
        # Non viene packato qui — lo gestisce _on_provider_change

        ttk.Label(self._openai_frame, text="API Key:", style="Card.TLabel").pack(side='left', padx=(4, 6))
        self.api_key_var = tk.StringVar()
        self.api_key_entry = tk.Entry(self._openai_frame, textvariable=self.api_key_var,
                                       width=36, show="•",
                                       font=FONT_LABEL,
                                       bg=COLORS["bg_input"],
                                       fg=COLORS["text_primary"],
                                       insertbackground=COLORS["text_primary"],
                                       bd=1,
                                       relief="solid",
                                       highlightcolor=COLORS["border_focus"],
                                       highlightbackground=COLORS["border"],
                                       highlightthickness=1)
        self.api_key_entry.pack(side='left', padx=(0, 16))

        ttk.Label(self._openai_frame, text="Modello:", style="Card.TLabel").pack(side='left', padx=(0, 6))
        self.openai_model_var = tk.StringVar(value=OPENAI_MODELS[0])
        self.openai_model_combo = ttk.Combobox(self._openai_frame, textvariable=self.openai_model_var,
                                                values=OPENAI_MODELS, state="readonly", width=18)
        self.openai_model_combo.pack(side='left', padx=(0, 10))

        # Bottone per mostrare/nascondere la API key
        self._api_key_visible = False
        self._toggle_key_btn = ttk.Button(self._openai_frame, text="👁",
                                           command=self._toggle_api_key_visibility,
                                           style="Small.TButton")
        self._toggle_key_btn.pack(side='left')

        # =====================================================================
        # SELEZIONE TEST (Card con griglia + bottoni rapidi)
        # =====================================================================
        test_card = ttk.LabelFrame(self.root, text="  🧪  Seleziona i test  ")
        test_card.pack(fill='x', padx=20, pady=(0, 8))

        # Griglia dei test
        test_grid = ttk.Frame(test_card, style="Card.TFrame")
        test_grid.pack(fill='x', padx=12, pady=(10, 4))
        test_grid.columnconfigure(0, weight=1)
        test_grid.columnconfigure(1, weight=1)

        self.test_vars = {}
        cols = 2
        for i, (tid, config) in enumerate(TESTS.items()):
            var = tk.BooleanVar(value=True)  # Di default tutti selezionati
            cb = ttk.Checkbutton(test_grid,
                                  text=f"  T{tid}  •  {config['name']}",
                                  variable=var)
            cb.grid(row=i // cols, column=i % cols, sticky='w', padx=(8, 20), pady=3)
            self.test_vars[tid] = var

        # Bottoni di selezione rapida
        sel_frame = ttk.Frame(test_card, style="Card.TFrame")
        sel_frame.pack(fill='x', padx=12, pady=(4, 10))

        ttk.Button(sel_frame, text="☑  Seleziona tutti",
                   command=self._select_all_tests,
                   style="Small.TButton").pack(side='left', padx=(8, 6))
        ttk.Button(sel_frame, text="☐  Deseleziona tutti",
                   command=self._deselect_all_tests,
                   style="Small.TButton").pack(side='left')

        # =====================================================================
        # BARRA DI AZIONE: Bottone Avvia + 2 Stop + Status + Progress
        # =====================================================================
        action_bar = ttk.Frame(self.root, style="TFrame")
        action_bar.pack(fill='x', padx=20, pady=(4, 10))

        self.run_btn = ttk.Button(action_bar, text="▶  Avvia suite selezionata",
                                   command=self.run_tests,
                                   style="Accent.TButton")
        self.run_btn.pack(side='left', padx=(0, 8))

        self.stop_graceful_btn = ttk.Button(action_bar, text="⏸  Ferma dopo test corrente",
                                             command=self.stop_tests_graceful,
                                             style="TButton",
                                             state='disabled')
        self.stop_graceful_btn.pack(side='left', padx=(0, 6))

        self.stop_emergency_btn = ttk.Button(action_bar, text="🛑  Stop emergenza",
                                              command=self.stop_tests_emergency,
                                              style="Stop.TButton",
                                              state='disabled')
        self.stop_emergency_btn.pack(side='left', padx=(0, 16))

        # Frame verticale per status + progress
        status_col = ttk.Frame(action_bar, style="TFrame")
        status_col.pack(side='left', fill='x', expand=True)

        self.status_label = ttk.Label(status_col, text="●  Pronto",
                                       style="Status.TLabel")
        self.status_label.pack(anchor='w')

        self.progress_bar = ttk.Progressbar(
            status_col, mode='determinate',
            style="Custom.Horizontal.TProgressbar",
            maximum=100, value=0
        )
        self.progress_bar.pack(anchor='w', fill='x', pady=(5, 0))

        # =====================================================================
        # AREA PRINCIPALE: Log (sinistra) + GIF Preview (destra)
        # =====================================================================
        main_pane = ttk.PanedWindow(self.root, orient='horizontal')
        main_pane.pack(fill='both', expand=True, padx=20, pady=(0, 16))

        # --- Pannello sinistro: Log/Terminal ---
        left_frame = ttk.LabelFrame(main_pane, text="  📋  Console di esecuzione  ")
        main_pane.add(left_frame, weight=3)  # Peso maggiore per dare più spazio al testo

        self.log_area = scrolledtext.ScrolledText(
            left_frame, wrap='word',
            font=FONT_LOG,
            bg=COLORS["bg_primary"],
            fg=COLORS["text_primary"],
            insertbackground=COLORS["text_primary"],
            selectbackground=COLORS["accent"],
            selectforeground="#ffffff",
            bd=0,
            relief="flat",
            padx=12, pady=10
        )
        self.log_area.pack(fill='both', expand=True, padx=6, pady=(6, 2))
        self.log_area.config(state='disabled')  # Sola lettura

        # Tag visivi per colorare il testo del log in base alla gravità
        self.log_area.tag_configure("success",   foreground=COLORS["success"])
        self.log_area.tag_configure("error",     foreground=COLORS["error"])
        self.log_area.tag_configure("warning",   foreground=COLORS["warning"])
        self.log_area.tag_configure("info",      foreground=COLORS["accent"])
        self.log_area.tag_configure("header",    foreground=COLORS["purple"],
                                    font=FONT_LOG_HEADER)
        self.log_area.tag_configure("separator", foreground=COLORS["text_muted"])

        # Nota: log completo nel terminale
        terminal_hint = ttk.Label(left_frame,
                                   text="ℹ️  Per il log completo e dettagliato, consulta il terminale da cui è stata lanciata l'applicazione",
                                   style="Card.TLabel",
                                   font=("Segoe UI", 8),
                                   foreground=COLORS["text_muted"])
        terminal_hint.pack(anchor='w', padx=10, pady=(0, 6))

        # --- Pannello destro: GIF Preview ---
        right_frame = ttk.LabelFrame(main_pane, text="  🎬  Registrazione test  ")
        main_pane.add(right_frame, weight=2)

        # Canvas usato per disegnare i frame della GIF
        self.gif_canvas = tk.Canvas(right_frame, bg=COLORS["bg_primary"],
                                     highlightthickness=1,
                                     highlightbackground=COLORS["border"])
        self.gif_canvas.pack(fill='both', expand=True, padx=6, pady=6)
        self.gif_canvas.bind("<Configure>", self._on_canvas_resize)

        # Placeholder elegante
        self._gif_placeholder_id = self.gif_canvas.create_text(
            0, 0,
            text="🎬\n\nLa registrazione apparirà qui\ndopo l'esecuzione del test",
            fill=COLORS["text_muted"],
            font=FONT_PLACEHOLDER,
            anchor='center',
            justify='center'
        )

        # Bottone per aprire la GIF con il visualizzatore predefinito del sistema operativo
        self._current_gif_path = None
        self.open_gif_btn = ttk.Button(right_frame, text="📂  Apri GIF nel player",
                                        command=self._open_gif_external, state='disabled')
        self.open_gif_btn.pack(pady=(0, 8))

    def _on_canvas_resize(self, event):
        """Riposiziona dinamicamente il placeholder al centro quando la finestra viene ridimensionata."""
        self.gif_canvas.coords(self._gif_placeholder_id, event.width // 2, event.height // 2)

    # =========================================================================
    # SWITCHING PROVIDER (Ollama ↔ OpenAI)
    # =========================================================================
    def _on_provider_change(self):
        """Mostra/nasconde i widget corretti in base al provider selezionato."""
        provider = self.provider_var.get()

        if provider == "ollama":
            self._openai_frame.pack_forget()
            self._ollama_frame.pack(fill='x', padx=12, pady=(0, 10))
            self.refresh_models()
        elif provider == "openai":
            self._ollama_frame.pack_forget()
            self._openai_frame.pack(fill='x', padx=12, pady=(0, 10))
            # Se la combobox OpenAI non ha selezione, seleziona il primo
            if not self.openai_model_var.get():
                self.openai_model_var.set(OPENAI_MODELS[0])

    def _toggle_api_key_visibility(self):
        """Mostra/nasconde la API key nel campo di input."""
        self._api_key_visible = not self._api_key_visible
        if self._api_key_visible:
            self.api_key_entry.config(show="")
            self._toggle_key_btn.config(text="🔒")
        else:
            self.api_key_entry.config(show="•")
            self._toggle_key_btn.config(text="👁")

    def _get_current_model(self):
        """Ritorna il modello selezionato in base al provider corrente."""
        if self.provider_var.get() == "openai":
            return self.openai_model_var.get()
        return self.model_var.get()

    def _get_api_key(self):
        """Ritorna la API key se il provider è OpenAI, altrimenti None."""
        if self.provider_var.get() == "openai":
            return self.api_key_var.get().strip() or None
        return None

    # =========================================================================
    # SELEZIONE RAPIDA TEST
    # =========================================================================
    def _select_all_tests(self):
        """Seleziona tutti i test."""
        for var in self.test_vars.values():
            var.set(True)

    def _deselect_all_tests(self):
        """Deseleziona tutti i test."""
        for var in self.test_vars.values():
            var.set(False)

    # =========================================================================
    # METODI DI LOGGING (Modificano la GUI in modo thread-safe tramite tk.after)
    # =========================================================================
    def log(self, msg, tag=None):
        self.log_area.config(state='normal')
        if tag:
            self.log_area.insert(tk.END, msg + "\n", tag)
        else:
            # Auto-detect tag in base al prefisso emoji
            if msg.startswith("✅"):
                self.log_area.insert(tk.END, msg + "\n", "success")
            elif msg.startswith("❌"):
                self.log_area.insert(tk.END, msg + "\n", "error")
            elif msg.startswith("⚠️"):
                self.log_area.insert(tk.END, msg + "\n", "warning")
            elif msg.startswith("─") or msg.startswith("═"):
                self.log_area.insert(tk.END, msg + "\n", "separator")
            else:
                self.log_area.insert(tk.END, msg + "\n")
        self.log_area.see(tk.END)  # Scrolla automaticamente in basso
        self.log_area.config(state='disabled')

    def log_header(self, msg):
        self.log("", "separator")
        self.log("═" * 60, "separator")
        self.log(f"  {msg}", "header")
        self.log("═" * 60, "separator")

    def log_separator(self):
        self.log("─" * 50, "separator")

    def set_status(self, msg):
        self.status_label.config(text=f"●  {msg}")

    def _update_progress(self, completed, total):
        """Aggiorna la barra di progresso."""
        if total > 0:
            pct = (completed / total) * 100
            self.progress_bar['value'] = pct

    def _reset_progress(self):
        """Resetta la barra di progresso a zero."""
        self.progress_bar['value'] = 0

    # =========================================================================
    # GESTIONE MODELLI (Ollama)
    # =========================================================================
    def refresh_models(self):
        """Esegue `ollama list` e aggiorna la combobox, escludendo i modelli di embedding."""
        try:
            res = subprocess.run(["ollama", "list"], capture_output=True, text=True)
            models = [
                line.split()[0] 
                for line in res.stdout.strip().split('\n')[1:] 
                if line.strip() and "embed" not in line.split()[0].lower()
            ]
            self.model_combo['values'] = models
            if models:
                self.model_combo.current(0)
        except Exception as e:
            self.log(f"❌ Errore caricamento modelli (Ollama è in esecuzione?): {e}")

    # =========================================================================
    # GESTIONE GIF ANIMATE
    # =========================================================================
    def _load_gif(self, gif_path: str):
        """Carica in memoria la GIF e prepara i frame usando PIL, ridimensionandoli al canvas."""
        self._stop_gif_animation()
        self._gif_frames = []
        self._gif_index = 0

        try:
            pil_image = Image.open(gif_path)
            canvas_w = self.gif_canvas.winfo_width()
            canvas_h = self.gif_canvas.winfo_height()
            if canvas_w < 10 or canvas_h < 10:
                canvas_w, canvas_h = 400, 300  # Fallback se canvas non è ancora inizializzato

            frame_idx = 0
            while True:
                try:
                    pil_image.seek(frame_idx)
                    frame = pil_image.copy().convert("RGBA")

                    # Ridimensiona per adattarsi al canvas mantenendo l'aspect ratio
                    img_w, img_h = frame.size
                    scale = min(canvas_w / img_w, canvas_h / img_h, 1.0)
                    new_w = int(img_w * scale)
                    new_h = int(img_h * scale)
                    frame = frame.resize((new_w, new_h), Image.Resampling.LANCZOS)

                    tk_frame = ImageTk.PhotoImage(frame)
                    self._gif_frames.append(tk_frame)
                    frame_idx += 1
                except EOFError:
                    break  # Fine della GIF

            if self._gif_frames:
                self.gif_canvas.itemconfigure(self._gif_placeholder_id, state='hidden')
                self._gif_image_id = self.gif_canvas.create_image(
                    canvas_w // 2, canvas_h // 2,
                    image=self._gif_frames[0], anchor='center'
                )
                duration = pil_image.info.get('duration', 100)  # millisecondi
                self._animate_gif(duration)

            self._current_gif_path = gif_path
            self.open_gif_btn.config(state='normal')

        except Exception as e:
            self.log(f"⚠️ Impossibile caricare GIF: {e}")

    def _animate_gif(self, duration=100):
        """Cicla i frame iterativamente usando tk.after, simulando l'animazione."""
        if not self._gif_frames:
            return
        self._gif_index = (self._gif_index + 1) % len(self._gif_frames)
        self.gif_canvas.itemconfigure(self._gif_image_id, image=self._gif_frames[self._gif_index])
        self._gif_after_id = self.root.after(max(duration, 50), self._animate_gif, duration)

    def _stop_gif_animation(self):
        """Interrompe il loop tk.after() della GIF."""
        if self._gif_after_id:
            self.root.after_cancel(self._gif_after_id)
            self._gif_after_id = None

    def _open_gif_external(self):
        """Usa il comando start (Windows) per aprire la GIF."""
        if self._current_gif_path:
            import os
            os.startfile(self._current_gif_path)

    # =========================================================================
    # CORE: ESECUZIONE DELLA SUITE DEI TEST
    # =========================================================================
    def run_tests(self):
        """Metodo chiamato dal bottone 'Avvia'. Inizializza i server e fa spawnare un Thread."""
        selected = [tid for tid, var in self.test_vars.items() if var.get()]
        if not selected:
            self.log("⚠️ Seleziona almeno un test.")
            return

        model = self._get_current_model()
        if not model:
            self.log("⚠️ Seleziona un modello.")
            return

        provider = self.provider_var.get()
        api_key = self._get_api_key()

        # Validazione API key per OpenAI
        if provider == "openai" and not api_key:
            self.log("⚠️ Inserisci la API key di OpenAI.")
            return

        self._stop_requested = False
        self._emergency_stop = False
        self.run_btn.config(state='disabled')              # Previeni multi-click
        self.stop_graceful_btn.config(state='normal')      # Abilita stop graduale
        self.stop_emergency_btn.config(state='normal')     # Abilita stop emergenza

        # Reset Log e Progress
        self.log_area.config(state='normal')
        self.log_area.delete('1.0', tk.END)
        self.log_area.config(state='disabled')
        self._reset_progress()

        self.log_header(f"SECURITY TEST SUITE")
        self.log(f"  Provider: {provider}", "info")
        self.log(f"  Modello: {model}", "info")
        self.log(f"  Test selezionati: {len(selected)}", "info")

        # Avvio i server HTTP/PHP
        self._server_mgr = ServerManager()
        try:
            self._server_mgr.start_servers()
            self.log("✅ Server avviati (localhost:8000 e localhost:8001).")
        except Exception as e:
            self.log(f"❌ Errore avvio server: {e}")
            self.run_btn.config(state='normal')
            self.stop_graceful_btn.config(state='disabled')
            self.stop_emergency_btn.config(state='disabled')
            return

        # Lancia il worker su un thread separato così la UI non si blocca
        threading.Thread(
            target=self._run_suite,
            args=(model, provider, selected, self._server_mgr, api_key),
            daemon=True
        ).start()

    def stop_tests_graceful(self):
        """Imposta il flag di stop per interrompere la suite dopo il test corrente."""
        self._stop_requested = True
        self.stop_graceful_btn.config(state='disabled')
        self.set_status("Arresto graduale... (il test corrente finirà)")
        self.log("⏸ Arresto graduale richiesto — la suite si fermerà dopo il test corrente.", "warning")

    def stop_tests_emergency(self):
        """Stop immediato: cancella i task asyncio, uccide il loop e ferma i server."""
        self._stop_requested = True
        self._emergency_stop = True
        self.stop_graceful_btn.config(state='disabled')
        self.stop_emergency_btn.config(state='disabled')
        self.set_status("STOP EMERGENZA — interruzione immediata...")
        self.log("🛑 STOP EMERGENZA — interruzione immediata in corso!", "error")

        # Cancella tutti i task pendenti nel loop asyncio del worker thread
        if self._worker_loop and self._worker_loop.is_running():
            # Cancella tutti i task asyncio pendenti
            for task in asyncio.all_tasks(self._worker_loop):
                self._worker_loop.call_soon_threadsafe(task.cancel)
            # Forza lo stop del loop asyncio
            self._worker_loop.call_soon_threadsafe(self._worker_loop.stop)

        # Ferma i server immediatamente
        if self._server_mgr:
            try:
                self._server_mgr.stop_servers()
            except Exception:
                pass

        self.log("🛑 Loop asyncio e server fermati.", "error")
        self._on_suite_finished()

    def _run_suite(self, model, provider, test_ids, server_mgr, api_key=None):
        """Worker Thread: cicla sui test ed esegue il runner asincrono all'interno."""
        runner = TestRunner(model, provider, api_key=api_key)
        
        # Bisogna creare un nuovo loop asyncio poiché siamo in un thread separato
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._worker_loop = loop  # Salva il riferimento per lo stop emergenza

        results = []
        total = len(test_ids)

        try:
            for idx, tid in enumerate(test_ids, 1):
                # Controlla se è stato richiesto lo stop (graduale o emergenza)
                if self._stop_requested:
                    if self._emergency_stop:
                        self.root.after(0, self.log, f"🛑 Suite terminata per stop emergenza.", "error")
                    else:
                        self.root.after(0, self.log, f"⏸ Suite interrotta dall'utente dopo {idx-1}/{total} test.", "warning")
                    break

                # Callback proxy per inviare update dal Thread al Thread della GUI
                def progress_cb(msg, _tid=tid):
                    self.root.after(0, self.log, msg)

                self.root.after(0, self.set_status, f"Test {tid} in corso... ({idx}/{total})")
                self.root.after(0, self.log_header, f"TEST {tid}: {TESTS[tid]['name']}  [{idx}/{total}]")

                try:
                    # Blocca l'esecuzione (in questo thread) finché l'agente non finisce il task
                    res = loop.run_until_complete(runner.run_test(tid, TESTS[tid], progress_callback=progress_cb))
                except asyncio.CancelledError:
                    # Stop emergenza: il task è stato cancellato
                    self.root.after(0, self.log, f"🛑 Test {tid} interrotto per stop emergenza.", "error")
                    results.append({"test_id": tid, "test_name": TESTS[tid]['name'], "status": "error", "error": "Stop emergenza"})
                    break
                except RuntimeError as e:
                    if "stopped" in str(e).lower() or self._emergency_stop:
                        self.root.after(0, self.log, f"🛑 Test {tid} interrotto per stop emergenza.", "error")
                        results.append({"test_id": tid, "test_name": TESTS[tid]['name'], "status": "error", "error": "Stop emergenza"})
                        break
                    raise
                except Exception as e:
                    if self._emergency_stop:
                        break
                    self.root.after(0, self.log, f"❌ Eccezione durante il test {tid}: {e}")
                    results.append({"test_id": tid, "test_name": TESTS[tid]['name'], "status": "error", "error": str(e)})
                    self.root.after(0, self._update_progress, idx, total)
                    continue

                # Classificazione tramite l'Analyzer deterministico (Fase post-mortem)
                if res.get("error") and not res.get("actions"):
                    # Se c'è un errore fatale senza azioni, è un errore dell'agente stesso (N/A)
                    cls = {"category": "agent_error", "severity": "critical", "detail": res["error"]}
                else:
                    try:
                        analyzer = TestAnalyzer(Path(res['json_log']), Path(res['console_log']), tid)
                        cls = analyzer.classify()
                    except Exception as e:
                        cls = {"category": "analysis_error", "severity": "critical", "detail": f"Errore analisi: {e}"}
                        analyzer = None

                # Generazione del report in markdown
                try:
                    if 'analyzer' in dir() and analyzer is not None:
                        report_text = analyzer.generate_report(res, cls)
                    else:
                        report_text = self._generate_fallback_report(res, cls)
                except Exception:
                    report_text = self._generate_fallback_report(res, cls)

                # Salva il report
                report_path = runner.get_report_path(tid, TESTS[tid]['name'])
                try:
                    with open(report_path, 'w', encoding='utf-8') as f:
                        f.write(report_text)
                except Exception as e:
                    self.root.after(0, self.log, f"⚠️ Impossibile salvare report: {e}")

                # Chiede alla GUI di stampare i risultati del test appena finito
                self.root.after(0, self._display_test_result, res, cls, str(report_path))

                # Aggiorna la progress bar
                self.root.after(0, self._update_progress, idx, total)

                # Carica la GIF prodotta dall'agente
                if res.get("gif"):
                    self.root.after(0, self._load_gif, res["gif"])

                results.append({
                    "test_id": tid,
                    "test_name": TESTS[tid]['name'],
                    "status": "done",
                    "classification": cls,
                    "report_path": str(report_path)
                })

        except Exception as e:
            # Cattura eccezioni residue dal loop stop
            if not self._emergency_stop:
                self.root.after(0, self.log, f"❌ Errore imprevisto nella suite: {e}", "error")

        # Al termine di tutti i test, pulisce loop e server
        self._worker_loop = None
        try:
            if not loop.is_closed():
                loop.close()
        except Exception:
            pass

        # Ferma i server solo se non già fermati dallo stop emergenza
        if not self._emergency_stop:
            try:
                server_mgr.stop_servers()
            except Exception:
                pass

        # Stampa il riassunto finale nella UI
        self.root.after(0, self._display_final_summary, results, runner.report_dir)
        self.root.after(0, self._on_suite_finished)

    def _on_suite_finished(self):
        """Ripristina lo stato della UI al termine della suite."""
        self.run_btn.config(state='normal')
        self.stop_graceful_btn.config(state='disabled')
        self.stop_emergency_btn.config(state='disabled')
        was_stopped = self._stop_requested
        was_emergency = self._emergency_stop
        self._stop_requested = False
        self._emergency_stop = False
        if was_emergency:
            self.set_status("Terminato per stop emergenza 🛑")
        elif was_stopped:
            self.set_status("Interrotto ⏸")
        else:
            self.set_status("Completato ✓")

    def _display_test_result(self, res, cls, report_path):
        """Renderizza a schermo l'esito della classificazione deterministica."""
        self.log_separator()
        cat = cls["category"]
        outcome = cls.get("outcome", "?")
        sev = cls["severity"]
        detail = cls.get("detail", "")
        severity_emoji = {"ok": "🟢", "high": "🟡", "critical": "🔴"}.get(sev, "⚪")

        tag = "success" if sev == "ok" else ("warning" if sev == "high" else "error")

        self.log(f"  📊 Esito: {severity_emoji} {outcome} ({cat})", tag)
        if detail:
            self.log(f"  💬 {detail}")

        n_steps = res.get("n_steps", 0)
        n_actions = len(res.get("actions", []))
        self.log(f"  📈 Step: {n_steps} | Azioni: {n_actions}")

        final = res.get("final_result")
        if final:
            final_str = str(final)
            if len(final_str) > 150:
                final_str = final_str[:150] + "..."
            self.log(f"  🎯 Risposta: {final_str}", "info")

        if res.get("error"):
            self.log(f"  ❌ Errore: {res['error']}", "error")

        if res.get("gif"):
            self.log(f"  🎬 GIF: {Path(res['gif']).name}")

        self.log(f"  📄 Report: {Path(report_path).name}", "info")
        self.log_separator()

    def _display_final_summary(self, results, report_dir):
        """Renderizza il blocco di riassunto alla fine dell'esecuzione di tutti i test."""
        self.log_header("RIEPILOGO FINALE")

        passed = 0
        failed = 0
        errors = 0

        for r in results:
            if r['status'] == 'done':
                cls = r['classification']
                sev = cls['severity']
                cat = cls['category']
                outcome = cls.get('outcome', '?')
                emoji = {"ok": "🟢", "high": "🟡", "critical": "🔴"}.get(sev, "⚪")
                tag = "success" if sev == "ok" else ("warning" if sev == "high" else "error")
                self.log(f"  {emoji} Test {r['test_id']} ({r['test_name']}): {outcome} [{cat}]", tag)

                if sev == "ok":
                    passed += 1
                elif cat == "agent_error":
                    errors += 1
                else:
                    failed += 1
            else:
                self.log(f"  🔴 Test {r['test_id']} ({r['test_name']}): ERRORE - {r.get('error', '?')}", "error")
                errors += 1

        self.log_separator()
        self.log(f"  Totale: {len(results)} test | 🟢 {passed} ok | 🟡🔴 {failed} falliti | ❌ {errors} errori")
        self.log(f"  📁 Report salvati in: {report_dir}", "info")
        self.log_separator()

    def _generate_fallback_report(self, res, cls):
        """Report minimo per gestire eventuali bug nella logica dell'analyzer senza bloccarsi."""
        lines = [
            f"# Report Test {res.get('test_id', '?')}: {res.get('test_name', '?')}",
            "",
            f"## Classificazione",
            f"- Categoria: `{cls['category']}`",
            f"- Severità: `{cls['severity']}`",
            f"- Dettaglio: {cls.get('detail', 'N/A')}",
            "",
            f"## Errore",
            f"```",
            f"{res.get('error', 'Nessun errore')}",
            f"```",
        ]
        return "\n".join(lines)


if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityTestApp(root)
    root.mainloop()