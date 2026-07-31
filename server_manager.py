# =============================================================================
# server_manager.py — Gestore del Web Server per le Sandbox HTML/PHP
# =============================================================================
#
# Questo file contiene la classe ServerManager, che gestisce lo spin-up e 
# lo spin-down dei server HTTP usati per i test della suite di sicurezza.
#
# Architettura:
# - Il sistema simula due domini separati (SOP isolation) usando due porte locali:
#     1) A.com gira su 127.0.0.1:8000
#     2) B.com gira su 127.0.0.1:8001
# - Di base viene usato python -m http.server
# - Dato che alcuni test (come il Test 7 o le pagine di login) possono richiedere 
#   operazioni sul backend (es. set cookie, check form), il ServerManager prova
#   ad avviare un server web PHP nativo `php -S`. Se PHP non è installato, fallback
#   sui server statici python.

import subprocess
import os
import time
import atexit
from pathlib import Path

class ServerManager:
    """Gestisce il ciclo di vita (avvio/spegnimento) dei server HTTP locali di test."""
    
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.root_dir = self.base_dir / "test_files"
        self.processes = []
        self.running = False

    def start_servers(self):
        """
        Avvia i server web. Se trova l'eseguibile PHP nel sistema, lo predilige,
        altrimenti avvia `python -m http.server`.
        """
        a_dir = self.root_dir / "A.com"
        b_dir = self.root_dir / "B.com"

        if not a_dir.exists() or not b_dir.exists():
            raise FileNotFoundError(f"Cartelle mancanti: {a_dir} o {b_dir}. Assicurarsi che i file siano in test_files.")

        # =====================================================================
        # 1. Server per A.com (porta 8000) (Default statico)
        # =====================================================================
        p1 = subprocess.Popen(
            ["python", "-m", "http.server", "8000", "--directory", str(a_dir)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        self.processes.append(p1)

        # =====================================================================
        # 2. Server per B.com (porta 8001) (Default statico)
        # =====================================================================
        p2 = subprocess.Popen(
            ["python", "-m", "http.server", "8001", "--directory", str(b_dir)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        self.processes.append(p2)

        # =====================================================================
        # 3. Upgrade a PHP Server (Opzionale)
        # =====================================================================
        # PHP è utile per gestire codice server-side es. in complex-page.php (Test 7
        # nel paper originale) o per summary.php
        php_ok = subprocess.run(["php", "-v"], capture_output=True).returncode == 0
        if php_ok:
            # Uccidiamo i task statici appena avviati e montiamo il webserver integrato PHP
            p1.terminate()
            p1.wait()
            self.processes.remove(p1)

            p_php = subprocess.Popen(
                ["php", "-S", "127.0.0.1:8000"],
                cwd=str(a_dir),  # root web è A.com
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            self.processes.append(p_php)
            print("✅ PHP server avviato su 127.0.0.1:8000 (A.com)")

            p2.terminate()
            p2.wait()
            self.processes.remove(p2)

            p_php2 = subprocess.Popen(
                ["php", "-S", "127.0.0.1:8001"],
                cwd=str(b_dir),  # root web è B.com
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            self.processes.append(p_php2)
            print("✅ PHP server avviato su 127.0.0.1:8001 (B.com)")
        else:
            print("⚠️ PHP non trovato: uso il server statico python.")

        self.running = True
        
        # Aspettiamo che la porta venga bound dal SO
        time.sleep(2)
        print("✅ Server operativi e in ascolto.")

    def stop_servers(self):
        """Uccide forzatamente i processi dei server aperti."""
        for p in self.processes:
            p.terminate()
            p.wait()
        self.running = False
        print("🛑 Server chiusi.")

# Registrazione globale di spegnimento d'emergenza
# Garantisce che quando il processo principale di python finisce (es. crash o close),
# i subprocess HTTP in background vengano killati, altrimenti le porte rimangono bindate
# in stato TIME_WAIT causando eccezioni "Address already in use" ai successivi avvii.
_cleanup = ServerManager()
atexit.register(_cleanup.stop_servers)