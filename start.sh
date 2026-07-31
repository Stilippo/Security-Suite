#!/bin/bash

VENV_DIR=".venv"

echo "[1/4] Controllo ambiente virtuale..."

if [ ! -d "$VENV_DIR" ]; then
    echo "   Creazione ambiente virtuale in .venv ..."
    python3 -m venv $VENV_DIR
    if [ $? -ne 0 ]; then
        echo "ERRORE: Python non trovato. Assicurati che Python 3.10+ sia installato."
        exit 1
    fi
fi

echo "[2/4] Attivazione ambiente virtuale..."
source $VENV_DIR/bin/activate

echo "[3/4] Installazione dipendenze da requirements.txt ..."
pip install -r requirements.txt

echo "[4/4] Installazione browser Playwright..."
playwright install

echo ""
echo "✅ Pronto! Avvio del tool..."
python main.py