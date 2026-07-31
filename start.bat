@echo off
title Security Test Suite - Setup

set VENV_DIR=.venv

:: 1. Controlla se l'ambiente virtuale esiste, altrimenti lo crea
if not exist "%VENV_DIR%" (
    echo [1/4] Creazione ambiente virtuale in .venv ...
    python -m venv %VENV_DIR%
    if errorlevel 1 (
        echo ERRORE: Python non trovato. Assicurati che Python 3.10+ sia installato.
        pause
        exit /b 1
    )
)

:: 2. Attiva l'ambiente virtuale
echo [2/4] Attivazione ambiente virtuale...
call %VENV_DIR%\Scripts\activate.bat

:: 3. Installa le dipendenze (se requirements.txt è più nuovo o mancano pacchetti)
echo [3/4] Installazione dipendenze da requirements.txt ...
pip install -r requirements.txt

:: 4. Installa i browser Playwright (necessario per browser-use)
echo [4/4] Installazione browser Playwright...
playwright install

:: 5. Avvia il tool
echo.
echo ✅ Pronto! Avvio del tool...
python main.py

:: Pausa solo se il tool si chiude con errore
if errorlevel 1 (
    echo.
    echo ❌ Il tool si è chiuso con un errore.
    pause
)