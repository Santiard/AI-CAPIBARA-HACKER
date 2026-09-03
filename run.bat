@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo   🦫 Iniciando AI-CAPIBARA-HACKER Cyber Dashboard...
echo ============================================================

if not exist "venv" (
    echo [!] ERROR: El entorno virtual 'venv' no existe.
    echo     Ejecuta primero: install.bat
    pause
    exit /b 1
)

call .\venv\Scripts\activate.bat
streamlit run src/ui/app.py
pause
