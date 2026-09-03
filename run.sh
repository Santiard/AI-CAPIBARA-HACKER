#!/usr/bin/env bash
# ============================================================
#   🦫 Launcher para AI-CAPIBARA-HACKER
# ============================================================

if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
elif [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate
else
    echo "[!] ERROR: No se encontró el entorno virtual 'venv'."
    echo "    Ejecuta primero: ./install.sh"
    exit 1
fi

streamlit run src/ui/app.py
