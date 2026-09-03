#!/usr/bin/env bash
# ============================================================
#   🦫 AI-CAPIBARA-HACKER - Script de Instalación Automática
#   Para Linux, macOS y Git Bash
# ============================================================

set -e

echo "============================================================"
echo "  🦫 AI-CAPIBARA-HACKER - Script de Instalación Automática"
echo "============================================================"
echo ""

# 1. Comprobar comando Python
if command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
elif command -v python &>/dev/null; then
    PYTHON_CMD="python"
else
    echo "[!] ERROR: No se encontró Python en el sistema."
    echo "    Por favor instala Python 3.10 o superior."
    exit 1
fi

echo "[*] Python detectado: $($PYTHON_CMD --version)"

# 2. Crear entorno virtual si no existe
if [ ! -d "venv" ]; then
    echo "[*] Creando entorno virtual 'venv'..."
    $PYTHON_CMD -m venv venv
    echo "[OK] Entorno virtual creado."
else
    echo "[*] Entorno virtual 'venv' ya existe."
fi

# 3. Activar entorno virtual
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
elif [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate
else
    echo "[!] No se pudo encontrar el script de activación del venv."
    exit 1
fi

# 4. Copiar .env si no existe
if [ ! -f ".env" ] && [ -f ".env.example" ]; then
    echo "[*] Configurando variables de entorno (.env)..."
    cp .env.example .env
    echo "[OK] .env creado desde .env.example."
fi

# 5. Instalar dependencias
echo "[*] Actualizando pip e instalando dependencias..."
pip install --upgrade pip
pip install -r requirements.txt
echo "[OK] Dependencias instaladas correctamente."

# 6. Comprobar Ollama y modelos
echo ""
echo "============================================================"
echo "  Verificando configuración de Ollama y Modelos"
echo "============================================================"
if command -v ollama &>/dev/null; then
    echo "[*] Ollama detectado en el sistema."
    echo "[*] Descargando/Verificando modelo LLM (qwen2.5:14b)..."
    ollama pull qwen2.5:14b || echo "[!] Advertencia al descargar qwen2.5:14b"
    echo "[*] Descargando/Verificando modelo de Embeddings (nomic-embed-text)..."
    ollama pull nomic-embed-text || echo "[!] Advertencia al descargar nomic-embed-text"
    echo "[OK] Modelos de Ollama listos."
else
    echo "[!] AVISO: 'ollama' no fue detectado en el PATH."
    echo "    Instala Ollama desde https://ollama.com/ y descarga:"
    echo "      ollama pull qwen2.5:14b"
    echo "      ollama pull nomic-embed-text"
fi

# 7. Ingestión RAG
echo ""
echo "============================================================"
echo "  Inicializando Base Vectorial Local (ChromaDB)"
echo "============================================================"
echo "[*] Ingestando CVEs, guías CIS y políticas corporativas..."
python src/rag/ingest.py || echo "[!] Advertencia al procesar la base vectorial."

echo ""
echo "============================================================"
echo "  🎉 INSTALACIÓN COMPLETADA EXITOSAMENTE"
echo "============================================================"
echo "Para iniciar la aplicación ejecuta:"
echo "   ./run.sh"
echo "O manualmente:"
echo "   source venv/bin/activate (o source venv/Scripts/activate)"
echo "   streamlit run src/ui/app.py"
echo "============================================================"
echo ""
