@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo   🦫 AI-CAPIBARA-HACKER - Script de Instalacion Automatica
echo ============================================================
echo.

:: 1. Verificar si Python esta instalado
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] ERROR: Python no fue encontrado en el PATH.
    echo     Por favor instala Python 3.10 o superior desde https://www.python.org/
    pause
    exit /b 1
)

echo [*] Python detectado correctamente.

:: 2. Crear entorno virtual si no existe
if not exist "venv" (
    echo [*] Creando entorno virtual 'venv'...
    python -m venv venv
    if %ERRORLEVEL% NEQ 0 (
        echo [!] ERROR al crear el entorno virtual.
        pause
        exit /b 1
    )
    echo [OK] Entorno virtual creado.
) else (
    echo [*] Entorno virtual 'venv' ya existe.
)

:: 3. Activar entorno virtual
call .\venv\Scripts\activate.bat

:: 4. Copiar archivo .env si no existe
if not exist ".env" (
    if exist ".env.example" (
        echo [*] Configurando archivo de variables de entorno (.env)...
        copy .env.example .env >nul
        echo [OK] .env creado desde .env.example.
    )
)

:: 5. Instalar dependencias de Python
echo [*] Actualizando pip e instalando dependencias...
python -m pip install --upgrade pip
pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
    echo [!] ERROR instalando dependencias de Python.
    pause
    exit /b 1
)
echo [OK] Dependencias instaladas correctamente.

:: 6. Verificar Ollama y descargar modelos
echo.
echo ============================================================
echo   Verificando configuracion de Ollama y Modelos
echo ============================================================
where ollama >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [*] Ollama detectado en el sistema.
    echo [*] Descargando/Verificando modelo LLM (qwen2.5:14b)...
    ollama pull qwen2.5:14b
    echo [*] Descargando/Verificando modelo de Embeddings (nomic-embed-text)...
    ollama pull nomic-embed-text
    echo [OK] Modelos de Ollama listos.
) else (
    echo [!] AVISO: 'ollama' no fue detectado en el PATH.
    echo     Asegurate de instalar Ollama desde https://ollama.com/ y descargar:
    echo       ollama pull qwen2.5:14b
    echo       ollama pull nomic-embed-text
)

:: 7. Ingesta de la Base de Conocimiento RAG
echo.
echo ============================================================
echo   Inicializando Base Vectorial Local (ChromaDB)
echo ============================================================
echo [*] Ingestando CVEs, guias CIS y politicas corporativas...
python src\rag\ingest.py
if %ERRORLEVEL% NEQ 0 (
    echo [!] AVISO: Hubo un inconveniente al inicializar la base vectorial.
    echo     Puedes ejecutarla manualmente despues con: python src\rag\ingest.py
) else (
    echo [OK] Base de conocimiento vectorial lista.
)

echo.
echo ============================================================
echo   🎉 INSTALACION COMPLETADA EXITOSAMENTE
echo ============================================================
echo Para iniciar la aplicacion ejecuta:
echo    .\run.bat
echo O manualmente:
echo    .\venv\Scripts\activate
echo    streamlit run src/ui/app.py
echo ============================================================
echo.
pause
