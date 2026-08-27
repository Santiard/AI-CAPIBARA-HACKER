"""
Configuración centralizada del sistema AI-CAPIBARA-HACKER.
Carga variables de entorno desde .env con valores por defecto seguros.
"""
import os
from pathlib import Path
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # Minimal fallback parser if dotenv is not yet installed
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.exists():
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())

# Rutas base del proyecto
BASE_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = BASE_DIR / "src"
DATA_DIR = BASE_DIR / "data"
SCANS_DIR = DATA_DIR / "scans"
CVES_DIR = DATA_DIR / "cves"
CIS_DIR = DATA_DIR / "cis_benchmarks"
POLICIES_DIR = DATA_DIR / "policies"
CHROMA_DIR = BASE_DIR / os.getenv("CHROMA_PERSIST_DIR", "chroma_data")

# Configuración Ollama
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:14b")
OLLAMA_EMBED_MODEL = os.getenv("OLLAMA_EMBEDDING_MODEL", "nomic-embed-text")
OLLAMA_TEMPERATURE = float(os.getenv("OLLAMA_TEMPERATURE", "0.2"))

# Configuración Colecciones ChromaDB
COLLECTION_CVES = os.getenv("COLLECTION_CVES", "cve_knowledge_base")
COLLECTION_CIS = os.getenv("COLLECTION_CIS", "hardening_cis_benchmarks")
COLLECTION_POLICIES = os.getenv("COLLECTION_POLICIES", "internal_policies")

# Flags de Ejecución
MAX_CONTEXT_TOKENS = int(os.getenv("MAX_CONTEXT_TOKENS", "8192"))
ENABLE_CRITIC = os.getenv("ENABLE_CRITIC_VALIDATION", "true").lower() == "true"
DEBUG_MODE = os.getenv("DEBUG_MODE", "true").lower() == "true"
