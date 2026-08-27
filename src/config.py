"""
Configuración centralizada del sistema AI-CAPIBARA-HACKER.
Carga variables de entorno desde .env con valores por defecto seguros.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Cargar .env si existe
load_dotenv()

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
