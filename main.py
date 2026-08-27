"""
Punto de entrada principal para AI-CAPIBARA-HACKER.
Permite ejecutar el pipeline en modo CLI o lanzar la UI de Streamlit.
"""
import sys
from src.config import OLLAMA_MODEL, OLLAMA_BASE_URL

def main():
    print("=" * 60)
    print(" 🦫 AI-CAPIBARA-HACKER: Auditor de Seguridad Multi-Agente")
    print("=" * 60)
    print(f"[*] Modelo LLM: {OLLAMA_MODEL}")
    print(f"[*] Endpoint Ollama: {OLLAMA_BASE_URL}")
    print("[*] Estado: Entorno configurado correctamente.")
    print("\nPara iniciar la interfaz gráfica ejecuta:")
    print("    streamlit run src/ui/app.py")
    print("=" * 60)

if __name__ == "__main__":
    main()
