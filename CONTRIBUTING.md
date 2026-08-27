# 🤝 Guía de Desarrollo en Equipo y Ramas

Esta guía resume la asignación de módulos y el flujo de trabajo con Git para el equipo de desarrollo.

---

## 👥 Asignación de Módulos

### 🧭 Dev 1: Orquestación Multi-Agente & UI
- **Ramas:** `feat/langgraph-orchestrator`, `feat/streamlit-dashboard`
- **Archivos:** `src/agents/*`, `src/ui/*`
- **Tareas clave:**
  1. Definir el estado global (`state.py`) y system prompts (`prompts.py`).
  2. Implementar el grafo de LangGraph con soporte para Ollama (`qwen2.5:14b`).
  3. Lógica del Agente Crítico / QA y Sliding Window de contexto.
  4. Interfaz interactiva en Streamlit para la presentación en clase.

---

### 📚 Dev 2: RAG & Base de Conocimiento (CVE / CIS)
- **Ramas:** `feat/rag-vectorstore`, `feat/cve-cis-dataset`
- **Archivos:** `src/rag/*`, `data/cves/*`, `data/cis_benchmarks/*`, `data/policies/*`
- **Tareas clave:**
  1. Inicializar ChromaDB y embeddings locales con `nomic-embed-text`.
  2. Crear datasets de prueba con vulnerabilidades (CVEs) y guías de hardening (CIS).
  3. Script de ingestión automática (`ingest.py`).
  4. Funciones de búsqueda híbrida y filtrado por servicios/versiones.

---

### ⚙️ Dev 3: Tools, Parsers & Generador de Reportes
- **Ramas:** `feat/nmap-xml-parser`, `feat/pdf-report-generator`
- **Archivos:** `src/tools/*`, `src/utils/*`, `data/scans/*`
- **Tareas clave:**
  1. Parser de escaneos de Nmap en XML y JSON (`nmap_parser.py`).
  2. Cálculo de métricas de severidad CVSS v3.
  3. Creación de muestras realistas de escaneo (`sample_scan.xml`).
  4. Generador de reportes consolidados en Markdown y PDF descargable.

---

## 📋 Flujo de Trabajo con Git

1. **Actualizar `main` antes de comenzar:**
   ```bash
   git checkout main
   git pull origin main
   ```
2. **Crear tu rama de trabajo:**
   ```bash
   git checkout -b feat/nombre-de-tu-modulo
   ```
3. **Guardar tus avances con commits claros:**
   ```bash
   git add .
   git commit -m "feat(modulo): descripcion de lo que hiciste"
   ```
4. **Subir tu rama a GitHub:**
   ```bash
   git push -u origin feat/nombre-de-tu-modulo
   ```
5. **Abrir Pull Request (PR) en GitHub para revisión y unir a `main`.**
