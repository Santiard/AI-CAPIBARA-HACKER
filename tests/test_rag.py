"""
Pruebas Unitarias y de Integración para el módulo RAG (VectorStore, Retriever y Pipeline de Ingestión).
Verifica:
- Inicialización y administración de colecciones de VectorStoreManager
- Fallbacks de funciones de embeddings y normalización de similitud
- Funciones de búsqueda del SecurityRetriever (CVEs, CIS Benchmarks, Políticas)
- División de texto con TextSplitter y validación de esquemas de datos
"""
import sys
import os
import unittest
from pathlib import Path

# Agregar directorio raíz al sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from src.rag.vectorstore import (
    VectorStoreManager,
    LocalOllamaEmbeddingFunction,
    SentenceTransformerEmbeddingFunction,
    get_vectorstore_manager
)
from src.rag.retriever import (
    SecurityRetriever,
    _distance_to_similarity,
    query_vulnerabilities,
    query_hardening_benchmarks,
    query_internal_policies
)
from src.rag.ingest import TextSplitter, KnowledgeIngestionPipeline
from src.config import COLLECTION_CVES, COLLECTION_CIS, COLLECTION_POLICIES


class TestEmbeddingFunctions(unittest.TestCase):
    def test_sentence_transformer_embedding_fallback(self):
        """Valida que el fallback de embeddings determinista opere correctamente."""
        emb_fn = SentenceTransformerEmbeddingFunction()
        vectors = emb_fn(["Test CVE Apache 2.4.49", "SSH configuration guide"])
        self.assertEqual(len(vectors), 2)
        self.assertGreater(len(vectors[0]), 0)

    def test_ollama_embedding_fallback(self):
        """Valida que no se lancen excepciones no controladas si Ollama está offline."""
        emb_fn = LocalOllamaEmbeddingFunction(base_url="http://localhost:11434", model_name="nomic-embed-text")
        vectors = emb_fn(["Consulta de prueba"])
        self.assertEqual(len(vectors), 1)
        self.assertEqual(len(vectors[0]), 768)

    def test_distance_to_similarity(self):
        """Valida la conversión de distancia de coseno a score de similitud normalizado."""
        self.assertEqual(_distance_to_similarity(0.0), 1.0)
        self.assertEqual(_distance_to_similarity(2.0), 0.0)
        self.assertAlmostEqual(_distance_to_similarity(0.4), 0.8, places=2)
        self.assertEqual(_distance_to_similarity(None), 1.0)


class TestVectorStoreManagerMock(unittest.TestCase):
    def setUp(self):
        self.test_dir = BASE_DIR / "chroma_test_data"
        self.vsm = VectorStoreManager(
            persist_directory=self.test_dir,
            embedding_type="sentence-transformers"
        )

    def test_manager_initialization(self):
        """Verifica la configuración inicial del VectorStoreManager."""
        self.assertEqual(str(self.vsm.persist_directory), str(self.test_dir))
        self.assertEqual(self.vsm.embedding_type, "sentence-transformers")
        self.assertIn("cves", self.vsm.KNOWN_COLLECTIONS)
        self.assertIn("cis", self.vsm.KNOWN_COLLECTIONS)
        self.assertIn("policies", self.vsm.KNOWN_COLLECTIONS)

    def test_get_collection_stats(self):
        """Verifica la generación del diccionario de estadísticas."""
        stats = self.vsm.get_collection_stats()
        self.assertIn("collections", stats)
        self.assertIn(COLLECTION_CVES, stats["collections"])
        self.assertIn(COLLECTION_CIS, stats["collections"])
        self.assertIn(COLLECTION_POLICIES, stats["collections"])


class TestSecurityRetriever(unittest.TestCase):
    def setUp(self):
        self.test_dir = BASE_DIR / "chroma_test_data"
        self.vsm = VectorStoreManager(
            persist_directory=self.test_dir,
            embedding_type="sentence-transformers"
        )
        self.retriever = SecurityRetriever(vectorstore_manager=self.vsm)

    def test_query_functions_handle_empty_collections_gracefully(self):
        """Verifica que las consultas manejen colecciones vacías de forma segura sin excepciones."""
        vulns = self.retriever.query_vulnerabilities(service_name="apache", version="2.4.49", top_k=3)
        self.assertIsInstance(vulns, list)

        cis = self.retriever.query_hardening_benchmarks(service_name="ssh", os_type="linux", top_k=3)
        self.assertIsInstance(cis, list)

        policies = self.retriever.query_internal_policies(query_text="SSH port rules", top_k=3)
        self.assertIsInstance(policies, list)

        all_ctx = self.retriever.query_all_relevant_context(service_name="apache", version="2.4.49")
        self.assertIn("vulnerabilities", all_ctx)
        self.assertIn("hardening_benchmarks", all_ctx)
        self.assertIn("internal_policies", all_ctx)


class TestIngestionPipeline(unittest.TestCase):
    def setUp(self):
        self.test_dir = BASE_DIR / "chroma_test_data"
        self.vsm = VectorStoreManager(
            persist_directory=self.test_dir,
            embedding_type="sentence-transformers"
        )
        self.pipeline = KnowledgeIngestionPipeline(vectorstore_manager=self.vsm)

    def tearDown(self):
        import shutil
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_text_splitter(self):
        """Verifica la división recursiva de texto en chunks."""
        splitter = TextSplitter(chunk_size=100, chunk_overlap=20)
        sample = "Primer párrafo con información de prueba.\n\nSegundo párrafo con detalles adicionales."
        chunks = splitter.split_text(sample)
        self.assertGreaterEqual(len(chunks), 1)

    def test_cve_json_file_exists_and_valid(self):
        """Verifica la existencia y el esquema estructurado de la base de datos de CVEs."""
        cve_json = BASE_DIR / "data" / "cves" / "cves_database.json"
        self.assertTrue(cve_json.exists())
        import json
        with open(cve_json, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertGreaterEqual(len(data), 15)
        first = data[0]
        self.assertIn("cve_id", first)
        self.assertIn("service", first)
        self.assertIn("cvss_score", first)
        self.assertIn("severity", first)

    def test_benchmark_and_policy_files_exist(self):
        """Verifica la presencia de las guías de hardening CIS y políticas en disco."""
        cis_files = list((BASE_DIR / "data" / "cis_benchmarks").glob("*.md"))
        self.assertGreaterEqual(len(cis_files), 4)
        policy_files = list((BASE_DIR / "data" / "policies").glob("*.md"))
        self.assertGreaterEqual(len(policy_files), 1)


if __name__ == "__main__":
    unittest.main()
