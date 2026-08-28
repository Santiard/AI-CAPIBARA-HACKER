"""
Módulo de RAG y Base de Conocimiento para AI-CAPIBARA-HACKER.
Exporta VectorStoreManager, SecurityRetriever, funciones de consulta y el pipeline de ingestión.
"""
from src.rag.vectorstore import (
    VectorStoreManager,
    LocalOllamaEmbeddingFunction,
    SentenceTransformerEmbeddingFunction,
    get_vectorstore_manager
)
from src.rag.retriever import (
    SecurityRetriever,
    get_retriever,
    query_vulnerabilities,
    query_hardening_benchmarks,
    query_internal_policies
)
from src.rag.ingest import KnowledgeIngestionPipeline

__all__ = [
    "VectorStoreManager",
    "LocalOllamaEmbeddingFunction",
    "SentenceTransformerEmbeddingFunction",
    "get_vectorstore_manager",
    "SecurityRetriever",
    "get_retriever",
    "query_vulnerabilities",
    "query_hardening_benchmarks",
    "query_internal_policies",
    "KnowledgeIngestionPipeline"
]
