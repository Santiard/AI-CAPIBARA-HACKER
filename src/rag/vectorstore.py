"""
VectorStore Manager for AI-CAPIBARA-HACKER.
Handles local embedding model initialization and persistent ChromaDB collections for:
1. cve_knowledge_base (CVEs, CVSS scores, technical vulnerability details)
2. hardening_cis_benchmarks (CIS security hardening guides: Apache, SSH, Nginx, Linux)
3. internal_policies (Corporate security and compliance policies)
"""
import os
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Union

try:
    import chromadb
    from chromadb.config import Settings
    from chromadb.api.types import EmbeddingFunction
except ImportError:
    chromadb = None
    Settings = None
    EmbeddingFunction = object

from src.config import (
    CHROMA_DIR,
    OLLAMA_BASE_URL,
    OLLAMA_EMBED_MODEL,
    COLLECTION_CVES,
    COLLECTION_CIS,
    COLLECTION_POLICIES,
)

logger = logging.getLogger("ai_capibara.rag.vectorstore")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


class LocalOllamaEmbeddingFunction(EmbeddingFunction):
    """
    ChromaDB compatible Embedding Function for local Ollama instances.
    Uses nomic-embed-text (or configured model) without internet connection.
    """
    def __init__(self, base_url: str = OLLAMA_BASE_URL, model_name: str = OLLAMA_EMBED_MODEL):
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name
        self._langchain_embeddings = None
        self._init_client()

    def _init_client(self):
        try:
            from langchain_ollama import OllamaEmbeddings
            self._langchain_embeddings = OllamaEmbeddings(
                base_url=self.base_url,
                model=self.model_name
            )
            logger.info("Initialized LangChain OllamaEmbeddings with model: %s", self.model_name)
        except ImportError:
            try:
                from langchain_community.embeddings import OllamaEmbeddings
                self._langchain_embeddings = OllamaEmbeddings(
                    base_url=self.base_url,
                    model=self.model_name
                )
                logger.info("Initialized LangChain Community OllamaEmbeddings with model: %s", self.model_name)
            except ImportError:
                self._langchain_embeddings = None
                logger.warning("langchain-ollama/community not installed. Direct HTTP requests will be used.")

    def __call__(self, input: Union[str, List[str]]) -> List[List[float]]:
        if isinstance(input, str):
            input = [input]

        # Use LangChain client if available
        if self._langchain_embeddings is not None:
            try:
                return self._langchain_embeddings.embed_documents(input)
            except Exception as e:
                logger.warning("LangChain OllamaEmbeddings call failed (%s). Attempting direct HTTP request.", e)

        # Fallback to direct HTTP request using urllib (no extra dependency)
        import json
        import urllib.request
        embeddings = []
        for text in input:
            req_data = json.dumps({"model": self.model_name, "prompt": text}).encode("utf-8")
            req = urllib.request.Request(
                f"{self.base_url}/api/embeddings",
                data=req_data,
                headers={"Content-Type": "application/json"}
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as response:
                    res_json = json.loads(response.read().decode("utf-8"))
                    embeddings.append(res_json.get("embedding", []))
            except Exception as err:
                logger.error("Failed to generate embedding via Ollama HTTP API: %s", err)
                # Fallback to zero vector or fallback representation if Ollama daemon is offline
                embeddings.append([0.0] * 768)
        return embeddings


class SentenceTransformerEmbeddingFunction(EmbeddingFunction):
    """
    ChromaDB compatible Embedding Function using local Sentence-Transformers / HuggingFace.
    Operates 100% offline without requiring Ollama daemon.
    """
    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
        self.model_name = model_name
        self.model = None
        self._init_model()

    def _init_model(self):
        try:
            from sentence_transformers import SentenceTransformer
            self.model = SentenceTransformer(self.model_name)
            logger.info("Initialized SentenceTransformer model: %s", self.model_name)
        except ImportError:
            logger.warning("sentence-transformers is not installed. SentenceTransformerEmbeddingFunction will use fallback.")
            self.model = None

    def __call__(self, input: Union[str, List[str]]) -> List[List[float]]:
        if isinstance(input, str):
            input = [input]
        if self.model is not None:
            embeddings = self.model.encode(input, convert_to_numpy=True)
            return embeddings.tolist()
        
        # Fallback deterministic pseudo-embeddings for testing offline without weights
        logger.warning("SentenceTransformer model unavailable. Generating deterministic fallback embeddings.")
        dim = 384
        result = []
        for text in input:
            vec = [0.0] * dim
            for i, char in enumerate(text[:dim]):
                vec[i % dim] += (ord(char) % 100) / 100.0
            # Normalize length
            norm = sum(v * v for v in vec) ** 0.5 or 1.0
            result.append([v / norm for v in vec])
        return result


class VectorStoreManager:
    """
    Central Manager for persistent ChromaDB storage and collections in AI-CAPIBARA-HACKER.
    
    Manages three dedicated collections:
    - cve_knowledge_base: Known CVEs, CVSS v3 vectors, CWE, affected products/versions.
    - hardening_cis_benchmarks: Hardening recommendations, rules, commands and configurations.
    - internal_policies: Organizational compliance rules, authorization scopes, and SLA guidelines.
    """

    KNOWN_COLLECTIONS = {
        "cves": COLLECTION_CVES,
        "cis": COLLECTION_CIS,
        "policies": COLLECTION_POLICIES
    }

    def __init__(
        self,
        persist_directory: Optional[Union[str, Path]] = None,
        embedding_type: str = "ollama",
        embedding_model: Optional[str] = None
    ):
        """
        Initialize the VectorStoreManager.

        Args:
            persist_directory: Path to store ChromaDB data on disk. Defaults to config.CHROMA_DIR.
            embedding_type: 'ollama' or 'sentence-transformers'.
            embedding_model: Optional specific embedding model name override.
        """
        self.persist_directory = Path(persist_directory) if persist_directory else CHROMA_DIR
        self.persist_directory.mkdir(parents=True, exist_ok=True)
        self.embedding_type = embedding_type.lower()
        self.embedding_model = embedding_model or (
            OLLAMA_EMBED_MODEL if self.embedding_type == "ollama" else "sentence-transformers/all-MiniLM-L6-v2"
        )
        
        self.embedding_function = self._setup_embedding_function()
        self.client = self._init_chroma_client()
        self._collections: Dict[str, Any] = {}
        self._initialize_default_collections()

    def _setup_embedding_function(self) -> Any:
        """Configures the local embedding function according to settings."""
        if self.embedding_type == "sentence-transformers":
            return SentenceTransformerEmbeddingFunction(model_name=self.embedding_model)
        else:
            return LocalOllamaEmbeddingFunction(
                base_url=OLLAMA_BASE_URL,
                model_name=self.embedding_model
            )

    def _init_chroma_client(self) -> Any:
        """Initializes the persistent ChromaDB client."""
        if chromadb is None:
            logger.error("ChromaDB library is not installed in the current environment.")
            return None
        
        try:
            client = chromadb.PersistentClient(
                path=str(self.persist_directory),
                settings=Settings(anonymized_telemetry=False, allow_reset=True)
            )
            logger.info("ChromaDB PersistentClient initialized at: %s", self.persist_directory)
            return client
        except Exception as e:
            logger.error("Failed to initialize ChromaDB PersistentClient: %s", e)
            return None

    def _initialize_default_collections(self):
        """Pre-initializes the three core collections if ChromaDB client is ready."""
        if self.client is None:
            return
        
        for col_alias, col_name in self.KNOWN_COLLECTIONS.items():
            self.get_or_create_collection(col_name)

    def get_or_create_collection(self, collection_name: str) -> Any:
        """
        Retrieves an existing ChromaDB collection or creates it with persistent metadata.
        
        Args:
            collection_name: Name of the collection (e.g. cve_knowledge_base)
            
        Returns:
            ChromaDB Collection object or None
        """
        if self.client is None:
            logger.warning("ChromaDB client is unavailable.")
            return None

        if collection_name in self._collections:
            return self._collections[collection_name]

        try:
            collection = self.client.get_or_create_collection(
                name=collection_name,
                embedding_function=self.embedding_function,
                metadata={"hnsw:space": "cosine"}
            )
            self._collections[collection_name] = collection
            logger.info("Collection '%s' ready. Items count: %d", collection_name, collection.count())
            return collection
        except Exception as e:
            logger.error("Error creating/retrieving collection '%s': %s", collection_name, e)
            return None

    def add_documents(
        self,
        collection_name: str,
        documents: List[str],
        metadatas: Optional[List[Dict[str, Any]]] = None,
        ids: Optional[List[str]] = None
    ) -> bool:
        """
        Adds or upserts text documents with metadata to a specified collection.

        Args:
            collection_name: Target collection name.
            documents: List of raw text chunks/descriptions.
            metadatas: List of metadata dicts corresponding to documents (e.g. service, version, cve_id).
            ids: Optional list of unique IDs. Generated automatically if not provided.

        Returns:
            bool: True if insertion succeeded, False otherwise.
        """
        collection = self.get_or_create_collection(collection_name)
        if collection is None:
            return False

        if not documents:
            logger.warning("No documents provided for insertion into '%s'.", collection_name)
            return False

        import uuid
        if ids is None:
            ids = [f"{collection_name}_{uuid.uuid4().hex[:12]}" for _ in range(len(documents))]

        # Ensure metadata values are compatible with ChromaDB (strings, ints, floats, bools)
        clean_metadatas = []
        if metadatas:
            for meta in metadatas:
                cleaned = {}
                for k, v in meta.items():
                    if isinstance(v, (str, int, float, bool)):
                        cleaned[k] = v
                    elif v is None:
                        cleaned[k] = ""
                    else:
                        cleaned[k] = str(v)
                clean_metadatas.append(cleaned)
        else:
            clean_metadatas = [{} for _ in range(len(documents))]

        try:
            collection.upsert(
                documents=documents,
                metadatas=clean_metadatas,
                ids=ids
            )
            logger.info("Successfully added/upserted %d documents into '%s'.", len(documents), collection_name)
            return True
        except Exception as e:
            logger.error("Failed to add documents into '%s': %s", collection_name, e)
            return False

    def get_collection_stats(self) -> Dict[str, Any]:
        """Returns document counts and status for all managed collections."""
        stats = {
            "persist_directory": str(self.persist_directory),
            "embedding_type": self.embedding_type,
            "embedding_model": self.embedding_model,
            "collections": {}
        }
        for alias, name in self.KNOWN_COLLECTIONS.items():
            collection = self.get_or_create_collection(name)
            count = collection.count() if collection else 0
            stats["collections"][name] = {
                "alias": alias,
                "count": count,
                "status": "active" if collection else "unavailable"
            }
        return stats

    def reset_collection(self, collection_name: str) -> bool:
        """Deletes and recreates a collection to clear all data."""
        if self.client is None:
            return False
        try:
            self.client.delete_collection(name=collection_name)
            if collection_name in self._collections:
                del self._collections[collection_name]
            self.get_or_create_collection(collection_name)
            logger.info("Collection '%s' reset successfully.", collection_name)
            return True
        except Exception as e:
            logger.error("Failed to reset collection '%s': %s", collection_name, e)
            return False


# Global singleton instance for easy import across agents
_default_vectorstore_manager: Optional[VectorStoreManager] = None


def get_vectorstore_manager(
    persist_directory: Optional[Union[str, Path]] = None,
    embedding_type: str = "ollama",
    embedding_model: Optional[str] = None
) -> VectorStoreManager:
    """Returns or initializes the global VectorStoreManager instance."""
    global _default_vectorstore_manager
    if _default_vectorstore_manager is None:
        _default_vectorstore_manager = VectorStoreManager(
            persist_directory=persist_directory,
            embedding_type=embedding_type,
            embedding_model=embedding_model
        )
    return _default_vectorstore_manager
