"""
Gestor de VectorStore para AI-CAPIBARA-HACKER.
Maneja la inicialización de modelos de embeddings locales y colecciones persistentes de ChromaDB:
1. cve_knowledge_base (Vulnerabilidades técnicas, CVSS, descripciones)
2. hardening_cis_benchmarks (Guías oficiales de configuración segura: Apache, SSH, Nginx, Linux)
3. internal_policies (Políticas corporativas de la empresa auditada)
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
    Función de embeddings compatible con ChromaDB para instancias locales de Ollama.
    Utiliza nomic-embed-text (o el modelo configurado) sin requerir conexión a internet.
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
            logger.info("LangChain OllamaEmbeddings inicializado con modelo: %s", self.model_name)
        except ImportError:
            try:
                from langchain_community.embeddings import OllamaEmbeddings
                self._langchain_embeddings = OllamaEmbeddings(
                    base_url=self.base_url,
                    model=self.model_name
                )
                logger.info("LangChain Community OllamaEmbeddings inicializado con modelo: %s", self.model_name)
            except ImportError:
                self._langchain_embeddings = None
                logger.warning("langchain-ollama/community no disponible. Se usarán peticiones HTTP directas.")

    def __call__(self, input: Union[str, List[str]]) -> List[List[float]]:
        if isinstance(input, str):
            input = [input]

        # Usar cliente de LangChain si está disponible
        if self._langchain_embeddings is not None:
            try:
                return self._langchain_embeddings.embed_documents(input)
            except Exception as e:
                logger.warning("Fallo al conectar con LangChain OllamaEmbeddings (%s). Intentando HTTP directo.", e)

        # Fallback a petición HTTP directa usando urllib (sin dependencias externas)
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
                logger.error("Error al generar embedding mediante API HTTP de Ollama: %s", err)
                # Vector de respaldo si el servicio de Ollama no está en ejecución
                embeddings.append([0.0] * 768)
        return embeddings


class SentenceTransformerEmbeddingFunction(EmbeddingFunction):
    """
    Función de embeddings compatible con ChromaDB usando Sentence-Transformers / HuggingFace local.
    Opera 100% offline sin requerir el daemon de Ollama.
    """
    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
        self.model_name = model_name
        self.model = None
        self._init_model()

    def _init_model(self):
        try:
            from sentence_transformers import SentenceTransformer
            self.model = SentenceTransformer(self.model_name)
            logger.info("Modelo SentenceTransformer inicializado: %s", self.model_name)
        except ImportError:
            logger.warning("sentence-transformers no está instalado. Se utilizará el fallback determinista.")
            self.model = None

    def __call__(self, input: Union[str, List[str]]) -> List[List[float]]:
        if isinstance(input, str):
            input = [input]
        if self.model is not None:
            embeddings = self.model.encode(input, convert_to_numpy=True)
            return embeddings.tolist()
        
        # Fallback determinista para pruebas locales sin librerías de modelos pesados
        logger.warning("Modelo SentenceTransformer no disponible. Generando embeddings deterministas de respaldo.")
        dim = 384
        result = []
        for text in input:
            vec = [0.0] * dim
            for i, char in enumerate(text[:dim]):
                vec[i % dim] += (ord(char) % 100) / 100.0
            # Normalización de norma Euclidiana
            norm = sum(v * v for v in vec) ** 0.5 or 1.0
            result.append([v / norm for v in vec])
        return result


class VectorStoreManager:
    """
    Gestor centralizado de base vectorial persistente con ChromaDB para AI-CAPIBARA-HACKER.
    
    Administra tres colecciones dedicadas:
    - cve_knowledge_base: CVEs conocidos, vectores CVSS v3, CWEs, versiones afectadas.
    - hardening_cis_benchmarks: Recomendaciones de hardening CIS, reglas y configuraciones seguras.
    - internal_policies: Políticas internas corporativas, alcances de auditoría y SLAs de remediación.
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
        Inicializa el VectorStoreManager.

        Args:
            persist_directory: Ruta en disco para persistencia de ChromaDB.
            embedding_type: 'ollama' o 'sentence-transformers'.
            embedding_model: Nombre del modelo de embeddings opcional.
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
        """Configura la función de embeddings locales según la configuración elegida."""
        if self.embedding_type == "sentence-transformers":
            return SentenceTransformerEmbeddingFunction(model_name=self.embedding_model)
        else:
            return LocalOllamaEmbeddingFunction(
                base_url=OLLAMA_BASE_URL,
                model_name=self.embedding_model
            )

    def _init_chroma_client(self) -> Any:
        """Inicializa el cliente persistente de ChromaDB en disco."""
        if chromadb is None:
            logger.error("La librería ChromaDB no está instalada en el entorno actual.")
            return None
        
        try:
            client = chromadb.PersistentClient(
                path=str(self.persist_directory),
                settings=Settings(anonymized_telemetry=False, allow_reset=True)
            )
            logger.info("ChromaDB PersistentClient inicializado en: %s", self.persist_directory)
            return client
        except Exception as e:
            logger.error("Error al inicializar PersistentClient de ChromaDB: %s", e)
            return None

    def _initialize_default_collections(self):
        """Pre-inicializa las 3 colecciones base del sistema si ChromaDB está disponible."""
        if self.client is None:
            return
        
        for col_alias, col_name in self.KNOWN_COLLECTIONS.items():
            self.get_or_create_collection(col_name)

    def get_or_create_collection(self, collection_name: str) -> Any:
        """
        Obtiene una colección existente o la crea con distancia de coseno en ChromaDB.
        
        Args:
            collection_name: Nombre de la colección (ej. cve_knowledge_base)
            
        Returns:
            Objeto Collection de ChromaDB o None
        """
        if self.client is None:
            logger.warning("El cliente de ChromaDB no se encuentra disponible.")
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
            logger.info("Colección '%s' lista. Total documentos: %d", collection_name, collection.count())
            return collection
        except Exception as e:
            logger.error("Error al crear/obtener la colección '%s': %s", collection_name, e)
            return None

    def add_documents(
        self,
        collection_name: str,
        documents: List[str],
        metadatas: Optional[List[Dict[str, Any]]] = None,
        ids: Optional[List[str]] = None
    ) -> bool:
        """
        Inserta o actualiza (upsert) documentos con metadatos estructurados en una colección.

        Args:
            collection_name: Nombre de la colección destino.
            documents: Lista de textos/fragmentos.
            metadatas: Lista de diccionarios de metadatos (ej. servicio, versión, cve_id).
            ids: Lista opcional de identificadores únicos.

        Returns:
            bool: True si la inserción fue exitosa, False en caso contrario.
        """
        collection = self.get_or_create_collection(collection_name)
        if collection is None:
            return False

        if not documents:
            logger.warning("No se proporcionaron documentos para insertar en '%s'.", collection_name)
            return False

        import uuid
        if ids is None:
            ids = [f"{collection_name}_{uuid.uuid4().hex[:12]}" for _ in range(len(documents))]

        # Sanitizar metadatos para compatibilidad estricta con ChromaDB
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
            logger.info("Se agregaron/actualizaron %d documentos en '%s'.", len(documents), collection_name)
            return True
        except Exception as e:
            logger.error("Error al agregar documentos en '%s': %s", collection_name, e)
            return False

    def get_collection_stats(self) -> Dict[str, Any]:
        """Retorna estadísticas del conteo de documentos por cada colección."""
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
        """Elimina y vuelve a crear una colección para vaciar su contenido."""
        if self.client is None:
            return False
        try:
            self.client.delete_collection(name=collection_name)
            if collection_name in self._collections:
                del self._collections[collection_name]
            self.get_or_create_collection(collection_name)
            logger.info("Colección '%s' reiniciada exitosamente.", collection_name)
            return True
        except Exception as e:
            logger.error("Error al reiniciar la colección '%s': %s", collection_name, e)
            return False


# Instancia singleton global para facilitar la importación en los agentes
_default_vectorstore_manager: Optional[VectorStoreManager] = None


def get_vectorstore_manager(
    persist_directory: Optional[Union[str, Path]] = None,
    embedding_type: str = "ollama",
    embedding_model: Optional[str] = None
) -> VectorStoreManager:
    """Retorna o inicializa la instancia global de VectorStoreManager."""
    global _default_vectorstore_manager
    if _default_vectorstore_manager is None:
        _default_vectorstore_manager = VectorStoreManager(
            persist_directory=persist_directory,
            embedding_type=embedding_type,
            embedding_model=embedding_model
        )
    return _default_vectorstore_manager
