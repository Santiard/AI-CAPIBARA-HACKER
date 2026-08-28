"""
Módulo de Recuperación (Retriever) para AI-CAPIBARA-HACKER.
Proporciona funciones de búsqueda semántica e híbrida sobre las colecciones persistentes de ChromaDB:
- query_vulnerabilities (service_name, version)
- query_hardening_benchmarks (service_name, os_name)
- query_internal_policies (query_text)
- query_all_relevant_context (búsqueda unificada multi-colección)
"""
import re
import logging
from typing import List, Dict, Any, Optional, Union

from src.rag.vectorstore import VectorStoreManager, get_vectorstore_manager
from src.config import COLLECTION_CVES, COLLECTION_CIS, COLLECTION_POLICIES

logger = logging.getLogger("ai_capibara.rag.retriever")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


def _distance_to_similarity(distance: Optional[float]) -> float:
    """
    Convierte la distancia de ChromaDB (coseno o L2) en un score de similitud normalizado entre 0.0 y 1.0.
    El rango de distancia de coseno es [0.0, 2.0] donde 0.0 indica vectores idénticos.
    """
    if distance is None:
        return 1.0
    sim = max(0.0, min(1.0, 1.0 - (distance / 2.0)))
    return round(sim, 4)


class SecurityRetriever:
    """
    Motor de recuperación que implementa búsqueda híbrida, filtrado por metadatos y
    enriquecimiento de contexto para los agentes de auditoría de AI-CAPIBARA-HACKER.
    """

    def __init__(self, vectorstore_manager: Optional[VectorStoreManager] = None):
        """
        Inicializa el SecurityRetriever.
        
        Args:
            vectorstore_manager: Instancia opcional de VectorStoreManager.
        """
        self.vsm = vectorstore_manager or get_vectorstore_manager()

    def hybrid_search(
        self,
        collection_name: str,
        query_text: str,
        where_filter: Optional[Dict[str, Any]] = None,
        top_k: int = 5,
        min_score: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """
        Ejecuta una búsqueda híbrida: combina filtrado por metadatos exactos con búsqueda semántica vectorial.
        Si el filtrado estricto arroja menos resultados que top_k, complementa con búsqueda semántica amplia.

        Args:
            collection_name: Nombre de la colección objetivo en ChromaDB.
            query_text: Texto de consulta para búsqueda semántica.
            where_filter: Diccionario de filtrado de metadatos opcional (ej. {"service": "apache"}).
            top_k: Número máximo de resultados a retornar.
            min_score: Umbral mínimo opcional de similitud (0.0 a 1.0).

        Returns:
            Lista de fragmentos estructurados ordenados por score de similitud.
        """
        collection = self.vsm.get_or_create_collection(collection_name)
        if collection is None:
            logger.warning("La colección '%s' no está disponible para búsqueda.", collection_name)
            return []

        try:
            if collection.count() == 0:
                logger.debug("La colección '%s' tiene 0 documentos.", collection_name)
                return []
        except Exception:
            pass

        results: List[Dict[str, Any]] = []
        seen_ids = set()

        # Paso 1: Búsqueda semántica filtrada por metadatos (si se definió filtro)
        if where_filter:
            try:
                filtered_query_results = collection.query(
                    query_texts=[query_text],
                    n_results=min(top_k, collection.count()),
                    where=where_filter,
                    include=["documents", "metadatas", "distances"]
                )
                results.extend(self._format_chroma_results(filtered_query_results, collection_name, seen_ids))
            except Exception as e:
                logger.warning("Búsqueda con filtro falló en colección '%s': %s", collection_name, e)

        # Paso 2: Búsqueda semántica amplia para completar top_k o tolerancia a variaciones
        remaining = top_k - len(results)
        if remaining > 0:
            try:
                broad_query_results = collection.query(
                    query_texts=[query_text],
                    n_results=min(top_k * 2, collection.count()),
                    include=["documents", "metadatas", "distances"]
                )
                broad_formatted = self._format_chroma_results(broad_query_results, collection_name, seen_ids)
                results.extend(broad_formatted)
            except Exception as e:
                logger.error("Búsqueda semántica amplia falló en colección '%s': %s", collection_name, e)

        # Ordenar de forma descendente por score de similitud
        results.sort(key=lambda x: x.get("similarity_score", 0.0), reverse=True)

        # Aplicar umbral de score mínimo si se solicitó
        if min_score is not None:
            results = [r for r in results if r.get("similarity_score", 0.0) >= min_score]

        return results[:top_k]

    def _format_chroma_results(
        self,
        raw_results: Dict[str, Any],
        collection_name: str,
        seen_ids: set
    ) -> List[Dict[str, Any]]:
        """Formatea los resultados crudos de ChromaDB en diccionarios limpios y estandarizados."""
        formatted = []
        ids_list = raw_results.get("ids", [[]])[0] if raw_results.get("ids") else []
        docs_list = raw_results.get("documents", [[]])[0] if raw_results.get("documents") else []
        metas_list = raw_results.get("metadatas", [[]])[0] if raw_results.get("metadatas") else []
        dists_list = raw_results.get("distances", [[]])[0] if raw_results.get("distances") else []

        for i in range(len(ids_list)):
            doc_id = ids_list[i]
            if doc_id in seen_ids:
                continue
            seen_ids.add(doc_id)

            content = docs_list[i] if i < len(docs_list) else ""
            meta = metas_list[i] if i < len(metas_list) and metas_list[i] else {}
            dist = dists_list[i] if i < len(dists_list) else None
            similarity = _distance_to_similarity(dist)

            formatted.append({
                "id": doc_id,
                "collection": collection_name,
                "content": content,
                "metadata": meta,
                "similarity_score": similarity,
                "distance": dist,
                # Atajos de campos clave para los prompts de los agentes
                "service": meta.get("service", ""),
                "version": meta.get("version", ""),
                "cve_id": meta.get("cve_id", meta.get("id", "")),
                "cvss_score": meta.get("cvss_score", meta.get("cvss", "")),
                "severity": meta.get("severity", "UNKNOWN")
            })

        return formatted

    def query_vulnerabilities(
        self,
        service_name: str,
        version: Optional[str] = None,
        top_k: int = 5,
        min_score: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """
        Consulta la base de CVEs en busca de vulnerabilidades conocidas, métricas CVSS y exploits
        coincidentes con el servicio y versión detectados.

        Args:
            service_name: Nombre del servicio de red (ej. 'apache', 'openssh', 'nginx', 'vsftpd').
            version: Cadena de versión opcional (ej. '2.4.49', '8.2p1').
            top_k: Número máximo de vulnerabilidades a retornar.
            min_score: Umbral mínimo de similitud.

        Returns:
            Lista de registros CVE con contenido técnico, CVSS y score de similitud.
        """
        service_clean = (service_name or "").strip().lower()
        version_clean = (version or "").strip()

        # Construir prompt de búsqueda enriquecido con contexto de seguridad
        if version_clean:
            query_text = (
                f"Security vulnerabilities, CVE exploits, remote code execution, CVSS vectors, "
                f"and security advisories affecting {service_clean} version {version_clean}."
            )
        else:
            query_text = (
                f"Known security vulnerabilities, common CVEs, CVSS ratings, and attack vectors "
                f"for service {service_clean}."
            )

        # Filtro de metadatos por servicio si está presente
        where_filter = None
        if service_clean:
            where_filter = {"service": service_clean}

        logger.info("Ejecutando query_vulnerabilities para servicio='%s', version='%s'", service_clean, version_clean)
        return self.hybrid_search(
            collection_name=COLLECTION_CVES,
            query_text=query_text,
            where_filter=where_filter,
            top_k=top_k,
            min_score=min_score
        )

    def query_hardening_benchmarks(
        self,
        service_name: str,
        os_type: Optional[str] = None,
        top_k: int = 5,
        min_score: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """
        Consulta las guías oficiales de CIS Benchmarks para configuración segura de servicios
        (ej. Apache, SSH, Nginx, Linux OS, Bases de Datos).

        Args:
            service_name: Nombre del servicio o tópico (ej. 'ssh', 'apache', 'nginx', 'linux').
            os_type: Sistema operativo objetivo opcional (ej. 'linux', 'ubuntu').
            top_k: Número máximo de recomendaciones a retornar.
            min_score: Umbral mínimo de similitud.

        Returns:
            Lista de fragmentos de guías CIS con pasos de remediación.
        """
        service_clean = (service_name or "").strip().lower()
        os_clean = (os_type or "").strip().lower()

        if os_clean:
            query_text = (
                f"CIS benchmark hardening rules, secure configuration parameters, "
                f"remediation guide, and configuration best practices for {service_clean} on {os_clean}."
            )
            where_filter = {"service": service_clean} if service_clean else {"os": os_clean}
        else:
            query_text = (
                f"Official CIS Benchmark hardening guidelines, configuration hardening parameters, "
                f"and security controls for {service_clean}."
            )
            where_filter = {"service": service_clean} if service_clean else None

        logger.info("Ejecutando query_hardening_benchmarks para servicio='%s', os='%s'", service_clean, os_clean)
        return self.hybrid_search(
            collection_name=COLLECTION_CIS,
            query_text=query_text,
            where_filter=where_filter,
            top_k=top_k,
            min_score=min_score
        )

    def query_internal_policies(
        self,
        query_text: str,
        top_k: int = 5,
        min_score: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """
        Consulta las políticas internas de seguridad corporativa, alcances de auditoría y SLAs de remediación.

        Args:
            query_text: Descripción en lenguaje natural del tema o regla a consultar.
            top_k: Número máximo de reglas de política a retornar.
            min_score: Umbral mínimo de similitud.

        Returns:
            Lista de cláusulas y requisitos de las políticas internas.
        """
        enhanced_query = (
            f"Organizational security policy, corporate compliance requirement, "
            f"auditing scope, and remediation SLA regarding: {query_text}"
        )
        logger.info("Ejecutando query_internal_policies para tema='%s'", query_text)
        return self.hybrid_search(
            collection_name=COLLECTION_POLICIES,
            query_text=enhanced_query,
            where_filter=None,
            top_k=top_k,
            min_score=min_score
        )

    def query_all_relevant_context(
        self,
        service_name: str,
        version: Optional[str] = None,
        os_type: Optional[str] = None,
        top_k_per_category: int = 3
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Consolida la información de seguridad relevante a través de las 3 bases de conocimiento:
        1. CVEs y Vulnerabilidades
        2. Guías de Hardening CIS Benchmarks
        3. Políticas Internas Corporativas

        Args:
            service_name: Nombre del servicio detectado.
            version: Cadena de versión detectada.
            os_type: Sistema operativo opcional.
            top_k_per_category: Cantidad de resultados por categoría.

        Returns:
            Diccionario estructurado con los resultados categorizados.
        """
        cves = self.query_vulnerabilities(service_name=service_name, version=version, top_k=top_k_per_category)
        cis = self.query_hardening_benchmarks(service_name=service_name, os_type=os_type, top_k=top_k_per_category)
        policies = self.query_internal_policies(query_text=f"{service_name} policy requirements and port exposure", top_k=top_k_per_category)

        return {
            "vulnerabilities": cves,
            "hardening_benchmarks": cis,
            "internal_policies": policies
        }


# Instancia singleton del retriever por defecto para llamadas directas
_default_retriever: Optional[SecurityRetriever] = None


def get_retriever() -> SecurityRetriever:
    """Retorna o inicializa la instancia global de SecurityRetriever."""
    global _default_retriever
    if _default_retriever is None:
        _default_retriever = SecurityRetriever()
    return _default_retriever


def query_vulnerabilities(
    service_name: str,
    version: Optional[str] = None,
    top_k: int = 5,
    min_score: Optional[float] = None
) -> List[Dict[str, Any]]:
    """Función de conveniencia para consultar vulnerabilidades CVE."""
    return get_retriever().query_vulnerabilities(
        service_name=service_name,
        version=version,
        top_k=top_k,
        min_score=min_score
    )


def query_hardening_benchmarks(
    service_name: str,
    os_type: Optional[str] = None,
    top_k: int = 5,
    min_score: Optional[float] = None
) -> List[Dict[str, Any]]:
    """Función de conveniencia para consultar guías de endurecimiento CIS."""
    return get_retriever().query_hardening_benchmarks(
        service_name=service_name,
        os_type=os_type,
        top_k=top_k,
        min_score=min_score
    )


def query_internal_policies(
    query_text: str,
    top_k: int = 5,
    min_score: Optional[float] = None
) -> List[Dict[str, Any]]:
    """Función de conveniencia para consultar políticas internas corporativas."""
    return get_retriever().query_internal_policies(
        query_text=query_text,
        top_k=top_k,
        min_score=min_score
    )
