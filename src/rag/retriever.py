"""
Retriever Module for AI-CAPIBARA-HACKER.
Provides semantic and hybrid search functions across persistent ChromaDB collections:
- query_vulnerabilities (service_name, version)
- query_hardening_benchmarks (service_name, os_name)
- query_internal_policies (query_text)
- query_all_relevant_context (aggregated multi-collection retrieval)
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
    Converts ChromaDB distance (cosine or L2) to a normalized similarity score between 0.0 and 1.0.
    Cosine distance range is [0.0, 2.0] where 0.0 means identical vectors.
    """
    if distance is None:
        return 1.0
    # For cosine distance: similarity = 1 - (distance / 2) or 1 / (1 + distance)
    # 1 - (distance / 2) mapped to [0, 1]
    sim = max(0.0, min(1.0, 1.0 - (distance / 2.0)))
    return round(sim, 4)


class SecurityRetriever:
    """
    Retrieval engine providing hybrid search, metadata filtering and contextual enrichment
    for AI-CAPIBARA-HACKER security auditing agents.
    """

    def __init__(self, vectorstore_manager: Optional[VectorStoreManager] = None):
        """
        Initialize the SecurityRetriever.
        
        Args:
            vectorstore_manager: Optional VectorStoreManager instance. Defaults to global manager.
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
        Performs hybrid retrieval: combines structured metadata filtering with semantic search.
        If metadata filtering yields fewer than top_k results, falls back seamlessly to semantic search.

        Args:
            collection_name: Target ChromaDB collection name.
            query_text: Natural language query string for semantic vector search.
            where_filter: Optional ChromaDB metadata filter dictionary (e.g. {"service": "apache"}).
            top_k: Maximum number of snippets to return.
            min_score: Optional minimum similarity threshold (0.0 to 1.0).

        Returns:
            List of parsed result dictionaries sorted by similarity score.
        """
        collection = self.vsm.get_or_create_collection(collection_name)
        if collection is None:
            logger.warning("Collection '%s' is unavailable for retrieval.", collection_name)
            return []

        # Check if collection is empty
        try:
            if collection.count() == 0:
                logger.debug("Collection '%s' has 0 documents.", collection_name)
                return []
        except Exception:
            pass

        results: List[Dict[str, Any]] = []
        seen_ids = set()

        # Step 1: Filtered Semantic Query (if where_filter provided)
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
                logger.warning("Metadata-filtered query failed on collection '%s': %s", collection_name, e)

        # Step 2: Broad Semantic Query to ensure top_k coverage or handle partial matches
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
                logger.error("Semantic search failed on collection '%s': %s", collection_name, e)

        # Sort all results descending by similarity score
        results.sort(key=lambda x: x.get("similarity_score", 0.0), reverse=True)

        # Apply score threshold if provided
        if min_score is not None:
            results = [r for r in results if r.get("similarity_score", 0.0) >= min_score]

        return results[:top_k]

    def _format_chroma_results(
        self,
        raw_results: Dict[str, Any],
        collection_name: str,
        seen_ids: set
    ) -> List[Dict[str, Any]]:
        """Formats ChromaDB query results into standardized dictionaries."""
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
                # Key shortcuts for convenience in agent prompts
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
        Queries the CVE Knowledge Base collection for known vulnerabilities, CVSS scores,
        exploits, and remediation steps matching the given service and version.

        Args:
            service_name: Name of the network service (e.g. 'apache', 'openssh', 'nginx', 'vsftpd').
            version: Optional service version string (e.g. '2.4.49', '8.2p1', '1.18.0').
            top_k: Maximum number of vulnerabilities to return.
            min_score: Optional minimum similarity threshold.

        Returns:
            List of matching CVE records with content, CVSS metrics, metadata, and similarity score.
        """
        service_clean = (service_name or "").strip().lower()
        version_clean = (version or "").strip()

        # Build optimized domain-specific query prompt for vector embedding
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

        # Build metadata filter if service is present
        where_filter = None
        if service_clean:
            where_filter = {"service": service_clean}

        logger.info("Executing query_vulnerabilities for service='%s', version='%s'", service_clean, version_clean)
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
        Queries official CIS Benchmarks and security hardening guides for secure configuration
        of services (e.g., Apache, SSH, Nginx, Linux OS).

        Args:
            service_name: Service name or configuration topic (e.g. 'ssh', 'apache', 'nginx', 'firewall').
            os_type: Optional target OS (e.g. 'linux', 'ubuntu', 'debian', 'rhel').
            top_k: Maximum number of benchmark recommendations to return.
            min_score: Optional minimum similarity threshold.

        Returns:
            List of CIS benchmark guidance snippets with remediation steps.
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

        logger.info("Executing query_hardening_benchmarks for service='%s', os='%s'", service_clean, os_clean)
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
        Queries corporate security policies, auditing scopes, compliance rules, and SLAs.

        Args:
            query_text: Natural language description of the policy, service, or rule to look up.
            top_k: Maximum number of policy rules to return.
            min_score: Optional minimum similarity threshold.

        Returns:
            List of matched internal policy clauses and requirements.
        """
        enhanced_query = (
            f"Organizational security policy, corporate compliance requirement, "
            f"auditing scope, and remediation SLA regarding: {query_text}"
        )
        logger.info("Executing query_internal_policies for topic='%s'", query_text)
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
        Consolidates relevant security intelligence across all 3 knowledge bases:
        1. CVEs & Vulnerabilities
        2. CIS Hardening Benchmarks
        3. Internal Security Policies

        Args:
            service_name: Detected service name.
            version: Detected version string.
            os_type: Optional operating system.
            top_k_per_category: Number of top results per knowledge base category.

        Returns:
            Dictionary containing categorized search results.
        """
        cves = self.query_vulnerabilities(service_name=service_name, version=version, top_k=top_k_per_category)
        cis = self.query_hardening_benchmarks(service_name=service_name, os_type=os_type, top_k=top_k_per_category)
        policies = self.query_internal_policies(query_text=f"{service_name} policy requirements and port exposure", top_k=top_k_per_category)

        return {
            "vulnerabilities": cves,
            "hardening_benchmarks": cis,
            "internal_policies": policies
        }


# Module-level convenience functions using default global retriever instance
_default_retriever: Optional[SecurityRetriever] = None


def get_retriever() -> SecurityRetriever:
    """Returns or initializes the global SecurityRetriever singleton."""
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
    """Convenience function to query CVE vulnerabilities using the default retriever."""
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
    """Convenience function to query CIS hardening benchmarks using the default retriever."""
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
    """Convenience function to query corporate internal policies using the default retriever."""
    return get_retriever().query_internal_policies(
        query_text=query_text,
        top_k=top_k,
        min_score=min_score
    )
