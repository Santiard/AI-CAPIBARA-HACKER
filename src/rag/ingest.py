"""
Automated Ingestion Pipeline for AI-CAPIBARA-HACKER Knowledge Bases.
Parses CVE databases, CIS hardening benchmarks, and corporate policies from data/,
applies strategic recursive chunking with structured metadata extraction,
and stores embeddings persistently in ChromaDB.

Usage:
    python src/rag/ingest.py
    python src/rag/ingest.py --reset
    python src/rag/ingest.py --collection cves
    python src/rag/ingest.py --dry-run
"""
import os
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import List, Dict, Any, Tuple

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR))

from src.config import (
    DATA_DIR,
    CVES_DIR,
    CIS_DIR,
    POLICIES_DIR,
    COLLECTION_CVES,
    COLLECTION_CIS,
    COLLECTION_POLICIES,
)
from src.rag.vectorstore import VectorStoreManager, get_vectorstore_manager

logger = logging.getLogger("ai_capibara.rag.ingest")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


class TextSplitter:
    """
    Strategic Recursive Character Text Splitter with LangChain compatibility
    and zero-dependency fallback.
    """
    def __init__(self, chunk_size: int = 700, chunk_overlap: int = 120, separators: List[str] = None):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.separators = separators or ["\n\n---\n\n", "\n\n## ", "\n\n### ", "\n\n", "\n", " ", ""]

    def split_text(self, text: str) -> List[str]:
        # Try LangChain splitter first if available
        try:
            from langchain_text_splitters import RecursiveCharacterTextSplitter
            splitter = RecursiveCharacterTextSplitter(
                chunk_size=self.chunk_size,
                chunk_overlap=self.chunk_overlap,
                separators=self.separators
            )
            return splitter.split_text(text)
        except ImportError:
            try:
                from langchain.text_splitter import RecursiveCharacterTextSplitter
                splitter = RecursiveCharacterTextSplitter(
                    chunk_size=self.chunk_size,
                    chunk_overlap=self.chunk_overlap,
                    separators=self.separators
                )
                return splitter.split_text(text)
            except ImportError:
                pass

        # Robust built-in recursive splitting fallback
        return self._recursive_split(text, self.separators)

    def _recursive_split(self, text: str, separators: List[str]) -> List[str]:
        final_chunks = []
        separator = separators[-1]
        for s in separators:
            if s == "":
                separator = ""
                break
            if s in text:
                separator = s
                break

        splits = text.split(separator) if separator else list(text)
        good_splits = []
        for s in splits:
            if s.strip():
                good_splits.append(s.strip())

        merged_text = ""
        for piece in good_splits:
            if len(merged_text) + len(piece) + len(separator) <= self.chunk_size:
                merged_text = f"{merged_text}{separator}{piece}" if merged_text else piece
            else:
                if merged_text:
                    final_chunks.append(merged_text.strip())
                if len(piece) > self.chunk_size and len(separators) > 1:
                    sub_chunks = self._recursive_split(piece, separators[1:])
                    final_chunks.extend(sub_chunks)
                    merged_text = ""
                else:
                    merged_text = piece

        if merged_text.strip():
            final_chunks.append(merged_text.strip())

        return final_chunks or [text]


class KnowledgeIngestionPipeline:
    """
    Orchestrates loading, parsing, chunking, and indexing of knowledge bases.
    """

    def __init__(self, vectorstore_manager: VectorStoreManager = None, chunk_size: int = 700, chunk_overlap: int = 120):
        self.vsm = vectorstore_manager or get_vectorstore_manager()
        self.splitter = TextSplitter(chunk_size=chunk_size, chunk_overlap=chunk_overlap)

    def ingest_cves(self, cves_dir: Path = CVES_DIR) -> Tuple[int, int]:
        """
        Ingests structured JSON CVE records and Markdown technical advisories into COLLECTION_CVES.
        """
        logger.info("--> Ingesting CVE Knowledge Base from: %s", cves_dir)
        documents = []
        metadatas = []
        ids = []

        if not cves_dir.exists():
            logger.warning("CVEs directory not found: %s", cves_dir)
            return (0, 0)

        # 1. Process JSON files
        json_files = list(cves_dir.glob("*.json"))
        for jfile in json_files:
            try:
                with open(jfile, "r", encoding="utf-8") as f:
                    cve_list = json.load(f)
                
                for item in cve_list:
                    cve_id = item.get("cve_id", "UNKNOWN-CVE")
                    service = item.get("service", "general").lower()
                    product = item.get("product", service)
                    cvss = float(item.get("cvss_score", 0.0))
                    severity = item.get("severity", "UNKNOWN")
                    min_ver = item.get("min_version", "")
                    max_ver = item.get("max_version", "")
                    affected_ver = item.get("affected_versions", "")
                    summary = item.get("summary", "")
                    tech = item.get("technical_details", "")
                    rem = item.get("remediation", "")
                    cwe = item.get("cwe", "")
                    vector = item.get("attack_vector", "")

                    content = (
                        f"Vulnerability ID: {cve_id}\n"
                        f"Target Service: {service} ({product})\n"
                        f"Affected Versions: {affected_ver} (Min: {min_ver}, Max: {max_ver})\n"
                        f"CVSS v3 Score: {cvss} ({severity}) | CWE: {cwe} | Vector: {vector}\n"
                        f"Summary: {summary}\n"
                        f"Technical Analysis: {tech}\n"
                        f"Remediation & Fix: {rem}"
                    )

                    documents.append(content)
                    metadatas.append({
                        "category": "cve",
                        "cve_id": cve_id,
                        "service": service,
                        "product": product,
                        "min_version": str(min_ver),
                        "max_version": str(max_ver),
                        "affected_versions": str(affected_ver),
                        "cvss_score": cvss,
                        "severity": severity,
                        "cwe": cwe,
                        "source_file": jfile.name
                    })
                    ids.append(f"cve_{cve_id.lower().replace('-', '_')}")
            except Exception as e:
                logger.error("Error reading CVE JSON file %s: %s", jfile.name, e)

        # 2. Process Markdown files
        md_files = list(cves_dir.glob("*.md"))
        for md_file in md_files:
            try:
                with open(md_file, "r", encoding="utf-8") as f:
                    text = f.read()

                service_guess = md_file.stem.split("_")[0].lower()
                chunks = self.splitter.split_text(text)
                for idx, chunk in enumerate(chunks):
                    # Extract CVE pattern if present
                    import re
                    cve_match = re.search(r"CVE-\d{4}-\d{4,7}", chunk, re.IGNORECASE)
                    cve_found = cve_match.group(0).upper() if cve_match else f"MD-{md_file.stem.upper()}-{idx+1}"
                    
                    # Severity extraction
                    sev = "HIGH"
                    if "CRITICAL" in chunk:
                        sev = "CRITICAL"
                    elif "MEDIUM" in chunk:
                        sev = "MEDIUM"
                    elif "LOW" in chunk:
                        sev = "LOW"

                    documents.append(chunk)
                    metadatas.append({
                        "category": "cve_advisory",
                        "cve_id": cve_found,
                        "service": service_guess,
                        "severity": sev,
                        "source_file": md_file.name,
                        "chunk_index": idx
                    })
                    ids.append(f"cve_md_{md_file.stem}_{idx}_{cve_found.lower().replace('-', '_')}")
            except Exception as e:
                logger.error("Error reading CVE Markdown file %s: %s", md_file.name, e)

        if documents:
            self.vsm.add_documents(COLLECTION_CVES, documents, metadatas, ids)
            logger.info("Successfully ingested %d records into '%s'.", len(documents), COLLECTION_CVES)

        return (len(json_files) + len(md_files), len(documents))

    def ingest_cis_benchmarks(self, cis_dir: Path = CIS_DIR) -> Tuple[int, int]:
        """
        Ingests CIS Benchmark hardening guides into COLLECTION_CIS.
        """
        logger.info("--> Ingesting CIS Benchmarks from: %s", cis_dir)
        documents = []
        metadatas = []
        ids = []

        if not cis_dir.exists():
            logger.warning("CIS directory not found: %s", cis_dir)
            return (0, 0)

        md_files = list(cis_dir.glob("*.md"))
        for md_file in md_files:
            try:
                with open(md_file, "r", encoding="utf-8") as f:
                    text = f.read()

                # Infer service from filename: cis_apache_http_server.md -> apache
                parts = md_file.stem.replace("cis_", "").split("_")
                service_inferred = parts[0].lower() if parts else "system"
                os_type = "linux" if "linux" in md_file.stem else ""

                chunks = self.splitter.split_text(text)
                for idx, chunk in enumerate(chunks):
                    import re
                    rule_match = re.search(r"CIS-[A-Z0-9\-.]+", chunk)
                    rule_id = rule_match.group(0) if rule_match else f"CIS-{service_inferred.upper()}-{idx+1}"

                    documents.append(chunk)
                    metadatas.append({
                        "category": "cis_benchmark",
                        "rule_id": rule_id,
                        "service": service_inferred,
                        "os": os_type,
                        "source_file": md_file.name,
                        "chunk_index": idx
                    })
                    ids.append(f"cis_{md_file.stem}_{idx}_{rule_id.lower().replace('-', '_')}")
            except Exception as e:
                logger.error("Error reading CIS Markdown file %s: %s", md_file.name, e)

        if documents:
            self.vsm.add_documents(COLLECTION_CIS, documents, metadatas, ids)
            logger.info("Successfully ingested %d records into '%s'.", len(documents), COLLECTION_CIS)

        return (len(md_files), len(documents))

    def ingest_policies(self, policies_dir: Path = POLICIES_DIR) -> Tuple[int, int]:
        """
        Ingests corporate cybersecurity policies into COLLECTION_POLICIES.
        """
        logger.info("--> Ingesting Corporate Policies from: %s", policies_dir)
        documents = []
        metadatas = []
        ids = []

        if not policies_dir.exists():
            logger.warning("Policies directory not found: %s", policies_dir)
            return (0, 0)

        md_files = list(policies_dir.glob("*.md"))
        for md_file in md_files:
            try:
                with open(md_file, "r", encoding="utf-8") as f:
                    text = f.read()

                chunks = self.splitter.split_text(text)
                for idx, chunk in enumerate(chunks):
                    documents.append(chunk)
                    metadatas.append({
                        "category": "corporate_policy",
                        "policy_name": md_file.stem,
                        "source_file": md_file.name,
                        "chunk_index": idx
                    })
                    ids.append(f"policy_{md_file.stem}_{idx}")
            except Exception as e:
                logger.error("Error reading Policy file %s: %s", md_file.name, e)

        if documents:
            self.vsm.add_documents(COLLECTION_POLICIES, documents, metadatas, ids)
            logger.info("Successfully ingested %d records into '%s'.", len(documents), COLLECTION_POLICIES)

        return (len(md_files), len(documents))

    def run_all(self, reset: bool = False, collections_filter: str = "all") -> Dict[str, Any]:
        """
        Executes full ingestion pipeline for selected collections.
        """
        logger.info("=" * 60)
        logger.info(" 🦫 AI-CAPIBARA-HACKER: Starting Knowledge Base Ingestion")
        logger.info("=" * 60)

        summary = {}

        if reset:
            logger.info("[*] Reset flag enabled: Clearing existing ChromaDB collections...")
            if collections_filter in ["all", "cves"]:
                self.vsm.reset_collection(COLLECTION_CVES)
            if collections_filter in ["all", "cis"]:
                self.vsm.reset_collection(COLLECTION_CIS)
            if collections_filter in ["all", "policies"]:
                self.vsm.reset_collection(COLLECTION_POLICIES)

        if collections_filter in ["all", "cves"]:
            files_count, doc_count = self.ingest_cves()
            summary["cves"] = {"files": files_count, "chunks": doc_count}

        if collections_filter in ["all", "cis"]:
            files_count, doc_count = self.ingest_cis_benchmarks()
            summary["cis"] = {"files": files_count, "chunks": doc_count}

        if collections_filter in ["all", "policies"]:
            files_count, doc_count = self.ingest_policies()
            summary["policies"] = {"files": files_count, "chunks": doc_count}

        stats = self.vsm.get_collection_stats()
        summary["collection_stats"] = stats

        logger.info("=" * 60)
        logger.info(" Ingestion Complete Summary:")
        for col, data in stats.get("collections", {}).items():
            logger.info(f"   * Collection: {col} -> Total vectors: {data.get('count', 0)} ({data.get('status')})")
        logger.info("=" * 60)

        return summary


def main():
    parser = argparse.ArgumentParser(
        description="Ingest CVEs, CIS Benchmarks, and Policies into AI-CAPIBARA-HACKER ChromaDB."
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Clear existing ChromaDB collections before ingesting."
    )
    parser.add_argument(
        "--collection",
        choices=["all", "cves", "cis", "policies"],
        default="all",
        help="Specify which knowledge base collection to ingest (default: all)."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate ingestion without writing to ChromaDB."
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Display current collection stats and exit."
    )

    args = parser.parse_args()
    vsm = get_vectorstore_manager()

    if args.stats:
        stats = vsm.get_collection_stats()
        print(json.dumps(stats, indent=2))
        return

    pipeline = KnowledgeIngestionPipeline(vectorstore_manager=vsm)

    if args.dry_run:
        print("[*] Dry run mode enabled. Testing file parsing & chunking...")
        # Inspect files without database insertion
        cve_json = list(CVES_DIR.glob("*.json"))
        cve_md = list(CVES_DIR.glob("*.md"))
        cis_md = list(CIS_DIR.glob("*.md"))
        pol_md = list(POLICIES_DIR.glob("*.md"))
        print(f"[*] Found {len(cve_json)} CVE JSON files and {len(cve_md)} CVE Markdown files.")
        print(f"[*] Found {len(cis_md)} CIS Benchmark Markdown files.")
        print(f"[*] Found {len(pol_md)} Corporate Policy Markdown files.")
        print("[*] Dry run completed successfully.")
        return

    pipeline.run_all(reset=args.reset, collections_filter=args.collection)


if __name__ == "__main__":
    main()
