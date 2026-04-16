"""ChromaDB vector store for CVE descriptions and security knowledge."""

from __future__ import annotations

import logging

import chromadb

from rao.config import settings

logger = logging.getLogger(__name__)


class KnowledgeBase:
    """Vector store for security knowledge retrieval."""

    def __init__(self, collection_name: str = "cve_knowledge") -> None:
        self.client = chromadb.PersistentClient(path=settings.chroma.persist_dir)
        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},
        )

    def add_cves(self, cves: list[dict]) -> None:
        """Store CVE data for later semantic retrieval."""
        if not cves:
            return

        ids = [c["id"] for c in cves]
        documents = [f"{c['id']}: {c['description']}" for c in cves]
        metadatas = [
            {
                "severity": c.get("severity", "unknown"),
                "score": c.get("score", 0.0),
            }
            for c in cves
        ]

        self.collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
        logger.info("Stored %d CVEs in knowledge base", len(cves))

    def search(self, query: str, n_results: int = 5) -> list[dict]:
        """Semantic search for relevant CVEs."""
        results = self.collection.query(query_texts=[query], n_results=n_results)

        entries = []
        for i, doc_id in enumerate(results["ids"][0]):
            entries.append(
                {
                    "id": doc_id,
                    "description": results["documents"][0][i],
                    "severity": results["metadatas"][0][i].get("severity", "unknown"),
                    "score": results["metadatas"][0][i].get("score", 0.0),
                    "distance": results["distances"][0][i] if results.get("distances") else None,
                }
            )
        return entries

    def count(self) -> int:
        return self.collection.count()
