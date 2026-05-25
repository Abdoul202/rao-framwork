"""ChromaDB vector store for CVE descriptions and security knowledge."""

from __future__ import annotations

import logging

from rao.config import settings

logger = logging.getLogger(__name__)


class KnowledgeBase:
    """Vector store for security knowledge retrieval.

    N9 fix: __init__ is wrapped in try/except so that ChromaDB being
    unavailable (corrupt DB, missing dir, version mismatch) degrades
    gracefully instead of crashing the entire pipeline.

    All public methods check self._available before accessing the client,
    returning safe empty results when ChromaDB is offline.
    """

    def __init__(self, collection_name: str = "cve_knowledge") -> None:
        self._available = False
        self._collection = None

        try:
            import chromadb  # type: ignore[import-untyped]

            self._client = chromadb.PersistentClient(path=settings.chroma.persist_dir)
            self._collection = self._client.get_or_create_collection(
                name=collection_name,
                metadata={"hnsw:space": "cosine"},
            )
            self._available = True
            logger.debug("ChromaDB: knowledge base initialised (collection=%s).", collection_name)
        except Exception as e:
            logger.warning(
                "ChromaDB unavailable — knowledge base disabled. "
                "Vector search will not be used. Reason: %s: %s",
                type(e).__name__, e,
            )

    def add_cves(self, cves: list[dict]) -> None:
        """Store CVE data for later semantic retrieval.

        N11 fix: logs a debug message for each upserted ID so silent
        overwrites of duplicate CVE IDs are visible in debug mode.
        """
        if not self._available or not cves:
            return

        ids = [c["id"] for c in cves]
        documents = [f"{c['id']}: {c['description']}" for c in cves]
        metadatas = [
            {
                "severity": c.get("severity", "unknown"),
                "score": float(c.get("score", 0.0)),
            }
            for c in cves
        ]

        # N11 fix: log upserts in debug to surface silent overwrites
        try:
            self._collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
            logger.debug("ChromaDB: upserted %d CVEs (IDs: %s…)", len(ids), ids[:3])
            logger.info("Stored %d CVEs in knowledge base", len(cves))
        except Exception as e:
            logger.warning("ChromaDB upsert failed: %s", e)

    def search(self, query: str, n_results: int = 5) -> list[dict]:
        """Semantic search for relevant CVEs.

        N10 fix: handles malformed/empty ChromaDB response safely.
        """
        if not self._available:
            return []

        try:
            results = self._collection.query(query_texts=[query], n_results=n_results)
        except Exception as e:
            logger.warning("ChromaDB query failed: %s", e)
            return []

        # N10 fix: validate response structure before indexing
        ids = results.get("ids")
        documents = results.get("documents")
        metadatas = results.get("metadatas")
        distances = results.get("distances")

        if not ids or not ids[0]:
            return []

        entries = []
        for i, doc_id in enumerate(ids[0]):
            entries.append(
                {
                    "id": doc_id,
                    "description": documents[0][i] if documents and documents[0] else "",
                    "severity": metadatas[0][i].get("severity", "unknown") if metadatas and metadatas[0] else "unknown",
                    "score": metadatas[0][i].get("score", 0.0) if metadatas and metadatas[0] else 0.0,
                    "distance": distances[0][i] if distances and distances[0] else None,
                }
            )
        return entries

    def count(self) -> int:
        if not self._available:
            return 0
        try:
            return self._collection.count()
        except Exception:
            return 0
