"""LLM provider factory with automatic cascade fallback.

Priority order: configured provider → groq → ollama → None
Each builder performs a lightweight health-check before returning.
"""

from __future__ import annotations

import logging

from langchain_core.language_models import BaseChatModel

from rao.config import settings

logger = logging.getLogger(__name__)


def _build_groq() -> BaseChatModel | None:
    """Try to build a Groq client. Returns None if unavailable."""
    try:
        if not settings.llm.groq_api_key:
            logger.debug("Groq: no API key configured, skipping.")
            return None
        from langchain_groq import ChatGroq

        model = ChatGroq(
            api_key=settings.llm.groq_api_key,
            model_name="llama-3.3-70b-versatile",
            temperature=0.1,
        )
        logger.debug("Groq: client initialised.")
        return model
    except Exception as e:
        logger.warning("Groq init failed: %s", e)
        return None


def _build_ollama() -> BaseChatModel | None:
    """Try to build an Ollama client. Performs a real health-check first.

    BUG #7 fix: also verifies that the configured model is actually available
    locally, not just that Ollama is running.
    """
    try:
        import requests as _req

        base = settings.llm.ollama_base_url
        resp = _req.get(f"{base}/api/tags", timeout=2)
        resp.raise_for_status()

        # BUG #7 fix: verify the required model is available
        desired = settings.llm.ollama_model
        available = [m.get("name", "") for m in resp.json().get("models", [])]
        # Ollama model names may include tags like "mistral:latest" — check prefix
        model_available = any(
            m == desired or m.startswith(f"{desired}:") for m in available
        )
        if not model_available:
            logger.warning(
                "Ollama: model '%s' not found locally (available: %s). "
                "Run: ollama pull %s",
                desired,
                available or "none",
                desired,
            )
            return None

        from langchain_community.chat_models import ChatOllama

        model = ChatOllama(
            base_url=base,
            model=desired,
            temperature=0.1,
        )
        logger.debug("Ollama: client initialised (model=%s).", desired)
        return model
    except Exception as e:
        logger.debug("Ollama unavailable: %s", e)
        return None


def get_llm() -> BaseChatModel:
    """Return first available LLM (cascade: configured → groq → ollama).

    Raises RuntimeError if no provider is reachable.
    """
    explicit = settings.llm.provider.lower()
    if explicit == "groq":
        primary, secondary = _build_groq, _build_ollama
    else:
        primary, secondary = _build_ollama, _build_groq

    for builder in (primary, secondary):
        llm = builder()
        if llm is not None:
            logger.info("LLM provider selected: %s", builder.__name__.replace("_build_", ""))
            return llm

    raise RuntimeError(
        "No LLM provider available. "
        "Set GROQ_API_KEY in .env or start Ollama with the correct model "
        f"(ollama pull {settings.llm.ollama_model})."
    )


def get_llm_or_none() -> BaseChatModel | None:
    """Return an LLM if any provider is available, None otherwise.

    BUG #8 fix: catches all exceptions (not just RuntimeError) so that
    ImportError, AttributeError, etc. from missing packages also degrade
    gracefully instead of crashing the calling agent.
    """
    try:
        return get_llm()
    except Exception as e:
        logger.warning(
            "No LLM provider reachable — operating in offline mode. Reason: %s: %s",
            type(e).__name__,
            e,
        )
        return None
