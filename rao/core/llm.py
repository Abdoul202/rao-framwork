"""LLM provider factory - abstracts away the model backend."""

from langchain_core.language_models import BaseChatModel

from rao.config import settings


def get_llm() -> BaseChatModel:
    """Return a chat model based on the configured provider."""
    provider = settings.llm.provider.lower()

    if provider == "groq":
        from langchain_groq import ChatGroq

        return ChatGroq(
            api_key=settings.llm.groq_api_key,
            model_name="llama-3.3-70b-versatile",
            temperature=0.1,
        )

    if provider == "ollama":
        from langchain_community.chat_models import ChatOllama

        return ChatOllama(
            base_url=settings.llm.ollama_base_url,
            model=settings.llm.ollama_model,
            temperature=0.1,
        )

    raise ValueError(f"Unknown LLM provider: {provider}")
