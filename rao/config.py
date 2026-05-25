"""Central configuration loaded from environment variables."""

import logging
from pathlib import Path

from dotenv import load_dotenv
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings

_cfg_logger = logging.getLogger(__name__)

load_dotenv()

ROOT_DIR = Path(__file__).parent.parent


class Neo4jSettings(BaseSettings):
    uri: str = Field(default="bolt://localhost:7687", alias="NEO4J_URI")
    user: str = Field(default="neo4j", alias="NEO4J_USER")
    # BUG #29 fix: no hardcoded default password in source code.
    # Set NEO4J_PASSWORD in your .env file.
    password: str = Field(default="", alias="NEO4J_PASSWORD")

    @model_validator(mode="after")
    def warn_if_no_password(self) -> "Neo4jSettings":
        if not self.password:
            _cfg_logger.warning(
                "NEO4J_PASSWORD is not set. Neo4j connection will likely fail. "
                "Add NEO4J_PASSWORD=yourpassword to your .env file."
            )
        return self


class ChromaSettings(BaseSettings):
    persist_dir: str = Field(
        default=str(ROOT_DIR / "chroma_data"), alias="CHROMA_PERSIST_DIR"
    )


class LLMSettings(BaseSettings):
    provider: str = Field(default="groq", alias="LLM_PROVIDER")
    groq_api_key: str = Field(default="", alias="GROQ_API_KEY")
    ollama_base_url: str = Field(
        default="http://localhost:11434", alias="OLLAMA_BASE_URL"
    )
    ollama_model: str = Field(default="mistral", alias="OLLAMA_MODEL")


class Settings(BaseSettings):
    neo4j: Neo4jSettings = Neo4jSettings()
    chroma: ChromaSettings = ChromaSettings()
    llm: LLMSettings = LLMSettings()
    report_output_dir: str = Field(
        default=str(ROOT_DIR / "results"), alias="REPORT_OUTPUT_DIR"
    )
    nvd_api_key: str = Field(default="", alias="NVD_API_KEY")


settings = Settings()
