"""LLM target adapters — the *victim* under test.

Provider-agnostic: a YAML/dict profile defines how to reach a chat endpoint.
Two shapes are supported out of the box:

  * HTTPTarget   — generic. You give a `body` mapping containing the literal
                   token "{{PROMPT}}" somewhere, and a dotted `response_path`
                   that locates the assistant text in the JSON response.
  * OpenAITarget — convenience for any /v1/chat/completions-compatible API.

All network I/O is async (httpx.AsyncClient) so the scanner can fan out
probes with bounded concurrency.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx

logger = logging.getLogger(__name__)

PROMPT_TOKEN = "{{PROMPT}}"


def _deep_substitute(obj: Any, prompt: str) -> Any:
    """Recursively replace PROMPT_TOKEN inside a parsed JSON structure.

    Working on the parsed structure (not a raw string) means the prompt is
    JSON-encoded safely by httpx — no manual escaping, no injection of the
    transport itself.
    """
    if isinstance(obj, str):
        return obj.replace(PROMPT_TOKEN, prompt)
    if isinstance(obj, list):
        return [_deep_substitute(v, prompt) for v in obj]
    if isinstance(obj, dict):
        return {k: _deep_substitute(v, prompt) for k, v in obj.items()}
    return obj


def _extract_path(data: Any, path: str) -> str:
    """Walk a dotted path (supporting numeric list indices) into `data`.

    e.g. "choices.0.message.content"
    """
    cur = data
    for part in path.split("."):
        if part == "":
            continue
        if isinstance(cur, list):
            cur = cur[int(part)]
        elif isinstance(cur, dict):
            cur = cur[part]
        else:
            raise KeyError(f"cannot descend into {type(cur).__name__} at '{part}'")
    if isinstance(cur, (dict, list)):
        return json.dumps(cur)
    return str(cur)


class LLMTarget(ABC):
    """A victim LLM endpoint."""

    label: str
    target_id: str

    @abstractmethod
    async def query(self, prompt: str, client: httpx.AsyncClient) -> str:
        """Send `prompt` to the target and return the assistant's text.

        Raises on transport/parse failure — the scanner catches and records it.
        """
        raise NotImplementedError


class HTTPTarget(LLMTarget):
    """Generic HTTP chat endpoint driven by a profile."""

    def __init__(
        self,
        *,
        url: str,
        body: dict[str, Any],
        response_path: str,
        method: str = "POST",
        headers: dict[str, str] | None = None,
        label: str = "",
        timeout: float = 30.0,
    ) -> None:
        if PROMPT_TOKEN not in json.dumps(body):
            raise ValueError(
                f"target body must contain the literal token {PROMPT_TOKEN!r} "
                "so the probe prompt can be injected."
            )
        self.url = url
        self.body = body
        self.response_path = response_path
        self.method = method.upper()
        self.headers = headers or {"Content-Type": "application/json"}
        self.timeout = timeout
        self.label = label or url
        self.target_id = self._compute_id()

    def _compute_id(self) -> str:
        digest = hashlib.sha1(
            f"{self.method} {self.url} {json.dumps(self.body, sort_keys=True)}".encode()
        ).hexdigest()
        return digest[:16]

    async def query(self, prompt: str, client: httpx.AsyncClient) -> str:
        payload = _deep_substitute(copy.deepcopy(self.body), prompt)
        resp = await client.request(
            self.method,
            self.url,
            json=payload,
            headers=self.headers,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return _extract_path(resp.json(), self.response_path)


class OpenAITarget(HTTPTarget):
    """Any OpenAI-compatible /v1/chat/completions endpoint."""

    def __init__(
        self,
        *,
        api_base: str,
        model: str,
        api_key: str = "",
        system: str = "",
        label: str = "",
        timeout: float = 30.0,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        url = api_base.rstrip("/") + "/chat/completions"
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": PROMPT_TOKEN})
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        if extra_headers:
            headers.update(extra_headers)
        super().__init__(
            url=url,
            body={"model": model, "messages": messages},
            response_path="choices.0.message.content",
            method="POST",
            headers=headers,
            label=label or f"openai:{model}",
            timeout=timeout,
        )


def build_target(profile: dict[str, Any]) -> LLMTarget:
    """Build a target from a profile mapping (typically loaded from YAML).

    Two shapes::

        # OpenAI-compatible
        type: openai
        api_base: http://localhost:8000/v1
        model: gpt-test
        api_key_env: OPENAI_API_KEY   # optional; read from environment
        system: "..."                  # optional

        # Generic HTTP
        type: http
        url: https://example.com/chat
        method: POST
        headers: { Authorization: "Bearer ..." }
        body: { prompt: "{{PROMPT}}" }
        response_path: reply.text
    """
    import os

    ttype = (profile.get("type") or "http").lower()
    timeout = float(profile.get("timeout", 30.0))

    if ttype == "openai":
        api_key = profile.get("api_key", "")
        env_name = profile.get("api_key_env")
        if not api_key and env_name:
            api_key = os.environ.get(env_name, "")
        return OpenAITarget(
            api_base=profile["api_base"],
            model=profile["model"],
            api_key=api_key,
            system=profile.get("system", ""),
            label=profile.get("label", ""),
            timeout=timeout,
            extra_headers=profile.get("headers"),
        )

    if ttype == "http":
        return HTTPTarget(
            url=profile["url"],
            body=profile["body"],
            response_path=profile["response_path"],
            method=profile.get("method", "POST"),
            headers=profile.get("headers"),
            label=profile.get("label", ""),
            timeout=timeout,
        )

    raise ValueError(f"unknown target type: {ttype!r} (expected 'openai' or 'http')")
