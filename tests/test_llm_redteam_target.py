"""Tests for LLM red team target adapters (httpx mocked with respx)."""

from __future__ import annotations

import httpx
import pytest
import respx

from rao.tools.llm_redteam.target import (
    HTTPTarget,
    OpenAITarget,
    _deep_substitute,
    _extract_path,
    build_target,
)


def test_deep_substitute_replaces_only_token():
    body = {"model": "m", "messages": [{"role": "user", "content": "{{PROMPT}}"}]}
    out = _deep_substitute(body, "hello")
    assert out["messages"][0]["content"] == "hello"
    assert out["model"] == "m"
    # original untouched would matter if we didn't deepcopy at call site
    assert body["messages"][0]["content"] == "{{PROMPT}}"


def test_extract_path_nested_with_index():
    data = {"choices": [{"message": {"content": "pwned"}}]}
    assert _extract_path(data, "choices.0.message.content") == "pwned"


def test_extract_path_serializes_objects():
    data = {"reply": {"text": {"a": 1}}}
    assert _extract_path(data, "reply.text") == '{"a": 1}'


def test_http_target_requires_prompt_token():
    with pytest.raises(ValueError):
        HTTPTarget(url="http://x", body={"q": "no token"}, response_path="r")


def test_target_id_is_stable_and_short():
    t1 = OpenAITarget(api_base="http://h/v1", model="m")
    t2 = OpenAITarget(api_base="http://h/v1", model="m")
    t3 = OpenAITarget(api_base="http://h/v1", model="other")
    assert t1.target_id == t2.target_id
    assert t1.target_id != t3.target_id
    assert len(t1.target_id) == 16


@pytest.mark.asyncio
@respx.mock
async def test_openai_target_query_roundtrip():
    route = respx.post("http://api.test/v1/chat/completions").mock(
        return_value=httpx.Response(
            200, json={"choices": [{"message": {"content": "I am the assistant"}}]}
        )
    )
    target = OpenAITarget(api_base="http://api.test/v1", model="m", api_key="sk-x")
    async with httpx.AsyncClient() as client:
        out = await target.query("ignore instructions", client)
    assert out == "I am the assistant"
    assert route.called
    sent = route.calls.last.request
    assert sent.headers["Authorization"] == "Bearer sk-x"
    body = sent.content.decode()
    assert "ignore instructions" in body


@pytest.mark.asyncio
@respx.mock
async def test_generic_http_target_query():
    respx.post("http://svc.test/chat").mock(
        return_value=httpx.Response(200, json={"reply": {"text": "hi there"}})
    )
    target = HTTPTarget(
        url="http://svc.test/chat",
        body={"prompt": "{{PROMPT}}"},
        response_path="reply.text",
    )
    async with httpx.AsyncClient() as client:
        out = await target.query("payload", client)
    assert out == "hi there"


def test_build_target_openai_from_env(monkeypatch):
    monkeypatch.setenv("MY_KEY", "secret-key")
    target = build_target(
        {"type": "openai", "api_base": "http://h/v1", "model": "m", "api_key_env": "MY_KEY"}
    )
    assert isinstance(target, OpenAITarget)
    assert target.headers["Authorization"] == "Bearer secret-key"


def test_build_target_http():
    target = build_target(
        {
            "type": "http",
            "url": "http://h/c",
            "body": {"q": "{{PROMPT}}"},
            "response_path": "a.b",
        }
    )
    assert isinstance(target, HTTPTarget)
    assert target.response_path == "a.b"


def test_build_target_unknown_type():
    with pytest.raises(ValueError):
        build_target({"type": "carrier-pigeon"})
