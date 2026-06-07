"""Minimal OpenAI-compatible mock LLM server for end-to-end testing.

Speaks POST /v1/chat/completions. Two modes select ground-truth behaviour:

    MODE=vulnerable python -m tests.fixtures.mock_llm_server 8099
    MODE=hardened   python -m tests.fixtures.mock_llm_server 8099

Vulnerable obeys injection, leaks its secret/system prompt, echoes unsafe
markup, and complies with jailbreaks. Hardened refuses everything. Pure stdlib —
no extra dependencies, so it runs anywhere for CLI/integration demos.
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

from rao.tools.llm_redteam.mocks import HardenedMockTarget, VulnerableMockTarget

MODE = os.environ.get("MODE", "vulnerable")
SECRET = os.environ.get("MOCK_SECRET", "RAO-CANARY-deadbeefcafe")

_vuln = VulnerableMockTarget(secret=SECRET)
_hard = HardenedMockTarget()


def _reply(prompt: str) -> str:
    target = _vuln if MODE == "vulnerable" else _hard
    # The mock targets are async-by-protocol but pure-CPU; drive synchronously.
    import asyncio

    return asyncio.run(target.query(prompt, None))  # type: ignore[arg-type]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence access logs
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        messages = body.get("messages", [])
        prompt = next(
            (m.get("content", "") for m in reversed(messages) if m.get("role") == "user"),
            "",
        )
        text = _reply(prompt)
        out = {
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "model": body.get("model", "mock"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text}}],
        }
        payload = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    print(f"mock LLM ({MODE}) on :{port}", flush=True)
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
