# Contributing to RAO-Framework

Thank you for your interest in contributing. RAO-Framework is a security tool — contributions are held to a high standard for both code quality and ethical responsibility.

---

## ⚠️ Security & Ethics First

Before contributing, read and accept the following:

1. **All contributions must be for AUTHORIZED penetration testing only.** Never add features that bypass the scope validator or the `--confirm` authorization gate.
2. **Do not add exploits, shellcode, or weaponized payloads.** Detection and planning only.
3. **CVE data is for assessment, not weaponization.** Do not add automatic exploitation capabilities.

Violations will result in immediate rejection and a potential security report.

---

## 📋 Prerequisites

- Python 3.10 or higher
- `make` (GNU Make)
- An LLM API key (Groq recommended — free tier works) OR a local Ollama instance

```bash
git clone https://github.com/your-org/rao-framework
cd rao-framework
make install-dev
cp .env.example .env
# Edit .env with your API key
```

---

## 🔀 Workflow

We use a **feature branch** workflow:

```
main          ← stable releases only
develop       ← integration branch
feature/xyz   ← your work
```

1. **Fork** the repository
2. **Create a branch** from `develop`:
   ```bash
   git checkout develop
   git pull origin develop
   git checkout -b feature/my-feature
   ```
3. **Write your code** following the style guidelines below
4. **Add tests** — PRs without tests will not be merged
5. **Run the full check suite**:
   ```bash
   make check   # lint + tests + type check
   ```
6. **Open a Pull Request** against `develop`

---

## 🏗️ Code Style

| Rule | Tool | Config |
|------|------|--------|
| Formatting | `ruff format` | `pyproject.toml` |
| Linting | `ruff check` | `pyproject.toml` |
| Type hints | Required on all public APIs | — |
| Docstrings | Google style | Required on all classes & public methods |

```bash
make lint      # check only
make fmt       # auto-fix formatting
```

### Naming Conventions

- **Agents**: `{Name}Agent` class in `rao/agents/{name}.py`
- **Tools**: `{Name}Tool` or plain functions in `rao/tools/{name}.py`
- **Tests**: `tests/test_{module_name}.py`

---

## 🔌 Adding a New Tool

Tools live in `rao/tools/`. To add one:

1. Create `rao/tools/my_tool.py` using the plugin protocol:

```python
"""My tool — brief description of what it does."""

from __future__ import annotations
from rao.tools.plugin import ToolPlugin, ToolResult

class MyTool(ToolPlugin):
    name = "my_tool"
    description = "One-line description shown in help output."

    def run(self, target: str, **kwargs) -> ToolResult:
        # Implementation here
        return ToolResult(success=True, data={...}, raw="...")
```

2. Register it in `rao/tools/__init__.py`
3. Add tests in `tests/test_my_tool.py`
4. Document it in `docs/tools/my_tool.md`

---

## 🤖 Adding a New Agent

Agents live in `rao/agents/`. They receive a `MissionState` and return an updated `MissionState`.

```python
from rao.core.state import MissionState
from rao.core.llm import get_llm_or_none

class MyAgent:
    def run(self, state: MissionState) -> MissionState:
        llm = get_llm_or_none()
        # Always handle llm=None gracefully
        ...
        return state
```

---

## ✅ Tests

We use `pytest` with `pytest-asyncio`. Tests are in `tests/`:

```bash
make test           # run all tests
make test-fast      # skip slow integration tests
```

**Minimum coverage for new code: 80%.**

Use mocks for:
- All LLM calls (`unittest.mock.patch`)
- Network calls — `responses`/`pytest-httpx` for `requests`, **`respx`** for the
  async `httpx` clients used by `rao/tools/llm_redteam/`
- External API calls (NVD, crt.sh, target LLM endpoints, etc.)

---

## 📦 Dependency Policy

- **Never add a new dependency without discussion in an issue first.**
- Pin versions using `requirements.in` bounded ranges, not `>=` without upper bound.
- Run `make deps-update` and commit the updated `requirements.txt`.

---

## 🐛 Reporting Security Issues

**Do NOT open a public issue for security vulnerabilities.**

Email: `security@rao-framework.example` (replace with real address)

Include:
- Description of the vulnerability
- Reproduction steps
- Potential impact
- Suggested fix (optional)

We will respond within 48 hours and coordinate a responsible disclosure timeline.

---

## 📄 License

By contributing, you agree that your contributions will be licensed under the same license as this project (see `LICENSE`).
