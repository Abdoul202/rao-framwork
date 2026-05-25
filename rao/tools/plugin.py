"""
Plugin system for RAO-Framework.

Provides a stable protocol for community-contributed tools.
Tools implementing ToolPlugin can be added without modifying core code.

Usage
-----
Create a class implementing ToolPlugin in rao/tools/my_tool.py:

    from rao.tools.plugin import ToolPlugin, ToolResult

    class PortKnocker(ToolPlugin):
        name = "port_knocker"
        description = "Attempts common port-knock sequences."
        version = "1.0.0"
        author = "Your Name"

        def run(self, target: str, **kwargs) -> ToolResult:
            ...

Then register it in rao/tools/__init__.py:

    from rao.tools.my_tool import PortKnocker
    REGISTERED_TOOLS["port_knocker"] = PortKnocker()

"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    """Standardized result returned by every tool."""

    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    raw: str = ""
    error: str | None = None
    duration_ms: float = 0.0

    def __bool__(self) -> bool:
        return self.success


@runtime_checkable
class ToolPlugin(Protocol):
    """
    Protocol (structural subtyping) for all RAO tools.

    Implementing classes MUST define:
        - name:        unique snake_case identifier
        - description: one-line description shown in help output
        - run():       the tool's main entry point

    Implementing classes SHOULD define:
        - version:     semver string
        - author:      contributor name / handle
        - requires:    list of system dependencies (e.g. ["nmap"])
    """

    name: str
    description: str
    version: str
    author: str
    requires: list[str]

    def run(self, target: str, **kwargs: Any) -> ToolResult:
        """
        Execute the tool against a target.

        Parameters
        ----------
        target:
            The hostname, IP, or URL to probe. Always validated by
            ScopeValidator before this method is called.
        **kwargs:
            Tool-specific parameters (e.g. ports, timeout, wordlist).

        Returns
        -------
        ToolResult
            Structured result. Never raise — catch exceptions and return
            ToolResult(success=False, error=str(e)).
        """
        ...


class ToolRegistry:
    """
    Central registry for all tool plugins.

    Tools are registered by name and can be discovered at runtime.
    This allows external packages to register tools without modifying
    the core codebase.
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolPlugin] = {}

    def register(self, tool: ToolPlugin) -> None:
        """Register a tool. Raises ValueError on name collision."""
        if not isinstance(tool, ToolPlugin):
            raise TypeError(
                f"{tool!r} does not implement the ToolPlugin protocol. "
                "Ensure it has: name, description, version, author, requires, and run()."
            )
        if tool.name in self._tools:
            raise ValueError(
                f"Tool '{tool.name}' is already registered. "
                "Use a unique name or call registry.override() to replace it."
            )
        self._tools[tool.name] = tool
        logger.debug("Registered tool: %s v%s", tool.name, getattr(tool, "version", "?"))

    def override(self, tool: ToolPlugin) -> None:
        """Register a tool, replacing any existing registration with the same name."""
        self._tools[tool.name] = tool
        logger.warning("Tool '%s' was overridden.", tool.name)

    def get(self, name: str) -> ToolPlugin | None:
        """Retrieve a tool by name. Returns None if not found."""
        return self._tools.get(name)

    def list_tools(self) -> list[dict[str, str]]:
        """Return a summary of all registered tools for display."""
        return [
            {
                "name": t.name,
                "description": t.description,
                "version": getattr(t, "version", "unknown"),
                "author": getattr(t, "author", "unknown"),
                "requires": ", ".join(getattr(t, "requires", [])) or "none",
            }
            for t in self._tools.values()
        ]

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: str) -> bool:
        return name in self._tools


# Module-level singleton \u2014 import and use directly:
#   from rao.tools.plugin import registry
#   registry.register(MyTool())
registry = ToolRegistry()
