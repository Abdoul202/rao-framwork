"""Agent package — expose sub-modules for mock resolution.

Importing the sub-modules here ensures that `unittest.mock.patch` can
resolve paths like ``rao.agents.librarian.LibrarianAgent.run`` without
raising ``AttributeError: module 'rao.agents' has no attribute 'librarian'``.
"""

from rao.agents import critic, librarian, operator, scout

__all__ = ["critic", "librarian", "operator", "scout"]
