"""RedForge Agents — an autonomous red-teamer for tool-using AI agents.

It attacks a target agent, proves each break with hard evidence (a tool-call log
entry or a leaked canary — never an LLM's opinion), recommends a fix, and
re-tests to show the fix holds. The same find -> prove -> patch -> verify loop as
RedForge, pointed at AI agents instead of smart contracts.

See CURSOR.md for the architecture and the 6-week build plan.
"""

__version__ = "0.1.0"
