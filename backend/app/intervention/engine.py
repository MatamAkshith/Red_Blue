"""Intervention engine — evaluates candidate defenses (kill agent, disable
CRM, block external email, restrict sensitive fields, require human
approval) by residual risk / operational disruption / cost, and picks the
smallest effective one. The LLM may explain the choice (see
app.understand.reasoning.recommendation) but is never the authority on
whether it is effective.

STUB: not yet implemented.
"""

from __future__ import annotations


def select_intervention(execution_graph, incident) -> dict:
    raise NotImplementedError("intervention engine: not yet implemented")
