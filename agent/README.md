# Test Agent (target)

This directory will hold the one real AI agent Blackbox protects for the
demo — not a Blackbox component itself, just the target.

Per the spec, it needs:
- A RAG/knowledge source (retrieval tool)
- A CRM/customer-data tool
- An email/external-action tool
- Wiring to `sdk/observer.py` so its operations are captured as Universal
  AgentEvents

Not yet built — this is a placeholder for a future milestone.
