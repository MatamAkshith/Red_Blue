"""AEGIS deterministic impact analysis contracts and implementations.

Submodules are intentionally not imported here.  The existing P1-to-P2
contract imports ``app.aegis.blast_radius``; eager package exports would
create an import cycle with the impact contract's shared boundary models.
"""
