"""Exceptions for P1 -> P2 adapter layer."""


class AdapterValidationError(ValueError):
    """Raised when adapter inputs violate graph integrity or provenance contracts."""
    pass
