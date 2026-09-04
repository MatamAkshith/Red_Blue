from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.app.events.schemas import AgentEvent, EventType, TrustLevel


class NormalizationError(ValueError):
    """Raised when raw event data fails strict normalization or validation rules."""

    pass


class Normalizer:
    """Strict Event Normalizer and Validation Layer.

    Translates raw observations/dictionaries into standard AgentEvent instances,
    enforcing type validation, trust boundary preservation, and safe metadata merging.
    """

    CORE_FIELDS = {
        "event_id",
        "parent_event_id",
        "session_id",
        "agent_id",
        "event_type",
        "source",
        "target",
        "resource",
        "action",
        "permission",
        "trust_level",
        "timestamp",
        "metadata",
    }

    @classmethod
    def normalize_event(
        cls,
        raw_data: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> AgentEvent:
        """Normalizes raw input data into a strictly validated AgentEvent.

        Args:
            raw_data: Optional dictionary or raw payload object containing event fields.
            **kwargs: Explicit keyword arguments overriding or supplementing raw_data.

        Returns:
            A strictly validated AgentEvent instance.

        Raises:
            NormalizationError: If required fields are missing or enums are invalid.
        """
        merged: dict[str, Any] = {}
        if raw_data is not None:
            if isinstance(raw_data, dict):
                merged.update(raw_data)
            elif hasattr(raw_data, "model_dump"):
                merged.update(raw_data.model_dump())
            elif hasattr(raw_data, "__dict__"):
                merged.update(raw_data.__dict__)
            else:
                raise NormalizationError(
                    f"Unsupported raw event data type: {type(raw_data)}"
                )

        merged.update(kwargs)

        # 1. Validation: session_id & agent_id
        session_id = merged.get("session_id")
        if not session_id or not isinstance(session_id, str) or not session_id.strip():
            raise NormalizationError(
                "Missing or invalid 'session_id'. Must be a non-empty string."
            )

        agent_id = merged.get("agent_id")
        if not agent_id or not isinstance(agent_id, str) or not agent_id.strip():
            raise NormalizationError(
                "Missing or invalid 'agent_id'. Must be a non-empty string."
            )

        # 2. Validation: event_type
        raw_event_type = merged.get("event_type")
        if not raw_event_type:
            raise NormalizationError("Missing required field 'event_type'.")

        if isinstance(raw_event_type, EventType):
            event_type = raw_event_type
        elif isinstance(raw_event_type, str):
            try:
                event_type = EventType(raw_event_type.upper())
            except ValueError:
                valid_types = [e.value for e in EventType]
                raise NormalizationError(
                    f"Invalid 'event_type' value '{raw_event_type}'. Must be one of {valid_types}."
                )
        else:
            raise NormalizationError(
                f"Malformed 'event_type' type: {type(raw_event_type)}"
            )

        # 3. Validation: trust_level
        raw_trust_level = merged.get("trust_level", TrustLevel.UNKNOWN)
        if isinstance(raw_trust_level, TrustLevel):
            trust_level = raw_trust_level
        elif isinstance(raw_trust_level, str):
            try:
                trust_level = TrustLevel(raw_trust_level.upper())
            except ValueError:
                valid_levels = [t.value for t in TrustLevel]
                raise NormalizationError(
                    f"Malformed 'trust_level' value '{raw_trust_level}'. Must be one of {valid_levels}."
                )
        else:
            raise NormalizationError(
                f"Malformed 'trust_level' type: {type(raw_trust_level)}"
            )

        # 4. Source validation
        source = merged.get("source")
        if not source or not isinstance(source, str) or not source.strip():
            raise NormalizationError(
                "Missing or invalid 'source'. Must be a non-empty string."
            )

        # Core fields extraction
        event_id = merged.get("event_id")
        if not event_id or not isinstance(event_id, str) or not event_id.strip():
            raise NormalizationError(
                "Missing or invalid 'event_id'. Must be a non-empty string."
            )

        parent_event_id = merged.get("parent_event_id")
        target = merged.get("target")
        resource = merged.get("resource")
        action = merged.get("action")
        permission = merged.get("permission")

        timestamp = merged.get("timestamp")
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        elif isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except ValueError:
                raise NormalizationError(f"Invalid timestamp ISO format: '{timestamp}'")

        # 5. Metadata preservation & safety
        existing_meta = merged.get("metadata")
        metadata: dict[str, Any] = {}
        if isinstance(existing_meta, dict):
            metadata.update(existing_meta)

        # Preserve declared permission in metadata if present
        if permission and "declared_permission" not in metadata:
            metadata["declared_permission"] = permission

        # Safely merge non-core payload kwargs into metadata without overwriting core schema fields
        for key, value in merged.items():
            if key not in cls.CORE_FIELDS and key not in metadata:
                metadata[key] = value

        return AgentEvent(
            event_id=event_id,
            parent_event_id=parent_event_id,
            session_id=session_id,
            agent_id=agent_id,
            event_type=event_type,
            source=source,
            target=target,
            resource=resource,
            action=action,
            permission=permission,
            trust_level=trust_level,
            timestamp=timestamp,
            metadata=metadata,
        )


def normalize_event(
    raw_data: dict[str, Any] | None = None,
    **kwargs: Any,
) -> AgentEvent:
    """Convenience wrapper to normalize raw observation data into an AgentEvent."""
    return Normalizer.normalize_event(raw_data=raw_data, **kwargs)
