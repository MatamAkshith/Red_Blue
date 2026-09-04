import json

from backend.app.understand.investigation.prompts import build_investigation_prompt


def test_prompt_has_system_and_user_messages():
    evidence = {"incident_id": "INC-1", "attack_path": ["E14", "E15"]}
    messages = build_investigation_prompt(evidence)

    assert [m["role"] for m in messages] == ["system", "user"]


def test_system_prompt_carries_philosophy_and_rules():
    messages = build_investigation_prompt({})
    system = messages[0]["content"]

    assert "We don't secure the model" in system
    assert "Technology changes. Failure patterns persist." in system
    assert "Insufficient evidence" in system


def test_system_prompt_lists_required_behaviors():
    system = build_investigation_prompt({})[0]["content"]

    for required in (
        "Use only the supplied evidence",
        "WHY the incident occurred",
        "Reconstruct the attack chain",
        "critical agent decision",
        "relate to each other",
        "event_id(s) that support each conclusion",
        "Distinguish facts",
    ):
        assert required in system


def test_system_prompt_forbids_inventing_every_listed_category():
    system = build_investigation_prompt({})[0]["content"]

    for forbidden in (
        "events",
        "event IDs",
        "tools",
        "permissions",
        "resources",
        "timestamps",
        "agents",
        "attack paths",
    ):
        assert forbidden in system


def test_system_prompt_forbids_modifying_p1_findings():
    system = build_investigation_prompt({})[0]["content"]

    assert "severity" in system
    assert "blast_radius" in system
    assert "not yours to change" in system
    assert "does not appear in the supplied evidence" in system


def test_user_prompt_embeds_the_evidence_as_json():
    evidence = {"incident_id": "INC-42", "attack_path": ["E1", "E2"]}
    messages = build_investigation_prompt(evidence)
    user = messages[1]["content"]

    assert json.dumps(evidence, indent=2) in user
