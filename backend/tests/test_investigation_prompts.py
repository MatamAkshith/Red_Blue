import json

from app.understand.investigation.prompts import build_investigation_prompt


def test_prompt_has_system_and_user_messages():
    evidence = {"incident_id": "INC-1", "attack_path": ["E14", "E15"]}
    messages = build_investigation_prompt(evidence)

    assert [m["role"] for m in messages] == ["system", "user"]


def test_system_prompt_carries_philosophy_and_rules():
    messages = build_investigation_prompt({})
    system = messages[0]["content"]

    assert "We don't secure the model" in system
    assert "Technology changes. Failure patterns persist." in system
    assert "Never invent events" in system
    assert "Insufficient evidence" in system


def test_user_prompt_embeds_the_evidence_as_json():
    evidence = {"incident_id": "INC-42", "attack_path": ["E1", "E2"]}
    messages = build_investigation_prompt(evidence)
    user = messages[1]["content"]

    assert json.dumps(evidence, indent=2) in user
