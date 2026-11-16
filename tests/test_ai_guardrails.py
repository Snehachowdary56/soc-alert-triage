import pytest

from triage.pipeline_steps import enrich, group, score
from triage.redact import redact
from triage.summarize import ai_summary, check_grounded, facts, template_summary


@pytest.fixture
def incident():
    inc = group([{"alert_id": "A1", "timestamp": "2026-11-10T09:00:00", "source": "Email", "type": "phishing_email",
                  "user": "carol", "domain": "payroll-update.example",
                  "details": "From hr@payroll-update.example; user clicked link; password=Winter2026!"}])[0]
    enrich(inc)
    score(inc)
    return inc


def test_redact_removes_emails_passwords_and_keys():
    text = redact("mail bob@corp.example password=Hunter2 token: abc123 key sk-ABCDEFGHIJKLMNOP")
    assert "bob@corp.example" not in text and "Hunter2" not in text and "abc123" not in text
    assert "sk-ABCDEFGHIJKLMNOP" not in text
    assert "[EMAIL]" in text and "[REDACTED]" in text


def test_llm_never_receives_secrets(incident):
    seen = {}

    def fake_llm(prompt):
        seen["prompt"] = prompt
        return "carol clicked a link to payroll-update.example. Block the domain and reset the password."

    ai_summary(incident, fake_llm)
    assert "Winter2026!" not in seen["prompt"]
    assert "hr@payroll-update.example" not in seen["prompt"]


def test_grounded_summary_is_accepted(incident):
    out, status = ai_summary(incident, lambda p: "carol clicked a phishing link from payroll-update.example.")
    assert status == "ai" and "carol" in out


def test_hallucinated_ip_falls_back_to_template(incident):
    out, status = ai_summary(incident, lambda p: "carol was attacked from 45.33.32.156; block it.")
    assert status.startswith("fallback_hallucination")
    assert "45.33.32.156" in status
    assert out == template_summary(incident)


def test_model_can_say_needs_human_review(incident):
    out, status = ai_summary(incident, lambda p: "NEEDS HUMAN REVIEW")
    assert status == "ai_needs_review"


def test_api_error_never_blocks_triage(incident):
    def broken(prompt):
        raise TimeoutError("no network")

    out, status = ai_summary(incident, broken)
    assert status.startswith("fallback_error") and out == template_summary(incident)


def test_empty_answer_falls_back(incident):
    assert ai_summary(incident, lambda p: "  ")[1] == "fallback_empty"


def test_check_grounded_lists_unknown_entities(incident):
    assert check_grounded("carol and payroll-update.example", incident) == []
    assert check_grounded("also SRV-DB02 and evil.example", incident) == ["evil.example", "srv-db02"]


def test_facts_are_redacted(incident):
    assert all("Winter2026!" not in d for d in facts(incident)["example_details"])
