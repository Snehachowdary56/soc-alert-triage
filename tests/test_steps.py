from datetime import datetime, timedelta

import pytest

from triage import intel, sample
from triage.pipeline_steps import correlate, enrich, group, score, validate


def alert(i, minute, **kw):
    t = datetime(2026, 11, 10, 9, 0) + timedelta(minutes=minute)
    return {"alert_id": f"A{i}", "timestamp": t.isoformat(), "source": "IdP", **kw}


@pytest.fixture(scope="module")
def alerts():
    return sample.generate_alerts()


def test_validate_drops_duplicates_and_bad_rows():
    rows = [alert(1, 0, type="x"), alert(1, 0, type="x"), {"alert_id": "A2", "type": "x"},
            {**alert(3, 0, type="x"), "timestamp": "not a date"}]
    good, issues = validate(rows)
    assert [a["alert_id"] for a in good] == ["A1"]
    assert {i["issue"] for i in issues} == {"duplicate alert", "missing fields ['source', 'timestamp']", "bad timestamp"}


def test_sample_duplicates_are_found(alerts):
    _, issues = validate(alerts)
    assert sum(i["issue"] == "duplicate alert" for i in issues) == 3


def test_grouping_merges_burst_into_one_incident():
    rows = [alert(i, i * 0.5, type="failed_login", user="bob", src_ip="203.0.113.45") for i in range(20)]
    incs = group(rows)
    assert len(incs) == 1 and incs[0].count == 20


def test_grouping_splits_when_far_apart_in_time():
    rows = [alert(1, 0, type="failed_login", user="bob", src_ip="10.0.0.1"),
            alert(2, 120, type="failed_login", user="bob", src_ip="10.0.0.1")]
    assert len(group(rows)) == 2


def test_grouping_keeps_different_users_apart():
    rows = [alert(1, 0, type="failed_login", user="bob", src_ip="10.0.0.1"),
            alert(2, 1, type="failed_login", user="eve", src_ip="10.0.0.1")]
    assert len(group(rows)) == 2


def test_internal_vs_external_ip():
    assert intel.is_internal("10.0.4.21")
    assert intel.is_internal("192.168.1.5")
    assert not intel.is_internal("203.0.113.45")
    assert not intel.is_internal("not-an-ip")
    assert intel.country("10.0.4.21") == "CA"
    assert intel.country("203.0.113.45") == "RU"


def test_enrichment_flags_threat_ip_privileged_user_and_phishing_domain():
    rows = [alert(1, 0, type="suspicious_connection", user="admin.ivan", dest_ip="198.51.100.23"),
            alert(2, 0, type="phishing_email", user="carol", domain="payroll-update.example")]
    a, b = group(rows)
    enrich(a)
    enrich(b)
    text = " ".join(a.enrichment + b.enrichment)
    assert "threat list" in text and "privileged" in text and "phishing" in text


def test_brute_force_then_success_is_escalated():
    rows = [alert(i, i * 0.5, type="failed_login", user="admin.ivan", src_ip="203.0.113.45") for i in range(15)]
    rows.append(alert(99, 10, type="successful_login", user="admin.ivan", src_ip="203.0.113.45"))
    incs = group(rows)
    correlate(incs)
    for i in incs:
        enrich(i)
        score(i)
    fails = next(i for i in incs if i.type == "failed_login")
    ok = next(i for i in incs if i.type == "successful_login")
    assert fails.severity == "High" and fails.escalate
    assert ok.escalate
    assert any("account takeover" in r for r in fails.reasons)


def test_routine_alerts_score_zero():
    incs = group([alert(1, 0, type="dns_query", host="LT-1", domain="github.com")])
    enrich(incs[0])
    score(incs[0])
    assert incs[0].score == 0 and incs[0].severity == "Low"


def test_single_internal_failed_login_is_low():
    incs = group([alert(1, 0, type="failed_login", user="bob", src_ip="10.0.4.21")])
    enrich(incs[0])
    score(incs[0])
    assert incs[0].severity == "Low" and not incs[0].escalate


def test_every_score_has_reasons(alerts):
    good, _ = validate(alerts)
    incs = group(good)
    correlate(incs)
    for i in incs:
        enrich(i)
        score(i)
        assert i.reasons
