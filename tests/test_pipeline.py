import csv

from triage import sample
from triage.pipeline import main, run


def test_pipeline_finds_all_planted_attacks(tmp_path):
    res = run(sample.generate_alerts(), tmp_path, show=False)
    escalated = {t["type"] for t in res["tickets"] if t["escalate"] == "yes"}
    for attack in ["failed_login", "successful_login", "phishing_email", "malware_detected",
                   "suspicious_connection", "foreign_login"]:
        assert attack in escalated
    assert res["stats"]["reduction_pct"] > 90


def test_routine_noise_gets_no_tickets(tmp_path):
    res = run(sample.generate_alerts(), tmp_path, show=False)
    assert not {t["type"] for t in res["tickets"]} & {"dns_query", "vpn_login", "av_scan_clean"}


def test_tickets_csv_and_report_written(tmp_path):
    res = run(sample.generate_alerts(), tmp_path, show=False)
    rows = list(csv.DictReader(open(res["tickets_csv"], encoding="utf-8")))
    assert len(rows) == res["stats"]["tickets"]
    assert rows[0]["ticket_id"] == "SEC-001"
    assert int(rows[0]["score"]) >= int(rows[-1]["score"])  # highest priority first
    assert "SAMPLE DATA" in res["report"].read_text(encoding="utf-8")


def test_ai_mode_with_fake_llm(tmp_path):
    res = run(sample.generate_alerts(), tmp_path, llm=lambda p: "NEEDS HUMAN REVIEW", show=False)
    assert all(t["summary_source"] == "ai_needs_review" for t in res["tickets"])


def test_load_and_save_jsonl(tmp_path):
    path = tmp_path / "alerts.jsonl"
    sample.save_jsonl(sample.generate_alerts(n_noise=5), path)
    assert len(sample.load_jsonl(path)) == len(sample.generate_alerts(n_noise=5))


def test_cli_runs(tmp_path, capsys):
    main(["--out", str(tmp_path)])
    assert "Tickets" in capsys.readouterr().out
    assert (tmp_path / "tickets.csv").exists()
