"""Runs everything: alerts -> validate -> group -> enrich -> score -> summarize -> tickets + report."""

from __future__ import annotations

import argparse
import csv
import time
from pathlib import Path

from . import sample
from .pipeline_steps import NOISE_TYPES, correlate, enrich, group, score, validate
from .summarize import ai_summary, anthropic_llm, template_summary

TICKET_FIELDS = ["ticket_id", "incident_id", "severity", "score", "escalate", "type", "alert_count",
                 "first_seen", "users", "hosts", "summary", "summary_source", "reasons", "status"]


def run(alerts: list[dict], out_dir: str | Path = "output", llm=None, show: bool = True) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()

    good, issues = validate(alerts)
    incidents = group(good)
    correlate(incidents)
    for inc in incidents:
        enrich(inc)
        score(inc)

    actionable = [i for i in incidents if i.type not in NOISE_TYPES and i.severity != "Low"]
    actionable.sort(key=lambda i: -i.score)

    tickets = []
    for n, inc in enumerate(actionable, start=1):
        if llm:
            summary, source = ai_summary(inc, llm)
        else:
            summary, source = template_summary(inc), "template"
        tickets.append({
            "ticket_id": f"SEC-{n:03d}", "incident_id": inc.incident_id, "severity": inc.severity, "score": inc.score,
            "escalate": "yes" if inc.escalate else "no", "type": inc.type, "alert_count": inc.count,
            "first_seen": inc.first_seen, "users": ";".join(inc.users), "hosts": ";".join(inc.hosts),
            "summary": summary, "summary_source": source, "reasons": "; ".join(inc.reasons),
            "status": "Escalated" if inc.escalate else "Open",
        })

    tickets_csv = out / "tickets.csv"
    with open(tickets_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=TICKET_FIELDS)
        w.writeheader()
        w.writerows(tickets)

    stats = {
        "alerts_received": len(alerts), "alerts_dropped": len(issues), "incidents": len(incidents),
        "tickets": len(tickets), "escalated": sum(t["escalate"] == "yes" for t in tickets),
        "noise_closed": len(incidents) - len(actionable),
        "reduction_pct": round(100 * (1 - len(tickets) / max(1, len(alerts))), 1),
        "seconds": round(time.perf_counter() - t0, 2),
    }

    report = out / "triage_report.md"
    lines = ["# Security alert triage report (SAMPLE DATA)", "",
             f"- Alerts received: **{stats['alerts_received']}** (dropped {stats['alerts_dropped']} duplicate or bad)",
             f"- Grouped into **{stats['incidents']}** incidents; {stats['noise_closed']} closed as routine or low",
             f"- Tickets created: **{stats['tickets']}**, escalated: **{stats['escalated']}**",
             f"- Analyst queue reduced by **{stats['reduction_pct']}%** (alerts to tickets)", "",
             "| Ticket | Severity | Score | Escalate | Summary |", "|---|---|---|---|---|"]
    for t in tickets:
        lines.append(f"| {t['ticket_id']} | {t['severity']} | {t['score']} | {t['escalate']} | {t['summary']} |")
    lines += ["", "## Dropped alerts", ""] + [f"- {i['alert_id']}: {i['issue']}" for i in issues]
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")

    if show:
        print("\nSecurity alert triage (sample data)\n" + "-" * 40)
        for k, v in stats.items():
            print(f"{k:<18}{v}")
        print("\nTickets (highest score first):")
        for t in tickets:
            print(f"  {t['ticket_id']} [{t['severity']:<6}] score {t['score']:>3}  {t['type']:<22} "
                  f"escalate={t['escalate']}  ({t['summary_source']})")
        print(f"\nTop ticket summary:\n  {tickets[0]['summary'] if tickets else '-'}")
        print(f"\nSaved: {tickets_csv}\nSaved: {report}")
    return {"stats": stats, "tickets": tickets, "incidents": incidents, "issues": issues,
            "tickets_csv": tickets_csv, "report": report}


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="AI-assisted security alert triage")
    p.add_argument("--alerts", help="alerts file (JSON Lines). Default: generate sample alerts")
    p.add_argument("--ai", action="store_true", help="use an LLM for summaries (needs ANTHROPIC_API_KEY)")
    p.add_argument("--out", default="output")
    a = p.parse_args(argv)
    alerts = sample.load_jsonl(a.alerts) if a.alerts else sample.generate_alerts()
    run(alerts, a.out, llm=anthropic_llm() if a.ai else None)


if __name__ == "__main__":
    main()
