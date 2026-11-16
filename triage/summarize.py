"""Writes a short summary and next steps for each incident.

Two modes:
* template (default, no AI, no API key): a clear summary built from the facts
* AI: an LLM writes the summary, with three guardrails
    1. it only receives redacted facts (no emails, passwords or tokens)
    2. it is told to use only those facts and say NEEDS HUMAN REVIEW if unsure
    3. its answer is checked: any IP, user, host or domain it mentions that is not in the
       facts is treated as a hallucination, and the template summary is used instead
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Callable

from .pipeline_steps import Incident
from .redact import redact

NEXT_STEPS = {
    "failed_login": "Check whether the account was accessed; reset the password and enforce MFA if needed.",
    "successful_login": "Confirm with the user that the sign-in was theirs.",
    "foreign_login": "Confirm travel with the user; if not theirs, revoke sessions and reset the password.",
    "phishing_email": "Remove the email from all inboxes, block the domain and reset the user's password.",
    "malware_detected": "Isolate the device, confirm quarantine and run a full scan.",
    "suspicious_connection": "Block the destination IP and check the device for other activity.",
    "port_scan": "Find out what is running on the scanning device and whether the scan was approved.",
    "suspicious_dns": "Block the domain and check whether the user entered credentials.",
}

LLMFn = Callable[[str], str]


def facts(inc: Incident) -> dict:
    return {
        "incident_id": inc.incident_id, "type": inc.type, "alerts": inc.count,
        "first_seen": inc.first_seen, "last_seen": inc.last_seen, "users": inc.users, "hosts": inc.hosts,
        "source_ips": inc.src_ips, "destination_ips": inc.dest_ips, "domains": inc.domains,
        "related_activity": inc.related_types, "enrichment": inc.enrichment,
        "severity": inc.severity, "score_reasons": inc.reasons,
        "example_details": [redact(d) for d in inc.sample_details],
    }


def template_summary(inc: Incident) -> str:
    who = ", ".join(inc.users or inc.hosts or inc.src_ips) or "unknown"
    text = f"{inc.severity} severity: {inc.count} {inc.type.replace('_', ' ')} alert(s) involving {who}"
    if inc.enrichment:
        text += "; " + "; ".join(inc.enrichment)
    if inc.related_types:
        text += "; related activity: " + ", ".join(t.replace("_", " ") for t in inc.related_types)
    return text + ". Next step: " + NEXT_STEPS.get(inc.type, "Review and close if expected.")


PROMPT = """You are helping a security analyst triage an incident.
Use ONLY the facts in the JSON below. Do not invent IPs, users, hosts, domains or events.
If the facts are not enough to decide, write exactly: NEEDS HUMAN REVIEW.
Reply in at most 3 sentences: what happened, why it matters, and the next step.

FACTS:
{facts}"""

ENTITY = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:example|com|net|org)\b|"
                    r"\b(?:LT|WS|SRV)-[A-Z0-9]+\b|\b(?:admin|svc)\.[a-z]+\b", re.I)


def check_grounded(summary: str, inc: Incident) -> list[str]:
    """Returns entities the summary mentions that are NOT in the incident facts (hallucinations)."""
    known = {x.lower() for x in inc.users + inc.hosts + inc.src_ips + inc.dest_ips + inc.domains}
    return sorted({m.lower() for m in ENTITY.findall(summary)} - known)


def ai_summary(inc: Incident, llm: LLMFn) -> tuple[str, str]:
    """Returns (summary, status). Status is ai, ai_needs_review, or fallback_* when a guardrail fired."""
    prompt = PROMPT.format(facts=json.dumps(facts(inc), indent=2))
    try:
        out = llm(prompt).strip()
    except Exception as exc:  # network or API problem: never block triage
        return template_summary(inc), f"fallback_error: {type(exc).__name__}"
    if not out:
        return template_summary(inc), "fallback_empty"
    if "NEEDS HUMAN REVIEW" in out.upper():
        return out, "ai_needs_review"
    unknown = check_grounded(out, inc)
    if unknown:
        return template_summary(inc), "fallback_hallucination: " + ", ".join(unknown)
    return out, "ai"


def anthropic_llm(model: str | None = None) -> LLMFn:
    """Real LLM call using the ANTHROPIC_API_KEY environment variable (never stored in code)."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("Set ANTHROPIC_API_KEY to use --ai (or run without --ai)")
    model = model or os.environ.get("TRIAGE_MODEL", "claude-haiku-5-5")

    def call(prompt: str) -> str:
        body = json.dumps({"model": model, "max_tokens": 300,
                           "messages": [{"role": "user", "content": prompt}]}).encode()
        req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, headers={
            "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.load(resp)
        return "".join(part.get("text", "") for part in data.get("content", []))

    return call
