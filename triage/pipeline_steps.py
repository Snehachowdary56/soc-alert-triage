"""The triage steps: validate -> deduplicate -> group into incidents -> enrich -> score."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from . import intel

REQUIRED = {"alert_id", "timestamp", "source", "type"}
# Alert types that are routine and only matter in large numbers
NOISE_TYPES = {"dns_query", "vpn_login", "av_scan_clean"}
GROUP_WINDOW = timedelta(minutes=30)


@dataclass
class Incident:
    incident_id: str
    type: str
    first_seen: str
    last_seen: str
    alert_ids: list[str]
    sources: list[str]
    users: list[str]
    hosts: list[str]
    src_ips: list[str]
    dest_ips: list[str]
    domains: list[str]
    sample_details: list[str]
    related_types: list[str] = field(default_factory=list)
    enrichment: list[str] = field(default_factory=list)
    score: int = 0
    severity: str = "Low"
    escalate: bool = False
    reasons: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.alert_ids)


def validate(alerts: list[dict]) -> tuple[list[dict], list[dict]]:
    """Drops malformed alerts and exact duplicates. Returns (good alerts, issue log)."""
    good, issues, seen = [], [], set()
    for a in alerts:
        missing = REQUIRED - a.keys()
        if missing:
            issues.append({"alert_id": a.get("alert_id", "?"), "issue": f"missing fields {sorted(missing)}"})
            continue
        try:
            datetime.fromisoformat(a["timestamp"])
        except (TypeError, ValueError):
            issues.append({"alert_id": a["alert_id"], "issue": "bad timestamp"})
            continue
        if a["alert_id"] in seen:
            issues.append({"alert_id": a["alert_id"], "issue": "duplicate alert"})
            continue
        seen.add(a["alert_id"])
        good.append(a)
    return good, issues


def _group_key(a: dict) -> tuple:
    """Alerts about the same thing: same type and the same main actor (user, host or source IP)."""
    t = a["type"]
    if t in {"failed_login", "successful_login", "foreign_login", "phishing_email"}:
        return (t, a.get("user"), a.get("src_ip") if t != "phishing_email" else a.get("domain"))
    if t in {"port_scan"}:
        return (t, a.get("src_ip"))
    if t in {"suspicious_dns", "dns_query"}:
        return (t, a.get("host"), a.get("domain"))
    return (t, a.get("user"), a.get("host"))


def group(alerts: list[dict], window: timedelta = GROUP_WINDOW) -> list[Incident]:
    """Groups related alerts that happen close together into one incident."""
    buckets: dict[tuple, list[list[dict]]] = defaultdict(list)
    for a in sorted(alerts, key=lambda x: x["timestamp"]):
        runs = buckets[_group_key(a)]
        ts = datetime.fromisoformat(a["timestamp"])
        if runs and ts - datetime.fromisoformat(runs[-1][-1]["timestamp"]) <= window:
            runs[-1].append(a)
        else:
            runs.append([a])

    incidents = []
    for runs in buckets.values():
        for run in runs:
            def uniq(k):
                return sorted({x[k] for x in run if x.get(k)})
            incidents.append(Incident(
                incident_id="", type=run[0]["type"], first_seen=run[0]["timestamp"], last_seen=run[-1]["timestamp"],
                alert_ids=[x["alert_id"] for x in run], sources=uniq("source"), users=uniq("user"),
                hosts=uniq("host"), src_ips=uniq("src_ip"), dest_ips=uniq("dest_ip"), domains=uniq("domain"),
                sample_details=[x.get("details", "") for x in run[:3]],
            ))
    incidents.sort(key=lambda x: x.first_seen)
    for n, inc in enumerate(incidents, start=1):
        inc.incident_id = f"INC-{n:04d}"
    return incidents


def correlate(incidents: list[Incident], window: timedelta = timedelta(hours=1)) -> None:
    """Links incidents that involve the same user or host within an hour (e.g. failed logins then success)."""
    for a in incidents:
        ta = datetime.fromisoformat(a.first_seen)
        for b in incidents:
            if a is b:
                continue
            tb = datetime.fromisoformat(b.first_seen)
            same_actor = set(a.users) & set(b.users) or set(a.hosts) & set(b.hosts)
            if (same_actor and abs(ta - tb) <= window and b.type not in NOISE_TYPES
                    and b.type != a.type and b.type not in a.related_types):
                a.related_types.append(b.type)


def enrich(inc: Incident) -> None:
    for ip in inc.src_ips + inc.dest_ips:
        if ip in intel.BAD_IPS:
            inc.enrichment.append(f"{ip} is on the threat list ({intel.BAD_IPS[ip]})")
        c = intel.country(ip)
        if c and c not in (intel.HOME_COUNTRY, "unknown"):
            inc.enrichment.append(f"{ip} is located outside Canada ({c})")
    for d in inc.domains:
        if d in intel.BAD_DOMAINS:
            inc.enrichment.append(f"{d} is a {intel.BAD_DOMAINS[d]}")
    for u in inc.users:
        if u in intel.PRIVILEGED_USERS:
            inc.enrichment.append(f"{u} is a privileged (admin or service) account")
    for h in inc.hosts:
        if h in intel.CRITICAL_HOSTS:
            inc.enrichment.append(f"{h} is a critical server")


BASE_SCORE = {"malware_detected": 50, "phishing_email": 40, "suspicious_connection": 40, "foreign_login": 30,
              "port_scan": 30, "suspicious_dns": 25, "failed_login": 10, "successful_login": 5}


def score(inc: Incident) -> None:
    s = BASE_SCORE.get(inc.type, 0)
    reasons = [f"{inc.type.replace('_', ' ')} (+{s})"] if s else []

    def add(points: int, why: str):
        nonlocal s
        s += points
        reasons.append(f"{why} (+{points})")

    if inc.type == "failed_login" and inc.count >= 10:
        add(30, f"{inc.count} failed logins in a short time")
    if inc.type == "port_scan" and inc.count >= 10:
        add(10, f"{inc.count} hosts probed")
    if any("threat list" in e for e in inc.enrichment):
        add(30, "IP on threat list")
    if any("outside Canada" in e for e in inc.enrichment):
        add(15, "connection from outside Canada")
    if any("phishing" in e or "look-alike" in e for e in inc.enrichment):
        add(15, "known phishing or look-alike domain")
    if any("privileged" in e for e in inc.enrichment):
        add(20, "privileged account involved")
    if any("critical server" in e for e in inc.enrichment):
        add(20, "critical server involved")
    if "clicked" in " ".join(inc.sample_details).lower():
        add(20, "user clicked the link")
    if inc.type == "failed_login" and "successful_login" in inc.related_types:
        add(30, "followed by a successful login (possible account takeover)")
    if inc.type == "foreign_login" and "successful_login" in inc.related_types:
        add(25, "home sign-in shortly before (impossible travel)")
    if inc.type == "successful_login" and "failed_login" in inc.related_types:
        add(30, "came right after many failed logins (possible account takeover)")
    if inc.type == "malware_detected" and "suspicious_connection" in inc.related_types:
        add(20, "same device then contacted a suspicious IP")
    if inc.type in NOISE_TYPES:
        s = 0
        reasons = ["routine activity"]

    inc.score = s
    inc.reasons = reasons
    inc.severity = "High" if s >= 70 else "Medium" if s >= 35 else "Low"
    inc.escalate = inc.severity == "High"
