"""Generates realistic SAMPLE security alerts (not real company data).

Sources mimic what a security team sees every day:
  IdP (sign-in system), Email gateway, EDR (endpoint/antivirus), Firewall, DNS, SIEM rules.
The stream deliberately contains repeats and noise, which is the problem triage solves.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "admin.ivan", "svc.backup"]
HOSTS = ["LT-0142", "LT-0188", "LT-0203", "WS-0007", "SRV-FILE01", "SRV-DB02"]
EXTERNAL_IPS = ["203.0.113.45", "198.51.100.23", "192.0.2.77", "203.0.113.200", "198.51.100.9"]
INTERNAL_IPS = ["10.0.4.21", "10.0.4.37", "10.0.8.15", "10.0.9.3"]
PHISH_DOMAINS = ["micros0ft-login.example", "payroll-update.example", "secure-docs.example"]
GOOD_DOMAINS = ["github.com", "office.com", "slack.com"]


def _alert(i: int, ts: datetime, **kw) -> dict:
    return {"alert_id": f"AL-{i:05d}", "timestamp": ts.isoformat(timespec="seconds"), **kw}


def generate_alerts(n_noise: int = 120, seed: int = 3, start: str = "2026-11-10T08:00:00") -> list[dict]:
    rng = random.Random(seed)
    t0 = datetime.fromisoformat(start)
    alerts: list[dict] = []
    i = 1

    def add(minutes: float, **kw):
        nonlocal i
        alerts.append(_alert(i, t0 + timedelta(minutes=minutes), **kw))
        i += 1

    # 1) Brute force: many failed logins for one user from one external IP, then a success
    for k in range(40):
        add(30 + k * 0.5, source="IdP", type="failed_login", user="admin.ivan", src_ip="203.0.113.45",
            details=f"Invalid password for admin.ivan@corp.example (attempt {k + 1})")
    add(51, source="IdP", type="successful_login", user="admin.ivan", src_ip="203.0.113.45",
        details="Sign-in succeeded after repeated failures")

    # 2) Phishing email clicked by a user
    add(95, source="Email", type="phishing_email", user="carol", domain="payroll-update.example",
        details="Email from hr@payroll-update.example with link; user clicked link. password=Winter2026! seen in form post")

    # 3) Malware on a laptop that then contacts a known bad IP
    add(140, source="EDR", type="malware_detected", user="dave", host="LT-0188",
        details="Trojan.GenericKD quarantined from Downloads/invoice.pdf.exe")
    add(143, source="Firewall", type="suspicious_connection", user="dave", host="LT-0188", src_ip="10.0.4.37",
        dest_ip="198.51.100.23", details="Outbound TCP 443 to IP on threat list")

    # 4) Port scan from inside the network
    for k in range(25):
        add(200 + k * 0.2, source="Firewall", type="port_scan", host="WS-0007", src_ip="10.0.8.15",
            dest_ip=f"10.0.4.{10 + k}", details=f"Connection attempts to many ports on 10.0.4.{10 + k}")

    # 5) Impossible travel: same user, two countries, 20 minutes apart
    add(260, source="IdP", type="successful_login", user="erin", src_ip="10.0.9.3", details="Sign-in from Toronto office")
    add(280, source="IdP", type="foreign_login", user="erin", src_ip="192.0.2.77", details="Sign-in from overseas location")

    # 6) DNS lookups to a look-alike domain
    for k in range(6):
        add(300 + k, source="DNS", type="suspicious_dns", host="LT-0203", user="frank",
            domain="micros0ft-login.example", details="DNS query to newly registered look-alike domain")

    # Noise: low-value alerts every security team sees
    for _ in range(n_noise):
        kind = rng.choice(["failed_login", "dns_ok", "vpn_login", "av_scan"])
        m = rng.uniform(0, 480)
        u = rng.choice(USERS[:8])
        if kind == "failed_login":
            add(m, source="IdP", type="failed_login", user=u, src_ip=rng.choice(INTERNAL_IPS),
                details=f"Invalid password for {u}@corp.example")
        elif kind == "dns_ok":
            add(m, source="DNS", type="dns_query", user=u, host=rng.choice(HOSTS), domain=rng.choice(GOOD_DOMAINS),
                details="Routine DNS lookup")
        elif kind == "vpn_login":
            add(m, source="VPN", type="vpn_login", user=u, src_ip=rng.choice(INTERNAL_IPS), details="VPN connected")
        else:
            add(m, source="EDR", type="av_scan_clean", user=u, host=rng.choice(HOSTS), details="Scheduled scan: no threats")

    # Exact duplicates (same alert sent twice by a connector)
    alerts += [dict(alerts[3]), dict(alerts[42]), dict(alerts[60])]
    alerts.sort(key=lambda a: a["timestamp"])
    return alerts


def save_jsonl(alerts: list[dict], path: str | Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for a in alerts:
            f.write(json.dumps(a) + "\n")


def load_jsonl(path: str | Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]
