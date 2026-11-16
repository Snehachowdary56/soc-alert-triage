# AI-Assisted Security Alert Triage

Security teams receive hundreds of alerts a day. Most are repeats or routine noise, and the real
attacks get buried. This project turns a noisy alert stream into a short, ranked list of tickets,
each with a plain-language summary and a recommended next step, using AI **with guardrails**.

> **Data note:** all alerts are **generated sample data**. IP addresses use reserved documentation
> ranges and domains end in `.example`, so nothing refers to a real person, company or server.

## What it does

```
alerts (JSON Lines) ─► validate ─► deduplicate & group ─► correlate ─► enrich ─► score ─► AI summary ─► tickets + report
```

| Step | What happens |
|---|---|
| Validate | Drops duplicate alerts (same ID sent twice) and malformed ones, and logs each one. |
| Group | Related alerts close in time become one incident, e.g. 40 failed logins from one IP becomes 1 incident. |
| Correlate | Links incidents for the same user or device within an hour, e.g. failed logins followed by a success. |
| Enrich | Adds context: IP on a threat list, connection from outside Canada, privileged account, critical server, phishing domain. |
| Score | Rule-based score with the reasons written out; High = escalate, Medium = open ticket, Low/routine = closed. |
| Summarize | Template summary by default. With `--ai`, an LLM writes it, protected by the guardrails below. |
| Output | `output/tickets.csv` (Jira-style tickets, highest priority first) and `output/triage_report.md`. |

On the sample data: **200 alerts → 10 tickets (6 escalated)**, about a 95% smaller queue, and all 6
planted attacks are escalated: brute-force then successful login on an admin account, phishing click,
malware plus a call to a known bad server, and impossible travel.

## AI guardrails

1. **No data leakage:** emails, passwords, tokens and keys are masked before anything is sent to the LLM.
2. **Facts only:** the model gets only the incident facts and must reply `NEEDS HUMAN REVIEW` if unsure.
3. **Hallucination check:** every IP, user, host or domain in the AI answer is checked against the facts.
   If it mentions anything that is not there, the answer is rejected and the template summary is used.
4. **Never blocks triage:** if the API fails or returns nothing, the template summary is used.
5. **The API key is read from an environment variable** and is never stored in code.

## Terms in plain language

- **Alert**: an automatic warning from a security tool (sign-in system, email filter, antivirus, firewall, DNS).
- **Incident**: one real event, which may produce many alerts.
- **Triage**: deciding which incidents matter most and what to do first.
- **Escalate**: pass a serious incident to a senior analyst right away.
- **Enrichment**: adding context that helps decide, such as "this IP is on a threat list".
- **Hallucination**: when an AI states something that is not true or not in the data.

## Run it (Windows Command Prompt)

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pytest -q
python -m triage
```

PowerShell or Bash one-command runs:

```
powershell -ExecutionPolicy Bypass -File scripts\run_triage.ps1
bash scripts/run_triage.sh
```

Optional AI summaries (needs your own Anthropic API key, never commit it):

```
set ANTHROPIC_API_KEY=your-key-here
python -m triage --ai
```

## Project layout

```
triage/sample.py          sample alerts with planted attacks, noise and duplicates
triage/intel.py           sample threat list, IP locations, privileged users, critical servers
triage/pipeline_steps.py  validate, group, correlate, enrich, score
triage/redact.py          masks secrets before AI use
triage/summarize.py       template and AI summaries with hallucination checks
triage/pipeline.py        runs everything (command line)
scripts/                  run_triage.sh (Bash) and run_triage.ps1 (PowerShell)
tests/                    26 pytest tests
```
