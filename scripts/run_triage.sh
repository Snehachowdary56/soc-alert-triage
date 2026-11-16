#!/usr/bin/env bash
# Runs the triage pipeline and prints the escalated tickets (Linux, macOS, Git Bash).
set -euo pipefail
cd "$(dirname "$0")/.."
python -m triage --out output "$@"
echo
echo "Escalated tickets:"
grep ",yes," output/tickets.csv | cut -d, -f1,3,6 || echo "none"
echo "High severity count: $(grep -c ',High,' output/tickets.csv || true)"
