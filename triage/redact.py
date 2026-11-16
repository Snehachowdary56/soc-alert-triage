"""Removes sensitive data before any text leaves the machine (for example, to an LLM).

This is the data-leakage guardrail: emails, passwords, tokens and card-like numbers are masked.
"""

import re

PATTERNS = [
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*\S+"), r"\1=[REDACTED]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[EMAIL]"),
    (re.compile(r"\b(?:\d[ -]?){13,16}\b"), "[NUMBER]"),
    (re.compile(r"\b(sk|ghp|AKIA)[A-Za-z0-9_-]{10,}\b"), "[KEY]"),
]


def redact(text: str) -> str:
    for pattern, repl in PATTERNS:
        text = pattern.sub(repl, text)
    return text
