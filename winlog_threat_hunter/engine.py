from __future__ import annotations

from .models import Event, Finding
from .rules import ALL_RULES

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def run_rules(events: list[Event], rules=None) -> list[Finding]:
    """Runs every rule against the full event set and returns findings
    sorted by severity (most severe first), then by first_seen."""
    rules = rules if rules is not None else ALL_RULES
    findings: list[Finding] = []
    for rule in rules:
        findings.extend(rule.evaluate(events))

    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), f.first_seen))
    return findings
