from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

from .models import Finding

_SEVERITY_COLOR = {
    "critical": "\033[41m\033[97m",  # white on red
    "high": "\033[91m",              # red
    "medium": "\033[93m",            # yellow
    "low": "\033[96m",               # cyan
}
_RESET = "\033[0m"


def print_console_report(findings: list[Finding], event_count: int, *, color: bool = True) -> None:
    print(f"\nWinLog Threat Hunter - analyzed {event_count} events, {len(findings)} finding(s)\n")

    if not findings:
        print("No findings. Nothing in this dataset matched a detection rule.")
        return

    counts = Counter(f.severity for f in findings)
    order = ["critical", "high", "medium", "low"]
    summary = "  ".join(f"{sev.upper()}: {counts.get(sev, 0)}" for sev in order if counts.get(sev))
    print(summary + "\n")

    for f in findings:
        c = _SEVERITY_COLOR.get(f.severity, "") if color else ""
        r = _RESET if color else ""
        print(f"{c}[{f.severity.upper():8}]{r} {f.title}")
        print(f"           rule: {f.rule_id}   mitre: {f.mitre_technique}")
        who = " / ".join(x for x in [f.account_name, f.host, f.source_ip] if x)
        if who:
            print(f"           who/where: {who}")
        print(f"           when: {f.first_seen.isoformat()} → {f.last_seen.isoformat()}")
        print(f"           {f.description}")
        print()


def write_json_report(findings: list[Finding], path: str | Path) -> None:
    path = Path(path)
    path.write_text(json.dumps([f.to_dict() for f in findings], indent=2), encoding="utf-8")


def write_csv_report(findings: list[Finding], path: str | Path) -> None:
    path = Path(path)
    fieldnames = [
        "rule_id", "title", "severity", "mitre_technique", "description",
        "first_seen", "last_seen", "account_name", "host", "source_ip", "evidence_count",
    ]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for f in findings:
            writer.writerow(f.to_dict())
