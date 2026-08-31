"""Flags process-creation events (4688 / Sysmon EventID 1) whose command
line matches a small set of well-known suspicious patterns: encoded/hidden
PowerShell, common credential-dumping tool names, LOLBins used for download
or defense evasion, and direct SAM/registry hive dumping.

This is intentionally a short, high-signal list rather than an attempt at a
full detection ruleset (that's what Sigma/Splunk are for) - the goal is to
demonstrate the detection-engineering pattern: known-bad indicators, a
match, an ATT&CK mapping, and a plain-English reason an analyst can act on.
"""

from __future__ import annotations

import re

from ..models import Event, Finding
from .base import Rule

_PATTERNS: list[tuple[str, str, str]] = [
    (r"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}", "Encoded/obfuscated PowerShell command", "T1059.001 - PowerShell"),
    (r"-w(indowstyle)?\s+hidden", "PowerShell launched with a hidden window", "T1564.003 - Hide Artifacts"),
    (r"\bmimikatz\b|sekurlsa::|lsadump::", "Reference to Mimikatz / credential dumping module", "T1003 - OS Credential Dumping"),
    (r"reg(\.exe)?\s+save\s+hklm\\sam", "Registry SAM hive export (offline credential extraction)", "T1003.002 - Security Account Manager"),
    (r"certutil(\.exe)?.*-urlcache", "certutil used as a download utility (LOLBin)", "T1105 - Ingress Tool Transfer"),
    (r"net(\.exe)?\s+user\s+\S+(\s+\S+)*\s+/add\b", "Local/domain account created via net.exe", "T1136 - Create Account"),
    (r"vssadmin(\.exe)?\s+delete\s+shadows", "Volume shadow copy deletion (common ransomware precursor)", "T1490 - Inhibit System Recovery"),
    (r"rundll32(\.exe)?\s+.*,\s*\w+", "rundll32 invoked with an exported function (possible proxy execution)", "T1218.011 - Rundll32"),
]

_COMPILED = [(re.compile(pat, re.IGNORECASE), label, technique) for pat, label, technique in _PATTERNS]


class SuspiciousProcessRule(Rule):
    rule_id = "PROC-001"
    title = "Suspicious process command line"
    severity = "high"
    mitre_technique = "T1059 - Command and Scripting Interpreter"

    def evaluate(self, events: list[Event]) -> list[Finding]:
        findings: list[Finding] = []

        for event in events:
            if not event.is_process_creation or not event.command_line:
                continue

            for pattern, label, technique in _COMPILED:
                if pattern.search(event.command_line):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=f"{self.title}: {label}",
                        severity=self.severity,
                        mitre_technique=technique,
                        description=(
                            f"Process '{event.process_name or 'unknown'}' launched by '{event.account_name or 'unknown'}' "
                            f"on {event.host} matched pattern for: {label}. Command line: {event.command_line!r}"
                        ),
                        first_seen=event.timestamp,
                        last_seen=event.timestamp,
                        account_name=event.account_name,
                        host=event.host,
                        evidence_count=1,
                    ))
                    break

        return findings
