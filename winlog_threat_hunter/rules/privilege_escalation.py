"""Flags accounts that receive special/administrative privileges (4672)
shortly after a logon, when that account has no other privileged activity
in the load. A single 4672 isn't inherently malicious - domain admins get
these constantly - but an account that suddenly starts triggering 4672
after a burst of failed logons or an unusual logon type is worth an
analyst's eyes.
"""

from __future__ import annotations

from datetime import timedelta

from ..models import Event, Finding
from .base import Rule

NOTABLE_LOGON_TYPES = {2, 8, 10}
LOOKBACK_MINUTES = 5


class PrivilegeEscalationRule(Rule):
    rule_id = "PRIVESC-001"
    title = "Special privileges assigned following a notable interactive logon"
    severity = "medium"
    mitre_technique = "T1078 - Valid Accounts / Privilege Escalation"

    def evaluate(self, events: list[Event]) -> list[Finding]:
        findings: list[Finding] = []
        priv_events = [e for e in events if e.is_special_privileges_assigned]

        for priv in priv_events:
            preceding_logons = [
                e for e in events
                if e.is_logon_success
                and e.account_name == priv.account_name
                and timedelta(0) <= (priv.timestamp - e.timestamp) <= timedelta(minutes=LOOKBACK_MINUTES)
            ]
            if not preceding_logons:
                continue

            logon = max(preceding_logons, key=lambda e: e.timestamp)
            if logon.logon_type not in NOTABLE_LOGON_TYPES:
                continue

            prior_failures = [
                e for e in events
                if e.is_logon_failure
                and e.account_name == priv.account_name
                and timedelta(0) <= (logon.timestamp - e.timestamp) <= timedelta(minutes=30)
            ]

            severity = "high" if prior_failures else self.severity
            desc = (
                f"Account '{priv.account_name}' was granted special privileges at {priv.timestamp.isoformat()} "
                f"following a logon type {logon.logon_type} at {logon.timestamp.isoformat()} on {logon.host}."
            )
            if prior_failures:
                desc += f" {len(prior_failures)} failed logon(s) for this account preceded the successful logon - review as a potential compromised-account escalation."

            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                severity=severity,
                mitre_technique=self.mitre_technique,
                description=desc,
                first_seen=logon.timestamp,
                last_seen=priv.timestamp,
                account_name=priv.account_name,
                host=priv.host,
                source_ip=logon.source_ip,
                evidence_count=1 + len(prior_failures),
            ))

        return findings
