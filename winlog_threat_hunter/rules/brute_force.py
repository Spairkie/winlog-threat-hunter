"""Detects password-guessing / brute-force patterns: a burst of failed
logons (4625) against the same account or from the same source IP inside a
short time window, and separately flags it as escalated if a successful
logon (4624) follows from that same source shortly after.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from ..models import Event, Finding
from .base import Rule

FAILURE_THRESHOLD = 5
WINDOW_MINUTES = 10
SUCCESS_FOLLOWUP_MINUTES = 15


class BruteForceRule(Rule):
    rule_id = "BRUTE-001"
    title = "Repeated failed logons (possible brute force / password spray)"
    severity = "high"
    mitre_technique = "T1110 - Brute Force"

    @staticmethod
    def _cluster(group_events: list[Event]) -> list[list[Event]]:
        """Chains events into clusters where each event is within
        WINDOW_MINUTES of the previous one - so one continuous burst
        produces exactly one cluster, however many events are in it."""
        clusters: list[list[Event]] = []
        current: list[Event] = []
        for e in sorted(group_events, key=lambda ev: ev.timestamp):
            if current and (e.timestamp - current[-1].timestamp) > timedelta(minutes=WINDOW_MINUTES):
                clusters.append(current)
                current = []
            current.append(e)
        if current:
            clusters.append(current)
        return clusters

    def evaluate(self, events: list[Event]) -> list[Finding]:
        findings: list[Finding] = []

        failures = [e for e in events if e.is_logon_failure]

        by_source = defaultdict(list)
        for e in failures:
            by_source[e.source_ip or "unknown"].append(e)

        by_account = defaultdict(list)
        for e in failures:
            by_account[e.account_name or "unknown"].append(e)

        for group_type, groups in (("source_ip", by_source), ("account", by_account)):
            for key, group_events in groups.items():
                if key in ("unknown", ""):
                    continue

                for cluster in self._cluster(group_events):
                    if len(cluster) < FAILURE_THRESHOLD:
                        continue

                    first, last = cluster[0], cluster[-1]

                    escalated = any(
                        ev.is_logon_success
                        and (ev.source_ip == last.source_ip if group_type == "source_ip" else ev.account_name == last.account_name)
                        and timedelta(0) <= (ev.timestamp - last.timestamp) <= timedelta(minutes=SUCCESS_FOLLOWUP_MINUTES)
                        for ev in events
                    )

                    severity = "critical" if escalated else self.severity
                    desc = (
                        f"{len(cluster)} failed logons for {group_type} '{key}' between "
                        f"{first.timestamp.isoformat()} and {last.timestamp.isoformat()}."
                    )
                    if escalated:
                        desc += " A successful logon from the same source followed shortly after — treat as a likely successful compromise, not just a blocked attempt."

                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title if not escalated else self.title + " — followed by successful logon",
                        severity=severity,
                        mitre_technique=self.mitre_technique,
                        description=desc,
                        first_seen=first.timestamp,
                        last_seen=last.timestamp,
                        account_name=last.account_name if group_type == "account" else "",
                        host=last.host,
                        source_ip=last.source_ip if group_type == "source_ip" else "",
                        evidence_count=len(cluster),
                    ))

        return findings
