"""Flags the classic 'create an account, immediately add it to a
privileged group' persistence pattern. Legitimate account provisioning
this fast is rare outside of scripted onboarding — and even then it's
worth an analyst confirming it was expected.
"""

from __future__ import annotations

from datetime import timedelta

from ..models import Event, Finding
from .base import Rule

WINDOW_MINUTES = 10
PRIVILEGED_GROUPS = {"domain admins", "enterprise admins", "administrators", "schema admins"}


class AdminPersistenceRule(Rule):
    rule_id = "PERSIST-001"
    title = "Account created and added to a privileged group in rapid succession"
    severity = "critical"
    mitre_technique = "T1136 - Create Account / T1098 - Account Manipulation"

    def evaluate(self, events: list[Event]) -> list[Finding]:
        findings: list[Finding] = []

        creations = [e for e in events if e.is_account_created]
        group_adds = [e for e in events if e.is_member_added_to_group]

        for creation in creations:
            created_account = creation.target_account or creation.account_name
            for add in group_adds:
                if add.target_account != created_account:
                    continue
                if not (timedelta(0) <= (add.timestamp - creation.timestamp) <= timedelta(minutes=WINDOW_MINUTES)):
                    continue

                is_privileged = (add.target_group or "").strip().lower() in PRIVILEGED_GROUPS
                severity = self.severity if is_privileged else "medium"

                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title + (f" ({add.target_group})" if is_privileged else ""),
                    severity=severity,
                    mitre_technique=self.mitre_technique,
                    description=(
                        f"Account '{created_account}' was created at {creation.timestamp.isoformat()} on {creation.host} "
                        f"and added to group '{add.target_group}' at {add.timestamp.isoformat()} — "
                        f"{int((add.timestamp - creation.timestamp).total_seconds())} seconds later. "
                        "Confirm this matches an expected, ticketed onboarding action."
                    ),
                    first_seen=creation.timestamp,
                    last_seen=add.timestamp,
                    account_name=created_account,
                    host=creation.host,
                    evidence_count=2,
                ))

        return findings
