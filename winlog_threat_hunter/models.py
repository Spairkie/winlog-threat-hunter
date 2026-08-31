"""Core data structures: a normalized Windows event record and a Finding
produced by a detection rule."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Event:
    """A normalized Windows Security/Sysmon event.

    Field names deliberately mirror the Windows Event Log fields analysts
    already know (EventID, Account Name, Source Network Address, etc.) so a
    real export needs minimal reshaping to match this schema.
    """

    event_id: int
    timestamp: datetime
    host: str = ""
    account_name: str = ""
    source_ip: str = ""
    logon_type: int | None = None
    status: str = ""            # "success" | "failure" | ""
    process_name: str = ""
    command_line: str = ""
    target_account: str = ""    # e.g. account created/modified by this event
    target_group: str = ""      # e.g. group an account was added to
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_logon_failure(self) -> bool:
        return self.event_id == 4625

    @property
    def is_logon_success(self) -> bool:
        return self.event_id == 4624

    @property
    def is_special_privileges_assigned(self) -> bool:
        return self.event_id == 4672

    @property
    def is_process_creation(self) -> bool:
        return self.event_id in (4688, 1)  # 4688 = Security log, 1 = Sysmon

    @property
    def is_account_created(self) -> bool:
        return self.event_id == 4720

    @property
    def is_member_added_to_group(self) -> bool:
        return self.event_id in (4728, 4732, 4756)


@dataclass
class Finding:
    """A single detection produced by a rule."""

    rule_id: str
    title: str
    severity: str            # "low" | "medium" | "high" | "critical"
    mitre_technique: str
    description: str
    first_seen: datetime
    last_seen: datetime
    account_name: str = ""
    host: str = ""
    source_ip: str = ""
    evidence_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        d = self.__dict__.copy()
        d["first_seen"] = self.first_seen.isoformat()
        d["last_seen"] = self.last_seen.isoformat()
        return d
