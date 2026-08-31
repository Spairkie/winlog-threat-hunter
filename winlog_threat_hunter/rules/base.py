from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Event, Finding


class Rule(ABC):
    """Base class for a detection rule. A rule receives every event in the
    load and returns zero or more Findings."""

    rule_id: str
    title: str
    severity: str
    mitre_technique: str

    @abstractmethod
    def evaluate(self, events: list[Event]) -> list[Finding]:
        ...
