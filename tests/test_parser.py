from __future__ import annotations

import json
from pathlib import Path

import pytest

from winlog_threat_hunter.parser import load_events


def test_loads_jsonl_sorted_by_timestamp(tmp_path: Path):
    path = tmp_path / "events.jsonl"
    path.write_text(
        '{"event_id": 4624, "timestamp": "2026-01-01T10:00:00Z", "host": "H1", "account_name": "b"}\n'
        '{"event_id": 4624, "timestamp": "2026-01-01T09:00:00Z", "host": "H1", "account_name": "a"}\n'
    )
    events = load_events(path)
    assert [e.account_name for e in events] == ["a", "b"]


def test_skips_blank_lines(tmp_path: Path):
    path = tmp_path / "events.jsonl"
    path.write_text(
        '{"event_id": 4624, "timestamp": "2026-01-01T10:00:00Z", "host": "H1"}\n'
        '\n'
        '{"event_id": 4625, "timestamp": "2026-01-01T11:00:00Z", "host": "H1"}\n'
    )
    events = load_events(path)
    assert len(events) == 2


def test_invalid_json_raises_with_line_number(tmp_path: Path):
    path = tmp_path / "events.jsonl"
    path.write_text('{"event_id": 4624, "timestamp": "2026-01-01T10:00:00Z"}\nnot json\n')
    with pytest.raises(ValueError, match=r"events\.jsonl:2"):
        load_events(path)


def test_loads_csv(tmp_path: Path):
    path = tmp_path / "events.csv"
    path.write_text("event_id,timestamp,host,account_name\n4625,2026-01-01T10:00:00Z,H1,alice\n")
    events = load_events(path)
    assert events[0].event_id == 4625
    assert events[0].account_name == "alice"


def test_unsupported_extension_raises(tmp_path: Path):
    path = tmp_path / "events.xml"
    path.write_text("<events/>")
    with pytest.raises(ValueError, match="Unsupported input format"):
        load_events(path)
