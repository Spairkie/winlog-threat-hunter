"""Loads normalized events from JSON Lines or CSV exports.

Real-world source: `Get-WinEvent -FilterHashtable @{LogName='Security'} |
Select-Object ... | ConvertTo-Json` or a Winlogbeat/Sysmon export flattened
to one JSON object per line. This module doesn't care which log shipper
produced the file - it only needs the field names below (extra fields are
kept in `Event.raw` and ignored otherwise).
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Iterator

from .models import Event

_INT_FIELDS = {"event_id", "logon_type"}


def _coerce_row(row: dict) -> Event:
    row = dict(row)

    raw = dict(row)

    for f in _INT_FIELDS:
        if row.get(f) not in (None, ""):
            row[f] = int(row[f])
        else:
            row[f] = None

    ts = row.get("timestamp")
    if isinstance(ts, str):
        ts = ts.replace("Z", "+00:00")
        row["timestamp"] = datetime.fromisoformat(ts)
    elif not isinstance(ts, datetime):
        raise ValueError(f"Event missing a parseable 'timestamp' field: {row}")

    known = {f.name for f in Event.__dataclass_fields__.values()}  # type: ignore[attr-defined]
    kwargs = {k: v for k, v in row.items() if k in known and k != "raw"}
    kwargs.setdefault("event_id", 0)
    kwargs["event_id"] = kwargs["event_id"] or 0

    return Event(raw=raw, **kwargs)


def load_jsonl(path: str | Path) -> Iterator[Event]:
    path = Path(path)
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON - {exc}") from exc
            yield _coerce_row(row)


def load_csv(path: str | Path) -> Iterator[Event]:
    path = Path(path)
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            yield _coerce_row(row)


def load_events(path: str | Path) -> list[Event]:
    """Loads events from a .jsonl or .csv file, sorted by timestamp."""
    path = Path(path)
    if path.suffix.lower() in (".jsonl", ".json", ".ndjson"):
        events = list(load_jsonl(path))
    elif path.suffix.lower() == ".csv":
        events = list(load_csv(path))
    else:
        raise ValueError(f"Unsupported input format: {path.suffix} (expected .jsonl or .csv)")
    return sorted(events, key=lambda e: e.timestamp)
