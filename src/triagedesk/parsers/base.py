"""Shared parser types and helpers."""

from __future__ import annotations

from dataclasses import dataclass, field

from triagedesk.models import Event

MAX_RAW_LENGTH = 4096


@dataclass
class ParseOutcome:
    """Events produced from one file, with counts for the evidence register.

    ``ignored`` lines are valid log lines that carry nothing the detection rules use
    (for example a session-closed message). ``malformed`` lines do not match the
    expected format at all.
    """

    events: list[Event] = field(default_factory=list)
    total: int = 0
    ignored: int = 0
    malformed: int = 0


def make_event_id(file_tag: str, line_no: int) -> str:
    """Build a stable event identifier such as ``F1-L42`` (file 1, line 42)."""
    return f"{file_tag}-L{line_no}"


def clip(line: str) -> str:
    """Limit the stored copy of a raw line so a single huge line cannot exhaust memory."""
    line = line.rstrip("\r\n")
    if len(line) > MAX_RAW_LENGTH:
        return line[:MAX_RAW_LENGTH] + " [truncated]"
    return line
