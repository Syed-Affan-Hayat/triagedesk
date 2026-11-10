"""Shared fixtures."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from triagedesk.config import Settings
from triagedesk.models import Event

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def settings() -> Settings:
    return Settings(enrichment_mode="mock")


@pytest.fixture
def sample_files() -> dict[str, bytes]:
    return {name: (SAMPLES / name).read_bytes() for name in ("auth.log", "access.log")}


def make_event(event_id: str, seconds: int, action: str = "ssh_failed", **kwargs) -> Event:
    """Build a minimal SSH event ``seconds`` after a fixed start time."""
    base = datetime(2026, 11, 3, 13, 0, tzinfo=timezone.utc)
    defaults = {
        "source": "ssh",
        "raw": f"line {event_id}",
        "line_no": 1,
        "file_name": "test.log",
        "src_ip": "203.0.113.1",
        "user": "admin",
        "outcome": "failure" if action == "ssh_failed" else "success",
    }
    defaults.update(kwargs)
    return Event(event_id=event_id, timestamp=base + timedelta(seconds=seconds), action=action, **defaults)
