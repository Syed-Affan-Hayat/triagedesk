"""Log parsers and source-type detection."""

from __future__ import annotations

from datetime import datetime, tzinfo

from triagedesk.parsers import auth_log, web_access
from triagedesk.parsers.base import ParseOutcome

SOURCE_TYPES = {
    "ssh": "Linux authentication log (OpenSSH)",
    "web": "Web server access log (Combined Log Format)",
}
SNIFF_LINES = 50


def detect_source_type(lines: list[str]) -> str | None:
    """Guess the log type from the first non-empty lines. Returns ``None`` if unrecognised."""
    sample = [line for line in lines if line.strip()][:SNIFF_LINES]
    if not sample:
        return None
    votes = {
        "ssh": sum(auth_log.matches_format(line) for line in sample),
        "web": sum(web_access.matches_format(line) for line in sample),
    }
    best = max(votes, key=votes.__getitem__)
    return best if votes[best] > 0 else None


def parse_lines(
    lines: list[str],
    source_type: str,
    file_tag: str,
    file_name: str,
    tz: tzinfo,
    now: datetime,
) -> ParseOutcome:
    """Parse ``lines`` with the parser for ``source_type``."""
    if source_type == "ssh":
        return auth_log.parse(lines, file_tag, file_name, tz=tz, now=now)
    if source_type == "web":
        return web_access.parse(lines, file_tag, file_name)
    raise ValueError(f"Unsupported source type: {source_type!r}")


__all__ = ["SOURCE_TYPES", "ParseOutcome", "detect_source_type", "parse_lines"]
