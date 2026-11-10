"""Parser for web server access logs in the Combined Log Format (Apache and Nginx default).

Example line::

    203.0.113.9 - - [03/Nov/2026:10:02:11 +0000] "GET /index.php?id=1 HTTP/1.1" 200 512 "-" "curl/8.5"

The request target is URL-decoded (twice, to expose double-encoded payloads) into
``fields.path_decoded``, which is the field the web detection rules inspect.
``fields.search_text`` joins the decoded target, referrer and user agent for rules that
look for attacker-written text anywhere in the request.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime
from urllib.parse import unquote_plus

from triagedesk.models import Event
from triagedesk.parsers.base import ParseOutcome, clip, make_event_id

COMBINED = re.compile(
    r"^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "
    r'"(?P<request>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referrer>(?:[^"\\]|\\.)*)" "(?P<agent>(?:[^"\\]|\\.)*)")?'
)
TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def matches_format(line: str) -> bool:
    """Return ``True`` if ``line`` looks like a Combined or Common Log Format line."""
    return bool(COMBINED.match(line))


def decode_target(target: str) -> str:
    """URL-decode a request target twice so that ``%2527`` becomes ``'``."""
    return unquote_plus(unquote_plus(target))


def parse(lines: Iterable[str], file_tag: str, file_name: str) -> ParseOutcome:
    """Parse access log lines into events. Timestamps in this format always carry an offset."""
    outcome = ParseOutcome()
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        outcome.total += 1
        raw = clip(line)
        match = COMBINED.match(raw)
        if match is None:
            outcome.malformed += 1
            continue
        try:
            timestamp = datetime.strptime(match["ts"], TIMESTAMP_FORMAT)
        except ValueError:
            outcome.malformed += 1
            continue

        parts = match["request"].split()
        method = parts[0] if len(parts) >= 2 else None
        target = parts[1] if len(parts) >= 2 else ""
        protocol = parts[2] if len(parts) >= 3 else None
        status = int(match["status"])
        size = match["size"]
        user = match["user"] if match["user"] != "-" else None
        path_decoded = decode_target(target)
        user_agent = match["agent"] or ""

        outcome.events.append(
            Event(
                event_id=make_event_id(file_tag, line_no),
                timestamp=timestamp,
                source="web",
                action="http_request",
                raw=raw,
                line_no=line_no,
                file_name=file_name,
                src_ip=match["ip"],
                user=user,
                outcome="success" if status < 400 else "failure",
                fields={
                    "method": method,
                    "path": target,
                    "path_decoded": path_decoded,
                    "protocol": protocol,
                    "status_code": status,
                    "bytes": int(size) if size.isdigit() else 0,
                    "referrer": match["referrer"],
                    "user_agent": user_agent,
                    "search_text": f"{path_decoded} {match['referrer'] or ''} {user_agent}",
                },
            )
        )
    return outcome
