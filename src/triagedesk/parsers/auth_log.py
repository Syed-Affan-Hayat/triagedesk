"""Parser for OpenSSH entries in Linux authentication logs (``/var/log/auth.log``).

Two timestamp layouts are supported:

* classic syslog, for example ``Nov  3 09:15:02 web01 sshd[1234]: ...``. This layout has no
  year or time zone, so both are supplied by the caller.
* RFC 3339, used by recent rsyslog defaults, for example
  ``2026-11-03T09:15:02.123456+05:00 web01 sshd[1234]: ...``.

Only ``sshd`` messages that matter for detection become events: failed logins, accepted
logins and invalid-user probes. Other well-formed lines are counted as ignored.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime, timedelta, tzinfo

from triagedesk.models import Event
from triagedesk.parsers.base import ParseOutcome, clip, make_event_id

CLASSIC_PREFIX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s"
    r"(?P<host>\S+)\s(?P<program>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s(?P<message>.*)$"
)
ISO_PREFIX = re.compile(
    r"^(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s"
    r"(?P<host>\S+)\s(?P<program>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s(?P<message>.*)$"
)

FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S*) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
INVALID_USER = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?")


def matches_format(line: str) -> bool:
    """Return ``True`` if ``line`` looks like a syslog line from this log type."""
    return bool(CLASSIC_PREFIX.match(line) or ISO_PREFIX.match(line))


def _classic_timestamp(match: re.Match[str], year: int, tz: tzinfo, now: datetime) -> datetime:
    text = f"{year} {match['month']} {int(match['day']):02d} {match['time']}"
    stamp = datetime.strptime(text, "%Y %b %d %H:%M:%S").replace(tzinfo=tz)
    # Classic syslog omits the year. A date more than a day in the future means the
    # line was written last year (for example a December log read in January).
    if stamp - now > timedelta(days=1):
        stamp = stamp.replace(year=year - 1)
    return stamp


def _iso_timestamp(text: str, tz: tzinfo) -> datetime:
    stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=tz)


def _classify(message: str) -> tuple[str, str, re.Match[str]] | None:
    """Return ``(action, outcome, match)`` for a relevant sshd message, else ``None``."""
    if match := FAILED.match(message):
        return "ssh_failed", "failure", match
    if match := ACCEPTED.match(message):
        return "ssh_success", "success", match
    if match := INVALID_USER.match(message):
        return "ssh_invalid_user", "failure", match
    return None


def parse(
    lines: Iterable[str],
    file_tag: str,
    file_name: str,
    tz: tzinfo,
    now: datetime,
) -> ParseOutcome:
    """Parse authentication log lines into events.

    ``tz`` is applied to timestamps that carry no offset. ``now`` supplies the year for
    classic syslog timestamps and must be time zone aware.
    """
    outcome = ParseOutcome()
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        outcome.total += 1
        raw = clip(line)
        prefix = CLASSIC_PREFIX.match(raw) or ISO_PREFIX.match(raw)
        if prefix is None:
            outcome.malformed += 1
            continue
        if prefix["program"] != "sshd":
            outcome.ignored += 1
            continue
        classified = _classify(prefix["message"])
        if classified is None:
            outcome.ignored += 1
            continue
        action, result, match = classified
        try:
            iso_text = prefix.groupdict().get("iso")
            if iso_text:
                timestamp = _iso_timestamp(iso_text, tz)
            else:
                timestamp = _classic_timestamp(prefix, now.year, tz, now)
        except ValueError:
            outcome.malformed += 1
            continue

        fields = {
            "method": match.groupdict().get("method"),
            "port": match.groupdict().get("port"),
            "search_text": prefix["message"],
        }
        if action == "ssh_failed":
            fields["invalid_user"] = bool(match["invalid"])
        outcome.events.append(
            Event(
                event_id=make_event_id(file_tag, line_no),
                timestamp=timestamp,
                source="ssh",
                action=action,
                raw=raw,
                line_no=line_no,
                file_name=file_name,
                host=prefix["host"],
                src_ip=match["ip"],
                user=match["user"] or None,
                outcome=result,
                fields=fields,
            )
        )
    return outcome
