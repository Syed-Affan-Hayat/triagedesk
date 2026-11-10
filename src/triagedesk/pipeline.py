"""End-to-end analysis: evidence, parsing, detection, enrichment, scoring and summaries."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from triagedesk import __version__
from triagedesk.ai import LLMSummariser, OfflineSummariser
from triagedesk.config import Settings, load_settings
from triagedesk.detection import Rule, load_rules, run_rules
from triagedesk.enrichment import Enricher
from triagedesk.evidence import register_evidence, sha256_hex
from triagedesk.models import AnalysisResult, Event
from triagedesk.parsers import SOURCE_TYPES, detect_source_type, parse_lines
from triagedesk.scoring import build_incidents


class InputError(ValueError):
    """Raised when an uploaded file cannot be analysed. The message is safe to show users."""


@dataclass
class InputFile:
    name: str
    data: bytes
    source_type: str | None = None


def _timezone(name: str):
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise InputError(f"Unknown time zone {name!r} in TRIAGEDESK_LOG_TIMEZONE") from exc


def make_summariser(settings: Settings, max_incidents: int = 5):
    """Use the language model when it is fully configured, otherwise the offline template."""
    if settings.llm_enabled:
        return LLMSummariser(
            base_url=settings.llm_base_url,
            api_key=settings.llm_api_key,
            model=settings.llm_model,
            timeout_seconds=settings.llm_timeout_seconds,
            max_incidents=max_incidents,
        )
    return OfflineSummariser()


def analyze(
    files: list[InputFile],
    settings: Settings | None = None,
    rules: list[Rule] | None = None,
    summariser=None,
    now: datetime | None = None,
) -> AnalysisResult:
    """Run the full pipeline over ``files`` and return the result."""
    if not files:
        raise InputError("No files were provided.")
    settings = settings or load_settings()
    rules = rules if rules is not None else load_rules()
    summariser = summariser or make_summariser(settings)
    now = now or datetime.now(timezone.utc)
    tz = _timezone(settings.log_timezone)
    limit = settings.max_upload_mb * 1024 * 1024

    evidence = []
    events: list[Event] = []
    for index, item in enumerate(files, start=1):
        if len(item.data) == 0:
            raise InputError(f"{item.name} is empty.")
        if len(item.data) > limit:
            raise InputError(f"{item.name} is larger than the {settings.max_upload_mb} MB limit.")
        lines = item.data.decode("utf-8", errors="replace").splitlines()
        if len(lines) > settings.max_lines_per_file:
            raise InputError(
                f"{item.name} has more than {settings.max_lines_per_file:,} lines; split it first."
            )
        source_type = item.source_type or detect_source_type(lines)
        if source_type not in SOURCE_TYPES:
            raise InputError(
                f"{item.name} was not recognised as a supported log type "
                "(OpenSSH auth log or web access log)."
            )
        file_tag = f"F{index}"
        record = register_evidence(file_tag, item.name, item.data, source_type)
        outcome = parse_lines(lines, source_type, file_tag, item.name, tz=tz, now=now)
        record.lines_total = outcome.total
        record.lines_parsed = len(outcome.events)
        record.lines_ignored = outcome.ignored
        record.lines_malformed = outcome.malformed
        evidence.append(record)
        events.extend(outcome.events)

    alerts = run_rules(rules, events)

    enricher = Enricher(settings.enrichment_mode, settings.abuseipdb_api_key)
    entities = sorted({alert.src_ip for alert in alerts if alert.src_ip})
    reputations = {ip: enricher.lookup(ip) for ip in entities}

    incidents = build_incidents(alerts, reputations)
    for incident in incidents:
        incident.summary = summariser.summarise(incident)

    combined = sha256_hex("".join(record.sha256 for record in evidence).encode())
    case_id = f"TD-{now.strftime('%Y%m%d-%H%M%S')}-{combined[:6]}"
    return AnalysisResult(
        case_id=case_id,
        generated_at=now,
        evidence=evidence,
        events=events,
        alerts=sorted(alerts, key=lambda a: (-a.score, a.first_seen)),
        incidents=incidents,
        enrichment_mode=settings.enrichment_mode,
        summariser=summariser.name,
        tool_version=__version__,
        rule_catalogue=[
            {"id": r.rule_id, "title": r.title, "severity": r.severity, "type": r.rule_type} for r in rules
        ],
    )
