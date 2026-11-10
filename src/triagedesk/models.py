"""Data models shared by every stage of the pipeline.

The pipeline moves through four record types:

* ``Event``: one parsed log line in a common schema.
* ``Alert``: one detection rule match, with the events that caused it.
* ``Incident``: the alerts that share a source IP address, triaged together.
* ``AnalysisResult``: everything produced by one run, used by the UI, CLI and report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Event:
    """One log line normalised into the common schema."""

    event_id: str
    timestamp: datetime
    source: str
    action: str
    raw: str
    line_no: int
    file_name: str
    host: str | None = None
    src_ip: str | None = None
    user: str | None = None
    outcome: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)

    def get(self, name: str) -> Any:
        """Return a top-level attribute or a ``fields.<key>`` value, or ``None``."""
        if name.startswith("fields."):
            return self.fields.get(name.split(".", 1)[1])
        return getattr(self, name, None)


@dataclass
class EvidenceRecord:
    """Integrity record for one uploaded file."""

    file_tag: str
    file_name: str
    sha256: str
    size_bytes: int
    received_at: datetime
    source_type: str
    lines_total: int = 0
    lines_parsed: int = 0
    lines_ignored: int = 0
    lines_malformed: int = 0


@dataclass
class Technique:
    """A MITRE ATT&CK or MITRE ATLAS technique."""

    technique_id: str
    name: str
    tactic: str
    framework: str
    url: str


@dataclass
class Alert:
    """A detection rule match."""

    alert_id: str
    rule_id: str
    title: str
    description: str
    severity: str
    source: str
    techniques: list[Technique]
    events: list[Event]
    group_value: str | None = None
    response: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    score: int = 0
    priority: str = "P4"
    score_breakdown: list[tuple[str, int]] = field(default_factory=list)

    @property
    def first_seen(self) -> datetime:
        return min(event.timestamp for event in self.events)

    @property
    def last_seen(self) -> datetime:
        return max(event.timestamp for event in self.events)

    @property
    def src_ip(self) -> str | None:
        return self.events[0].src_ip if self.events else None


@dataclass
class Reputation:
    """Threat intelligence for one IP address."""

    ip: str
    provider: str
    looked_up: bool
    abuse_score: int | None = None
    total_reports: int | None = None
    country: str | None = None
    isp: str | None = None
    note: str | None = None


@dataclass
class Finding:
    """One statement in a triage summary, tied to the events that support it."""

    statement: str
    evidence_ids: list[str]


@dataclass
class TriageSummary:
    """Validated summary of an incident, written by an LLM or by the offline template."""

    generator: str
    assessment: str
    overview: str
    findings: list[Finding]
    recommended_actions: list[str]
    validation_notes: list[str] = field(default_factory=list)


@dataclass
class Incident:
    """Alerts grouped by source IP address."""

    incident_id: str
    entity: str
    alerts: list[Alert]
    reputation: Reputation | None = None
    summary: TriageSummary | None = None

    @property
    def score(self) -> int:
        return max(alert.score for alert in self.alerts)

    @property
    def priority(self) -> str:
        return min(alert.priority for alert in self.alerts)

    @property
    def severity(self) -> str:
        return max((alert.severity for alert in self.alerts), key=SEVERITY_ORDER.__getitem__)

    @property
    def techniques(self) -> list[Technique]:
        seen: dict[str, Technique] = {}
        for alert in self.alerts:
            for technique in alert.techniques:
                seen.setdefault(technique.technique_id, technique)
        return sorted(seen.values(), key=lambda t: t.technique_id)

    @property
    def events(self) -> list[Event]:
        unique = {event.event_id: event for alert in self.alerts for event in alert.events}
        return sorted(unique.values(), key=lambda e: (e.timestamp, e.event_id))

    @property
    def first_seen(self) -> datetime:
        return min(alert.first_seen for alert in self.alerts)

    @property
    def last_seen(self) -> datetime:
        return max(alert.last_seen for alert in self.alerts)


@dataclass
class AnalysisResult:
    """Everything one analysis run produced."""

    case_id: str
    generated_at: datetime
    evidence: list[EvidenceRecord]
    events: list[Event]
    alerts: list[Alert]
    incidents: list[Incident]
    enrichment_mode: str
    summariser: str
    tool_version: str
    rule_catalogue: list[dict[str, str]] = field(default_factory=list)
