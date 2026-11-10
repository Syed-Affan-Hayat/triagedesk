"""Incident report export.

The Markdown report follows the PICERL incident response phases (Preparation, Identification,
Containment, Eradication, Recovery, Lessons learned). The JSON export carries the same data in
machine-readable form for other tools.

Raw log lines are placed inside code fences and model-written text is Markdown-escaped, so
nothing taken from a log or from a model is rendered as a link, image or HTML.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any

from triagedesk.ai.guardrails import select_evidence
from triagedesk.models import AnalysisResult, Incident

MARKDOWN_SPECIAL = re.compile(r"([\\`*_\[\]<>!|])")
ASSESSMENT_LABELS = {
    "likely_malicious": "Likely malicious",
    "suspicious": "Suspicious",
    "likely_benign": "Likely benign",
    "insufficient_evidence": "Insufficient evidence",
}


def escape_markdown(text: str) -> str:
    """Escape the characters Markdown uses for links, images, emphasis, code, HTML and tables."""
    return MARKDOWN_SPECIAL.sub(r"\\\1", text)


def code_block(lines: list[str]) -> str:
    """Fence ``lines`` with more backticks than any run inside them."""
    longest = max((len(run) for line in lines for run in re.findall(r"`+", line)), default=0)
    fence = "`" * max(3, longest + 1)
    return "\n".join([f"{fence}text", *lines, fence])


def _ts(stamp) -> str:
    return stamp.strftime("%Y-%m-%d %H:%M:%S %Z").strip()


def _incident_section(incident: Incident) -> list[str]:
    summary = incident.summary
    rep = incident.reputation
    out = [
        f"### {incident.incident_id}: {incident.entity} ({incident.priority}, score {incident.score})",
        "",
        f"- **Activity window:** {_ts(incident.first_seen)} to {_ts(incident.last_seen)}",
        f"- **Highest severity:** {incident.severity}",
        "- **Techniques:** "
        + ", ".join(f"[{t.technique_id}]({t.url}) {t.name}" for t in incident.techniques),
    ]
    if rep is None:
        out.append("- **Reputation:** enrichment disabled")
    elif rep.looked_up:
        out.append(
            f"- **Reputation ({rep.provider}):** abuse confidence {rep.abuse_score}, "
            f"{rep.total_reports} report(s), ISP {escape_markdown(rep.isp or 'unknown')}"
            + (f". {rep.note}" if rep.note else "")
        )
    else:
        out.append(f"- **Reputation ({rep.provider}):** not looked up ({rep.note})")

    if summary:
        out += [
            "",
            f"**Assessment:** {ASSESSMENT_LABELS[summary.assessment]} "
            f"(summary by {escape_markdown(summary.generator)})",
            "",
            escape_markdown(summary.overview),
            "",
            "**Findings**",
            "",
        ]
        out += [
            f"- {escape_markdown(f.statement)} [{', '.join(f.evidence_ids)}]" for f in summary.findings
        ] or ["- None supported by the evidence."]
        if summary.validation_notes:
            out += ["", "**Validation notes**", ""]
            out += [f"- {escape_markdown(note)}" for note in summary.validation_notes]

    out += [
        "",
        "**Alerts**",
        "",
        "| Alert | Rule | Title | Severity | Events | Score | Priority |",
        "|---|---|---|---|---|---|---|",
    ]
    out += [
        f"| {a.alert_id} | {a.rule_id} | {a.title} | {a.severity} | {len(a.events)} "
        f"| {a.score} | {a.priority} |"
        for a in incident.alerts
    ]
    top = incident.alerts[0]
    out += ["", f"**Score breakdown for {top.alert_id}**", ""]
    out += [f"- {reason}: +{points}" for reason, points in top.score_breakdown]

    evidence = select_evidence(incident)
    out += ["", f"**Representative evidence** ({len(evidence)} of {len(incident.events)} events)", ""]
    out.append(code_block([f"{e.event_id}  {e.raw}" for e in evidence]))
    out.append("")
    return out


def render_markdown(result: AnalysisResult) -> str:
    """Render the full incident report as Markdown."""
    priorities = Counter(incident.priority for incident in result.incidents)
    out = [
        "# TriageDesk Incident Triage Report",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Case ID | {result.case_id} |",
        f"| Generated | {_ts(result.generated_at)} |",
        f"| Tool | TriageDesk {result.tool_version} |",
        f"| Enrichment mode | {result.enrichment_mode} |",
        f"| Summaries | {escape_markdown(result.summariser)} |",
        "",
        "> Detections and summaries are decision support. Every containment action listed in this "
        "report requires analyst approval before it is carried out.",
        "",
        "## 1. Executive summary",
        "",
        f"- {len(result.events)} events parsed from {len(result.evidence)} file(s).",
        f"- {len(result.alerts)} alert(s) grouped into {len(result.incidents)} incident(s).",
        "- Incidents by priority: "
        + ", ".join(f"{p}: {priorities.get(p, 0)}" for p in ("P1", "P2", "P3", "P4")),
    ]
    if result.incidents:
        lead = result.incidents[0]
        out.append(
            f"- Highest priority: {lead.incident_id} from {lead.entity}, "
            f"{ASSESSMENT_LABELS[lead.summary.assessment].lower() if lead.summary else 'not assessed'}."
        )

    out += [
        "",
        "## 2. Preparation: evidence register",
        "",
        "SHA-256 hashes were computed when each file was received. Recompute them on the original "
        "files to confirm this analysis used unaltered evidence.",
        "",
        "| Tag | File | Type | SHA-256 | Bytes | Parsed | Ignored | Malformed |",
        "|---|---|---|---|---|---|---|---|",
    ]
    out += [
        f"| {r.file_tag} | {escape_markdown(r.file_name)} | {r.source_type} | `{r.sha256}` "
        f"| {r.size_bytes} | {r.lines_parsed} | {r.lines_ignored} | {r.lines_malformed} |"
        for r in result.evidence
    ]

    out += ["", "## 3. Identification", ""]
    if not result.incidents:
        out.append("No rule fired on the supplied evidence.")
    for incident in result.incidents:
        out += _incident_section(incident)

    out += [
        "## 4. Containment, eradication and recovery (recommended)",
        "",
        "Tick each step once it has been approved and completed.",
        "",
    ]
    for incident in result.incidents:
        actions = incident.summary.recommended_actions if incident.summary else []
        out.append(f"**{incident.incident_id} ({incident.entity})**")
        out.append("")
        out += [f"- [ ] {escape_markdown(action)}" for action in actions] or ["- [ ] Review manually."]
        out.append("")

    fired = Counter(alert.rule_id for alert in result.alerts)
    malformed = sum(r.lines_malformed for r in result.evidence)
    out += [
        "## 5. Lessons learned",
        "",
        f"- {len(fired)} of {len(result.rule_catalogue)} rules fired on this evidence.",
        f"- {malformed} malformed line(s) were skipped; review them if the count is unexpected.",
        "- Analyst notes: root cause, what worked, what to tune, follow-up owners and dates.",
        "",
        "## Appendix A. Techniques observed",
        "",
        "| ID | Name | Tactic | Framework | Incidents |",
        "|---|---|---|---|---|",
    ]
    techniques: dict[str, tuple[Any, set[str]]] = {}
    for incident in result.incidents:
        for t in incident.techniques:
            techniques.setdefault(t.technique_id, (t, set()))[1].add(incident.incident_id)
    out += [
        f"| [{t.technique_id}]({t.url}) | {t.name} | {t.tactic} | {t.framework} | {', '.join(sorted(ids))} |"
        for t, ids in (techniques[k] for k in sorted(techniques))
    ]
    out += [
        "",
        "## Appendix B. Rules evaluated",
        "",
        "| Rule | Title | Type | Severity | Alerts |",
        "|---|---|---|---|---|",
    ]
    out += [
        f"| {r['id']} | {r['title']} | {r['type']} | {r['severity']} | {fired.get(r['id'], 0)} |"
        for r in result.rule_catalogue
    ]
    out.append("")
    return "\n".join(out)


def to_dict(result: AnalysisResult) -> dict[str, Any]:
    """Convert the result into JSON-serialisable data (events are referenced, not repeated)."""

    def event(e):
        return {"event_id": e.event_id, "timestamp": e.timestamp.isoformat(), "raw": e.raw}

    return {
        "case_id": result.case_id,
        "generated_at": result.generated_at.isoformat(),
        "tool_version": result.tool_version,
        "enrichment_mode": result.enrichment_mode,
        "summariser": result.summariser,
        "evidence": [
            {
                "file_tag": r.file_tag,
                "file_name": r.file_name,
                "source_type": r.source_type,
                "sha256": r.sha256,
                "size_bytes": r.size_bytes,
                "received_at": r.received_at.isoformat(),
                "lines_total": r.lines_total,
                "lines_parsed": r.lines_parsed,
                "lines_ignored": r.lines_ignored,
                "lines_malformed": r.lines_malformed,
            }
            for r in result.evidence
        ],
        "event_count": len(result.events),
        "incidents": [
            {
                "incident_id": inc.incident_id,
                "entity": inc.entity,
                "priority": inc.priority,
                "score": inc.score,
                "severity": inc.severity,
                "first_seen": inc.first_seen.isoformat(),
                "last_seen": inc.last_seen.isoformat(),
                "techniques": [t.technique_id for t in inc.techniques],
                "reputation": None
                if inc.reputation is None
                else {
                    "provider": inc.reputation.provider,
                    "looked_up": inc.reputation.looked_up,
                    "abuse_score": inc.reputation.abuse_score,
                    "total_reports": inc.reputation.total_reports,
                    "note": inc.reputation.note,
                },
                "summary": None
                if inc.summary is None
                else {
                    "generator": inc.summary.generator,
                    "assessment": inc.summary.assessment,
                    "overview": inc.summary.overview,
                    "findings": [
                        {"statement": f.statement, "evidence_ids": f.evidence_ids}
                        for f in inc.summary.findings
                    ],
                    "recommended_actions": inc.summary.recommended_actions,
                    "validation_notes": inc.summary.validation_notes,
                },
                "alerts": [
                    {
                        "alert_id": a.alert_id,
                        "rule_id": a.rule_id,
                        "title": a.title,
                        "severity": a.severity,
                        "score": a.score,
                        "priority": a.priority,
                        "score_breakdown": [{"reason": r, "points": p} for r, p in a.score_breakdown],
                        "first_seen": a.first_seen.isoformat(),
                        "last_seen": a.last_seen.isoformat(),
                        "event_count": len(a.events),
                        "events": [event(e) for e in a.events],
                    }
                    for a in inc.alerts
                ],
            }
            for inc in result.incidents
        ],
    }


def render_json(result: AnalysisResult) -> str:
    return json.dumps(to_dict(result), indent=2)
