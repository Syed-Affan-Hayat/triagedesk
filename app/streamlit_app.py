"""TriageDesk dashboard.

Run locally with::

    streamlit run app/streamlit_app.py

Text that comes from log files or from a language model is never rendered as HTML. Raw log
lines are shown in code blocks, and summaries are Markdown-escaped before display.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pandas as pd
import streamlit as st

from triagedesk import __version__
from triagedesk.ai.guardrails import select_evidence
from triagedesk.config import load_settings
from triagedesk.pipeline import InputError, InputFile, analyze
from triagedesk.report import ASSESSMENT_LABELS, escape_markdown, render_json, render_markdown

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "data" / "samples"
SAMPLE_FILES = ("auth.log", "access.log")
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

st.set_page_config(page_title="TriageDesk", layout="wide")


def safe(text: str) -> str:
    """Escape untrusted text for display with ``st.markdown``."""
    return escape_markdown(text)


@st.cache_data
def load_samples() -> list[tuple[str, bytes]]:
    return [(name, (SAMPLES_DIR / name).read_bytes()) for name in SAMPLE_FILES]


def sidebar(settings) -> None:
    with st.sidebar:
        st.header("Configuration")
        st.markdown(f"**Enrichment:** {settings.enrichment_mode}")
        summaries = f"language model ({settings.llm_model})" if settings.llm_enabled else "offline template"
        st.markdown(f"**Summaries:** {safe(summaries)}")
        st.markdown(f"**Upload limit:** {settings.max_upload_mb} MB per file")
        st.divider()
        st.caption(
            "Demonstration instance. Do not upload logs that contain personal or confidential data. "
            "Uploaded files are processed in memory and are not stored."
        )
        st.caption(f"TriageDesk {__version__}")


def collect_input() -> list[InputFile] | None:
    source = st.radio("Evidence", ["Bundled sample logs", "Upload log files"], horizontal=True)
    if source == "Bundled sample logs":
        st.caption(
            "Synthetic logs for one day on a web server, with six planted attack scenarios. "
            "All addresses are from documentation ranges (RFC 5737)."
        )
        files = [InputFile(name, data) for name, data in load_samples()]
    else:
        uploads = st.file_uploader(
            "OpenSSH auth logs or web access logs (Combined Log Format)",
            type=["log", "txt"],
            accept_multiple_files=True,
        )
        files = [InputFile(upload.name, upload.getvalue()) for upload in uploads or []]
    if st.button("Run analysis", type="primary", disabled=not files):
        return files
    return None


def overview_tab(result) -> None:
    priorities = Counter(incident.priority for incident in result.incidents)
    columns = st.columns(5)
    columns[0].metric("Events parsed", len(result.events))
    columns[1].metric("Alerts", len(result.alerts))
    columns[2].metric("Incidents", len(result.incidents))
    columns[3].metric("P1 incidents", priorities.get("P1", 0))
    columns[4].metric("P2 incidents", priorities.get("P2", 0))

    st.subheader("Incidents")
    st.dataframe(
        pd.DataFrame(
            {
                "Incident": inc.incident_id,
                "Priority": inc.priority,
                "Score": inc.score,
                "Source": inc.entity,
                "Severity": inc.severity,
                "Assessment": ASSESSMENT_LABELS[inc.summary.assessment] if inc.summary else "",
                "Rules": ", ".join(sorted({a.rule_id for a in inc.alerts})),
                "First seen": inc.first_seen.strftime(TIME_FORMAT),
            }
            for inc in result.incidents
        ),
        hide_index=True,
    )

    st.subheader("Evidence register")
    st.caption("SHA-256 hashes computed on receipt. Recompute them on the originals to verify integrity.")
    st.dataframe(
        pd.DataFrame(
            {
                "Tag": r.file_tag,
                "File": r.file_name,
                "Type": r.source_type,
                "SHA-256": r.sha256,
                "Bytes": r.size_bytes,
                "Parsed": r.lines_parsed,
                "Ignored": r.lines_ignored,
                "Malformed": r.lines_malformed,
            }
            for r in result.evidence
        ),
        hide_index=True,
    )


def alert_queue_tab(result) -> None:
    if not result.alerts:
        st.info("No rule fired on the supplied evidence.")
        return
    st.dataframe(
        pd.DataFrame(
            {
                "Priority": a.priority,
                "Score": a.score,
                "Alert": a.alert_id,
                "Rule": a.rule_id,
                "Title": a.title,
                "Severity": a.severity,
                "Source": a.src_ip,
                "Events": len(a.events),
                "First seen": a.first_seen.strftime(TIME_FORMAT),
            }
            for a in result.alerts
        ),
        hide_index=True,
    )
    labels = {f"{a.alert_id}  {a.rule_id}  {a.title} ({a.src_ip})": a for a in result.alerts}
    alert = labels[st.selectbox("Alert details", list(labels))]

    left, right = st.columns([3, 2])
    with left:
        st.markdown(f"**{alert.title}** ({alert.severity}, {alert.priority}, score {alert.score})")
        st.write(alert.description)
        st.markdown(
            "**Techniques:** " + ", ".join(f"[{t.technique_id}]({t.url}) {t.name}" for t in alert.techniques)
        )
        st.markdown("**Known false positives**")
        for item in alert.false_positives:
            st.markdown(f"- {item}")
    with right:
        st.markdown("**Score breakdown**")
        st.dataframe(
            pd.DataFrame({"Reason": r, "Points": p} for r, p in alert.score_breakdown),
            hide_index=True,
        )
    st.markdown(f"**Evidence** ({len(alert.events)} events)")
    st.code("\n".join(f"{e.event_id}  {e.raw}" for e in alert.events[:200]), language="text")


def incidents_tab(result) -> None:
    if not result.incidents:
        st.info("No incidents.")
        return
    for incident in result.incidents:
        summary = incident.summary
        title = f"{incident.incident_id}   {incident.entity}   {incident.priority}   score {incident.score}"
        with st.expander(title, expanded=incident is result.incidents[0]):
            rep = incident.reputation
            if rep and rep.looked_up:
                st.caption(
                    f"Reputation ({rep.provider}): abuse confidence {rep.abuse_score}, "
                    f"{rep.total_reports} reports. {rep.note or ''}"
                )
            if summary:
                st.markdown(
                    f"**Assessment:** {ASSESSMENT_LABELS[summary.assessment]} (by {safe(summary.generator)})"
                )
                st.markdown(safe(summary.overview))
                st.markdown("**Findings**")
                for finding in summary.findings:
                    st.markdown(f"- {safe(finding.statement)} `{', '.join(finding.evidence_ids)}`")
                if summary.validation_notes:
                    st.warning("\n\n".join(safe(note) for note in summary.validation_notes))
                st.markdown("**Recommended actions** (require analyst approval)")
                for action in summary.recommended_actions:
                    st.markdown(f"- {safe(action)}")
            evidence = select_evidence(incident)
            st.markdown(f"**Representative evidence** ({len(evidence)} of {len(incident.events)} events)")
            st.code("\n".join(f"{e.event_id}  {e.raw}" for e in evidence), language="text")


def techniques_tab(result) -> None:
    rows: dict[str, dict] = {}
    for incident in result.incidents:
        for t in incident.techniques:
            row = rows.setdefault(
                t.technique_id,
                {
                    "ID": t.technique_id,
                    "Name": t.name,
                    "Tactic": t.tactic,
                    "Framework": t.framework,
                    "Incidents": 0,
                    "Reference": t.url,
                },
            )
            row["Incidents"] += 1
    if not rows:
        st.info("No techniques observed.")
        return
    st.dataframe(
        pd.DataFrame(sorted(rows.values(), key=lambda r: r["ID"])),
        hide_index=True,
        column_config={"Reference": st.column_config.LinkColumn("Reference")},
    )


def report_tab(result) -> None:
    markdown = render_markdown(result)
    left, right = st.columns(2)
    left.download_button(
        "Download report (Markdown)", markdown, file_name=f"{result.case_id}.md", mime="text/markdown"
    )
    right.download_button(
        "Download data (JSON)",
        render_json(result),
        file_name=f"{result.case_id}.json",
        mime="application/json",
    )
    st.divider()
    st.markdown(markdown)


def main() -> None:
    st.title("TriageDesk")
    st.caption("Evidence-grounded triage of SSH and web server logs, mapped to MITRE ATT&CK.")
    try:
        settings = load_settings()
    except ValueError as exc:
        st.error(f"Configuration error: {exc}")
        st.stop()
    sidebar(settings)

    files = collect_input()
    if files is not None:
        with st.spinner("Analysing evidence"):
            try:
                st.session_state["result"] = analyze(files, settings=settings)
            except InputError as exc:
                st.error(str(exc))
                st.session_state.pop("result", None)

    result = st.session_state.get("result")
    if result is None:
        st.info("Choose the evidence and select Run analysis.")
        return

    st.success(f"Case {result.case_id}: {len(result.alerts)} alerts in {len(result.incidents)} incidents.")
    tabs = st.tabs(["Overview", "Alert queue", "Incidents", "Techniques", "Report"])
    with tabs[0]:
        overview_tab(result)
    with tabs[1]:
        alert_queue_tab(result)
    with tabs[2]:
        incidents_tab(result)
    with tabs[3]:
        techniques_tab(result)
    with tabs[4]:
        report_tab(result)


main()
