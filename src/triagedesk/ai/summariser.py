"""Incident summaries.

``OfflineSummariser`` builds a summary from the alerts with a fixed template and needs no
network access. ``LLMSummariser`` asks a language model through any OpenAI-compatible chat
completions endpoint (for example Google Gemini, Groq or a local Ollama server) and passes the
reply through the guardrails in ``guardrails.py``. If the model is unavailable or its reply
fails validation, the offline summary is used and the reason is recorded.
"""

from __future__ import annotations

import requests

from triagedesk.ai.guardrails import (
    SYSTEM_PROMPT,
    SummaryError,
    build_user_prompt,
    select_evidence,
    validate_reply,
)
from triagedesk.models import SEVERITY_ORDER, Finding, Incident, TriageSummary


def _fmt(stamp) -> str:
    return stamp.strftime("%Y-%m-%d %H:%M:%S %Z").strip()


class OfflineSummariser:
    """Deterministic summaries built only from rule output."""

    name = "offline template"

    def summarise(self, incident: Incident) -> TriageSummary:
        top = incident.severity
        reputation = incident.reputation
        high_reputation = bool(reputation and reputation.looked_up and (reputation.abuse_score or 0) >= 75)
        if top == "critical" or (top == "high" and high_reputation):
            assessment = "likely_malicious"
        else:
            assessment = "suspicious"

        titles = ", ".join(dict.fromkeys(alert.title for alert in incident.alerts))
        overview = (
            f"{len(incident.alerts)} alert(s) from {incident.entity} between "
            f"{_fmt(incident.first_seen)} and {_fmt(incident.last_seen)}: {titles}."
        )
        if reputation and reputation.looked_up:
            overview += (
                f" Reputation ({reputation.provider}): abuse confidence {reputation.abuse_score}, "
                f"{reputation.total_reports} report(s)."
            )

        findings = []
        for alert in sorted(incident.alerts, key=lambda a: a.first_seen):
            first, last = alert.events[0], alert.events[-1]
            cited = [first.event_id] if first is last else [first.event_id, last.event_id]
            findings.append(
                Finding(
                    statement=f"{alert.rule_id} {alert.title}: {len(alert.events)} matching event(s).",
                    evidence_ids=cited,
                )
            )

        actions: list[str] = []
        for alert in sorted(incident.alerts, key=lambda a: -SEVERITY_ORDER[a.severity]):
            for step in alert.response:
                if step not in actions:
                    actions.append(step)

        return TriageSummary(
            generator=self.name,
            assessment=assessment,
            overview=overview,
            findings=findings,
            recommended_actions=actions[:6],
        )


class LLMSummariser:
    """Summaries from a language model, validated, with the offline template as fallback."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        timeout_seconds: int = 30,
        max_incidents: int = 5,
        session: requests.Session | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.name = f"LLM ({model})"
        self._api_key = api_key
        self._timeout = timeout_seconds
        self._remaining = max_incidents
        self._session = session or requests.Session()
        self._fallback = OfflineSummariser()

    def _complete(self, user_prompt: str) -> str:
        response = self._session.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self._api_key}"},
            json={
                "model": self.model,
                "temperature": 0.1,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
            },
            timeout=self._timeout,
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]

    def _fallback_with(self, incident: Incident, reason: str) -> TriageSummary:
        summary = self._fallback.summarise(incident)
        summary.validation_notes.append(f"Offline summary used: {reason}.")
        return summary

    def summarise(self, incident: Incident) -> TriageSummary:
        if self._remaining <= 0:
            return self._fallback_with(incident, "the per-run limit of model calls was reached")
        self._remaining -= 1

        evidence = select_evidence(incident)
        allowed = {event.event_id for event in evidence}
        try:
            reply = self._complete(build_user_prompt(incident, evidence))
        except requests.RequestException as exc:
            return self._fallback_with(incident, f"the model request failed ({type(exc).__name__})")
        except (KeyError, IndexError, TypeError, ValueError):
            return self._fallback_with(incident, "the model response had an unexpected format")
        try:
            return validate_reply(reply, incident, allowed, generator=self.name)
        except SummaryError as exc:
            return self._fallback_with(incident, f"the model reply failed validation ({exc})")
