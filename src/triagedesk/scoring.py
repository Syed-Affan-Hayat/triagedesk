"""Alert prioritisation.

Each alert gets a score from 0 to 100 built from a few visible factors. Every point added is
recorded with its reason in ``Alert.score_breakdown``, so an analyst can see exactly why one
alert sits above another. The weights are a starting point and are meant to be tuned.

Points:

* rule severity: low 20, medium 40, high 60, critical 80
* abuse confidence of the source: +15 at 75 or above, +8 at 25 to 74
* web exploit attempt answered with a 2xx status: +10
* source triggered three or more different rules: +5
* events in the alert: +5 at 50 or more, +3 at 10 to 49

The total is capped at 100. Priority bands: P1 >= 85, P2 >= 65, P3 >= 45, otherwise P4.
"""

from __future__ import annotations

from collections import defaultdict

from triagedesk.models import Alert, Incident, Reputation

SEVERITY_POINTS = {"low": 20, "medium": 40, "high": 60, "critical": 80}
PRIORITY_BANDS = ((85, "P1"), (65, "P2"), (45, "P3"))
EXPLOIT_TECHNIQUE = "T1190"


def priority_for(score: int) -> str:
    for minimum, label in PRIORITY_BANDS:
        if score >= minimum:
            return label
    return "P4"


def score_alert(alert: Alert, reputation: Reputation | None, rules_for_source: int) -> None:
    """Fill in ``score``, ``priority`` and ``score_breakdown`` on ``alert``."""
    breakdown = [(f"Rule severity is {alert.severity}", SEVERITY_POINTS[alert.severity])]

    if reputation and reputation.looked_up and reputation.abuse_score is not None:
        if reputation.abuse_score >= 75:
            breakdown.append((f"Source abuse confidence is {reputation.abuse_score}", 15))
        elif reputation.abuse_score >= 25:
            breakdown.append((f"Source abuse confidence is {reputation.abuse_score}", 8))

    is_exploit = any(t.technique_id == EXPLOIT_TECHNIQUE for t in alert.techniques)
    answered = [e for e in alert.events if 200 <= (e.fields.get("status_code") or 0) < 300]
    if is_exploit and answered:
        breakdown.append((f"{len(answered)} exploit request(s) answered with a 2xx status", 10))

    if rules_for_source >= 3:
        breakdown.append((f"Source triggered {rules_for_source} different rules", 5))

    count = len(alert.events)
    if count >= 50:
        breakdown.append((f"{count} events in the alert", 5))
    elif count >= 10:
        breakdown.append((f"{count} events in the alert", 3))

    alert.score_breakdown = breakdown
    alert.score = min(100, sum(points for _, points in breakdown))
    alert.priority = priority_for(alert.score)


def build_incidents(alerts: list[Alert], reputations: dict[str, Reputation | None]) -> list[Incident]:
    """Score alerts, group them by source IP address and order incidents by priority."""
    rules_by_source: dict[str, set[str]] = defaultdict(set)
    for alert in alerts:
        rules_by_source[alert.src_ip or "unknown"].add(alert.rule_id)

    grouped: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        entity = alert.src_ip or "unknown"
        score_alert(alert, reputations.get(entity), len(rules_by_source[entity]))
        grouped[entity].append(alert)

    incidents = [
        Incident(incident_id="", entity=entity, alerts=members, reputation=reputations.get(entity))
        for entity, members in grouped.items()
    ]
    incidents.sort(key=lambda inc: (-inc.score, inc.first_seen))
    for number, incident in enumerate(incidents, start=1):
        incident.incident_id = f"INC-{number:03d}"
        incident.alerts.sort(key=lambda a: (-a.score, a.first_seen))
    return incidents
