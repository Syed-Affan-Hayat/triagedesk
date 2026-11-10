from conftest import make_event

from triagedesk.detection import load_rules, run_rules
from triagedesk.models import Reputation
from triagedesk.scoring import build_incidents, priority_for


def test_priority_bands():
    assert [priority_for(s) for s in (100, 85, 84, 65, 45, 44)] == ["P1", "P1", "P2", "P2", "P3", "P4"]


def test_score_breakdown_explains_every_point():
    rules = [r for r in load_rules() if r.rule_id == "TD-SSH-001"]
    events = [make_event(f"E{i}", i * 5) for i in range(12)]
    reputation = Reputation(
        ip="203.0.113.1", provider="mock", looked_up=True, abuse_score=90, total_reports=5
    )
    incident = build_incidents(run_rules(rules, events), {"203.0.113.1": reputation})[0]
    alert = incident.alerts[0]
    assert alert.score == sum(points for _, points in alert.score_breakdown) == 60 + 15 + 3
    assert alert.priority == "P2"
