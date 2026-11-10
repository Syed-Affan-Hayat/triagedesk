import pytest
from conftest import make_event

from triagedesk.detection import RuleError, load_rules, run_rules
from triagedesk.detection.engine import parse_rule

RULES = {rule.rule_id: rule for rule in load_rules()}


def fired(rule_id, events):
    return run_rules([RULES[rule_id]], events)


def test_bundled_rules_load():
    assert len(RULES) == 10


def test_brute_force_needs_threshold_inside_window():
    four = [make_event(f"E{i}", i * 10) for i in range(4)]
    assert fired("TD-SSH-001", four) == []
    five = [make_event(f"E{i}", i * 10) for i in range(5)]
    assert len(fired("TD-SSH-001", five)) == 1


def test_brute_force_spread_out_does_not_fire():
    slow = [make_event(f"E{i}", i * 200) for i in range(10)]
    assert fired("TD-SSH-001", slow) == []


def test_burst_produces_one_alert():
    burst = [make_event(f"E{i}", i * 5) for i in range(40)]
    alerts = fired("TD-SSH-001", burst)
    assert len(alerts) == 1 and len(alerts[0].events) == 40


def test_spraying_counts_distinct_users():
    users = ["admin", "test", "oracle", "guest"]
    events = [make_event(f"E{i}", i * 200, user=u) for i, u in enumerate(users)]
    assert len(fired("TD-SSH-002", events)) == 1
    same_user = [make_event(f"E{i}", i * 200) for i in range(6)]
    assert fired("TD-SSH-002", same_user) == []


def test_success_after_failures_sequence():
    events = [make_event(f"F{i}", i * 10) for i in range(5)]
    events.append(make_event("S", 60, action="ssh_success"))
    alerts = fired("TD-SSH-003", events)
    assert len(alerts) == 1 and alerts[0].events[-1].event_id == "S"


def test_success_after_few_failures_is_not_an_alert():
    events = [make_event("F1", 0), make_event("F2", 10), make_event("S", 20, action="ssh_success")]
    assert fired("TD-SSH-003", events) == []


def test_groups_are_kept_apart():
    events = [make_event(f"A{i}", i, src_ip="203.0.113.1") for i in range(3)]
    events += [make_event(f"B{i}", i, src_ip="203.0.113.2") for i in range(3)]
    assert fired("TD-SSH-001", events) == []


def test_invalid_rule_is_rejected():
    with pytest.raises(RuleError, match="techniques not in the catalogue"):
        parse_rule(
            {
                "id": "X",
                "title": "x",
                "description": "x",
                "source": "ssh",
                "severity": "low",
                "type": "match",
                "techniques": ["T9999"],
                "filter": [{"field": "action", "equals": "a"}],
            },
            "test.yml",
        )
    with pytest.raises(RuleError, match="threshold"):
        parse_rule(
            {
                "id": "X",
                "title": "x",
                "description": "x",
                "source": "ssh",
                "severity": "low",
                "type": "threshold",
                "window_seconds": 60,
                "techniques": ["T1190"],
                "filter": [{"field": "action", "equals": "a"}],
            },
            "test.yml",
        )
