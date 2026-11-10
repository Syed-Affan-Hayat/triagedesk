"""Detection rule engine.

Rules are YAML files in ``detection/rules/``. The format is inspired by Sigma
(https://github.com/SigmaHQ/sigma) but is deliberately smaller: it only covers what this tool
needs, and it is not Sigma-compatible.

Rule types
----------
``match``
    Every event that satisfies ``filter``. Matches from the same group (for example the
    same source IP) are combined into one alert per burst.
``threshold``
    At least ``threshold`` filtered events from one group inside ``window_seconds``.
``distinct``
    At least ``threshold`` different values of ``distinct_field`` from one group inside
    ``window_seconds`` (for example one IP trying many user names).
``sequence``
    At least ``threshold`` filtered events followed by an event satisfying ``then``, all
    from one group inside ``window_seconds`` (for example failures followed by a success).

Bursts
------
For ``match``, ``threshold`` and ``distinct`` rules an alert opens when the condition is met
and stays open while further matching events arrive less than one window apart. This yields
one alert per burst of activity instead of one alert per event.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import timedelta
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from triagedesk.detection.attack import CATALOGUE
from triagedesk.models import SEVERITY_ORDER, Alert, Event

RULE_TYPES = ("match", "threshold", "distinct", "sequence")
OPERATORS = ("equals", "not_equals", "in", "contains", "regex", "gte", "lte")
DEFAULT_MATCH_WINDOW = 3600


class RuleError(ValueError):
    """Raised when a rule file is missing a field or uses an unknown value."""


@dataclass
class Condition:
    field_name: str
    operator: str
    value: Any
    pattern: re.Pattern[str] | None = None

    def holds(self, event: Event) -> bool:
        actual = event.get(self.field_name)
        if actual is None:
            return False
        if self.operator == "equals":
            return actual == self.value
        if self.operator == "not_equals":
            return actual != self.value
        if self.operator == "in":
            return actual in self.value
        if self.operator == "contains":
            return str(self.value).lower() in str(actual).lower()
        if self.operator == "regex":
            return bool(self.pattern.search(str(actual)))
        if self.operator == "gte":
            return actual >= self.value
        if self.operator == "lte":
            return actual <= self.value
        raise AssertionError(f"unhandled operator {self.operator}")


@dataclass
class Rule:
    rule_id: str
    title: str
    description: str
    source: str
    severity: str
    rule_type: str
    techniques: list[str]
    conditions: list[Condition]
    group_by: str = "src_ip"
    threshold: int = 1
    window_seconds: int = DEFAULT_MATCH_WINDOW
    distinct_field: str | None = None
    then: list[Condition] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    response: list[str] = field(default_factory=list)

    def applies_to(self, event: Event) -> bool:
        return self.source in ("any", event.source)

    def filter(self, event: Event) -> bool:
        return self.applies_to(event) and all(c.holds(event) for c in self.conditions)

    def closes(self, event: Event) -> bool:
        return self.applies_to(event) and all(c.holds(event) for c in self.then)


# ---------------------------------------------------------------------------
# Loading and validation
# ---------------------------------------------------------------------------


def _parse_conditions(raw: Any, origin: str) -> list[Condition]:
    if not isinstance(raw, list) or not raw:
        raise RuleError(f"{origin}: conditions must be a non-empty list")
    conditions = []
    for item in raw:
        if not isinstance(item, dict) or "field" not in item:
            raise RuleError(f"{origin}: each condition needs a 'field'")
        operators = [key for key in item if key != "field"]
        if len(operators) != 1 or operators[0] not in OPERATORS:
            raise RuleError(f"{origin}: each condition needs exactly one of {', '.join(OPERATORS)}")
        operator = operators[0]
        value = item[operator]
        pattern = None
        if operator == "regex":
            try:
                pattern = re.compile(value)
            except re.error as exc:
                raise RuleError(f"{origin}: invalid regex {value!r}: {exc}") from exc
        conditions.append(Condition(item["field"], operator, value, pattern))
    return conditions


def parse_rule(data: dict[str, Any], origin: str) -> Rule:
    """Validate one rule document and convert it to a ``Rule``."""
    required = ("id", "title", "description", "source", "severity", "type", "techniques", "filter")
    missing = [key for key in required if key not in data]
    if missing:
        raise RuleError(f"{origin}: missing {', '.join(missing)}")
    if data["type"] not in RULE_TYPES:
        raise RuleError(f"{origin}: type must be one of {', '.join(RULE_TYPES)}")
    if data["severity"] not in SEVERITY_ORDER:
        raise RuleError(f"{origin}: severity must be one of {', '.join(SEVERITY_ORDER)}")
    if data["source"] not in ("ssh", "web", "any"):
        raise RuleError(f"{origin}: source must be ssh, web or any")
    unknown = [t for t in data["techniques"] if t not in CATALOGUE]
    if unknown:
        raise RuleError(f"{origin}: techniques not in the catalogue: {', '.join(unknown)}")

    rule_type = data["type"]
    default_window = DEFAULT_MATCH_WINDOW if rule_type == "match" else None
    window = data.get("window_seconds", default_window)
    if window is None:
        raise RuleError(f"{origin}: {rule_type} rules need window_seconds")
    threshold = data.get("threshold", 1)
    if rule_type != "match" and "threshold" not in data:
        raise RuleError(f"{origin}: {rule_type} rules need threshold")
    if rule_type == "distinct" and not data.get("distinct_field"):
        raise RuleError(f"{origin}: distinct rules need distinct_field")
    if rule_type == "sequence" and not data.get("then"):
        raise RuleError(f"{origin}: sequence rules need then")

    return Rule(
        rule_id=data["id"],
        title=data["title"],
        description=" ".join(str(data["description"]).split()),
        source=data["source"],
        severity=data["severity"],
        rule_type=rule_type,
        techniques=list(data["techniques"]),
        conditions=_parse_conditions(data["filter"], origin),
        group_by=data.get("group_by", "src_ip"),
        threshold=int(threshold),
        window_seconds=int(window),
        distinct_field=data.get("distinct_field"),
        then=_parse_conditions(data["then"], origin) if rule_type == "sequence" else [],
        false_positives=list(data.get("false_positives", [])),
        response=list(data.get("response", [])),
    )


def load_rules(directory: Path | None = None) -> list[Rule]:
    """Load and validate every ``*.yml`` rule. Defaults to the bundled rule set."""
    if directory is None:
        root = resources.files("triagedesk.detection").joinpath("rules")
        files = sorted((f for f in root.iterdir() if f.name.endswith(".yml")), key=lambda f: f.name)
    else:
        files = sorted(Path(directory).glob("*.yml"))
    rules = [parse_rule(yaml.safe_load(f.read_text(encoding="utf-8")), f.name) for f in files]
    ids = [rule.rule_id for rule in rules]
    duplicates = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
    if duplicates:
        raise RuleError(f"duplicate rule ids: {', '.join(duplicates)}")
    return rules


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def _bursts(events: list[Event], rule: Rule) -> list[list[Event]]:
    """Split one group's time-ordered events into bursts that satisfy the rule."""
    window = timedelta(seconds=rule.window_seconds)
    bursts: list[list[Event]] = []
    start = 0
    index = 0
    while index < len(events):
        while events[index].timestamp - events[start].timestamp > window:
            start += 1
        in_window = events[start : index + 1]
        if rule.rule_type == "distinct":
            met = len({e.get(rule.distinct_field) for e in in_window}) >= rule.threshold
        else:
            met = len(in_window) >= rule.threshold
        if met:
            burst = list(in_window)
            index += 1
            while index < len(events) and events[index].timestamp - burst[-1].timestamp <= window:
                burst.append(events[index])
                index += 1
            bursts.append(burst)
            start = index
            continue
        index += 1
    return bursts


def _sequences(events: list[Event], rule: Rule) -> list[list[Event]]:
    """Find runs of filtered events closed by a ``then`` event inside the window."""
    window = timedelta(seconds=rule.window_seconds)
    found: list[list[Event]] = []
    preceding: deque[Event] = deque()
    for event in events:
        if rule.closes(event):
            while preceding and event.timestamp - preceding[0].timestamp > window:
                preceding.popleft()
            if len(preceding) >= rule.threshold:
                found.append([*preceding, event])
            preceding.clear()
        elif rule.filter(event):
            preceding.append(event)
    return found


def _group(events: list[Event], rule: Rule, keep) -> dict[Any, list[Event]]:
    groups: dict[Any, list[Event]] = defaultdict(list)
    for event in events:
        if keep(event):
            key = event.get(rule.group_by)
            if key is not None:
                groups[key].append(event)
    return groups


def evaluate(rule: Rule, events: list[Event]) -> list[tuple[Any, list[Event]]]:
    """Return ``(group value, events)`` pairs for every place the rule fires."""
    ordered = sorted(events, key=lambda e: (e.timestamp, e.event_id))
    results: list[tuple[Any, list[Event]]] = []
    if rule.rule_type == "sequence":
        groups = _group(ordered, rule, lambda e: rule.filter(e) or rule.closes(e))
        for key, members in groups.items():
            results.extend((key, run) for run in _sequences(members, rule))
    else:
        groups = _group(ordered, rule, rule.filter)
        for key, members in groups.items():
            results.extend((key, burst) for burst in _bursts(members, rule))
    return results


def run_rules(rules: list[Rule], events: list[Event]) -> list[Alert]:
    """Evaluate every rule and return alerts ordered by first event time."""
    pending = []
    for rule in rules:
        for group_value, matched in evaluate(rule, events):
            pending.append((rule, group_value, matched))
    pending.sort(key=lambda item: (item[2][0].timestamp, item[0].rule_id))

    alerts = []
    for number, (rule, group_value, matched) in enumerate(pending, start=1):
        alerts.append(
            Alert(
                alert_id=f"A-{number:04d}",
                rule_id=rule.rule_id,
                title=rule.title,
                description=rule.description,
                severity=rule.severity,
                source=matched[0].source,
                techniques=[CATALOGUE[t] for t in rule.techniques],
                events=matched,
                group_value=str(group_value),
                response=rule.response,
                false_positives=rule.false_positives,
            )
        )
    return alerts
