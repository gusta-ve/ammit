"""A small declarative rule engine.

A rule selects a named *dataset* (a list of flat records built from the case by
:mod:`ammit.rules.datasets`), filters it with a list of ANDed conditions, and
emits :class:`~ammit.models.Finding` objects. Rules may aggregate with
``group_by`` + ``having`` (e.g. "≥ 8 failed logins from one source IP").
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..models import Finding, Severity

_MAX_EVIDENCE = 50


class _SafeDict(dict):
    def __missing__(self, key: str) -> str:  # noqa: D105
        return ""


def render(template: str, row: dict[str, Any]) -> str:
    """Format ``template`` with ``row``; missing fields render as empty."""
    try:
        return template.format_map(_SafeDict(row))
    except (ValueError, IndexError, KeyError):
        return template


@dataclass
class Condition:
    field: str
    op: str
    value: Any = None

    def test(self, row: dict[str, Any]) -> bool:
        actual = row.get(self.field)
        op = self.op
        if op == "exists":
            return self.field in row and actual is not None
        if op == "not_exists":
            return actual is None
        if op == "truthy":
            return bool(actual)
        if op == "falsy":
            return not bool(actual)
        if op == "eq":
            return actual == self.value
        if op == "ne":
            return actual != self.value
        if op == "in":
            return actual in (self.value or [])
        if op == "not_in":
            return actual not in (self.value or [])
        if op == "contains":
            return actual is not None and self.value in actual
        if op == "regex":
            return actual is not None and re.search(str(self.value), str(actual)) is not None
        if op == "startswith":
            return str(actual).startswith(str(self.value))
        if op == "under":
            return any(str(actual).startswith(p) for p in self.value)
        if op == "not_under":
            return actual is not None and not any(str(actual).startswith(p) for p in self.value)
        if op in {"gt", "ge", "lt", "le"}:
            return self._compare(actual, op)
        raise ValueError(f"unknown operator: {op!r}")

    def _compare(self, actual: Any, op: str) -> bool:
        if actual is None:
            return False
        try:
            a, b = float(actual), float(self.value)
        except (TypeError, ValueError):
            return False
        return {"gt": a > b, "ge": a >= b, "lt": a < b, "le": a <= b}[op]


@dataclass
class Having:
    op: str  # ge, gt, eq, le, lt
    count: int

    def test(self, n: int) -> bool:
        return {
            "ge": n >= self.count,
            "gt": n > self.count,
            "eq": n == self.count,
            "le": n <= self.count,
            "lt": n < self.count,
        }[self.op]


@dataclass
class Rule:
    id: str
    title: str
    severity: Severity
    dataset: str
    description: str
    evidence: str
    where: list[Condition] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    group_by: list[str] = field(default_factory=list)
    having: Having | None = None
    evidence_each: str | None = None
    enabled: bool = True


def _condition(raw: dict[str, Any]) -> Condition:
    return Condition(field=raw["field"], op=raw["op"], value=raw.get("value"))


def parse_rule(raw: dict[str, Any]) -> Rule:
    having = Having(**raw["having"]) if raw.get("having") else None
    return Rule(
        id=raw["id"],
        title=raw["title"],
        severity=Severity(raw["severity"]),
        dataset=raw["dataset"],
        description=raw.get("description", "").strip(),
        evidence=raw["evidence"],
        where=[_condition(c) for c in raw.get("where", [])],
        mitre=list(raw.get("mitre", [])),
        group_by=list(raw.get("group_by", [])),
        having=having,
        evidence_each=raw.get("evidence_each"),
        enabled=raw.get("enabled", True),
    )


def load_rules(path: str | Path) -> list[Rule]:
    """Load rules from a YAML file or every ``*.yaml`` in a directory."""
    path = Path(path)
    files = sorted(path.glob("*.yaml")) if path.is_dir() else [path]
    rules: list[Rule] = []
    for file in files:
        data = yaml.safe_load(file.read_text(encoding="utf-8")) or []
        rules.extend(parse_rule(raw) for raw in data)
    return rules


def evaluate(rule: Rule, rows: list[dict[str, Any]]) -> list[Finding]:
    """Apply ``rule`` to ``rows`` and return the findings it produces."""
    matched = [r for r in rows if all(cond.test(r) for cond in rule.where)]
    if not matched:
        return []

    if rule.group_by:
        return _evaluate_grouped(rule, matched)

    evidence = [render(rule.evidence, r) for r in matched[:_MAX_EVIDENCE]]
    return [_finding(rule, evidence, matched)]


def _evaluate_grouped(rule: Rule, matched: list[dict[str, Any]]) -> list[Finding]:
    groups: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    for row in matched:
        groups[tuple(row.get(k) for k in rule.group_by)].append(row)

    findings: list[Finding] = []
    for members in groups.values():
        if rule.having and not rule.having.test(len(members)):
            continue
        context = {**members[0], "count": len(members)}
        evidence = [render(rule.evidence, context)]
        if rule.evidence_each:
            evidence += [render(rule.evidence_each, m) for m in members[:_MAX_EVIDENCE]]
        findings.append(_finding(rule, evidence, members))
    return findings


def _finding(rule: Rule, evidence: list[str], rows: list[dict[str, Any]]) -> Finding:
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        severity=rule.severity,
        description=rule.description,
        evidence=evidence,
        mitre=rule.mitre,
        artifacts=[rule.dataset],
        metadata={"matches": len(rows)},
    )
