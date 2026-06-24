"""Unit tests for the declarative rule engine."""

from ammit.models import Severity
from ammit.rules.engine import Condition, Having, Rule, evaluate, parse_rule, render


def test_condition_operators():
    row = {"path": "/tmp/x", "port": 4444, "name": "evil", "flag": True}
    assert Condition("flag", "truthy").test(row)
    assert Condition("missing", "falsy").test(row)
    assert Condition("missing", "not_exists").test(row)
    assert Condition("path", "exists").test(row)
    assert Condition("port", "eq", 4444).test(row)
    assert Condition("port", "ge", 4000).test(row)
    assert not Condition("port", "lt", 80).test(row)
    assert Condition("name", "in", ["evil", "bad"]).test(row)
    assert Condition("path", "contains", "/tmp").test(row)
    assert Condition("path", "regex", r"^/tmp/").test(row)
    assert Condition("path", "not_under", ["/usr/bin/", "/bin/"]).test(row)
    assert not Condition("path", "under", ["/usr/bin/"]).test(row)


def test_unknown_operator_raises():
    try:
        Condition("x", "bogus").test({"x": 1})
    except ValueError as exc:
        assert "bogus" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError")


def test_render_missing_field_is_empty():
    assert render("{a}-{b}", {"a": "x"}) == "x-"


def test_having_thresholds():
    assert Having("ge", 8).test(8)
    assert not Having("ge", 8).test(7)
    assert Having("gt", 1).test(2)
    assert Having("eq", 3).test(3)


def _rule(**kw) -> Rule:
    base = {
        "id": "r",
        "title": "t",
        "severity": "high",
        "dataset": "d",
        "description": "",
        "evidence": "{x}",
    }
    base.update(kw)
    return parse_rule(base)


def test_evaluate_simple_where_one_finding_per_rule():
    rule = _rule(where=[{"field": "bad", "op": "truthy"}], evidence="hit {x}")
    rows = [{"bad": True, "x": 1}, {"bad": False, "x": 2}, {"bad": True, "x": 3}]
    findings = evaluate(rule, rows)
    assert len(findings) == 1
    assert findings[0].metadata["matches"] == 2
    assert findings[0].evidence == ["hit 1", "hit 3"]


def test_evaluate_no_match_returns_nothing():
    rule = _rule(where=[{"field": "bad", "op": "truthy"}])
    assert evaluate(rule, [{"bad": False}]) == []


def test_evaluate_grouped_with_having():
    rule = _rule(
        severity="high",
        group_by=["ip"],
        having={"op": "ge", "count": 3},
        evidence="{count} from {ip}",
    )
    rows = [{"ip": "a"}] * 3 + [{"ip": "b"}] * 2
    findings = evaluate(rule, rows)
    assert len(findings) == 1  # only group "a" meets the threshold
    assert findings[0].severity is Severity.HIGH
    assert "3 from a" in findings[0].evidence[0]


def test_evaluate_grouped_evidence_each():
    rule = _rule(
        group_by=["uid"],
        having={"op": "ge", "count": 2},
        evidence="{count} share uid {uid}",
        evidence_each="  {name}",
    )
    rows = [{"uid": 0, "name": "root"}, {"uid": 0, "name": "backdoor"}]
    findings = evaluate(rule, rows)
    assert findings[0].evidence == ["2 share uid 0", "  root", "  backdoor"]
