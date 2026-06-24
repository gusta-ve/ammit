"""Unit tests for the verdict (weighing of the heart)."""

from ammit.models import Finding, Severity, Verdict
from ammit.verdict import compute_verdict, total_weight, verdict_summary


def _f(sev: Severity) -> Finding:
    return Finding(rule_id="r", title="t", severity=sev, description="")


def test_empty_is_clean():
    assert compute_verdict([]) is Verdict.CLEAN


def test_single_critical_is_compromised():
    assert compute_verdict([_f(Severity.CRITICAL)]) is Verdict.COMPROMISED


def test_weight_tips_to_compromised():
    # Three highs = 24 >= 20.
    assert compute_verdict([_f(Severity.HIGH)] * 3) is Verdict.COMPROMISED


def test_single_medium_is_suspicious():
    assert compute_verdict([_f(Severity.MEDIUM)]) is Verdict.SUSPICIOUS


def test_single_high_is_suspicious():
    assert compute_verdict([_f(Severity.HIGH)]) is Verdict.SUSPICIOUS


def test_lone_low_stays_clean():
    assert compute_verdict([_f(Severity.LOW)]) is Verdict.CLEAN
    assert compute_verdict([_f(Severity.LOW), _f(Severity.LOW)]) is Verdict.CLEAN


def test_three_lows_become_suspicious():
    assert compute_verdict([_f(Severity.LOW)] * 3) is Verdict.SUSPICIOUS


def test_total_weight():
    assert total_weight([_f(Severity.CRITICAL), _f(Severity.MEDIUM)]) == 23


def test_summary_counts():
    summary = verdict_summary([_f(Severity.CRITICAL), _f(Severity.HIGH), _f(Severity.HIGH)])
    assert summary["verdict"] == "COMPROMISED"
    assert summary["findings"] == 3
    assert summary["severity_counts"]["high"] == 2
    assert summary["severity_counts"]["critical"] == 1
