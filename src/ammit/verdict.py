"""The weighing of the heart: turn findings into a verdict.

Each finding carries a forensic *weight* (see :class:`~ammit.models.Severity`).
A single CRITICAL finding — or enough lighter ones to tip the scales — drags the
heart down and the verdict becomes COMPROMISED.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .models import Finding, Severity, Verdict

# The scales tip to COMPROMISED at the weight of one critical finding.
COMPROMISED_THRESHOLD = Severity.CRITICAL.weight  # 20
# …and to SUSPICIOUS at the weight of one medium finding.
SUSPICIOUS_THRESHOLD = Severity.MEDIUM.weight  # 3


def total_weight(findings: Iterable[Finding]) -> int:
    return sum(f.severity.weight for f in findings)


def compute_verdict(findings: Iterable[Finding]) -> Verdict:
    """Render the verdict for a set of findings."""
    findings = list(findings)
    if not findings:
        return Verdict.CLEAN
    weight = total_weight(findings)
    if weight >= COMPROMISED_THRESHOLD or any(f.severity is Severity.CRITICAL for f in findings):
        return Verdict.COMPROMISED
    if weight >= SUSPICIOUS_THRESHOLD:
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN


def verdict_summary(findings: Iterable[Finding]) -> dict[str, Any]:
    """A compact, JSON-friendly summary recorded in the manifest."""
    findings = list(findings)
    counts = {sev.value: 0 for sev in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return {
        "verdict": compute_verdict(findings).value,
        "findings": len(findings),
        "weight": total_weight(findings),
        "severity_counts": counts,
    }
