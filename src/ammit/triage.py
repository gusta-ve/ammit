"""Orchestration for ``ammit triage``: weigh a collected case against the
feather of Maat (the rule set) and record the findings and verdict.

Triage is *analysis over sealed evidence*: it reads the artifacts a
:class:`~ammit.case.Case` left behind and writes its own ``findings.json``,
then stamps the verdict into the existing ``manifest.json``. It never mutates
the collected artifacts or the chain-of-custody log.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import __version__
from .models import Finding, Verdict, iso_utc, utcnow
from .rules.datasets import Datasets
from .rules.engine import Rule, evaluate, load_rules
from .verdict import compute_verdict, verdict_summary

BUILTIN_RULES_DIR = Path(__file__).parent / "rules" / "builtin"


def load_ruleset(extra: str | Path | None = None) -> list[Rule]:
    """The built-in rules, plus any extra rules file/directory the user supplied."""
    rules = load_rules(BUILTIN_RULES_DIR)
    if extra is not None:
        rules.extend(load_rules(extra))
    return rules


def run_triage(
    case_dir: str | Path,
    *,
    extra_rules: str | Path | None = None,
    baseline: dict[str, Any] | None = None,
) -> tuple[list[Finding], Verdict, dict[str, Any]]:
    """Evaluate every enabled rule and return ``(findings, verdict, summary)``."""
    case_dir = Path(case_dir)
    rules = load_ruleset(extra_rules)
    datasets = Datasets(case_dir, baseline=baseline)

    findings: list[Finding] = []
    for rule in rules:
        if not rule.enabled:
            continue
        findings.extend(evaluate(rule, datasets.get(rule.dataset)))

    # Heaviest first, then by rule id for a stable order.
    findings.sort(key=lambda f: (-f.severity.rank, f.rule_id))
    verdict = compute_verdict(findings)
    summary = verdict_summary(findings)

    _write_findings(case_dir, findings, verdict, summary, len(rules))
    _stamp_manifest(case_dir, verdict, summary)
    return findings, verdict, summary


def _write_findings(
    case_dir: Path,
    findings: list[Finding],
    verdict: Verdict,
    summary: dict[str, Any],
    rules_evaluated: int,
) -> None:
    payload = {
        "tool": "ammit",
        "version": __version__,
        "generated_at": iso_utc(utcnow()),
        "rules_evaluated": rules_evaluated,
        "verdict": verdict.value,
        "summary": summary,
        "findings": [f.to_dict() for f in findings],
    }
    (case_dir / "findings.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def _stamp_manifest(case_dir: Path, verdict: Verdict, summary: dict[str, Any]) -> None:
    """Record the verdict in the existing manifest without disturbing the rest."""
    manifest_path = case_dir / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    manifest["verdict"] = verdict.value
    manifest["summary"] = summary
    manifest["triage"] = {
        "generated_at": iso_utc(utcnow()),
        "tool_version": __version__,
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
