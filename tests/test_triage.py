"""End-to-end triage: collect a synthetic compromised system, weigh it, and
check the verdict and the rules that fired."""

import json
from pathlib import Path

from ammit.models import Verdict
from ammit.triage import run_triage

# Rules the synthetic compromised image is built to trip.
EXPECTED_RULES = {
    "deleted_binary_process",
    "duplicate_uid0",
    "ssh_bruteforce",
    "ld_preload_rootkit",
    "suspicious_suid",
    "suspicious_cron",
    "suspicious_systemd",
    "ssh_key_for_system_account",
    "suspicious_connection",
    "shell_history_tampered",
    "hidden_temp_file",
    "off_hours_login",
}


def test_compromised_image_verdict(collected_case: Path):
    findings, verdict, summary = run_triage(collected_case)
    assert verdict is Verdict.COMPROMISED
    assert summary["verdict"] == "COMPROMISED"
    assert summary["findings"] == len(findings)
    assert summary["weight"] >= 20


def test_compromised_image_fires_expected_rules(collected_case: Path):
    findings, _, _ = run_triage(collected_case)
    fired = {f.rule_id for f in findings}
    missing = EXPECTED_RULES - fired
    assert not missing, f"rules that should have fired but didn't: {sorted(missing)}"


def test_critical_findings_present(collected_case: Path):
    findings, _, _ = run_triage(collected_case)
    criticals = {f.rule_id for f in findings if f.severity.value == "critical"}
    assert {"deleted_binary_process", "duplicate_uid0"} <= criticals


def test_findings_have_evidence(collected_case: Path):
    findings, _, _ = run_triage(collected_case)
    deleted = next(f for f in findings if f.rule_id == "deleted_binary_process")
    assert deleted.evidence
    assert any("xmrig" in line for line in deleted.evidence)
    assert deleted.mitre  # every rule maps to ATT&CK


def test_findings_sorted_heaviest_first(collected_case: Path):
    findings, _, _ = run_triage(collected_case)
    ranks = [f.severity.rank for f in findings]
    assert ranks == sorted(ranks, reverse=True)


def test_triage_persists_findings_and_stamps_manifest(collected_case: Path):
    _, verdict, summary = run_triage(collected_case)

    findings_doc = json.loads((collected_case / "findings.json").read_text())
    assert findings_doc["verdict"] == "COMPROMISED"
    assert findings_doc["rules_evaluated"] >= 12
    assert findings_doc["findings"]

    manifest = json.loads((collected_case / "manifest.json").read_text())
    assert manifest["verdict"] == "COMPROMISED"
    assert manifest["summary"]["weight"] == summary["weight"]
    assert manifest["triage"]["tool_version"]
    # Triage must not disturb the sealed collection integrity hash.
    assert len(manifest["integrity"]["chain_of_custody_sha256"]) == 64


def test_clean_image_verdict(clean_case: Path):
    findings, verdict, _ = run_triage(clean_case)
    assert verdict is Verdict.CLEAN, f"unexpected findings: {[f.rule_id for f in findings]}"
