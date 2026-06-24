"""Unit tests for dataset loading and enrichment over a collected case."""

from pathlib import Path

from ammit.rules.datasets import Datasets


def test_connections_enriched_port_and_external(collected_case: Path):
    conns = Datasets(collected_case).get("connections")
    assert conns, "expected at least the bind-shell connection"
    assert any(c["port_suspicious"] for c in conns)
    listener = next(c for c in conns if c["local_port"] == 4444)
    assert listener["port_suspicious"] is True
    assert listener["remote_external"] is False  # 0.0.0.0 is not external


def test_cron_entries_flag_indicator(collected_case: Path):
    rows = Datasets(collected_case).get("cron_entries")
    flagged = [r for r in rows if r["indicator"]]
    assert flagged
    assert any("curl" in r["command"] for r in flagged)
    # The env-assignment and comment lines must have been skipped.
    assert all(not r["line"].startswith(("#", "PATH=")) for r in rows)


def test_systemd_admin_exec_and_indicator(collected_case: Path):
    rows = Datasets(collected_case).get("systemd_admin")
    unit = next(r for r in rows if r["unit"] == "backdoor.service")
    assert "/dev/tcp/" in unit["exec_start"]
    assert unit["indicator"]


def test_auth_events_parsed(collected_case: Path):
    events = Datasets(collected_case).get("auth_events")
    failed = [e for e in events if e["event"] == "failed_password"]
    assert len(failed) >= 8
    assert all(e["source_ip"] == "203.0.113.66" for e in failed)
    off_hours = [e for e in events if e["event"].startswith("accepted_") and e["off_hours"]]
    assert any(e["user"] == "backdoor" and e["hour"] == 3 for e in off_hours)


def test_suid_standard_location(collected_case: Path):
    rows = Datasets(collected_case).get("suid_sgid")
    rootbash = next(r for r in rows if r["path"] == "/tmp/.cache/rootbash")
    assert rootbash["suid"] is True
    assert rootbash["standard_location"] is False


def test_authorized_keys_shell_join(collected_case: Path):
    keys = Datasets(collected_case).get("authorized_keys")
    www = next(k for k in keys if k["user"] == "www-data")
    assert www["shell"] == "/usr/sbin/nologin"
    assert www["shell_nologin"] is True


def test_unknown_dataset_raises(collected_case: Path):
    try:
        Datasets(collected_case).get("nope")
    except ValueError as exc:
        assert "nope" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError for unknown dataset")
