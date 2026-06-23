"""Tests for the case folder, manifest and chain of custody."""

import json
from pathlib import Path

from ammit.case import Case
from ammit.context import ScanContext
from ammit.integrity import sha256_bytes
from ammit.models import Verdict


def make_image(tmp_path: Path) -> Path:
    root = tmp_path / "image"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "hostname").write_text("victim01\n")
    return root


def _ctx(root: Path) -> ScanContext:
    # image mode => authorized, host read from <root>/etc/hostname
    return ScanContext.image(root)


def test_case_create_layout(tmp_path: Path):
    case = Case.create(tmp_path / "cases", _ctx(make_image(tmp_path)), label="ir-001")
    assert case.path.is_dir()
    assert (case.path / "artifacts").is_dir()
    assert (case.path / "manifest.json").is_file()
    assert (case.path / "chain_of_custody.log").is_file()
    assert case.case_id.startswith("victim01_")

    m = json.loads((case.path / "manifest.json").read_text())
    assert m["tool"] == "ammit"
    assert m["case"]["target_host"] == "victim01"
    assert m["case"]["mode"] == "image"
    assert m["case"]["label"] == "ir-001"
    assert m["case"]["operator"]["uid"] >= 0


def test_write_artifact_hashes_and_records(tmp_path: Path):
    case = Case.create(tmp_path / "cases", _ctx(make_image(tmp_path)), None)
    art = case.write_artifact("volatile", "processes.txt", "pid 1 init\n", collector="proc")

    dest = case.path / art.path
    assert dest.read_text() == "pid 1 init\n"
    assert art.sha256 == sha256_bytes(b"pid 1 init\n")
    assert art.path == "artifacts/volatile/processes.txt"

    m = json.loads((case.path / "manifest.json").read_text())
    assert any(a["path"] == "artifacts/volatile/processes.txt" for a in m["artifacts"])

    custody = (case.path / "chain_of_custody.log").read_text()
    assert "processes.txt" in custody
    assert art.sha256 in custody


def test_copy_artifact_from_target(tmp_path: Path):
    root = make_image(tmp_path)
    (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
    case = Case.create(tmp_path / "cases", _ctx(root), None)

    art = case.copy_artifact("accounts", root / "etc" / "passwd", "passwd", collector="accounts")
    assert art is not None
    assert (case.path / art.path).read_text().startswith("root:x:0:0")
    assert art.source.endswith("etc/passwd")


def test_nested_artifact_name_creates_dirs(tmp_path: Path):
    case = Case.create(tmp_path / "cases", _ctx(make_image(tmp_path)), None)
    art = case.write_artifact("logs", "users/root/.bash_history", "id\nwhoami\n", collector="logs")
    assert (case.path / "artifacts" / "logs" / "users" / "root" / ".bash_history").is_file()
    assert art.path == "artifacts/logs/users/root/.bash_history"


def test_collector_run_records_failure_without_raising(tmp_path: Path):
    case = Case.create(tmp_path / "cases", _ctx(make_image(tmp_path)), None)
    with case.collector_run("boom"):
        raise RuntimeError("kaboom")  # must be swallowed and recorded

    entry = next(c for c in case.collectors if c["name"] == "boom")
    assert entry["status"] == "error"
    assert "kaboom" in entry["error"]


def test_finalize_seals_case(tmp_path: Path):
    case = Case.create(tmp_path / "cases", _ctx(make_image(tmp_path)), None)
    case.write_artifact("volatile", "x.txt", "data", collector="t")
    case.finalize(verdict=Verdict.COMPROMISED, summary={"findings": 3})

    m = json.loads((case.path / "manifest.json").read_text())
    assert m["case"]["finished_at"] is not None
    assert m["verdict"] == "COMPROMISED"
    assert m["summary"] == {"findings": 3}
    assert len(m["integrity"]["chain_of_custody_sha256"]) == 64
