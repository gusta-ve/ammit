"""The case folder: where collected evidence, its manifest and the chain of
custody live.

A :class:`Case` owns a directory named ``<host>_<timestamp>`` containing:

* ``artifacts/`` — the collected evidence, grouped by category;
* ``manifest.json`` — every artifact with its SHA-256 and collection metadata;
* ``chain_of_custody.log`` — an append-only, UTC-timestamped audit trail.

Collectors only ever *write* into the case folder; they read the target through
:mod:`ammit.integrity` so evidence is never perturbed.
"""

from __future__ import annotations

import getpass
import json
import os
import platform
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .context import ScanContext
from .integrity import copy_noatime, sha256_bytes, sha256_file
from .models import Artifact, Verdict, iso_utc, utcnow


def _stamp(when: datetime) -> str:
    """Filesystem-safe UTC stamp, e.g. ``2026-06-23T18-04-12Z``."""
    return when.astimezone(UTC).strftime("%Y-%m-%dT%H-%M-%SZ")


def _safe_host(host: str) -> str:
    cleaned = "".join(c if (c.isalnum() or c in "-_.") else "_" for c in host)
    return cleaned or "host"


def _case_id(host: str, when: datetime) -> str:
    return f"{_safe_host(host)}_{_stamp(when)}"


def _operator_info() -> dict[str, Any]:
    """Who is running Ammit (recorded in the chain of custody)."""
    try:
        user = getpass.getuser()
    except Exception:  # pragma: no cover - environment without a passwd entry
        user = os.environ.get("USER", "unknown")
    return {
        "user": user,
        "uid": os.getuid(),
        "ammit_host": platform.node(),
        "platform": platform.platform(),
        "python": platform.python_version(),
    }


class Case:
    """A forensic case: an on-disk evidence folder with manifest and custody log."""

    def __init__(self, path: Path, context: ScanContext, label: str | None = None) -> None:
        self.path = Path(path)
        self.context = context
        self.label = label
        self.case_id = self.path.name
        self.artifacts: list[Artifact] = []
        self.collectors: list[dict[str, Any]] = []
        self.operator = _operator_info()
        self.verdict: Verdict | None = None
        self.summary: dict[str, Any] = {}
        self._finished: datetime | None = None
        self._integrity: dict[str, Any] = {}
        self._custody = self.path / "chain_of_custody.log"
        self._manifest = self.path / "manifest.json"

    # -- lifecycle -------------------------------------------------------------
    @classmethod
    def create(
        cls,
        parent: str | Path,
        context: ScanContext,
        label: str | None = None,
    ) -> Case:
        """Create a fresh case folder under ``parent`` and open its custody log."""
        parent = Path(parent)
        path = parent / _case_id(context.target_host, context.started_at)
        path.mkdir(parents=True, exist_ok=False)
        (path / "artifacts").mkdir()
        case = cls(path, context, label)
        case.log(
            f"case opened: {case.case_id} (mode={context.mode} root={context.root} "
            f"host={context.target_host} by {case.operator['user']} uid={case.operator['uid']})",
            level="OPEN",
        )
        case._persist_manifest()
        return case

    def finalize(
        self, *, verdict: Verdict | None = None, summary: dict[str, Any] | None = None
    ) -> None:
        """Seal the case: record finish time and the custody log's own hash."""
        self._finished = utcnow()
        if verdict is not None:
            self.verdict = verdict
        if summary is not None:
            self.summary = summary
        self.log(f"case closed: {len(self.artifacts)} artifacts recorded", level="CLOSE")
        # Hash the custody log last so the digest covers every entry above.
        self._integrity = {"chain_of_custody_sha256": sha256_file(self._custody)}
        self._persist_manifest()

    # -- audit trail -----------------------------------------------------------
    def log(self, message: str, *, level: str = "INFO") -> None:
        """Append a UTC-timestamped line to the chain-of-custody log."""
        line = f"{iso_utc(utcnow())} [{level}] {message}\n"
        with self._custody.open("a", encoding="utf-8") as fh:
            fh.write(line)

    @contextmanager
    def collector_run(self, name: str) -> Iterator[None]:
        """Time and record a collector, isolating its failures from the run."""
        start = utcnow()
        entry: dict[str, Any] = {
            "name": name,
            "status": "running",
            "started_at": iso_utc(start),
            "finished_at": None,
            "artifacts": 0,
            "error": None,
        }
        self.collectors.append(entry)
        n_before = len(self.artifacts)
        self.log(f"collector '{name}' started", level="RUN")
        try:
            yield
        except Exception as exc:  # one collector must never abort the whole triage
            entry["status"] = "error"
            entry["error"] = f"{type(exc).__name__}: {exc}"
            self.log(f"collector '{name}' FAILED: {entry['error']}", level="ERROR")
        else:
            entry["status"] = "ok"
        finally:
            entry["finished_at"] = iso_utc(utcnow())
            entry["artifacts"] = len(self.artifacts) - n_before
            self._persist_manifest()

    # -- recording evidence ----------------------------------------------------
    def write_artifact(
        self,
        category: str,
        name: str,
        data: str | bytes,
        *,
        collector: str,
        source: str | None = None,
        description: str | None = None,
    ) -> Artifact:
        """Write Ammit-generated output (e.g. command results) as an artifact."""
        raw = data.encode("utf-8") if isinstance(data, str) else data
        dest = self._dest(category, name)
        dest.write_bytes(raw)
        art = Artifact(
            name=name,
            path=dest.relative_to(self.path).as_posix(),
            sha256=sha256_bytes(raw),
            size=len(raw),
            collected_at=iso_utc(utcnow()),
            collector=collector,
            source=source,
            description=description,
        )
        self._add(art)
        return art

    def write_json(
        self,
        category: str,
        name: str,
        obj: Any,
        *,
        collector: str,
        source: str | None = None,
        description: str | None = None,
    ) -> Artifact:
        """Convenience wrapper to serialise ``obj`` as pretty JSON and record it."""
        text = json.dumps(obj, indent=2, ensure_ascii=False, default=str) + "\n"
        return self.write_artifact(
            category, name, text, collector=collector, source=source, description=description
        )

    def copy_artifact(
        self,
        category: str,
        src: str | Path,
        name: str | None = None,
        *,
        collector: str,
        description: str | None = None,
    ) -> Artifact | None:
        """Copy a file from the target into the case (atime-preserving)."""
        src = Path(src)
        dest = self._dest(category, name or src.name)
        try:
            size = copy_noatime(src, dest)
        except OSError as exc:
            self.log(f"failed to copy {src}: {exc}", level="ERROR")
            return None
        art = Artifact(
            name=dest.name,
            path=dest.relative_to(self.path).as_posix(),
            sha256=sha256_file(dest),
            size=size,
            collected_at=iso_utc(utcnow()),
            collector=collector,
            source=str(src),
            description=description,
        )
        self._add(art)
        return art

    # -- internals -------------------------------------------------------------
    def _dest(self, category: str, name: str) -> Path:
        dest = self.path / "artifacts" / category / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        return dest

    def _add(self, art: Artifact) -> None:
        self.artifacts.append(art)
        trailer = f" <- {art.source}" if art.source else ""
        self.log(
            f"collected {art.path} sha256={art.sha256} ({art.size} bytes){trailer}",
            level="COLLECT",
        )
        self._persist_manifest()

    def manifest(self) -> dict[str, Any]:
        return {
            "tool": "ammit",
            "version": __version__,
            "case": {
                "id": self.case_id,
                "label": self.label,
                "target_host": self.context.target_host,
                "mode": self.context.mode,
                "root": str(self.context.root),
                "authorized": self.context.authorized,
                "started_at": iso_utc(self.context.started_at),
                "finished_at": iso_utc(self._finished) if self._finished else None,
                "operator": self.operator,
            },
            "verdict": self.verdict.value if self.verdict else None,
            "summary": self.summary,
            "integrity": self._integrity,
            "collectors": self.collectors,
            "artifacts": [a.to_dict() for a in self.artifacts],
        }

    def _persist_manifest(self) -> None:
        self._manifest.write_text(
            json.dumps(self.manifest(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
