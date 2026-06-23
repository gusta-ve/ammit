"""Core data models shared across collection, triage and reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


def utcnow() -> datetime:
    """Timezone-aware current time in UTC (all Ammit timestamps are UTC)."""
    return datetime.now(UTC)


def iso_utc(dt: datetime) -> str:
    """Render a datetime as an ISO-8601 UTC string with a trailing ``Z``."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


class Severity(StrEnum):
    """Severity of a finding, ordered by forensic weight."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        """Numeric weight used to tip the scales toward a verdict."""
        return {"info": 0, "low": 1, "medium": 3, "high": 8, "critical": 20}[self.value]

    @property
    def rank(self) -> int:
        """Ordinal for sorting (info=0 .. critical=4)."""
        return ["info", "low", "medium", "high", "critical"].index(self.value)


class Verdict(StrEnum):
    """The weighing of the heart — Ammit's final judgement."""

    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    COMPROMISED = "COMPROMISED"


@dataclass
class Finding:
    """A single weighed observation produced by the triage engine."""

    rule_id: str
    title: str
    severity: Severity
    description: str
    evidence: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "mitre": self.mitre,
            "artifacts": self.artifacts,
            "metadata": self.metadata,
        }


@dataclass
class Artifact:
    """An item recorded in the case manifest / chain of custody."""

    name: str
    path: str  # relative to the case directory
    sha256: str
    size: int
    collected_at: str  # ISO-8601 UTC
    collector: str
    source: str | None = None  # original path/command on the target
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "collected_at": self.collected_at,
            "collector": self.collector,
            "source": self.source,
            "description": self.description,
        }
