"""Scan context: where Ammit looks, and under what authority."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .models import utcnow


def _read_image_hostname(root: Path) -> str:
    """Best-effort hostname for a mounted image root."""
    hostname_file = root / "etc" / "hostname"
    try:
        name = hostname_file.read_text(encoding="utf-8", errors="replace").strip()
        return name or "image"
    except OSError:
        return "image"


@dataclass
class ScanContext:
    """Everything a collector needs to know about *where* and *how* it runs.

    ``root`` is the filesystem root of the target: ``/`` for the live host, or
    the mountpoint of a read-only image. Collectors must never write under it.
    """

    root: Path
    mode: str  # "live" | "image"
    authorized: bool = False
    target_host: str = "unknown"
    started_at: datetime = field(default_factory=utcnow)

    @classmethod
    def live(cls, *, authorized: bool) -> ScanContext:
        return cls(
            root=Path("/"),
            mode="live",
            authorized=authorized,
            target_host=socket.gethostname(),
        )

    @classmethod
    def image(cls, root: Path) -> ScanContext:
        root = root.resolve()
        # Analysing a mounted image never touches a live host, so it is always
        # considered authorized.
        return cls(
            root=root,
            mode="image",
            authorized=True,
            target_host=_read_image_hostname(root),
        )

    @property
    def is_live(self) -> bool:
        return self.mode == "live"

    def resolve(self, target_path: str | Path) -> Path:
        """Map an absolute *target* path onto the real filesystem under ``root``.

        ``resolve("/etc/passwd")`` returns ``/etc/passwd`` live, or
        ``<root>/etc/passwd`` for an image.
        """
        p = Path(target_path)
        if p.is_absolute():
            return self.root / p.relative_to("/")
        return self.root / p

    def to_target(self, real_path: str | Path) -> str:
        """Inverse of :meth:`resolve`: map a real on-disk path back to the path
        it represents *on the target* (e.g. ``<root>/etc/passwd`` -> ``/etc/passwd``).
        """
        real = Path(real_path)
        try:
            rel = real.relative_to(self.root).as_posix()
        except ValueError:
            return str(real)
        return "/" if rel == "." else "/" + rel
