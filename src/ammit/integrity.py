"""Cryptographic integrity helpers.

Every artifact Ammit records is hashed with SHA-256. When reading from a live
target we open files with ``O_NOATIME`` where possible so that hashing evidence
does not perturb its access time — falling back to a normal read when the kernel
or permissions disallow it.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

_CHUNK = 1024 * 1024  # 1 MiB

# O_NOATIME is Linux-specific; 0 is a no-op everywhere else.
_O_NOATIME = getattr(os, "O_NOATIME", 0)


def _open_ro(path: str | os.PathLike[str]) -> int:
    """Open ``path`` read-only, preferring ``O_NOATIME`` to preserve atime."""
    fspath = os.fspath(path)
    if _O_NOATIME:
        try:
            return os.open(fspath, os.O_RDONLY | _O_NOATIME)
        except OSError:
            # Not the owner / unsupported fs — fall back to a normal read.
            pass
    return os.open(fspath, os.O_RDONLY)


def sha256_bytes(data: bytes) -> str:
    """SHA-256 hex digest of an in-memory buffer."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    """SHA-256 hex digest of a file, read in chunks without following atime."""
    h = hashlib.sha256()
    fd = _open_ro(path)
    with os.fdopen(fd, "rb", closefd=True) as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def copy_noatime(src: str | Path, dest: str | Path) -> int:
    """Copy ``src`` to ``dest`` without disturbing ``src``'s access time.

    Returns the number of bytes copied. Only the source is read with
    ``O_NOATIME``; the destination lives inside the (writable) case folder.
    """
    fd = _open_ro(src)
    size = 0
    with os.fdopen(fd, "rb", closefd=True) as fsrc, open(dest, "wb") as fdst:
        for chunk in iter(lambda: fsrc.read(_CHUNK), b""):
            fdst.write(chunk)
            size += len(chunk)
    return size
