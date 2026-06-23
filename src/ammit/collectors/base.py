"""Shared scaffolding for collectors: a registry, a read-only filesystem walker,
and small stat/bodyfile helpers.

Collectors register themselves with :func:`collector`. The ``collect`` command
discovers them via :func:`all_collectors` and runs them in ``order`` — lowest
first, honouring the order of volatility.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from ..case import Case
from ..context import ScanContext

CollectorFn = Callable[[ScanContext, Case], None]

# Pseudo / volatile filesystems we never descend into during a tree walk.
EXCLUDE_PATHS = frozenset({"/proc", "/sys", "/dev", "/run"})

# Security-relevant roots scanned by default for the filesystem inventory.
DEFAULT_SCAN_ROOTS: tuple[str, ...] = (
    "/etc",
    "/root",
    "/home",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local",
    "/opt",
    "/srv",
    "/var/www",
    "/var/spool",
    "/lib/systemd",
    "/usr/lib/systemd",
)

_REGISTRY: list[Collector] = []


@dataclass(frozen=True)
class Collector:
    """Metadata + entry point for one artifact collector."""

    name: str
    category: str
    run: CollectorFn
    description: str = ""
    live_only: bool = False
    order: int = 100


def collector(
    name: str,
    category: str,
    *,
    description: str = "",
    live_only: bool = False,
    order: int = 100,
) -> Callable[[CollectorFn], CollectorFn]:
    """Decorator registering a collector function ``(ctx, case) -> None``."""

    def decorate(fn: CollectorFn) -> CollectorFn:
        _REGISTRY.append(
            Collector(
                name=name,
                category=category,
                run=fn,
                description=description,
                live_only=live_only,
                order=order,
            )
        )
        return fn

    return decorate


def all_collectors() -> list[Collector]:
    """All registered collectors, ordered by volatility then name."""
    return sorted(_REGISTRY, key=lambda c: (c.order, c.name))


# --- filesystem traversal ------------------------------------------------------
@dataclass
class Entry:
    """One filesystem entry, with its path on the target and its ``lstat``."""

    target: str  # path as it appears on the target, e.g. /etc/passwd
    real: Path  # actual path on disk (under ctx.root)
    st: os.stat_result  # lstat() — symlinks are never followed
    is_dir: bool
    is_symlink: bool


def iter_tree(
    ctx: ScanContext,
    start_targets: tuple[str, ...] = DEFAULT_SCAN_ROOTS,
    *,
    exclude: frozenset[str] = EXCLUDE_PATHS,
    max_entries: int = 400_000,
) -> Iterator[Entry]:
    """Walk the target read-only, yielding :class:`Entry` for every node.

    Symlinks are never followed; pseudo-filesystems are skipped; permission
    errors are ignored; traversal is bounded by ``max_entries``.
    """
    count = 0

    def emit(real: Path) -> Iterator[Entry]:
        nonlocal count
        try:
            st = real.lstat()
        except OSError:
            return
        count += 1
        yield Entry(
            target=ctx.to_target(real),
            real=real,
            st=st,
            is_dir=stat.S_ISDIR(st.st_mode),
            is_symlink=stat.S_ISLNK(st.st_mode),
        )

    def walk(real: Path) -> Iterator[Entry]:
        nonlocal count
        try:
            scan = list(os.scandir(real))
        except OSError:
            return
        for de in scan:
            if count >= max_entries:
                return
            child = Path(de.path)
            try:
                st = de.stat(follow_symlinks=False)
            except OSError:
                continue
            count += 1
            is_dir = stat.S_ISDIR(st.st_mode)
            yield Entry(
                target=ctx.to_target(child),
                real=child,
                st=st,
                is_dir=is_dir,
                is_symlink=stat.S_ISLNK(st.st_mode),
            )
            if is_dir and ctx.to_target(child) not in exclude:
                yield from walk(child)

    for target in start_targets:
        real = ctx.resolve(target)
        if not real.exists():
            continue
        yield from emit(real)
        if real.is_dir():
            yield from walk(real)


# --- stat / bodyfile helpers ---------------------------------------------------
def is_suid(mode: int) -> bool:
    return bool(mode & stat.S_ISUID)


def is_sgid(mode: int) -> bool:
    return bool(mode & stat.S_ISGID)


def is_world_writable(mode: int) -> bool:
    return bool(mode & stat.S_IWOTH)


def has_sticky(mode: int) -> bool:
    return bool(mode & stat.S_ISVTX)


def bodyfile_line(target: str, st: os.stat_result, md5: str = "0") -> str:
    """A Sleuth Kit ``mactime`` body-file line for one filesystem entry.

    Fields: ``md5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime``.
    Linux does not expose a birth time via ``os.lstat``, so ``crtime`` is ``0``.
    """
    return "|".join(
        [
            md5,
            target,
            str(st.st_ino),
            stat.filemode(st.st_mode),
            str(st.st_uid),
            str(st.st_gid),
            str(st.st_size),
            str(int(st.st_atime)),
            str(int(st.st_mtime)),
            str(int(st.st_ctime)),
            "0",
        ]
    )


# --- safe reads ----------------------------------------------------------------
def safe_read_bytes(path: str | Path, *, limit: int | None = None) -> bytes | None:
    """Read bytes, returning ``None`` on any OS error. Optionally truncated."""
    try:
        with open(path, "rb") as fh:
            return fh.read(limit) if limit is not None else fh.read()
    except OSError:
        return None


def safe_read_text(path: str | Path, *, limit: int | None = None) -> str | None:
    """Read text (utf-8, lossy), returning ``None`` on any OS error."""
    data = safe_read_bytes(path, limit=limit)
    return None if data is None else data.decode("utf-8", "replace")


# --- account helpers (shared by several collectors) ---------------------------
_PSEUDO_HOMES = frozenset({"/", "/nonexistent", "/dev/null", "", "/bin", "/sbin"})


def parse_passwd(ctx: ScanContext) -> list[dict[str, object]]:
    """Parse ``/etc/passwd`` under the root into structured records."""
    text = safe_read_text(ctx.resolve("/etc/passwd")) or ""
    users: list[dict[str, object]] = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        f = line.split(":")
        if len(f) < 7:
            continue
        users.append(
            {
                "name": f[0],
                "uid": int(f[2]) if f[2].isdigit() else None,
                "gid": int(f[3]) if f[3].isdigit() else None,
                "gecos": f[4],
                "home": f[5],
                "shell": f[6],
            }
        )
    return users


def home_dirs(ctx: ScanContext) -> list[tuple[str, str]]:
    """Return ``(user, home)`` for real home directories, root always included."""
    homes: dict[str, str] = {}
    for user in parse_passwd(ctx):
        home = str(user["home"])
        if home.startswith("/") and home not in _PSEUDO_HOMES:
            homes.setdefault(home, str(user["name"]))
    homes.setdefault("/root", "root")
    return [(user, home) for home, user in homes.items()]
