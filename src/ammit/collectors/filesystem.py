"""Filesystem collectors.

A single read-only walk over the security-relevant roots produces the mactime
body file that feeds the timeline, plus the derived views investigators reach
for first: SUID/SGID binaries, world-writable paths and recently changed files.
A separate shallow scan looks for hidden files in the world-writable temp dirs.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from ..case import Case
from ..context import ScanContext
from .base import (
    bodyfile_line,
    collector,
    has_sticky,
    is_sgid,
    is_suid,
    is_world_writable,
    iter_tree,
)

RECENT_DAYS = 7
_HIDDEN_SCAN_DIRS = ("/tmp", "/var/tmp", "/dev/shm", "/dev")


@collector(
    "filesystem",
    "filesystem",
    description="MAC-time body file plus SUID/SGID, world-writable and recent-change views.",
    order=40,
)
def collect_filesystem(ctx: ScanContext, case: Case) -> None:
    body: list[str] = []
    suid: list[dict[str, object]] = []
    world_writable: list[dict[str, object]] = []
    recent: list[dict[str, object]] = []
    threshold = ctx.started_at.timestamp() - RECENT_DAYS * 86400

    for entry in iter_tree(ctx):
        st = entry.st
        mode = st.st_mode
        body.append(bodyfile_line(entry.target, st))

        if stat.S_ISREG(mode) and (is_suid(mode) or is_sgid(mode)):
            suid.append(
                {
                    "path": entry.target,
                    "mode": stat.filemode(mode),
                    "uid": st.st_uid,
                    "gid": st.st_gid,
                    "suid": is_suid(mode),
                    "sgid": is_sgid(mode),
                    "size": st.st_size,
                }
            )

        if is_world_writable(mode) and not entry.is_symlink:
            if stat.S_ISDIR(mode) and not has_sticky(mode):
                world_writable.append(
                    {"path": entry.target, "type": "dir", "mode": stat.filemode(mode)}
                )
            elif stat.S_ISREG(mode):
                world_writable.append(
                    {"path": entry.target, "type": "file", "mode": stat.filemode(mode)}
                )

        if max(st.st_mtime, st.st_ctime) >= threshold:
            recent.append(
                {
                    "path": entry.target,
                    "mtime": int(st.st_mtime),
                    "ctime": int(st.st_ctime),
                    "mode": stat.filemode(mode),
                    "uid": st.st_uid,
                }
            )

    case.write_artifact(
        "filesystem",
        "bodyfile.txt",
        "\n".join(body) + ("\n" if body else ""),
        collector="filesystem",
        source="walk of security-relevant roots",
        description="Sleuth Kit mactime body file.",
    )
    case.write_json("filesystem", "suid_sgid.json", suid, collector="filesystem")
    case.write_json("filesystem", "world_writable.json", world_writable, collector="filesystem")

    recent.sort(key=lambda r: max(int(r["mtime"]), int(r["ctime"])), reverse=True)
    case.write_json(
        "filesystem",
        "recent_changes.json",
        recent[:2000],
        collector="filesystem",
        description=f"Entries changed within {RECENT_DAYS} days of collection.",
    )


@collector(
    "hidden_files",
    "filesystem",
    description="Hidden files in world-writable temp directories.",
    order=41,
)
def collect_hidden_files(ctx: ScanContext, case: Case) -> None:
    suspicious: list[dict[str, object]] = []
    for d in _HIDDEN_SCAN_DIRS:
        real = ctx.resolve(d)
        if not real.is_dir():
            continue
        try:
            children = os.scandir(real)
        except OSError:
            continue
        for child in children:
            if not child.name.startswith("."):
                continue
            try:
                st = child.stat(follow_symlinks=False)
            except OSError:
                continue
            suspicious.append(
                {
                    "path": ctx.to_target(Path(child.path)),
                    "name": child.name,
                    "size": st.st_size,
                    "mode": stat.filemode(st.st_mode),
                    "mtime": int(st.st_mtime),
                    "is_dir": stat.S_ISDIR(st.st_mode),
                }
            )
    case.write_json(
        "filesystem",
        "hidden_suspicious.json",
        suspicious,
        collector="hidden_files",
        source=", ".join(_HIDDEN_SCAN_DIRS),
    )
