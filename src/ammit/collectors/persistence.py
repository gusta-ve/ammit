"""Persistence collectors: the places attackers plant themselves to survive a
reboot — cron, systemd units/timers, SSH keys, init hooks and ``at`` jobs.

Originals are copied into the case (atime-preserving) and indexed with their
timestamps so triage can spot recently-planted persistence.
"""

from __future__ import annotations

import base64
import hashlib
import os
import stat
from pathlib import Path

from ..case import Case
from ..commands import have, run_command
from ..context import ScanContext
from .base import collector, home_dirs, iter_tree, safe_read_text


def _files_in(ctx: ScanContext, target: str, *, recursive: bool) -> list[tuple[str, Path]]:
    """Resolve ``target`` to a list of ``(target_path, real_path)`` files."""
    real = ctx.resolve(target)
    out: list[tuple[str, Path]] = []
    if real.is_symlink() or real.is_file():
        out.append((target, real))
    elif real.is_dir():
        if recursive:
            out.extend((e.target, e.real) for e in iter_tree(ctx, (target,)) if not e.is_dir)
        else:
            try:
                children = sorted(os.scandir(real), key=lambda d: d.name)
            except OSError:
                return out
            for child in children:
                p = Path(child.path)
                if child.is_file(follow_symlinks=False) or child.is_symlink():
                    out.append((ctx.to_target(p), p))
    return out


def _index_file(
    ctx: ScanContext, case: Case, target: str, real: Path, *, subdir: str, collector_name: str
) -> dict[str, object] | None:
    try:
        st = real.lstat()
    except OSError:
        return None
    rel = target.lstrip("/")
    entry: dict[str, object] = {
        "source": target,
        "mtime": int(st.st_mtime),
        "ctime": int(st.st_ctime),
        "size": st.st_size,
        "mode": stat.filemode(st.st_mode),
        "uid": st.st_uid,
    }
    if stat.S_ISLNK(st.st_mode):
        try:
            entry["symlink_to"] = os.readlink(real)
        except OSError:
            entry["symlink_to"] = None
        return entry
    art = case.copy_artifact(
        "persistence",
        real,
        f"{subdir}/{rel}",
        collector=collector_name,
        description=f"from {target}",
    )
    entry["sha256"] = art.sha256 if art else None
    entry["copied"] = art is not None
    return entry


# --- cron ----------------------------------------------------------------------
_CRON_TARGETS = (
    "/etc/crontab",
    "/etc/anacrontab",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron/crontabs",
    "/var/spool/cron",
)


@collector("cron", "persistence", description="System and per-user cron jobs.", order=20)
def collect_cron(ctx: ScanContext, case: Case) -> None:
    index = []
    for target in _CRON_TARGETS:
        for tpath, real in _files_in(ctx, target, recursive=False):
            entry = _index_file(ctx, case, tpath, real, subdir="cron", collector_name="cron")
            if entry:
                index.append(entry)
    case.write_json(
        "persistence", "cron_index.json", index, collector="cron", source=", ".join(_CRON_TARGETS)
    )


# --- systemd -------------------------------------------------------------------
_SYSTEMD_ADMIN = ("/etc/systemd/system", "/etc/systemd/user")
_SYSTEMD_VENDOR = ("/lib/systemd/system", "/usr/lib/systemd/system")
_UNIT_SUFFIXES = (".service", ".timer", ".socket", ".path", ".mount")


@collector(
    "systemd", "persistence", description="systemd units and timers (admin units copied).", order=21
)
def collect_systemd(ctx: ScanContext, case: Case) -> None:
    admin = []
    for base_target in _SYSTEMD_ADMIN:
        for tpath, real in _files_in(ctx, base_target, recursive=True):
            if tpath.endswith(_UNIT_SUFFIXES):
                entry = _index_file(
                    ctx, case, tpath, real, subdir="systemd", collector_name="systemd"
                )
                if entry:
                    admin.append(entry)

    vendor = []
    for base_target in _SYSTEMD_VENDOR:
        for e in iter_tree(ctx, (base_target,)):
            if not e.is_dir and e.target.endswith((".service", ".timer")):
                vendor.append(
                    {"source": e.target, "mtime": int(e.st.st_mtime), "ctime": int(e.st.st_ctime)}
                )

    case.write_json(
        "persistence",
        "systemd_units.json",
        {"admin": admin, "vendor": vendor},
        collector="systemd",
        source=", ".join(_SYSTEMD_ADMIN + _SYSTEMD_VENDOR),
    )

    if ctx.is_live and have("systemctl"):
        for name, args in (
            ("systemd_timers.txt", ["systemctl", "list-timers", "--all", "--no-pager"]),
            (
                "systemd_enabled.txt",
                ["systemctl", "list-unit-files", "--state=enabled", "--no-pager"],
            ),
        ):
            _, out = run_command(args)
            case.write_artifact(
                "persistence", name, out, collector="systemd", source=" ".join(args)
            )


# --- SSH authorized_keys -------------------------------------------------------
def _key_fingerprint(b64blob: str) -> str | None:
    try:
        raw = base64.b64decode(b64blob, validate=True)
    except Exception:  # malformed base64 (binascii.Error subclasses ValueError)
        return None
    digest = hashlib.sha256(raw).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def _parse_authorized_key(line: str) -> dict[str, object] | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split()
    for i, tok in enumerate(parts):
        if tok.startswith(("ssh-", "ecdsa-", "sk-")):
            b64 = parts[i + 1] if i + 1 < len(parts) else ""
            comment = " ".join(parts[i + 2 :]) if i + 2 < len(parts) else ""
            return {
                "type": tok,
                "fingerprint": _key_fingerprint(b64),
                "comment": comment,
                "options": " ".join(parts[:i]),
            }
    return None


@collector("ssh_keys", "persistence", description="SSH authorized_keys per user.", order=22)
def collect_ssh_keys(ctx: ScanContext, case: Case) -> None:
    result: dict[str, list[dict[str, object]]] = {}
    for user, home in home_dirs(ctx):
        for fname in ("authorized_keys", "authorized_keys2"):
            target = f"{home}/.ssh/{fname}"
            real = ctx.resolve(target)
            text = safe_read_text(real)
            if text is None:
                continue
            keys = [k for k in (_parse_authorized_key(line) for line in text.splitlines()) if k]
            for k in keys:
                k["user"] = user
                k["file"] = target
            result.setdefault(user, []).extend(keys)
            case.copy_artifact(
                "persistence",
                real,
                f"ssh/{target.lstrip('/')}",
                collector="ssh_keys",
                description=f"{user}'s {fname}",
            )
    case.write_json(
        "persistence",
        "authorized_keys.json",
        result,
        collector="ssh_keys",
        source="~/.ssh/authorized_keys",
    )


# --- init hooks: rc.local, profile.d, ld.so.preload ---------------------------
_INIT_TARGETS = (
    "/etc/rc.local",
    "/etc/profile",
    "/etc/profile.d",
    "/etc/bash.bashrc",
    "/etc/ld.so.preload",
    "/etc/ld.so.conf",
)


@collector(
    "init_hooks",
    "persistence",
    description="rc.local, profile.d and the dynamic-linker preload.",
    order=23,
)
def collect_init_hooks(ctx: ScanContext, case: Case) -> None:
    index = []
    for target in _INIT_TARGETS:
        for tpath, real in _files_in(ctx, target, recursive=False):
            entry = _index_file(ctx, case, tpath, real, subdir="init", collector_name="init_hooks")
            if entry:
                index.append(entry)
    case.write_json(
        "persistence",
        "init_hooks_index.json",
        index,
        collector="init_hooks",
        source=", ".join(_INIT_TARGETS),
    )


# --- at jobs -------------------------------------------------------------------
_AT_TARGETS = ("/var/spool/cron/atjobs", "/var/spool/at", "/var/spool/atjobs")


@collector("at_jobs", "persistence", description="Scheduled `at` jobs.", order=24)
def collect_at_jobs(ctx: ScanContext, case: Case) -> None:
    index = []
    for target in _AT_TARGETS:
        for tpath, real in _files_in(ctx, target, recursive=False):
            entry = _index_file(ctx, case, tpath, real, subdir="at", collector_name="at_jobs")
            if entry:
                index.append(entry)
    case.write_json(
        "persistence",
        "at_jobs_index.json",
        index,
        collector="at_jobs",
        source=", ".join(_AT_TARGETS),
    )
