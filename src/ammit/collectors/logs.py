"""Log collectors: authentication logs, shell histories and journald.

Authentication logs and shell histories are copied verbatim (atime-preserving)
so the triage rules can parse them. Per-user history state is indexed, flagging
the classic anti-forensics move of redirecting history to ``/dev/null``.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from ..case import Case
from ..commands import have, run_command
from ..context import ScanContext
from .base import collector, home_dirs

_AUTH_LOG_PREFIXES = ("auth.log", "secure")
_HISTORY_FILES = (
    ".bash_history",
    ".zsh_history",
    ".sh_history",
    ".ash_history",
    ".history",
    ".python_history",
    ".mysql_history",
)


@collector("auth_logs", "logs", description="Authentication logs (auth.log / secure).", order=50)
def collect_auth_logs(ctx: ScanContext, case: Case) -> None:
    log_dir = ctx.resolve("/var/log")
    copied = 0
    if log_dir.is_dir():
        try:
            children = sorted(os.scandir(log_dir), key=lambda d: d.name)
        except OSError:
            children = []
        for child in children:
            if child.name.startswith(_AUTH_LOG_PREFIXES) and child.is_file(follow_symlinks=False):
                art = case.copy_artifact(
                    "logs", Path(child.path), f"var/log/{child.name}", collector="auth_logs"
                )
                copied += art is not None
    case.log(f"auth_logs: copied {copied} authentication log file(s)", level="INFO")

    if ctx.is_live and have("journalctl"):
        _, out = run_command(
            ["journalctl", "--no-pager", "-o", "short-iso", "_COMM=sshd", "-n", "5000"]
        )
        case.write_artifact(
            "logs", "journal_sshd.txt", out, collector="auth_logs", source="journalctl _COMM=sshd"
        )


@collector(
    "shell_history", "logs", description="Per-user shell history (+ tamper detection).", order=51
)
def collect_shell_history(ctx: ScanContext, case: Case) -> None:
    index: list[dict[str, object]] = []
    for user, home in home_dirs(ctx):
        for fname in _HISTORY_FILES:
            target = f"{home}/{fname}"
            real = ctx.resolve(target)
            if not (real.is_file() or real.is_symlink()):
                continue
            try:
                st = real.lstat()
            except OSError:
                continue
            symlink_to = os.readlink(real) if stat.S_ISLNK(st.st_mode) else None
            entry: dict[str, object] = {
                "user": user,
                "file": target,
                "size": st.st_size,
                "mtime": int(st.st_mtime),
                "symlink_to": symlink_to,
                "neutralized": symlink_to == "/dev/null" or (not symlink_to and st.st_size == 0),
            }
            index.append(entry)
            if symlink_to is None:
                case.copy_artifact(
                    "logs",
                    real,
                    f"history/{user}/{fname}",
                    collector="shell_history",
                    description=f"{user}'s {fname}",
                )
    case.write_json(
        "logs",
        "shell_history_index.json",
        index,
        collector="shell_history",
        source="~/.<shell>_history",
    )


@collector(
    "journald", "logs", description="Recent journald entries (live only).", live_only=True, order=52
)
def collect_journald(ctx: ScanContext, case: Case) -> None:
    if not have("journalctl"):
        return
    _, out = run_command(["journalctl", "--no-pager", "-o", "short-iso", "-n", "5000"])
    case.write_artifact(
        "logs", "journal_recent.txt", out, collector="journald", source="journalctl -n 5000"
    )
