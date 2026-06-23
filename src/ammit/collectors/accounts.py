"""Account collectors: users, password metadata, sudo rights, duplicate UID 0
and login history.

Password *hashes* are deliberately never copied — only metadata (whether a
password is set, the hashing scheme, ageing fields) is recorded from
``/etc/shadow``.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..case import Case
from ..commands import have, run_command
from ..context import ScanContext
from .base import collector, parse_passwd, safe_read_text


def _int_or_none(value: str) -> int | None:
    return int(value) if value.lstrip("-").isdigit() else None


def _shadow_algorithm(h: str) -> str | None:
    return {
        "$6$": "sha512crypt",
        "$y$": "yescrypt",
        "$gy": "gost-yescrypt",
        "$7$": "scrypt",
        "$2a": "bcrypt",
        "$2b": "bcrypt",
        "$2y": "bcrypt",
        "$5$": "sha256crypt",
        "$1$": "md5crypt",
    }.get(h[:3])


def _shadow_meta(line: str) -> dict[str, object] | None:
    f = line.split(":")
    if len(f) < 2 or not f[0]:
        return None
    h = f[1]
    locked = h.startswith(("!", "*")) or h == ""
    return {
        "name": f[0],
        "has_password": bool(h) and not h.startswith(("!", "*")),
        "locked": locked,
        "algorithm": _shadow_algorithm(h) if not locked else None,
        "last_change_days": _int_or_none(f[2]) if len(f) > 2 else None,
        "max_age_days": _int_or_none(f[4]) if len(f) > 4 else None,
        "expire_days": _int_or_none(f[7]) if len(f) > 7 else None,
    }


@collector(
    "accounts", "accounts", description="Users, password metadata and duplicate UID 0.", order=30
)
def collect_accounts(ctx: ScanContext, case: Case) -> None:
    users = parse_passwd(ctx)
    case.write_json("accounts", "passwd.json", users, collector="accounts", source="/etc/passwd")
    case.copy_artifact("accounts", ctx.resolve("/etc/passwd"), "etc/passwd", collector="accounts")
    case.copy_artifact("accounts", ctx.resolve("/etc/group"), "etc/group", collector="accounts")

    # Duplicate UID 0 — any non-root account with uid 0 is a backdoor.
    uid0 = [u for u in users if u["uid"] == 0]
    case.write_json(
        "accounts",
        "uid0_accounts.json",
        uid0,
        collector="accounts",
        source="/etc/passwd",
        description="Accounts with UID 0 (more than one => suspicious).",
    )

    # Shadow metadata only — never the hashes themselves.
    shadow = safe_read_text(ctx.resolve("/etc/shadow"))
    if shadow is not None:
        meta = [m for m in (_shadow_meta(line) for line in shadow.splitlines() if line) if m]
        case.write_json(
            "accounts",
            "shadow_meta.json",
            meta,
            collector="accounts",
            source="/etc/shadow",
            description="Password metadata only; hashes intentionally excluded.",
        )


@collector("sudoers", "accounts", description="sudoers policy files.", order=31)
def collect_sudoers(ctx: ScanContext, case: Case) -> None:
    case.copy_artifact(
        "accounts", ctx.resolve("/etc/sudoers"), "sudoers/sudoers", collector="sudoers"
    )
    sudoers_d = ctx.resolve("/etc/sudoers.d")
    if sudoers_d.is_dir():
        try:
            children = sorted(os.scandir(sudoers_d), key=lambda d: d.name)
        except OSError:
            children = []
        for child in children:
            if child.is_file(follow_symlinks=False):
                case.copy_artifact(
                    "accounts",
                    Path(child.path),
                    f"sudoers/sudoers.d/{child.name}",
                    collector="sudoers",
                )


@collector(
    "login_history", "accounts", description="utmp/wtmp/btmp and last/lastb output.", order=32
)
def collect_login_history(ctx: ScanContext, case: Case) -> None:
    for target in ("/var/log/wtmp", "/var/log/btmp", "/var/run/utmp", "/run/utmp"):
        real = ctx.resolve(target)
        if real.is_file():
            case.copy_artifact(
                "accounts",
                real,
                f"loginlog/{target.lstrip('/')}",
                collector="login_history",
                description="binary accounting file (parse with `last`/`utmpdump`)",
            )

    if ctx.is_live:
        if have("last"):
            _, out = run_command(["last", "-Faiwx"])
            case.write_artifact(
                "accounts", "last.txt", out, collector="login_history", source="last -Faiwx"
            )
        if have("lastb"):
            _, out = run_command(["lastb", "-Faiwx"])
            case.write_artifact(
                "accounts", "lastb.txt", out, collector="login_history", source="lastb -Faiwx"
            )
