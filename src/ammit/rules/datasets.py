"""Datasets: the bridge between collected artifacts and the rule engine.

Each *dataset* is a flat ``list[dict]`` built lazily from the JSON (and copied
files) a :class:`~ammit.case.Case` left behind. Builders also *enrich* records
with derived fields (e.g. ``port_suspicious`` on a connection, ``indicator`` on
a cron line) so the YAML rules can stay declarative and readable.

The rule engine only ever sees these dictionaries — it never touches the case
layout — which keeps rules decoupled from collector internals.
"""

from __future__ import annotations

import gzip
import ipaddress
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

# Ports commonly used by reverse/bind shells, miners and C2 frameworks.
SUSPICIOUS_PORTS: frozenset[int] = frozenset(
    {1234, 1337, 2323, 4444, 4445, 5555, 6666, 6667, 9001, 12345, 31337}
)

# Tokens that betray a command spawned for download-and-execute, reverse shells,
# in-memory staging or privilege escalation. Shared by the cron and systemd
# datasets. Kept deliberately specific so legitimate scripts rarely trip it.
_SUSPICIOUS_CMD = re.compile(
    r"""(
        curl | wget |                      # download
        /dev/shm | /tmp/ |                 # world-writable staging
        base64\s+-d | base64\s+--decode |  # decode-and-run
        \bn(?:c|cat)\b | \bsocat\b |       # netcat / socat
        bash\s+-i | sh\s+-i |              # interactive reverse shell
        /dev/tcp/ | /dev/udp/ |            # bash pseudo-device networking
        \bmkfifo\b |                       # named-pipe reverse shell
        chmod\s+[0-7]*[+]?s |              # set SUID
        python[0-9.]*\s+-c | perl\s+-e |   # inline interpreters
        \bxmrig\b                          # known miner
    )""",
    re.IGNORECASE | re.VERBOSE,
)

# Cron schedule prefix: five time fields or an @nickname, then the command.
_CRON_SCHED = re.compile(r"^\s*(?:@\w+|[\d*/,\-]+(?:\s+[\d*/,\-]+){4})\s+(.*)$")
# Environment assignment lines in a crontab (PATH=, MAILTO=, SHELL=…).
_CRON_ENV = re.compile(r"^[A-Z_][A-Z0-9_]*\s*=")

_EXEC_KEYS = ("ExecStart=", "ExecStartPre=", "ExecStartPost=", "ExecStopPost=")

# auth.log timestamp formats → capture the hour.
_TS_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}[T ](\d{2}):\d{2}:\d{2}")
_TS_SYSLOG = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+(\d{2}):\d{2}:\d{2}")
_AUTH_FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)")
_AUTH_ACCEPTED = re.compile(
    r"Accepted (password|publickey) for (?:invalid user )?(\S+) from (\S+) port (\d+)"
)

# Benign sockets/dirs that always live in /tmp — not worth flagging as hidden.
_HIDDEN_BENIGN = frozenset(
    {".X11-unix", ".ICE-unix", ".XIM-unix", ".font-unix", ".Test-unix", ".Xor-unix"}
)

# SUID/SGID binaries are expected only under these system prefixes.
_SUID_SYSTEM_DIRS = (
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/usr/lib/",
    "/usr/libexec/",
    "/lib/",
    "/lib64/",
    "/usr/lib64/",
    "/opt/",
)

_NOLOGIN_SHELLS = frozenset(
    {"/bin/false", "/usr/bin/false", "/sbin/nologin", "/usr/sbin/nologin", "/bin/nologin"}
)


def _hour_of(line: str) -> int | None:
    m = _TS_ISO.match(line) or _TS_SYSLOG.match(line)
    return int(m.group(1)) if m else None


def _is_external(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_multicast
        or addr.is_reserved
    )


def _indicator(text: str) -> str | None:
    m = _SUSPICIOUS_CMD.search(text)
    return m.group(0).strip() if m else None


class Datasets:
    """Lazily builds and caches enriched datasets from a collected case."""

    def __init__(self, case_dir: str | Path, *, baseline: dict[str, Any] | None = None) -> None:
        self.case_dir = Path(case_dir)
        self.artifacts = self.case_dir / "artifacts"
        self.baseline = baseline or {}
        self._cache: dict[str, list[dict[str, Any]]] = {}
        self._builders: dict[str, Callable[[], list[dict[str, Any]]]] = {
            "processes": self._ds_processes,
            "deleted_binaries": self._ds_deleted_binaries,
            "connections": self._ds_connections,
            "uid0_accounts": self._ds_uid0_accounts,
            "authorized_keys": self._ds_authorized_keys,
            "suid_sgid": self._ds_suid_sgid,
            "hidden_suspicious": self._ds_hidden_suspicious,
            "shell_history": self._ds_shell_history,
            "init_hooks": self._ds_init_hooks,
            "cron_entries": self._ds_cron_entries,
            "systemd_admin": self._ds_systemd_admin,
            "auth_events": self._ds_auth_events,
        }

    def get(self, name: str) -> list[dict[str, Any]]:
        if name not in self._cache:
            build = self._builders.get(name)
            if build is None:
                raise ValueError(f"unknown dataset: {name!r}")
            self._cache[name] = build()
        return self._cache[name]

    # -- low-level loading -----------------------------------------------------
    def _load(self, *rel: str, default: Any = None) -> Any:
        path = self.artifacts.joinpath(*rel)
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default if default is not None else []

    @staticmethod
    def _read_text(path: Path) -> str:
        try:
            if path.suffix == ".gz":
                with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
                    return fh.read()
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    # -- volatile --------------------------------------------------------------
    def _ds_processes(self) -> list[dict[str, Any]]:
        return self._load("volatile", "processes.json")

    def _ds_deleted_binaries(self) -> list[dict[str, Any]]:
        return self._load("volatile", "deleted_process_binaries.json")

    def _ds_connections(self) -> list[dict[str, Any]]:
        conns = self._load("volatile", "connections.json")
        for c in conns:
            lp, rp = c.get("local_port"), c.get("remote_port")
            c["port_suspicious"] = lp in SUSPICIOUS_PORTS or rp in SUSPICIOUS_PORTS
            c["remote_external"] = bool(c.get("remote_ip")) and _is_external(str(c["remote_ip"]))
        return conns

    # -- accounts --------------------------------------------------------------
    def _ds_uid0_accounts(self) -> list[dict[str, Any]]:
        return self._load("accounts", "uid0_accounts.json")

    def _ds_authorized_keys(self) -> list[dict[str, Any]]:
        by_user = self._load("persistence", "authorized_keys.json", default={})
        shells = {u.get("name"): u.get("shell") for u in self._load("accounts", "passwd.json")}
        flat: list[dict[str, Any]] = []
        for user, keys in by_user.items():
            shell = shells.get(user)
            for key in keys:
                key = dict(key)
                key.setdefault("user", user)
                key["shell"] = shell
                key["shell_nologin"] = bool(shell) and (
                    shell in _NOLOGIN_SHELLS or shell.endswith("nologin")
                )
                flat.append(key)
        return flat

    # -- filesystem ------------------------------------------------------------
    def _ds_suid_sgid(self) -> list[dict[str, Any]]:
        rows = self._load("filesystem", "suid_sgid.json")
        for r in rows:
            path = str(r.get("path", ""))
            r["standard_location"] = any(path.startswith(p) for p in _SUID_SYSTEM_DIRS)
        return rows

    def _ds_hidden_suspicious(self) -> list[dict[str, Any]]:
        rows = self._load("filesystem", "hidden_suspicious.json")
        for r in rows:
            r["benign"] = r.get("name") in _HIDDEN_BENIGN
            r["executable"] = "x" in str(r.get("mode", ""))
        return rows

    # -- logs ------------------------------------------------------------------
    def _ds_shell_history(self) -> list[dict[str, Any]]:
        return self._load("logs", "shell_history_index.json")

    # -- persistence -----------------------------------------------------------
    def _ds_init_hooks(self) -> list[dict[str, Any]]:
        return self._load("persistence", "init_hooks_index.json")

    def _ds_cron_entries(self) -> list[dict[str, Any]]:
        index = self._load("persistence", "cron_index.json")
        entries: list[dict[str, Any]] = []
        for item in index:
            if not item.get("copied"):
                continue
            source = str(item.get("source", ""))
            copied = self.artifacts / "persistence" / "cron" / source.lstrip("/")
            for raw in self._read_text(copied).splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or _CRON_ENV.match(line):
                    continue
                sched = _CRON_SCHED.match(line)
                command = sched.group(1) if sched else line
                reason = _indicator(line)
                entries.append(
                    {
                        "source": source,
                        "line": line,
                        "command": command,
                        "indicator": reason,
                        "mtime": item.get("mtime"),
                    }
                )
        return entries

    def _ds_systemd_admin(self) -> list[dict[str, Any]]:
        units = self._load("persistence", "systemd_units.json", default={})
        rows: list[dict[str, Any]] = []
        for item in units.get("admin", []):
            source = str(item.get("source", ""))
            copied = self.artifacts / "persistence" / "systemd" / source.lstrip("/")
            execs: list[str] = []
            for raw in self._read_text(copied).splitlines():
                line = raw.strip()
                if line.startswith(_EXEC_KEYS):
                    execs.append(line.split("=", 1)[1].strip())
            exec_start = " ; ".join(e for e in execs if e)
            rows.append(
                {
                    "unit": Path(source).name,
                    "source": source,
                    "exec_start": exec_start,
                    "indicator": _indicator(exec_start),
                    "mtime": item.get("mtime"),
                    "sha256": item.get("sha256"),
                }
            )
        return rows

    def _ds_auth_events(self) -> list[dict[str, Any]]:
        log_dir = self.artifacts / "logs" / "var" / "log"
        events: list[dict[str, Any]] = []
        if not log_dir.is_dir():
            return events
        for path in sorted(log_dir.iterdir()):
            if not path.name.startswith(("auth.log", "secure")):
                continue
            for line in self._read_text(path).splitlines():
                event = self._parse_auth_line(line, path.name)
                if event:
                    events.append(event)
        return events

    @staticmethod
    def _parse_auth_line(line: str, log: str) -> dict[str, Any] | None:
        failed = _AUTH_FAILED.search(line)
        accepted = _AUTH_ACCEPTED.search(line)
        if failed:
            event, user, ip, port = "failed_password", failed[1], failed[2], failed[3]
        elif accepted:
            event = f"accepted_{accepted[1]}"
            user, ip, port = accepted[2], accepted[3], accepted[4]
        else:
            return None
        hour = _hour_of(line)
        return {
            "event": event,
            "user": user,
            "source_ip": ip,
            "port": int(port),
            "hour": hour,
            "off_hours": hour is not None and (hour < 6 or hour >= 22),
            "log": log,
        }
