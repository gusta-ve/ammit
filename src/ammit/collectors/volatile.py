"""Volatile-state collectors — captured first, as they change fastest.

Everything here is parsed from ``/proc`` under the scan root, so it works on the
live host and against any captured ``/proc`` tree (e.g. the test fixture). On a
live host we additionally capture the output of ``ps``/``ss``/``lsmod`` etc. for
the investigator's convenience.
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path

from ..case import Case
from ..commands import have, run_command
from ..context import ScanContext
from .base import collector, safe_read_bytes, safe_read_text

# --- /proc process table -------------------------------------------------------
_DELETED_SUFFIX = " (deleted)"


def _parse_status(path: Path) -> dict[str, object]:
    out: dict[str, object] = {}
    text = safe_read_text(path)
    if not text:
        return out
    for line in text.splitlines():
        key, _, value = line.partition(":")
        value = value.strip()
        if key == "Name":
            out["name"] = value
        elif key == "State":
            out["state"] = value
        elif key == "PPid":
            out["ppid"] = int(value) if value.isdigit() else None
        elif key == "Uid":
            parts = value.split()
            if parts and parts[0].isdigit():
                out["uid"] = int(parts[0])
        elif key == "Gid":
            parts = value.split()
            if parts and parts[0].isdigit():
                out["gid"] = int(parts[0])
    return out


def _read_cmdline(path: Path) -> str:
    data = safe_read_bytes(path)
    if not data:
        return ""
    return data.replace(b"\x00", b" ").decode("utf-8", "replace").strip()


def _read_exe(path: Path) -> tuple[str | None, bool]:
    """Return ``(exe_path, was_deleted)`` for a ``/proc/<pid>/exe`` link."""
    try:
        target = os.readlink(path)
    except OSError:
        return None, False
    if target.endswith(_DELETED_SUFFIX):
        return target[: -len(_DELETED_SUFFIX)], True
    return target, False


def scan_processes(ctx: ScanContext) -> list[dict[str, object]]:
    """Build a process table from ``/proc/<pid>`` directories under the root."""
    procfs = ctx.resolve("/proc")
    procs: list[dict[str, object]] = []
    if not procfs.is_dir():
        return procs
    try:
        entries = list(os.scandir(procfs))
    except OSError:
        return procs
    for entry in entries:
        if not entry.name.isdigit():
            continue
        base = Path(entry.path)
        status = _parse_status(base / "status")
        exe, deleted = _read_exe(base / "exe")
        procs.append(
            {
                "pid": int(entry.name),
                "name": status.get("name"),
                "ppid": status.get("ppid"),
                "uid": status.get("uid"),
                "gid": status.get("gid"),
                "state": status.get("state"),
                "cmdline": _read_cmdline(base / "cmdline"),
                "exe": exe,
                "exe_deleted": deleted,
            }
        )
    procs.sort(key=lambda p: p["pid"])
    return procs


@collector(
    "processes",
    "volatile",
    description="Running processes from /proc, flagging binaries deleted from disk.",
    order=10,
)
def collect_processes(ctx: ScanContext, case: Case) -> None:
    procs = scan_processes(ctx)
    case.write_json(
        "volatile", "processes.json", procs, collector="processes", source="/proc/<pid>"
    )

    deleted = [p for p in procs if p.get("exe_deleted")]
    case.write_json(
        "volatile",
        "deleted_process_binaries.json",
        deleted,
        collector="processes",
        source="/proc/<pid>/exe",
        description="Processes whose executable was unlinked from disk while running.",
    )

    if ctx.is_live and have("ps"):
        _, out = run_command(["ps", "auxww"])
        case.write_artifact(
            "volatile", "ps_auxww.txt", out, collector="processes", source="ps auxww"
        )


# --- network connections from /proc/net ---------------------------------------
_TCP_STATES = {
    0x01: "ESTABLISHED",
    0x02: "SYN_SENT",
    0x03: "SYN_RECV",
    0x04: "FIN_WAIT1",
    0x05: "FIN_WAIT2",
    0x06: "TIME_WAIT",
    0x07: "CLOSE",
    0x08: "CLOSE_WAIT",
    0x09: "LAST_ACK",
    0x0A: "LISTEN",
    0x0B: "CLOSING",
}


def _decode_addr(token: str, ipv6: bool) -> tuple[str, int]:
    addr_hex, port_hex = token.rsplit(":", 1)
    port = int(port_hex, 16)
    raw = bytes.fromhex(addr_hex)
    if ipv6:
        # /proc stores IPv6 as four little-endian 32-bit words.
        raw = b"".join(raw[i : i + 4][::-1] for i in range(0, 16, 4))
        return str(ipaddress.ip_address(raw)), port
    return str(ipaddress.ip_address(raw[::-1])), port


def _parse_proc_net(path: Path, proto: str) -> list[dict[str, object]]:
    text = safe_read_text(path)
    if not text:
        return []
    ipv6 = proto.endswith("6")
    conns: list[dict[str, object]] = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10:
            continue
        try:
            local_ip, local_port = _decode_addr(fields[1], ipv6)
            remote_ip, remote_port = _decode_addr(fields[2], ipv6)
            st = int(fields[3], 16)
        except ValueError:
            continue
        conns.append(
            {
                "proto": proto,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "state": _TCP_STATES.get(st, str(st)) if proto.startswith("tcp") else "-",
                "uid": int(fields[7]) if fields[7].isdigit() else None,
                "inode": fields[9],
            }
        )
    return conns


def _socket_inode_to_pid(ctx: ScanContext) -> dict[str, int]:
    mapping: dict[str, int] = {}
    procfs = ctx.resolve("/proc")
    if not procfs.is_dir():
        return mapping
    try:
        entries = list(os.scandir(procfs))
    except OSError:
        return mapping
    for entry in entries:
        if not entry.name.isdigit():
            continue
        fd_dir = Path(entry.path) / "fd"
        try:
            fds = list(os.scandir(fd_dir))
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(fd.path)
            except OSError:
                continue
            if target.startswith("socket:["):
                mapping[target[len("socket:[") : -1]] = int(entry.name)
    return mapping


@collector(
    "network",
    "volatile",
    description="TCP/UDP connections and listeners parsed from /proc/net.",
    order=12,
)
def collect_network(ctx: ScanContext, case: Case) -> None:
    conns: list[dict[str, object]] = []
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        conns.extend(_parse_proc_net(ctx.resolve(f"/proc/net/{proto}"), proto))

    inode_pid = _socket_inode_to_pid(ctx)
    for c in conns:
        c["pid"] = inode_pid.get(str(c["inode"]))

    case.write_json(
        "volatile",
        "connections.json",
        conns,
        collector="network",
        source="/proc/net/{tcp,tcp6,udp,udp6}",
    )

    if ctx.is_live and have("ss"):
        _, out = run_command(["ss", "-tunaup"])
        case.write_artifact("volatile", "ss.txt", out, collector="network", source="ss -tunaup")


# --- kernel modules ------------------------------------------------------------
@collector(
    "kernel_modules",
    "volatile",
    description="Loaded kernel modules from /proc/modules.",
    order=13,
)
def collect_kernel_modules(ctx: ScanContext, case: Case) -> None:
    text = safe_read_text(ctx.resolve("/proc/modules")) or ""
    modules = []
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        modules.append(
            {
                "name": fields[0],
                "size": int(fields[1]) if len(fields) > 1 and fields[1].isdigit() else None,
                "refcount": int(fields[2]) if len(fields) > 2 and fields[2].isdigit() else None,
                "used_by": fields[3] if len(fields) > 3 and fields[3] != "-" else "",
            }
        )
    case.write_json(
        "volatile",
        "kernel_modules.json",
        modules,
        collector="kernel_modules",
        source="/proc/modules",
    )

    if ctx.is_live and have("lsmod"):
        _, out = run_command(["lsmod"])
        case.write_artifact(
            "volatile", "lsmod.txt", out, collector="kernel_modules", source="lsmod"
        )


# --- logged-in users (live only — utmp is volatile) ---------------------------
@collector(
    "logged_in_users",
    "volatile",
    description="Currently logged-in users (who / w).",
    live_only=True,
    order=14,
)
def collect_logged_in_users(ctx: ScanContext, case: Case) -> None:
    for tool, args in (("who", ["who", "-a"]), ("w", ["w"])):
        if have(tool):
            _, out = run_command(args)
            case.write_artifact(
                "volatile", f"{tool}.txt", out, collector="logged_in_users", source=" ".join(args)
            )
