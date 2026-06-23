"""Thin, safe wrappers for capturing the output of system commands.

These are only ever used to *enrich* a live collection (e.g. ``ss``, ``ps``).
Commands are run without a shell, with a timeout, and never raise: a failure is
captured as text so it lands in the evidence rather than aborting the run.
"""

from __future__ import annotations

import shutil
import subprocess


def have(command: str) -> bool:
    """True if ``command`` is on PATH."""
    return shutil.which(command) is not None


def run_command(args: list[str], *, timeout: int = 60) -> tuple[int, str]:
    """Run ``args`` (no shell), returning ``(returncode, combined_output)``.

    Never raises. On failure the return code is ``-1`` and the output explains
    what went wrong, so the result is always safe to record as an artifact.
    """
    try:
        proc = subprocess.run(  # noqa: S603 - args is a fixed list, never shell
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return -1, f"[ammit] failed to run {' '.join(args)}: {exc}\n"
    out = proc.stdout or ""
    if proc.stderr:
        out += f"\n[stderr]\n{proc.stderr}"
    return proc.returncode, out
