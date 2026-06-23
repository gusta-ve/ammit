"""Shared Rich consoles and theme for Ammit's output."""

from __future__ import annotations

from rich.console import Console
from rich.theme import Theme

AMMIT_THEME = Theme(
    {
        "verdict.clean": "bold green",
        "verdict.suspicious": "bold yellow",
        "verdict.compromised": "bold white on red",
        "sev.info": "dim cyan",
        "sev.low": "cyan",
        "sev.medium": "yellow",
        "sev.high": "bold orange3",
        "sev.critical": "bold red",
        "info": "cyan",
        "warn": "yellow",
        "err": "bold red",
        "muted": "dim",
        "accent": "magenta",
    }
)

# stdout: machine-readable data and primary output.
console = Console(theme=AMMIT_THEME, highlight=False)
# stderr: progress, warnings, diagnostics — never pollutes piped stdout.
err_console = Console(stderr=True, theme=AMMIT_THEME, highlight=False)
