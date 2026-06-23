"""Orchestration for ``ammit collect``: build a scan context, run every
registered collector in order of volatility, and seal the case.
"""

from __future__ import annotations

from pathlib import Path

from rich.table import Table

from .case import Case

# Importing the collector packages registers their collectors as a side effect.
from .collectors import (  # noqa: F401
    accounts,
    filesystem,
    logs,
    persistence,
    volatile,
)
from .collectors.base import all_collectors
from .console import err_console
from .context import ScanContext


def build_context(root: Path, *, authorized: bool) -> ScanContext:
    """Live context when ``root`` is ``/``, otherwise a read-only image context."""
    if root == Path("/"):
        return ScanContext.live(authorized=authorized)
    return ScanContext.image(root.resolve())


def run_collection(ctx: ScanContext, output_dir: Path, *, label: str | None = None) -> Case:
    """Create a case and run all applicable collectors into it."""
    case = Case.create(output_dir, ctx, label=label)
    for collector in all_collectors():
        if collector.live_only and not ctx.is_live:
            case.log(
                f"collector '{collector.name}' skipped (live-only, mode={ctx.mode})",
                level="SKIP",
            )
            continue
        err_console.print(
            f"[muted]·[/muted] {collector.category}/[accent]{collector.name}[/accent]"
        )
        with case.collector_run(collector.name):
            collector.run(ctx, case)
    case.finalize()
    return case


def print_summary(case: Case) -> None:
    """Render a collection summary table to stderr."""
    table = Table(title=f"Ammit collection — {case.case_id}", title_style="accent", expand=False)
    table.add_column("collector")
    table.add_column("status")
    table.add_column("artifacts", justify="right")
    for entry in case.collectors:
        status = str(entry["status"])
        style = {"ok": "verdict.clean", "error": "err"}.get(status, "warn")
        table.add_row(str(entry["name"]), f"[{style}]{status}[/{style}]", str(entry["artifacts"]))
    err_console.print(table)
    err_console.print(
        f"[info]{len(case.artifacts)} artifacts[/info] recorded in [accent]{case.path}[/accent]"
    )
