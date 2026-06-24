"""The ``ammit`` command-line interface.

Subcommands map to the stages of the weighing ceremony: ``collect`` gathers the
heart, ``timeline`` orders its memories, ``triage`` weighs it against the
feather, and ``report``/``verdict`` pronounce judgement. ``baseline`` records a
known-good heart for future comparison.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from . import __version__
from .collect import build_context, print_summary, run_collection
from .console import console, err_console
from .models import Verdict
from .render import findings_table, print_findings, verdict_panel
from .triage import run_triage

app = typer.Typer(
    name="ammit",
    help=(
        "Ammit — DFIR triage for Linux. The Devourer of the Dead weighs a "
        "system's heart (its artifacts) against the feather of Maat (baselines "
        "and IOC rules) and renders a verdict."
    ),
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"ammit {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            help="Show version and exit.",
            is_eager=True,
            callback=_version_callback,
        ),
    ] = False,
) -> None:
    """Weigh the heart of a Linux system against the feather of Maat."""


def _todo(name: str) -> None:
    err_console.print(
        f"[warn]⚖  '{name}' is not implemented yet — landing in an upcoming commit.[/warn]"
    )
    raise typer.Exit(code=1)


# --- Stage 1: gather the heart -------------------------------------------------
@app.command()
def collect(
    root: Annotated[
        Path,
        typer.Option(help="Target filesystem root. '/' = live host; a mountpoint = image mode."),
    ] = Path("/"),
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Directory that will hold the case folder."),
    ] = Path("cases"),
    authorized: Annotated[
        bool,
        typer.Option(
            "--i-have-authorization",
            help="REQUIRED to collect from a LIVE host. Asserts you are authorized to do so.",
        ),
    ] = False,
    label: Annotated[
        str | None,
        typer.Option(help="Optional human-readable label recorded in the case manifest."),
    ] = None,
) -> None:
    """Collect forensic artifacts into a case folder (order of volatility respected)."""
    is_live = root == Path("/")
    if is_live and not authorized:
        err_console.print(
            "[err]Refusing to collect from a LIVE host without authorization.[/err]\n"
            "[muted]Collecting from a running system requires the explicit "
            "[bold]--i-have-authorization[/bold] flag, asserting you are authorized "
            "to examine this host. Use [bold]--root <mountpoint>[/bold] for a dead image.[/muted]"
        )
        raise typer.Exit(code=2)
    if not is_live and not root.exists():
        err_console.print(f"[err]--root path does not exist:[/err] {root}")
        raise typer.Exit(code=2)

    ctx = build_context(root, authorized=authorized)
    err_console.print(
        f"[accent]⚖  Ammit[/accent] collecting from [bold]{ctx.target_host}[/bold] "
        f"([info]{ctx.mode}[/info], root={ctx.root})"
    )
    case = run_collection(ctx, output, label=label)
    print_summary(case)
    # The case path goes to stdout so it can be captured by a pipeline.
    console.print(str(case.path))


# --- Stage 2: order the memories ----------------------------------------------
@app.command()
def timeline(
    case: Annotated[
        Path, typer.Argument(help="Path to a case folder produced by `ammit collect`.")
    ],
    fmt: Annotated[
        str,
        typer.Option(
            "--format", "-f", help="Output format: csv | json | body (mactime body file)."
        ),
    ] = "csv",
    output: Annotated[
        Path | None,
        typer.Option(
            "--output", "-o", help="Where to write the timeline (defaults inside the case)."
        ),
    ] = None,
) -> None:
    """Build an ordered super-timeline (MAC times + log events)."""
    _todo("timeline")


# --- Stage 3: weigh against the feather ---------------------------------------
@app.command()
def triage(
    case: Annotated[
        Path, typer.Argument(help="Path to a case folder produced by `ammit collect`.")
    ],
    rules: Annotated[
        Path | None,
        typer.Option(help="Additional rules file or directory (YAML)."),
    ] = None,
    baseline: Annotated[
        Path | None,
        typer.Option(help="Known-good baseline to compare against."),
    ] = None,
    fmt: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: table | json."),
    ] = "table",
    exit_code: Annotated[
        bool,
        typer.Option(
            "--exit-code",
            "-e",
            help="Exit 1 if SUSPICIOUS, 2 if COMPROMISED (otherwise 0).",
        ),
    ] = False,
) -> None:
    """Run the rule engine over collected artifacts and emit weighed findings."""
    if not (case / "manifest.json").is_file():
        err_console.print(f"[err]Not an Ammit case folder (no manifest.json):[/err] {case}")
        raise typer.Exit(code=2)

    baseline_data = None
    if baseline is not None:
        try:
            baseline_data = json.loads(baseline.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            err_console.print(f"[err]Could not read baseline:[/err] {exc}")
            raise typer.Exit(code=2) from exc

    err_console.print(
        f"[accent]⚖  Ammit[/accent] weighing [bold]{case.name}[/bold] against the feather…"
    )
    findings, verdict, summary = run_triage(case, extra_rules=rules, baseline=baseline_data)

    if fmt == "json":
        console.print((case / "findings.json").read_text(encoding="utf-8").rstrip())
    else:
        if findings:
            console.print(findings_table(findings))
            print_findings(console, findings)
        else:
            console.print("[muted]No findings — the heart bears no mark.[/muted]")
        console.print()
        console.print(verdict_panel(verdict, summary))

    if exit_code:
        raise typer.Exit(
            code={Verdict.CLEAN: 0, Verdict.SUSPICIOUS: 1, Verdict.COMPROMISED: 2}[verdict]
        )


# --- Stage 4: pronounce judgement ---------------------------------------------
@app.command()
def report(
    case: Annotated[Path, typer.Argument(help="Path to a triaged case folder.")],
    fmt: Annotated[
        str,
        typer.Option("--format", "-f", help="Report format: md | json | html | all."),
    ] = "md",
    output: Annotated[
        Path | None,
        typer.Option(
            "--output", "-o", help="Where to write the report (defaults inside the case)."
        ),
    ] = None,
) -> None:
    """Render the full 'weighing of the heart' report (Markdown / JSON / HTML)."""
    _todo("report")


@app.command()
def verdict(
    case: Annotated[Path, typer.Argument(help="Path to a triaged case folder.")],
) -> None:
    """Print only the verdict: CLEAN / SUSPICIOUS / COMPROMISED."""
    _todo("verdict")


# --- The feather: record a known-good heart -----------------------------------
@app.command()
def baseline(
    root: Annotated[
        Path,
        typer.Option(help="Target filesystem root to snapshot. '/' = live host."),
    ] = Path("/"),
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Path to write the baseline snapshot (JSON)."),
    ] = Path("baseline.json"),
    authorized: Annotated[
        bool,
        typer.Option(
            "--i-have-authorization",
            help="REQUIRED to snapshot a LIVE host. Asserts you are authorized to do so.",
        ),
    ] = False,
) -> None:
    """Snapshot a known-good state (binary hashes, ports, cron, users) for later comparison."""
    _todo("baseline")


def run() -> None:
    """Console-script entry point (see ``[project.scripts]`` in pyproject)."""
    app()
