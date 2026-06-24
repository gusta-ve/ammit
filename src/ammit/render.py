"""Rich rendering helpers for verdicts and findings, shared by ``triage`` and
``report`` so the two stay visually consistent.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import Finding, Severity, Verdict

_VERDICT_STYLE = {
    Verdict.CLEAN: "verdict.clean",
    Verdict.SUSPICIOUS: "verdict.suspicious",
    Verdict.COMPROMISED: "verdict.compromised",
}

_VERDICT_VERB = {
    Verdict.CLEAN: "The heart is light. It balances the feather of Maat.",
    Verdict.SUSPICIOUS: "The scales waver. The heart bears weight worth examining.",
    Verdict.COMPROMISED: "The heart is heavy with deeds. Ammit has fed.",
}


def severity_tag(sev: Severity) -> str:
    """Inline markup tag for a severity, e.g. ``[sev.high]HIGH[/sev.high]``."""
    return f"[sev.{sev.value}]{sev.value.upper()}[/sev.{sev.value}]"


def verdict_panel(verdict: Verdict, summary: dict[str, object]) -> Panel:
    """A bannered verdict suitable for the end of a triage/report run."""
    style = _VERDICT_STYLE[verdict]
    counts = summary.get("severity_counts", {}) or {}
    tally = "  ".join(
        f"{sev.value}={counts.get(sev.value, 0)}"
        for sev in reversed(list(Severity))
        if counts.get(sev.value, 0)
    )
    body = Text()
    body.append(f"VERDICT: {verdict.value}\n", style=style)
    body.append(_VERDICT_VERB[verdict] + "\n", style="muted")
    body.append(
        f"{summary.get('findings', 0)} findings · weight {summary.get('weight', 0)}"
        + (f" · {tally}" if tally else ""),
        style="muted",
    )
    return Panel(body, title="⚖  Weighing of the Heart", border_style=style, expand=False)


def findings_table(findings: list[Finding]) -> Table:
    """A one-row-per-finding overview table."""
    table = Table(title="Findings", title_style="accent", expand=False)
    table.add_column("severity")
    table.add_column("rule")
    table.add_column("title")
    table.add_column("hits", justify="right")
    table.add_column("ATT&CK")
    for f in findings:
        table.add_row(
            severity_tag(f.severity),
            f.rule_id,
            f.title,
            str(f.metadata.get("matches", "")),
            ", ".join(f.mitre),
        )
    return table


def print_findings(console: Console, findings: list[Finding]) -> None:
    """Detailed, evidence-bearing rendering of each finding."""
    for f in findings:
        console.print(f"\n{severity_tag(f.severity)} [bold]{f.rule_id}[/bold] — {f.title}")
        if f.mitre:
            console.print(f"  [muted]ATT&CK:[/muted] {', '.join(f.mitre)}")
        for line in f.evidence:
            console.print(f"  [muted]•[/muted] {line}")
