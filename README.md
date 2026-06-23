<div align="center">

# ⚖️ Ammit

**Devourer of the Dead — DFIR triage for Linux.**

*Ammit collects a system's artifacts (the heart), weighs them against baselines
and IOC rules (the feather of Maat), and renders a verdict.*

[![CI](https://github.com/gusta-ve/ammit/actions/workflows/ci.yml/badge.svg)](https://github.com/gusta-ve/ammit/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/style-ruff-261230.svg)](https://github.com/astral-sh/ruff)

</div>

---

## The lore

In Egyptian myth, **Ammit** — *"Devourer of the Dead"* — crouches beside the
scales in the Hall of Judgement. When a soul is judged, its **heart** is weighed
against the **feather of Maat**, the principle of truth and order. A heart heavy
with wrongdoing tips the scales, and Ammit renders judgement.

This tool performs the same ceremony on a Linux host:

| Myth | Ammit (the tool) |
| --- | --- |
| The heart of the deceased | Forensic artifacts collected from the system |
| The feather of Maat | Baselines + declarative IOC rules |
| The weighing of the heart | The triage engine scoring findings |
| Ammit's judgement | A verdict: **CLEAN · SUSPICIOUS · COMPROMISED** |

---

## ⚠️ Authorized use only

Ammit is a **defensive** incident-response tool. Collecting artifacts from a
system you do not own or administer may be illegal. Collection from a **live
host** requires the explicit `--i-have-authorization` flag, which asserts that
**you have authorization** to examine the target. You are responsible for your
use of this tool.

---

## What it does

- **Read-only & non-destructive.** Ammit never modifies the target. Images are
  treated as read-only; it does its best to preserve access times.
- **Order of volatility.** Volatile evidence (processes, network state) is
  captured before things that persist on disk.
- **Integrity by default.** Every artifact is hashed with SHA-256 and recorded
  in a `manifest.json` plus a chain-of-custody log — all timestamps in **UTC**.
- **Auditable & reproducible.** Exactly what was collected, and how, is logged.
- **Live or dead.** Works on the current host (`--root /`) or a read-only image
  mounted elsewhere (`--root /mnt/evidence`).

---

## The ceremony (pipeline)

```
            ┌───────────┐   ┌────────────┐   ┌───────────┐   ┌──────────────────┐
  target ──▶│  collect  │──▶│  timeline  │──▶│  triage   │──▶│ report / verdict │
            └───────────┘   └────────────┘   └───────────┘   └──────────────────┘
             gather the      order the         weigh vs.       pronounce the
             heart           memories          the feather     judgement
                  │                                 ▲
                  │            ┌──────────┐         │
                  └───────────▶│ baseline │─────────┘
                  record a     └──────────┘  compare against
                  known-good heart            known-good
```

---

## Install

```bash
# recommended: isolated install via pipx
pipx install git+https://github.com/gusta-ve/ammit.git

# or from a clone, for development
git clone https://github.com/gusta-ve/ammit.git
cd ammit
pip install -e ".[dev]"
```

Requires Python 3.11+.

---

## Quickstart

```bash
# 1) Collect from the LIVE host (note the required authorization flag)
ammit collect --i-have-authorization -o cases/

# ...or from a read-only mounted image
ammit collect --root /mnt/evidence -o cases/

# 2) Build a super-timeline (mactime-compatible body file, CSV or JSON)
ammit timeline cases/web01_2026-06-23T18-04-12Z --format body

# 3) Weigh the artifacts against the rules
ammit triage cases/web01_2026-06-23T18-04-12Z

# 4) Render the full report — and the verdict
ammit report  cases/web01_2026-06-23T18-04-12Z --format all
ammit verdict cases/web01_2026-06-23T18-04-12Z
```

> A picture of the verdict in action (asciinema) lands here once `collect` and
> `triage` are wired end-to-end.

---

## The verdict

Findings carry a severity, and severities carry weight. Ammit tips the scales:

| Verdict | Meaning |
| --- | --- |
| 🟢 **CLEAN** | No findings tipped the scales beyond noise. |
| 🟡 **SUSPICIOUS** | Findings warrant a human investigator's eyes. |
| 🔴 **COMPROMISED** | Strong indicators of compromise — treat as an incident. |

The verdict is always **justified**: the report lists every finding, its
evidence, and the [MITRE ATT&CK](https://attack.mitre.org/) technique it maps to.

---

## Output layout

```
cases/web01_2026-06-23T18-04-12Z/
├── manifest.json            # every artifact + SHA-256 + collection metadata
├── chain_of_custody.log     # append-only, UTC-timestamped activity log
├── artifacts/               # the collected evidence (read-only copies & outputs)
│   ├── volatile/
│   ├── persistence/
│   ├── accounts/
│   ├── filesystem/
│   └── logs/
├── timeline.csv             # produced by `ammit timeline`
├── findings.json            # produced by `ammit triage`
└── report.md                # produced by `ammit report`
```

---

## Architecture

```
src/ammit/
├── cli.py            # typer app: collect / timeline / triage / report / verdict / baseline
├── context.py        # ScanContext — root, live/image mode, authorization
├── case.py           # case directory, manifest.json, chain of custody
├── integrity.py      # SHA-256, hashing of files & streams
├── models.py         # Severity, Verdict, Finding, Artifact
├── collectors/       # one module per artifact category (volatile, persistence, …)
├── rules/            # declarative YAML rules + evaluation engine
├── timeline.py       # super-timeline builder (mactime body file / CSV / JSON)
├── triage.py         # orchestrates rules over collected artifacts
├── verdict.py        # weighs findings into a verdict
├── report.py         # Markdown / JSON / HTML report
└── baseline.py       # known-good snapshot + diff
```

---

## Detection rules

Rules are declarative YAML weighed by the triage engine. The built-in set
focuses on high-signal Linux intrusion indicators:

| Rule | Severity | ATT&CK |
| --- | --- | --- |
| SSH brute-force / password spraying | High | T1110 |
| New key added to `authorized_keys` | High | T1098.004 |
| Running process whose binary was deleted from disk | Critical | T1036 / T1014 |
| Connection to a suspicious port/address | Medium | T1571 |
| Recently created cron/systemd persistence | High | T1053 / T1543.002 |
| System binary hash differs from its package (`dpkg --verify`) | Critical | T1554 |
| Login outside business hours | Low | T1078 |
| Shell history cleared or redirected to `/dev/null` | Medium | T1070.003 |

*(Status tracked in the roadmap below — rules ship with the `triage` engine.)*

---

## Development

```bash
pip install -e ".[dev]"

ruff check .          # lint
ruff format .         # format (black-compatible)
pytest                # tests run against a SYNTHETIC compromised filesystem —
                      # no root and no real host required
```

The test suite builds a fake "compromised system" file tree as a fixture, so the
full `collect → triage → COMPROMISED` path is exercised safely and reproducibly.

---

## Roadmap

- [x] Project skeleton, CLI surface, packaging, CI
- [ ] Core plumbing: integrity, case dir, manifest, chain of custody
- [ ] `collect` — volatile, persistence, accounts, filesystem, logs
- [ ] `triage` — rule engine + built-in rules
- [ ] `verdict` / `report` — Markdown / JSON (HTML optional)
- [ ] `timeline` — super-timeline (mactime body file / CSV / JSON)
- [ ] `baseline` — known-good snapshot + diff
- [ ] Synthetic compromised-system fixture + end-to-end tests

---

## Prior art & inspiration

Ammit stands on the shoulders of established DFIR tooling — studied for
inspiration, not copied:

- [**UAC** — Unix-like Artifacts Collector](https://github.com/tclahr/uac):
  YAML-driven artifact collection that respects the order of volatility.
- [**Velociraptor**](https://docs.velociraptor.app/): endpoint visibility and
  hunting at scale.
- [**The Sleuth Kit**](https://github.com/sleuthkit/sleuthkit): `mactime` and
  the body-file timeline format Ammit's `timeline` interoperates with.

---

## License

[MIT](LICENSE) © 2026 Gustavo Almeida
