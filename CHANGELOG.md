# Changelog

All notable changes to Ammit are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project aims to
adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Project skeleton: packaging (`pyproject.toml`), `ammit` CLI entry point with
  `collect`, `timeline`, `triage`, `report`, `verdict` and `baseline`
  subcommands (stubs), core models, scan context, and CI (ruff + pytest).
- Integrity & case management: SHA-256 hashing with `O_NOATIME`-preserving reads
  to avoid perturbing evidence, a case folder with `manifest.json` and an
  append-only `chain_of_custody.log`, and a collector-run recorder that isolates
  individual collector failures from the overall run.
- `collect`: read-only artifact collection honouring the order of volatility,
  working live (`--root /`, gated by `--i-have-authorization`) or against a
  mounted image (`--root <mountpoint>`):
  - **volatile** — processes from `/proc` (flagging binaries deleted from disk),
    TCP/UDP connections from `/proc/net` mapped to PIDs, kernel modules,
    logged-in users;
  - **persistence** — cron, systemd units/timers, SSH `authorized_keys`,
    `rc.local`/`profile.d`, `ld.so.preload`, `at` jobs;
  - **accounts** — `passwd`/`group`, `shadow` metadata (no hashes), sudoers,
    duplicate UID 0, login history;
  - **filesystem** — a mactime body file plus SUID/SGID, world-writable, recent
    changes and hidden temp files;
  - **logs** — auth logs, per-user shell histories (with tamper detection) and
    journald. Live mode enriches with `ss`/`ps`/`lsmod`/`last`/`journalctl`.
- `triage`: a declarative YAML rule engine that weighs collected artifacts
  against the feather of Maat and renders a verdict.
  - Datasets layer that loads and *enriches* artifacts (suspicious ports on
    connections, IOC indicators on cron/systemd commands, parsed `auth.log`
    events with off-hours flags, SUID outside system dirs, nologin SSH keys).
  - Rule engine with ANDed conditions, regex/path operators and
    `group_by` + `having` aggregation (e.g. "≥ 8 failed logins from one IP").
  - 12 built-in rules mapped to MITRE ATT&CK: deleted-binary process, duplicate
    UID 0, SSH brute-force, `ld.so.preload`, off-path SUID, malicious
    cron/systemd, nologin `authorized_keys`, C2-port connection, neutralized
    shell history, hidden temp files, off-hours login.
  - Verdict engine (CLEAN / SUSPICIOUS / COMPROMISED) by forensic weight, written
    to `findings.json` and stamped into the manifest without disturbing the
    sealed chain-of-custody hash. `--exit-code` maps the verdict to the process
    exit status; `--rules` adds custom rule files.
- Test suite: a synthetic, root-free "compromised system" fixture exercised
  end-to-end (collect → triage → COMPROMISED), plus unit tests for the engine,
  verdict thresholds and dataset enrichment.
