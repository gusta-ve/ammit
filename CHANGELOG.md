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
