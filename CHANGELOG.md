# Changelog

## 0.3.1-beta — 2026-09-27

- Fix `mktemp: not found` on the reported GT-AX11000 firmware: remove that
  dependency from the documented command, online bootstrap and local installer.
- Use private atomically created directories; refuse or skip pre-existing paths.
- Remove FIFO logging dependency. Preserve worker exit status across streaming
  logging; retain logs under `/tmp/mafw-{install,bootstrap}.PID.N/output.log`.
- Add fallback logging when `tee` is not available and explicit handling of logger
  failures. Keep SSH login shells independent of child installer errors.
- Add reduced-BusyBox installer regressions without the missing applets exposed.
- Firewall policy, application settings and filtering code are unchanged apart
  from the version identifier. No acceleration, IPv6 or reboot changes.

## 0.3.0-beta — 2026-09-27

- Add a self-contained one-command GitHub bootstrap and simplify local installation to `sh install.sh`.
- Use BusyBox-compatible temporary-file templates and avoid duplicate full-history payloads.
- Check/install missing Python/curl dependencies and log complete installer output while preserving the child-process error status.
- Remove interactive `|| exit 1` installation instructions that could close the SSH login shell after a failure.
- Add manual selected-country refresh, independent 1–720-hour scheduling, automatic-refresh disable and source status/error details.
- Separate reputation refresh from country updates; unchanged country data avoids a kernel rebuild and changed data retains reputation/port settings.
- Add independent 1–720-hour GitHub scheduling, manual-only mode and a full check/download/install disable switch; keep local rollback and explicit install confirmation.
- Retain the legacy updater-settings file shape for 0.2.0 application rollback, and replace its fixed update cron with due-time maintenance.
- Add sampled CPU/interface rates, conntrack occupancy, IP/port/protocol/state rankings, rule-decision deltas, charts and CSV/JSON exports.
- Add configurable sample interval/history/top-list size, monotonic/reset-aware rate calculation, bounded scans and high-load/memory deferral.
- Keep packet filtering independent of statistics sampling; do not add permanent packet logging or an online lookup per connection.
- Add 70 offline tests (167 total) and extend browser-demo checks to 30; document actual testing limits.

## 0.2.0-beta — 2026-09-27

- Translate the add-on interface, errors, CLI output, demo and documentation into English.
- Use the project name MerlinWRT Advanced Firewall while retaining legacy paths and launcher compatibility.
- Add a GitHub Updates tab with commit-based change detection, bounded verified staging, application backups and explicit installation.
- Add installation/update/recovery documentation, a manifest builder and offline updater tests.
- Preserve IPv4 country allowlists, reputation mirroring, port controls, validated own DROP rules and bounded statistics.

## 0.1.0-beta

Initial independent Country Guard prototype with a Dutch interface, country
allowlists, local reputation sets, port rules and policy-trial rollback.

These are unvalidated router betas, not claims of measured throughput, complete
threat detection or successful recovery on hardware.
