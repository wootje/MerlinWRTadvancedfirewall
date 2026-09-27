# Test results — 0.3.1-beta

Performed in the development container on 27 September 2026. This report applies
to the installer compatibility hotfix. It is not a physical router test report.

## Executed checks

| Check | Result |
| --- | --- |
| Offline Python regression suite | **182 passed**, including 15 new portable-installer tests. No tests skipped on this development host. |
| Reduced-command BusyBox environment | Common logging exercised without `mktemp` or `mkfifo` in PATH; missing `tee` fallback also tested. |
| Actual standalone entry points | Local installer and online bootstrap executed unchanged inside a minimal chroot exposing neither missing applet; each reached its expected read-only failure and preserved the calling shell. |
| Documented one-command launcher | Tested in that minimal chroot with successful and failing mock downloads. A failed download was not executed; a downloaded child's exit code was preserved; temporary download directories were cleaned. No live network download was attempted. |
| Log safety | Modes 0700/0600 checked; pre-existing directories and symlinks were not reused; unavailable temporary storage prevented worker execution. |
| Failure handling | Worker errors were not hidden by successful `tee`. Logger failure returned nonzero with an explicit warning. Standard output and error were retained. |
| Browser-demo regression suite | **30 checks passed** with Playwright and Chromium. These are simulated UI actions, not native Merlin requests. |
| Source syntax | Python parsing/compilation, JavaScript syntax and POSIX shell/BusyBox ash syntax checks passed. |
| Manifest and distribution | Manifest and SHA256SUMS regenerated and verified. The final archive was round-trip checked with the current verifier/extractor and standalone bootstrap extractor. |

Evidence: [unit-test-results.txt](unit-test-results.txt),
[browser-test-results.json](browser-test-results.json), and
[installer compatibility regressions](../tests/test_install_compat.py).
The common logging source and generated installers match byte-for-byte on rebuild.

The unchanged firewall, updater, country-refresh and statistics test coverage is
included in the full regression run. The two old `mktemp`-template tests were
replaced with checks of the embedded portable helper and documented launcher;
those earlier tests did not establish utility availability on the router.

## Scope of the missing-utility tests

The local BusyBox binary is an x86-64 development-host binary, not the router's
AArch64 firmware. A small set of applets is exposed as commands; `mktemp` and
`mkfifo` are intentionally not exposed. No fallback calls to their BusyBox applets
exist in the installation code. The helpers, unchanged entry points and launcher
are exercised with their real shell logic rather than only syntax inspection.

Local-installer tests use an invalid argument, and online-bootstrap tests stop at
missing `nvram`. They do not pass router preflight, run `opkg`, write live /jffs or
/opt configuration, or install a firewall. Launcher tests use a local curl fixture,
not GitHub. The tests do not establish that every later firmware prerequisite is
available. Root/chroot-dependent tests may be skipped on less privileged hosts.

## Not tested

- Installation or upgrades on the reported GT-AX11000 / 3004.388.12_2 firmware.
- Live GitHub bootstrap downloads or a full online installation after publication.
- Actual Entware package installation, native Addons API/menu integration or hooks.
- Packet filtering, flow acceleration, country feeds, API lookups, schedules or rollback on hardware.
- Router CPU/RAM use, storage wear, network throughput or behavior after power loss.
- GitHub-hosted CI; the package has not been pushed to the repository in this session.

Logs remain under `/tmp/mafw-install.PID.N/output.log` and
`/tmp/mafw-bootstrap.PID.N/output.log`; they disappear on reboot. Keep wired
management, back up configuration and inspect `mcg doctor` before activation.
These tests resolve the demonstrated missing-command failure path, not all
possible later installation failures. Offline success is not production readiness.

The [0.3.0 report](TEST-RESULTS-0.3.0.md) is retained as historical evidence only.
