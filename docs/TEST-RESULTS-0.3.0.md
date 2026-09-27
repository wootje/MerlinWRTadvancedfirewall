# Test results — 0.3.0-beta

Performed in the development container on 27 September 2026. This report applies
to the supplied one-command-install, independent-schedule and expanded-statistics
package. It is not an actual GT-AX11000 installation report.

## Executed checks

| Check | Result |
| --- | --- |
| Offline Python unit tests | **167 passed**: 97 earlier tests plus 70 installation/schedule/country/telemetry regressions. |
| Browser-demo tests | **30 passed** using Playwright and system Chromium. |
| Python syntax | All application, helper, bootstrap and build Python compiled; package verification additionally parses candidate Python with the declared 3.9 grammar. |
| JavaScript syntax | `node --check web/guard.js` passed. |
| Shell syntax | `sh -n` and `busybox ash -n` passed for install.sh, uninstall.sh, mcg and tools/install-online.sh. |
| BusyBox temporary-file compatibility | A real local BusyBox mktemp call created the new log template with mode 0600. Templates end in XXXXXX. |
| SSH-shell failure regression | A real child-shell invalid-argument failure preserved the caller, returned the failure status and logged the explanatory error. No router installation was attempted in this test. |
| Firewall dry run | example-config.json compiled to rule text without router commands or source downloads. |
| Manifest verification | Final source manifest and checksums regenerated and checked. |
| Distribution round-trip | Final ZIP checked through the current updater extractor/verifier and standalone bootstrap extractor. The 0.2.0 verifier also accepted the new source tree. See the packaged verification scope below. |

Evidence: [unit-test-results.txt](unit-test-results.txt),
[browser-test-results.json](browser-test-results.json) and
[example-rules.txt](example-rules.txt). Screenshots show **synthetic offline demo
data**, not router measurements. Statistics and Updates screenshots were visually
inspected after browser checks.

## Regression coverage

Existing firewall tests cover country/port/IP validation, empty-allowlist rejection,
country-before-reputation order, no blanket ACCEPT or established-flow exemption,
memory bounds, counter/conntrack parsing, acceleration interpretation, policy trial
confirmation/expiry, mocked rollback and marked native-hook preservation.

Existing updater tests cover commit/path/schema checks, hashes, missing/unlisted
files, unsafe/duplicate ZIP members, limits, parsing without candidate execution,
resource deferral, version-independent change detection, initial baseline adoption,
API failures/cooldowns, staging, backup/recovery and private-setting preservation.

New tests cover independent hour intervals, full GitHub disable without requests,
manual-only mode, old-preference compatibility, cron reconstruction/removal,
country automatic-off/manual-on semantics, unchanged source commit reuse, download
failure retaining live data, confirmed-versus-draft selection, mocked generation
switch recovery and refusal when acceleration preflight is not ready.

Telemetry tests cover private/DNAT endpoint attribution, partial byte accounting,
rankings, CPU deltas, per-interface rates without summing, monotonic/reset-aware
rule rates, bounded retention/top lists, no online checks, sampling due time,
load/memory deferral and cached status without repeated conntrack scans. The legacy
load chart uses a short series, not a second full interface-history payload.

Bootstrap tests exercise bounded verified extraction, malformed/unsafe/duplicate
archives, unchanged embedded source, publication prerequisites, actual child-shell
failure logging and local BusyBox template compatibility. These use local synthetic
archives/API fixtures; they do not download or install from GitHub on a router.

The browser test covers country search/empty-selection handling, port validation,
simulated rollback, table inspection, manual country refresh/schedule disable,
GitHub full-disable/manual-only/frequency controls, simulated update/rollback,
statistics settings/rankings/charts/filters and CSV/JSON downloads. Layouts at
1440, 768 and 390 pixels have no page-level horizontal overflow in the tested tabs.
No external network requests or JavaScript page errors occurred.

## Packaged verification scope

The delivered archive is extracted into a clean temporary directory and verified
against its actual final manifest. The standalone bootstrap validator is exercised
without invoking its network or installation entry point. The prior 0.2.0 source
verifier checks manifest/path/hash/syntax compatibility only. Acceptance is not
proof of a live upgrade or native firmware integration. ZIP checks use the
complete final distribution rather than only the small unit-test fixtures.

## Not tested

- Installation, update, uninstall, reboot or packet filtering on a physical GT-AX11000.
- Real native page/menu mounting, Addons API/form submission, session/CSRF or diagnostic-file access controls.
- Live ipset/iptables behavior, accelerated packet paths, existing-flow coverage or actual cron execution on Merlin.
- Recovery under power loss, removed/full/failed USB, process death, lost network access or broken firmware.
- Initial online installation or live GitHub staging/install from the newly published release; this package was not pushed to the repository.
- Live country-data downloads, authenticated AbuseIPDB responses or actual source/GeoIP accuracy.
- Real concurrent Skynet or other add-on updates and hook changes.
- Measured router CPU/RAM consumption, memory peaks, USB wear, throughput or gigabit speed.
- Runtime testing on Python 3.9 itself; the development interpreter is newer. Grammar compatibility is not full runtime qualification.
- A run of the included workflow on GitHub. Equivalent local checks passed, but target-repository CI has not run in this session.

BusyBox checks use the local container binary, not the router's exact firmware
build. Passing offline tests is not a production-readiness or complete security
claim. Back up configuration, use wired management and review `mcg doctor` before
activating filtering. The preceding installation's original error remains unknown
without its actual output; avoiding interactive exit does not fix every possible
prerequisite, integrity or firmware-integration failure.
