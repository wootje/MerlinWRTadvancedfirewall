# Independent updates, installation and recovery

Version 0.3.0-beta has separate schedules for country data and GitHub software.
Both use persisted preferences, elapsed-hour due checks and one native five-minute
maintenance job. No resident polling daemon or automatic software installation is
introduced.

## Country data

`country-settings.json` contains `auto_update` (default true) and `interval_hours`
(default 24, range 1–720). Manual country refresh remains available when automatic
updates are off. It checks only selected IPv4 files from the fixed country source.
A commit-pinned cache is reused when unchanged; checking manually does not force an
unnecessary download of identical file content.

A manual request may contain draft country choices. It only replaces live country
data when those choices exactly match an enabled confirmed/active country policy.
Otherwise it prepares the cache without changing the policy. Empty manual choices
are refused; scheduled work with no confirmed choices skips downloads. All files
must validate before replacing a live generation. The old reputation sets, ports
and own rules are preserved. Identical country networks avoid a generation rebuild.
Failures/deferred updates preserve existing filtering and report an error; stale
data is not silently called up-to-date.

Country metadata includes last attempt, last successful refresh, last actual
network change, entry count and selected-file commits. The due time is based on the
last attempt, including failures, to avoid retry storms. Manual retry cooldown is
60 seconds. A five-minute evaluator and resource/lock limits can delay execution.

## GitHub settings and modes

| Setting | Default | Effect |
| --- | --- | --- |
| `enabled` | true | Master permission for online check/download/install through the updater. |
| `auto_check` | true | Scheduled commit checks. |
| `auto_download` | true | Stage detected changes when checking. Requires automatic checks enabled. |
| `interval_hours` | 24 | Elapsed interval from the last scheduled/manual attempt, integer 1–720. |

For manual-only operation keep `enabled` true and both automatic preferences false.
For complete disable set `enabled` false; saved automatic preferences become false
too. Manual/CLI checks, downloads and installations then fail with an explanatory
message. Offline application rollback is still permitted. An existing downloaded
package is not deleted and installed software is not downgraded by disabling.
Country/reputation schedules and kernel filtering are independent of this master.

The fixed source is `wootje/MerlinWRTadvancedfirewall`, branch `main`. A public
GitHub commit query is followed by a manifest pinned to its 40-character SHA. A
change with the same version string is still detected. An identical manually
installed tree can adopt the matching GitHub commit as its baseline.

**Check for changes** may stage a change when automatic download is enabled.
**Download checked update** is explicit staging. **Install downloaded update**
requires confirmation and the exact staged commit. The updater never installs as
a result of a timer or ordinary status read.

## Cron integration and scheduling

| Job | Schedule / purpose |
| --- | --- |
| `MCG_Tick` | Every minute; safety/status tick, sample details only when due. |
| `MCG_Mirror` | Hourly at minute 23; mirror Skynet when applicable. |
| `MCG_Feeds` | Daily at 04:43 router time; reputation refresh only. |
| `MCG_Maintenance` | Every five minutes only while country automatic updates or GitHub automatic checks are enabled. Evaluates each independently. |

The old fixed `MCG_Updates` job is removed. Saving update preferences reschedules
maintenance immediately; startup reconstructs jobs from saved settings. When both
new automatic services are off, their shared job is removed. A country failure is
recorded without concealing the independent GitHub result. No maintenance network
request happens simply because a browser polls cached status.

These are elapsed-hour schedules, not “run at exactly this time” promises. After
reboot, the persisted last-attempt time still controls due work. A router with an
incorrect clock needs time correction for TLS and scheduling. A pending policy
trial, high load, insufficient RAM/USB, network failure or lock contention can
defer work. Turning automatic country updates off does not prevent explicit policy
changes/tests from obtaining data they need.

## One-command bootstrap and integrity

`tools/install-online.sh` is a self-contained shell/embedded-Python bootstrap,
generated from `tools/bootstrap.py` by `tools/build_installer.py`. It validates
router/Entware prerequisites and installs missing standard Python/curl dependencies.
The initial command in README uses a child `sh -c`, stores the script in a private
temporary file, then executes it. No instruction is executed as `exit` in the
interactive login shell. Do not source either installer.

The bootstrap downloads the selected commit's manifest and source archive to a
separate USB directory. It enforces compressed/expanded/file-count limits and
validates every listed file before running `sh install.sh --commit SHA`. The local
installer verifies the package again. The initial shell and repository maintainer
are part of the trust boundary: hashes from a compromised repository cannot prove
that its new code is benign. No independent signing key is implemented.

Limits: 12 MiB compressed, 40 MiB expanded, 400 manifest files, bounded ZIP entries,
no traversal, duplicate paths, symlinks, special files or unlisted file content.
Downloads use fixed HTTPS endpoints without disabling certificate validation.
New Python is parsed against the compatibility grammar, not imported/executed just
to validate it. Shell files are checked with `sh -n`.

Bootstrap and local installer output are recorded in `/tmp/mafw-bootstrap.*`
and `/tmp/mafw-install.*`. Those are volatile logs; copy the printed file before
rebooting when diagnosing a failure. Dependency checks cannot repair a broken
Entware mount, failed TLS, missing package repository or incompatible firmware.

## Replacement and compatibility

Installation takes the application lock, checks resources and the pending-trial
state, copies a verified candidate, creates an application backup and snapshots
integration/preferences. The launcher/menu/hooks are integrated while private
configuration, keys and source data stay outside the program directory. Active
kernel rules are not deliberately flushed or rebuilt just by replacing software.
Later confirmed policy/source operations use the new code.

Version 0.2.0 can accept this package: new support modules live under the existing
allowed `tools/` path. Its two-field `update-settings.json` shape is preserved;
new master/cadence fields live in `update-policy.json`. Country/statistics settings
use separate files. Full GitHub disable also saves both legacy automatic switches
false, so a rollback to 0.2.0 does not silently resume its automatic GitHub checks.

A 0.2.0 rollback does **not** implement the new country-schedule disable/frequency;
it returns to that version's old combined feed schedule and simpler statistics.
A 0.1.0 rollback restores its Dutch UI and lacks GitHub updates. Settings are not
rewound to their values at backup time. Reinstall this version to regain the new
controls. Review rollback semantics before relying on an older version.

## Useful SSH commands

Each command below is an independent action; do not append `|| exit 1`:

```sh
/jffs/scripts/mcg country-refresh
/jffs/scripts/mcg update-check
/jffs/scripts/mcg update-download
/jffs/scripts/mcg update-rollback
```

To install a staged update via SSH, read its full commit ID, then substitute it
in the second command. The web page handles this selection for you.

```sh
/opt/bin/python3 -c 'import json; print(json.load(open("/opt/var/lib/merlin-country-guard/updates/staged.json"))["commit"])'
/jffs/scripts/mcg update-install REPLACE_WITH_FULL_STAGED_COMMIT
```

Inspect status, journal and application backups:

```sh
/jffs/scripts/mcg doctor
/jffs/scripts/mcg status
cat /opt/var/lib/merlin-country-guard/update-journal.json
ls -la /opt/var/backups/merlin-country-guard
cat /tmp/mcg-maintenance.log
```

Logs may be absent before the corresponding job runs. Backups are not pruned
automatically. Review their contents and available USB storage.

## Failure and emergency recovery

Caught replacement errors attempt to restore the previous application and
integration. That is not a crash-proof transaction across USB, JFFS, mounts and
kernel state. Power loss, removed media, process termination or filesystem errors
may require manual recovery. Actual router recovery has not been tested here.

For immediate add-on rule removal, including without working Python/USB:

```sh
/jffs/scripts/mcg emergency-off
```

Only add-on anchors are cleared; this does not erase the native firewall/Skynet.
Repair storage/Python and run normal `/jffs/scripts/mcg disable` before reboot
when the disabled state must persist. A reboot clears the temporary emergency
marker and can restore confirmed filtering.

Prefer reinstalling a complete verified package from a separate USB folder with
`sh install.sh` after resolving the reported error. If application-file rollback
is available, use the restore button or `mcg update-rollback`. For manual backup
recovery, inspect the journal's actual backup path and its `app/` directory; never
guess a timestamp or blindly replace other add-ons' hooks. The package does not
promise automatic repair of a failed disk or a broken firmware installation.

## Publishing coherent updates

Regenerate `tools/install-online.sh` when its embedded Python changes, and regenerate
the preview after UI edits. Run tests, then rebuild `manifest.json`/`SHA256SUMS`
**last**. Publish the complete tree and manifest in the same commit. Adding or
editing a package file without updating the manifest makes staging fail safely.
Never rebuild a manifest on a router to bypass a failed integrity check.
