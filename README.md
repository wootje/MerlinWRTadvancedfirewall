# MerlinWRT Advanced Firewall

**English web interface for country allowlists, automatic local reputation checks,
port blocking, IPTables inspection, sampled traffic statistics and GitHub updates.**

Repository: [wootje/MerlinWRTadvancedfirewall](https://github.com/wootje/MerlinWRTadvancedfirewall)

**Version: 0.3.1-beta. Prepared for ASUS GT-AX11000 with Asuswrt-Merlin, Entware and
IPv6 disabled. Not validated on physical router hardware.**

This independent add-on runs alongside Skynet. It is not replacement firmware,
a modem, an unrestricted IPTables editor or a guarantee against every attack.
A fresh installation leaves its filtering **OFF**. Upgrades retain the existing
confirmed policy; they do not deliberately deactivate existing protection.
The original Skynet program and web page are not replaced.

## Installer hotfix in 0.3.1-beta

The GT-AX11000 report `sh: mktemp: not found` exposed a missing dependency
assumption in the 0.3.0 launcher and both installers. This release removes that
external utility requirement everywhere in the installation path. It also removes
the FIFO utility requirement. Private directories are created with `mkdir` (never
`mkdir -p`) under `umask 077`; existing paths are never reused. Logs remain in those
private directories and the worker exit code is retained even when output is
streamed through `tee`. Without `tee`, output is logged and shown afterwards.

No firewall behavior, country selection, statistics or update schedules are changed
by this hotfix. Hardware installation still needs validation on the target router.

## Features introduced in 0.3.0-beta

| Area | Included |
| --- | --- |
| One-command installation | An online bootstrap and a local `sh install.sh` entry point; missing Python/curl dependencies, package validation, installation and diagnostics handled together. |
| SSH failure handling | Installer errors are logged and stop a child process, rather than asking your interactive SSH shell to exit. |
| Country list updates | Manual refresh, automatic refresh on/off and an independent interval of **1–720 hours**. |
| GitHub updates | Manual check/download/install, automatic check/download preferences, an independent **1–720-hour** interval and a full disable switch. Installation remains explicit. |
| Richer statistics | CPU usage, per-interface RX/TX rates, conntrack occupancy, top IPs/ports/protocols/states, decision-counter deltas, charts and exports. |
| Statistics controls | Sample every **1–60 minutes**, keep **1–168 hours**, and show **5–50** ranking entries. |

Country, reputation, port and own DROP-rule filtering remain in the kernel's
software packet path; increasing a statistics interval does **not** mean fewer
packets are filtered. All public IPv4 packets actually traversing the add-on's
chains are checked, including existing connections. This is not an online API
request or a new numeric reputation score for each address. An unlisted address
is unknown, not proven safe. See [scope and limitations](docs/SAFETY.md).

Open [preview.html](preview.html) locally for the English demonstration. Its traffic,
updates and installations are **simulated**. It makes no external network requests.

## Install with one command

### Requirements before starting

Use a wired LAN connection, export your normal Merlin and Skynet backups, and keep
SSH available. Sign in with the router's configured administrator username.

You need a **GT-AX11000 in router mode**, compatible Asuswrt-Merlin with its native
Addons API (`am_addons`), working USB-mounted **Entware** and enabled **JFFS custom
scripts and configs** under **Administration > System**. This beta refuses other
models. The installer does not install Entware, upgrade firmware or reboot.

The online command needs a working `curl` initially. The installer uses Entware's
`opkg` to install missing Python/curl packages, not to upgrade every installed
package. Python must be **3.9+** with the required standard-library modules.
`iptables`, `iptables-save`, `iptables-restore`, `ipset`, `cru`, `mount` and `nvram`
are also required. Correct TLS/clock/certificate failures; never use `curl -k`.

### Option A — download and install from GitHub

**Publish the complete extracted 0.3.1-beta package to the repository root on `main`
first**, including `tools/install-online.sh`, `manifest.json` and every listed file.
Uploading just a ZIP, putting files in an extra subdirectory, or publishing an
incomplete manifest will not work. This package has not been pushed on your behalf.

Paste this **single command** into the router's SSH terminal:

```sh
sh -c 'umask 077; d=/tmp/mafw-online.$$; mkdir "$d" || exit 1; trap "rm -f \"$d/install-online.sh\"; rmdir \"$d\"" 0; if curl --fail --silent --show-error --proto "=https" --connect-timeout 10 --max-time 60 --output "$d/install-online.sh" "https://raw.githubusercontent.com/wootje/MerlinWRTadvancedfirewall/main/tools/install-online.sh"; then sh "$d/install-online.sh"; r=$?; else r=$?; fi; exit "$r"'
```

The command runs in a separate `sh -c` shell. The bootstrap resolves `main` to a
specific Git commit, downloads a bounded commit-pinned archive, validates its
manifest and hashes, and calls the local installer. It keeps TLS verification on.
The bootstrap itself is trusted code from this repository over HTTPS; hashes are
not independent signatures and cannot protect against a compromised maintainer.
Review [tools/install-online.sh](tools/install-online.sh) before trusting it as root.

### Option B — install the ZIP you already copied to USB

Extract the release ZIP on your computer and copy the **whole project folder** to
a separate directory on the router's USB storage. From that extracted folder,
run just:

```sh
sh install.sh
```

No separate `chmod`, dependency-install, manifest-check or `doctor` command is
required. The installer performs those prerequisites/checks itself. Do **not**
extract over the live `/opt/share/merlin-country-guard` directory. Do not run the
script with `. install.sh` or `source install.sh`, and do not append `|| exit 1`.

### What happens during installation

The installer checks prerequisites, installs missing dependencies when needed,
verifies the source package, creates an application backup and replaces program
files. It retains confirmed countries/ports/reputation settings and the private
API key, integrates the native page/hooks, and prints read-only preflight results.
It does not change acceleration, IPv6, WAN administration or the global firewall.

It prints an actual native page such as `/user7.asp` (the free slot varies). Open
that path on your existing router-administration host and port, or use
**Firewall > Advanced Firewall**. Reload the page after an upgrade.

**Installation success is not proof that filtering is active or safe to enable.**
Read the preflight output. Activation requires IPv6 explicitly disabled, WAN
administration disabled, and both Flow Cache and hardware acceleration verifiably
off. Enabled or unknown acceleration status blocks activation. The installer does
not guess commands to disable acceleration. Throughput has not been measured.

### Fixing `sh: mktemp: not found`

The previous launch command stopped before downloading anything when that command
was unavailable. Both old installers used it too, so changing only the first line
was insufficient. Do not bypass integrity verification or install unverified
replacement system utilities to work around the problem.

Use the complete **0.3.1-beta** package and run `sh install.sh` from its extracted
USB directory. For the online command, publish **all** extracted package files to
`main` first, including VERSION, the two installer scripts and the regenerated
manifest. Do not copy only one fixed script into a release with old checksums.

Paste the command using the code block's copy button: the URL must be plain text
inside quotes, not Markdown `[label](url)`. Visual terminal wrapping is fine; do not
insert escaped underscores or a backslash before an option such as `--connect-timeout`.
The command and installers now use no external temporary-file utility.

### Why the previous instructions closed PuTTY

The old instructions used `command || exit 1` directly in an interactive session.
When that command failed, `exit` terminated the login shell and the SSH session.
That explains the logout mechanism, **not which preceding command failed**.
A manifest mismatch, incomplete upload, missing Python or other prerequisite may
still need correction; the new log exposes the actual error.

Both installers log full worker output and print the log filename on failure:

```sh
ls -t /tmp/mafw-install.*/output.log /tmp/mafw-bootstrap.*/output.log 2>/dev/null
```

Read the exact file printed by the installer with `cat`. Files in `/tmp` disappear
on reboot. **Never regenerate the manifest on the router to make a failed check
pass.** Obtain a complete, consistent published package instead.

The new entry points avoid deliberately exiting your login shell. They cannot
promise SSH survives unrelated network loss, a router crash or your terminal closing.

## Configure and test the firewall

In **Allowed countries**, select the countries you wish to **allow** and enable
**Allow only the selected countries**. Enable Advanced Firewall in **Overview**.
An enabled, empty country allowlist is refused. Add reputation sources and any
TCP/UDP port blocks or own DROP rules, then use **Test policy for 120 seconds**.
Only confirm **Working correctly: confirm** after checking management, DNS and
internet access. An unconfirmed trial triggers a rollback attempt, not a guaranteed
recovery under power, storage or kernel failure.

The decision order is country rejection, local reputation blocks, then port/custom
blocks, followed by the existing Merlin/Skynet policy. An allowed country does not
override a bad reputation or another firewall's block. Local/special-use addresses
remain subject to the original firewall; no blanket ACCEPT rule is inserted.

Remove conflicting country blocks in the original Skynet interface deliberately;
this add-on does not override or silently remove them. Keep the native firewall.

## Update country IP lists

Open **Allowed countries > Country list updates**.

| Control | Behavior |
| --- | --- |
| **Update selected country lists now** | Check the country's source commit and fetch selected IPv4 files when changed; unchanged commit-pinned files are reused. |
| **Automatically update selected country lists** | On by default. Turning it off stops scheduled country-source refreshes, not manual refreshes or packet filtering. |
| **Interval (hours)** | Any integer from **1 to 720**; default **24**. For example: 6, 24 or 168 hours. |
| Status | Last attempt/success, next due time, entry count and last error. |

The source is `ebrasha/cidr-ip-ranges-by-country`, branch `master`. Only selected
IPv4 country files are used; the full repository ZIP and IPv6 data are unnecessary.
When the selected countries exactly match the active confirmed country policy,
a successful refresh applies all prepared data together and preserves reputation
and port settings. Changed selections in an unsaved draft are **only cached**;
they still require a normal policy test and confirmation. No partial country list
is activated after a download/validation failure. Unchanged networks do not trigger
a kernel generation rebuild.

Schedules use elapsed hours after the last **attempt** and are evaluated every
five minutes. Lock contention, load/resource limits and failures can defer work.
This is not an exact-time scheduler. On failure, existing loaded data remains in
place and can become stale. A manual retry has a 60-second cooldown.

## GitHub software updates

Open **Updates**. Repository and branch are fixed to
`wootje/MerlinWRTadvancedfirewall`, `main`.

| Desired mode | Settings |
| --- | --- |
| Automatic check and download | Enable GitHub updates, automatic checks and automatic downloads. Default interval: **24 hours**. |
| Check automatically, download manually | Keep updates and automatic checks enabled; turn automatic downloads off. |
| Entirely manual | Keep **Enable GitHub updates** on; turn automatic checks and downloads off. |
| Completely off | Turn **Enable GitHub updates** off. Checks, downloads and installations through this updater are refused, including manual ones. Local application rollback remains available. |

Choose an interval of **1–720 hours** independently of country updates. Settings
persist across restarts. **Software is never installed automatically.** Turning
GitHub updates off does not disable filtering, country updates or reputation lists.
It also does not undo an already installed version or delete a staged package.

**Check for changes** compares commit IDs, not only version numbers. With automatic
downloads enabled, a manual check can also stage the change. **Download checked
update** stages it without installing. **Install downloaded update** requires
confirmation, checks the package again and creates an application backup.
**Restore previous application** restores recorded program files, not an old copy
of current private settings or active kernel rules.

Checks use the public GitHub API; no token is required. Manual check/download
attempts have a 60-second cooldown. Scheduled attempts follow the chosen elapsed-hour
interval through the five-minute maintenance evaluator. Ordinary status refreshes
and packet matching do not query GitHub. A GitHub outage or API limit is not evidence
of a compromised router.

Downloads are limited to 12 MiB compressed, 40 MiB expanded and 400 manifest-listed
files. Unsafe ZIP paths, symlinks, missing/unlisted files, mismatched hashes and
unsupported syntax are rejected. Downloaded Python is parsed, not executed during
staging. Actual installation executes the verified code after your authorization.

Country rules can block GitHub or a feed provider. There is **no hidden bypass** for
updates: inspect the error and adjust your policy deliberately. Existing code/rules
are retained on a failed check or download. See [update design and recovery](docs/UPDATES.md).

## Expanded statistics and router load

Open **Statistics**. The default is one sample per minute, 24 hours of history and
the top 20 entries. Each preference is independently editable without a policy test.

| View | Meaning |
| --- | --- |
| CPU, load and memory | CPU busy percentage measured between samples, load average and available memory. First-sample CPU rate can be unavailable. |
| Interface RX/TX | Byte counters and interval-average Mbit/s for the selected interface; interfaces are not summed. |
| Conntrack occupancy | Kernel table entries/capacity when available, alongside a bounded IPv4 connection-detail snapshot. |
| Top lists | Local IPs, remote IPs, destination ports, protocols and states in the sampled rows. |
| Block reasons | Packet/byte deltas and rates by direction and country/reputation/port/custom-rule decision. |
| Graphs and exports | Select a history window/metric/interface, filter connections, export CSV or a local JSON snapshot/history. |

Statistics are **not a complete connection audit or a list of detected hackers**.
Short flows may be absent; raw-table drops are not logged as conntrack connections.
Known flow bytes are cumulative for still-present flows, not monthly billing totals.
Missing accounting is shown as unavailable. Counter resets/policy regeneration
create a gap, not fabricated lifetime totals. Do not add bridge/VLAN/WAN counters
together: the same traffic can appear on several interfaces.

Kernel filtering remains independent of sample frequency. There is no permanent
packet capture, per-packet USB logging, online reputation call from the statistics
collector, extra web server or always-running Python statistics daemon.

| Resource control | Limit / default |
| --- | --- |
| Combined country/reputation IP-set entries | 200,000; never silently truncate to fit. |
| Detailed connection rows | Default 3,000; policy setting 100–5,000. Scan also has record/time bounds. |
| Statistics sampling | Every 1–60 minutes; default 1. Extra manual samples have a 10-second cooldown. |
| History retention | 1–168 hours; default 24; at most 10,080 compact samples. |
| Storage | RAM history, checkpointed roughly hourly to USB; up to an hour of history may be lost on reboot. |
| Busy router | Detailed sampling defers at high load or below 64 MiB available memory. Updates/activation have stronger checks. |
| Source maintenance | Selected country checks follow their own schedule; Skynet mirror hourly at minute 23; reputation refresh daily at 04:43 router time. |
| Application backups | Retained for review; not automatically pruned. Monitor USB space. |

Long history and a one-minute interval consume more RAM, storage and browser
bandwidth than a five-minute interval. These are bounds, **not measured router
performance guarantees**. For a lighter starting point, use 5-minute statistics,
24-hour history and 24-hour country/GitHub checks. See [statistics definitions](docs/STATISTICS.md).

## IP reputation and IPTables

Skynet mirroring uses a separate local copy of its non-empty blacklist/range sets.
Skynet itself already combines several sources. Optional AbuseIPDB provides an
additional locally matched list and on-demand details. Set your own private API key:

```sh
/jffs/scripts/mcg key
```

The key stays outside the web directory with permissions 0600. The API list is
limited to 10,000 requested IPv4 entries and is normally cached for 24 hours.
Provider quotas/subscription restrictions apply. A local score threshold only
filters the received records; it cannot recover data the provider did not return.
Details are cached for 24 hours with bounded size and request rate. Higher abuse
scores indicate more evidence of misuse, not a better safety rating.

The full raw/mangle/nat/filter IPTables view is read-only. The editor accepts up to
12 own validated DROP rules, for example:

```text
out -p tcp --dport 853 -j DROP
both -p udp --dport 1900 -j DROP
```

Only `in`, `out`, `both`, protocol, source/destination networks, source/destination
ports and `-j DROP` are accepted. No arbitrary shell, ACCEPT, global flush or
unrestricted modifications to other add-ons' rules are exposed.

## Upgrade, diagnostics and recovery

Install this package from a separate extracted directory with `sh install.sh`, or
use the online bootstrap after publication. The 0.2.0 updater can also stage a
consistent 0.3.0 package. The 0.1.0 interface needs the manual/online first upgrade.
Legacy `mcg` command and directory names are intentionally retained.

Application replacement preserves confirmed filtering settings, cached source data
and API keys; it does not immediately rebuild active kernel rules. Existing source
schedules can rebuild them later using the new code. Retest preflight and review
changes before relying on an upgraded firewall. Rollback to 0.2.0 restores its old
fixed schedules and simpler UI; the new schedule preferences take effect again
when 0.3.0 is restored. See the detailed compatibility notes in UPDATES.md.

Useful individual commands (each is safe to run in an interactive session without
an appended `|| exit 1`):

```sh
/jffs/scripts/mcg doctor
/jffs/scripts/mcg status
/jffs/scripts/mcg country-refresh
/jffs/scripts/mcg stats-refresh
/jffs/scripts/mcg update-check
/jffs/scripts/mcg update-download
/jffs/scripts/mcg update-rollback
```

Normal persistent disable:

```sh
/jffs/scripts/mcg disable
```

Emergency disable also works without Python/USB:

```sh
/jffs/scripts/mcg emergency-off
```

It flushes only add-on anchors and creates a temporary marker. A reboot removes
that marker and can restore confirmed filtering. Repair Python/USB and use normal
`disable` before reboot when it must stay off. To deliberately clear the temporary
marker, use `/jffs/scripts/mcg clear-emergency`, then test again.

Uninstall with:

```sh
sh /opt/share/merlin-country-guard/uninstall.sh
```

Private data, API keys, staged files and application backups remain for separate
review/removal. No recovery has been validated under actual power/storage loss.

## Files and privacy

| Purpose | Path |
| --- | --- |
| Application | `/opt/share/merlin-country-guard` |
| Launcher | `/jffs/scripts/mcg` |
| Private configuration, key and preferences | `/opt/var/lib/merlin-country-guard` |
| Staged update | `/opt/var/lib/merlin-country-guard/updates` |
| Application backups | `/opt/var/backups/merlin-country-guard` |
| Runtime statistics/status | `/tmp/merlin-country-guard` |
| Installation logs | `/tmp/mafw-install.*`, `/tmp/mafw-bootstrap.*` |
| Scheduled logs | `/tmp/mcg-tick.log`, `/tmp/mcg-maintenance.log`, `/tmp/mcg-mirror.log`, `/tmp/mcg-refresh.log` |

Connection and IPTables exports expose network details. Review/redact them before
sharing. Keep WAN administration off; actual firmware authentication/CSRF and
static-file access controls still require hardware validation. The surrounding
ASUS menus follow your firmware's language; the add-on's own interface is English.

## Publish this package on GitHub

Copy the **contents** of the project folder to the repository root on `main`, not
the ZIP itself or an extra `MerlinWRTadvancedfirewall/` directory. Keep all manifest
files and the source in one coherent commit. Include hidden files such as `.github`.
Nothing has been uploaded to the repository by this delivery.

For later edits on Linux/WSL (development tools, not router commands):

```sh
# Regenerate the standalone bootstrap after editing tools/bootstrap.py.
python3 tools/build_installer.py
# Regenerate the offline demo/native body after changing the interface.
python3 build_preview.py
python3 -m unittest discover -s tests -v
node --check web/guard.js
sh -n install.sh
sh -n tools/install-online.sh
sh -n uninstall.sh
sh -n mcg

# LAST: after all source, docs, generated screenshots and test evidence changes.
python3 tools/build_manifest.py
python3 tools/build_manifest.py --check
```

The manifest builder works on Windows too; backend tests require Unix facilities.
Keep LF line endings. Do not rebuild the preview or edit files after the final
manifest unless you regenerate it. Full instructions: [CONTRIBUTING.md](CONTRIBUTING.md).

From your existing checkout, review and publish without force-pushing:

```sh
git status
git add .
git update-index --chmod=+x install.sh uninstall.sh mcg tools/install-online.sh
git diff --cached --stat
git commit -m "Add one-command install, independent update schedules and richer statistics"
git push origin main
```

Do not commit private configuration, API keys, unrelated files or generated ZIPs.
A stale manifest correctly prevents installation; do not turn off verification.
Commit-based detection also notices documentation changes without a version bump.
CI verifies consistency; it does not publish releases, install on routers or approve
security. The router verifies the package manifest, not the GitHub CI result.

## Test status, license and sources

**167 offline tests and 30 browser-demo checks passed in the development container.**
No physical-router installation, packet-path test, throughput measurement or live
GitHub installation of this release has been completed. Read the exact scope in
[TEST-RESULTS.md](docs/TEST-RESULTS.md) before activating filtering.

Independent add-on code is MIT licensed. External firmware, Skynet, country data,
services and trademarks retain their own terms. See [third-party notices](THIRD_PARTY_NOTICES.md),
[security policy](SECURITY.md) and [primary references](docs/SOURCES.md).
