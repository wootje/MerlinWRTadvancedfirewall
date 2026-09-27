# Safety, scope and limitations

This is a beta add-on, not a validated security appliance. Do not deploy it as the
only protection for a production network. Keep the native firewall and Skynet,
back up router configuration and use a wired management session.

## What is inspected

The add-on targets public IPv4 traffic traversing its raw-table software chains.
It checks country membership first, then local reputation sets, then port/custom
DROP rules. Rejected countries do not need reputation checks. An allowed country
never overrides an existing block. Unmatched traffic returns to the existing
router policy; the add-on does not issue blanket ACCEPT rules.

Local and special-use IPv4 addresses return to the original firewall without this
add-on's public-IP checks. No new local-network permission is created. This add-on
does not edit IPv6 rules; activation requires IPv6 to be explicitly disabled.
Existing connections are not exempt from these software-chain checks.

Same-switch/bridge traffic, routes bypassing this router, hardware-accelerated
flows and tunnel payloads are not automatically inspected. Country assignments can
be stale or inaccurate, and a country is not proof of a user's physical location.
VPNs, proxies and hosting providers limit geofencing. IP reputation misses unknown
or newly abused addresses and may include false positives. Absence from a list
is not proof of safety. HTTPS payloads are not decrypted by this add-on.

## Acceleration and performance

Preflight requires explicit disabled statuses for Flow Cache and hardware
acceleration. Unknown is not treated as disabled. It reads `/bin/fc status`;
firmware-specific acceleration-disable procedures and clearing already accelerated
flows must be verified on the actual router. Text-status checks are not a measured
packet-path test. Disabling acceleration can affect throughput; no gigabit speed
claim is made.

IP-set sizes, RAM, archive sizes, history and connection snapshots are bounded.
Temporary old/new IP-set generations require extra memory. The Skynet mirror
duplicates entries rather than holding direct references to Skynet's own sets.
Resource limits reduce risk but do not prove acceptable performance under attack.

## Policy trials and emergency recovery

Policy changes are prepared before activation. A 120-second watchdog is armed
before switching candidate anchors. Confirmation persists the exact configuration
and validated source bundle. Expiry causes a rollback attempt, and a normal reboot
restores only the confirmed policy. Kernel errors, removed USB, failed Python,
process termination or filesystem failure can defeat recovery; it is not a guarantee.

`/jffs/scripts/mcg disable` persists a disabled configuration. The JFFS launcher
also supports `emergency-off` without Python/USB. It flushes only the two add-on
anchors and places a temporary marker preventing automatic repair from re-enabling
its policy. Reboot removes the marker and may restore confirmed filtering. Repair
storage/Python and disable normally when persistence is required. `clear-emergency`
only removes the marker; it is not proof that filtering is active again.

Arbitrary third-party hook scripts may exit early or alter ordering. The installer
preserves unrelated lines and a conventional final `exit`, but cannot prove the
behavior of every customized shell program. Inspect unusual native hooks manually.
The shared menu uses the native temporary menu/bind-mount mechanism; it does not
rewrite the firmware image. Native session handling, static-file access controls
and CSRF behavior require testing on the real firmware.

## Software updates

Software updates preserve private settings and do not flush active kernel rules.
The code used at a later scheduled policy rebuild may change, so review release
changes and retest after updates. Automatic downloads do not imply automatic
installation. Commit pinning, TLS and file hashes reduce accidental inconsistency;
they do not defend against a malicious or compromised repository maintainer.

Caught installation failures trigger an application-file recovery attempt.
Power/storage loss is different and can require manual recovery. See
[UPDATES.md](UPDATES.md). There is no promise of atomic recovery across all flash,
USB, launcher, menu and filesystem operations.

## Credentials and privacy

The AbuseIPDB key is stored outside the web directory with root-only permissions.
There is no extra listening web server. Changes use Merlin's existing authenticated
add-on route, not a new unauthenticated API. Keep WAN administration disabled and
isolate untrusted LAN clients. Do not expose the router UI or its static diagnostic
files directly to the internet.

Status, connection snapshots and IPTables exports can expose private addresses and
network details. Redact them before sharing. Manual online IP details send the
requested public address to AbuseIPDB. GitHub checks contact GitHub from your router.
Automatic packet matching does not send each connection address to a remote service.
The browser preview uses synthetic data only.
