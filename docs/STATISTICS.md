# Statistics: definitions, cost and limits

Version 0.3.0-beta adds a bounded sampler, not full packet capture or an accounting
daemon. Sampling occurs from the existing one-minute maintenance tick when due.
The web page reads cached JSON; opening a chart does not scan conntrack or contact
an external IP service.

## Controls

| Preference | Range | Default |
| --- | --- | --- |
| Sample interval | 1–60 minutes | 1 minute |
| History retention | 1–168 hours | 24 hours |
| Top entries per ranking | 5–50 | 20 |

Saving statistics preferences does not change countries, reputation settings,
ports, ipsets or packet filtering. Manual sampling uses the same bounds and has a
10-second cooldown. The policy's separate connection-row cap is 100–5,000,
default 3,000; the browser renders at most 250 matching detail rows, while CSV
includes all collected matching rows.

The scan stops at the row cap, a maximum of 100,000 scanned records or an
approximately three-second time budget, checked periodically. These are not exact
hard realtime deadlines. Truncated/unavailable data is explicitly marked.
Rankings describe only the rows retained, not the entire conntrack table.

## CPU and memory

CPU busy percentage is the delta of Linux aggregate CPU ticks between successful
samples, excluding idle and I/O-wait ticks. It is not a process-level CPU profile.
The first observation, a reboot or invalid/reset counters produce an unavailable
rate rather than zero. Load average is shown separately and is not a percentage.
Available memory is the kernel's estimate, not just unused RAM.

Detailed sampling is deferred when available RAM is below 64 MiB or load average
exceeds 1.5 times detected CPU count. The previous sample remains visible with a
warning. Statistics use no online reputation API. Kernel filtering is independent
of whether a detail sample was skipped.

## Interface throughput

RX/TX counters are read per interface. Interval-average rates are computed from
the counter delta divided by monotonic elapsed time, in bits per second. The UI
shows Mbit/s. Cumulative counters represent what the kernel reports for that
interface, normally since its counter reset, not a chosen billing period.

Select the appropriate WAN or LAN interface deliberately. A packet can be counted
on an Ethernet interface, a VLAN and a bridge, so this add-on does not sum interface
figures into a purported total internet usage number. Reboots, counter decreases
and newly appearing interfaces reset the baseline and create a gap.

## Connection observations and top lists

Conntrack occupancy uses the kernel's entry count and configured maximum when
available. Its scope can differ from the retained IPv4 detail snapshot.

Local/remote attribution uses private/link-local/loopback IPv4 ranges and the
original/reply tuples. Incoming DNAT can associate the remote address with the
internal reply-source host. Router-public/public tuples without a private endpoint
are labelled accordingly; not every environment permits reliable device attribution.
Ports are original destination ports and are combined with protocol, such as
`tcp/443`. State is reported as available, not inferred as maliciousness.

Top local IPs, remote IPs, ports, protocols and states are ranked by observed
connection count, then known flow bytes. Flow-byte values are cumulative for
connections still present in the snapshot; they are **not** bytes sent during the
sample interval or lifetime device usage. When conntrack accounting is absent,
bytes remain unavailable and the UI reports the limited accounting coverage.

A connection that starts and finishes between samples can be absent even though
its packets were filtered. Increasing sampling frequency does not turn this into
a lossless traffic audit. IPs, state labels and large connection counts are not
proof of attackers or compromised systems.

## Rule decisions and blocked rates

Own raw-table rule counters are grouped by direction, reason and target. Deltas
are valid only within the same kernel-policy generation and boot, with nondecreasing
counters. Packet/byte totals in the raw IPTables view are generation-scoped; a new
policy rebuild starts new counters. There is no fabricated lifetime total spanning
missing generations.

Country rejection happens before reputation/port rules. Packets rejected there
cannot be counted again as reputation blocks later in this add-on. The figures
refer to packets, **not unique blocked connections or unique attackers**.

Raw-table drops happen before normal conntrack recording, so this implementation
does not have a per-IP list of every blocked flow. A “passed” counter only means
passed this add-on's rules; another Merlin/Skynet rule may still reject that packet.
No flood-prone LOG target or per-packet disk logging is added for richer statistics.

## History and exports

Compact samples contain time, load/CPU, memory, observed counts, blocked rate and
per-interface rates. Detailed connection rows and rankings are retained only for
the current snapshot, not appended to every history sample. There is a cap of
10,080 compact history records. Old/out-of-window records are discarded.

History is maintained in RAM and checkpointed approximately hourly to USB. Up to
one hour of samples can be lost after a reboot/crash, and rate continuity restarts
after reboot. Tick/repair work still runs each minute even when statistics are set
to a slower interval. A longer history increases JSON size, RAM use and browser
transfer cost; choose a slower sample interval to reduce this cost.

CSV exports the selected ranking or collected filtered connections. JSON exports
local status/history and, when selected in the UI, current connection details.
These files contain private network information. No export is uploaded automatically.
The preview and its screenshots use synthetic data, never evidence from a router.

## Not supplied by these statistics

There is no TLS payload decryption, application/process identification on remote
clients, country-by-country historical byte accounting, full DNS enrichment, full
flow logging, packet capture, per-IP blocked-flow history or guaranteed complete
threat detection. Such features would require additional data collection and
resource/privacy trade-offs. No actual GT-AX11000 performance measurement has yet
been performed for this release.
