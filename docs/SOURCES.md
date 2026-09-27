# Primary sources and compatibility references

Documentation reviewed for the installation/scheduling/statistics package on 27 September 2026.
External service terms, limits and code can change. Local tests do not establish
live service compatibility or successful operation on router hardware.

## Project and source lineage

- Target project: https://github.com/wootje/MerlinWRTadvancedfirewall
- Skynet: https://github.com/Adamm00/IPSet_ASUS
- Merlin Addons API: https://github.com/RMerl/asuswrt-merlin/wiki/Addons-API
- Merlin acceleration status implementation: https://github.com/RMerl/asuswrt-merlin.ng/blob/main/release/src/router/httpd/sysinfo.c

This release evolves the supplied independent Country Guard 0.1.0-beta and
English MerlinWRT Advanced Firewall 0.2.0-beta packages.
It does not bundle the original Skynet firewall program, firmware assets or
third-party reputation databases. The native integration uses userN.asp pages,
`amng_custom`, `service-event`, `am_settings_get` and add-on-marked hook lines.

## Country data and kernel matching

- Country CIDR source: https://github.com/ebrasha/cidr-ip-ranges-by-country
- Country source README: https://raw.githubusercontent.com/ebrasha/cidr-ip-ranges-by-country/master/README.md
- IP-set manual: https://ipset.netfilter.org/ipset.man.html

Country file paths are discovered through the commit/tree API, selected by country
code/name aliases and pinned to the discovered commit. Only selected IPv4 files
are downloaded. This release does not independently validate every live country
file or the accuracy of the dataset. Unknown layouts/missing files fail explicitly.
`countries.json` is a local country-name/code selection catalogue, not a GeoIP map.

## Reputation

- AbuseIPDB API: https://docs.abuseipdb.com/
- Skynet feed list: https://github.com/Adamm00/IPSet_ASUS/blob/master/filter.list

The integration uses `/api/v2/blacklist` for an optional locally matched list and
`/api/v2/check` for optional address details. API keys use a request header; provider
limits and subscription-dependent threshold behavior apply. Received records are
filtered locally by score. Skynet already combines several feeds; a second provider
does not imply every unknown address is covered.

## GitHub software updates

- Commit API: https://docs.github.com/en/rest/commits/commits
- Repository archives: https://docs.github.com/en/rest/repos/contents#download-a-repository-archive-zip
- Downloading source archives: https://docs.github.com/en/repositories/working-with-files/using-files/downloading-source-code-archives
- REST rate limits: https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
- Checkout action: https://github.com/actions/checkout

The updater queries a public branch commit, fetches a manifest at that immutable
commit and uses a commit-specific codeload archive. Public API reads do not require
a GitHub token but are rate-limited. The fixed repository and commit checks do not
provide independent maintainer-signature validation.

The public target repository's raw VERSION was 0.2.0-beta when checked during this
release session. The new package was not pushed to GitHub. Web-based source reading
is distinct from running the actual bootstrap: live downloads/installations from
a published 0.3.0 package must still be tested after upload. Included tests use
synthetic API responses/archives.

## Dependencies and measurements

- Entware Python package definition: https://github.com/Entware/entware-packages/blob/master/lang/python/python3/Makefile
- Linux proc interface documentation: https://www.kernel.org/doc/html/latest/filesystems/proc.html

The installer uses Entware's python3 package and native/Entware curl. Telemetry
reads kernel proc data and own rule counters; it does not use an external analytics
service. CPU/network figures in the demo are synthetic, not benchmark results.

- BusyBox mktemp implementation/template requirements: https://github.com/mirror/busybox/blob/master/coreutils/mktemp.c
