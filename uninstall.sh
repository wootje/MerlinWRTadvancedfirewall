#!/bin/sh
set -eu
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/opt/sbin:/opt/bin
export PATH
[ "$(id -u)" = 0 ] || { echo 'Root is required.' >&2; exit 1; }
APP=/opt/share/merlin-country-guard
[ -x /opt/bin/python3 ] || { echo 'Python is required for normal removal. First use /jffs/scripts/mcg emergency-off.' >&2; exit 1; }
/jffs/scripts/mcg disable
/opt/bin/python3 "$APP/install_support.py" uninstall
# Remove ONLY exact entrypoint jumps and owned empty anchor chains.
while iptables -t raw -D PREROUTING -j MCG_PRE 2>/dev/null; do :; done
while iptables -t raw -D OUTPUT -j MCG_OUT 2>/dev/null; do :; done
iptables -t raw -X MCG_PRE 2>/dev/null || true
iptables -t raw -X MCG_OUT 2>/dev/null || true
rm -f /jffs/scripts/mcg /tmp/mcg-emergency-off
rm -rf "$APP"
echo 'Add-on removed. Merlin/Skynet and other add-ons were not removed.'
echo 'Private data, API key and backups remain under /opt/var/lib/merlin-country-guard and /opt/var/backups/merlin-country-guard.'
echo 'Delete those directories only after reviewing them if you also want to erase that data.'
