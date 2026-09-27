#!/usr/bin/env python3
"""Rebuild the self-contained network bootstrap after editing bootstrap.py."""
from pathlib import Path
R=Path(__file__).resolve().parents[1]
header='''#!/bin/sh
# Downloaded code runs as administrator. Trust this repository before running it.
# Execute with sh; do not source. Never disables TLS verification or firewall rules.
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/opt/sbin:/opt/bin
export PATH
umask 077
@@PORTABLE_LOGGING@@
if [ "${1:-}" != --worker ]; then
    mafw_run_logged bootstrap sh "$0" --worker "$@"
    exit "$?"
fi
shift
set -eu
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "Bootstrap failed; the error above explains why. Your login shell was not instructed to exit." >&2; fi' 0
[ "$(id -u)" = 0 ] || { echo 'Run as the router administrator/root.' >&2; exit 1; }
command -v nvram >/dev/null || { echo 'Merlin nvram is missing; this is not a supported router.' >&2; exit 1; }
[ "$(nvram get productid)" = GT-AX11000 ] || { echo 'This beta is prepared for the GT-AX11000 only.' >&2; exit 1; }
[ "$(nvram get jffs2_scripts)" = 1 ] || { echo 'Enable JFFS custom scripts and configs in Administration / System first.' >&2; exit 1; }
case "$(nvram get rc_support)" in *am_addons*) ;; *) echo 'The native Merlin Addons API is missing.' >&2; exit 1 ;; esac
[ -x /opt/bin/opkg ] && [ -w /opt ] || { echo 'Install and mount Entware using amtm first.' >&2; exit 1; }
echo '[1/4] Checking bootstrap dependencies...'
NEEDED=
if ! /opt/bin/python3 -c 'import sys,fcntl,resource,zipfile,hashlib,json,ast,ipaddress,unicodedata; assert sys.version_info >= (3,9)' >/dev/null 2>&1; then NEEDED=python3; fi
if ! command -v curl >/dev/null 2>&1; then NEEDED="$NEEDED curl"; fi
if [ -n "$NEEDED" ]; then
    /opt/bin/opkg update
    /opt/bin/opkg install $NEEDED
fi
/opt/bin/python3 -B - <<'MAFW_BOOTSTRAP_PY'
'''
common=(R/'tools/installer-log.sh').read_text()
header=header.replace('@@PORTABLE_LOGGING@@',common)
local=R/'install.sh'
text=local.read_text()
start=text.index('# BEGIN MAFW PORTABLE INSTALLER LOGGING')
end=text.index('# END MAFW PORTABLE INSTALLER LOGGING')+len('# END MAFW PORTABLE INSTALLER LOGGING\n')
local.write_text(text[:start]+common+text[end:])
(R/'tools/install-online.sh').write_text(header+(R/'tools/bootstrap.py').read_text()+"\nMAFW_BOOTSTRAP_PY\n")
print('Rebuilt tools/install-online.sh')
