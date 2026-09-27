#!/bin/sh
# Execute with: sh install.sh. Never source this script into an SSH login shell.
# Failure exits only this child script; it does not run `exit` in the login shell.
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/opt/sbin:/opt/bin
export PATH
umask 077

# BEGIN MAFW PORTABLE INSTALLER LOGGING
# No external temporary-file or FIFO utility is required. Keep this block in
# sync with tools/installer-log.sh using python3 tools/build_installer.py.
mafw_log_directory() {
    case "$1" in install|bootstrap) ;; *) return 1 ;; esac
    MAFW_TRY=0
    while [ "$MAFW_TRY" -lt 32 ]; do
        MAFW_DIR="/tmp/mafw-$1.$$.$MAFW_TRY"
        # Never use mkdir -p: an existing directory/symlink must not be reused.
        if (umask 077; mkdir "$MAFW_DIR") 2>/dev/null; then
            printf '%s\n' "$MAFW_DIR"
            return 0
        fi
        MAFW_TRY=$((MAFW_TRY + 1))
    done
    printf '%s\n' 'Cannot create a private installation log directory in /tmp.' >&2
    return 1
}

mafw_run_logged() {
    MAFW_KIND=$1
    shift
    MAFW_WORK=$(mafw_log_directory "$MAFW_KIND") || return 1
    MAFW_LOG="$MAFW_WORK/output.log"
    if ! : > "$MAFW_LOG"; then
        rmdir "$MAFW_WORK" 2>/dev/null || :
        printf '%s\n' 'Cannot create the installation log. Check free /tmp space.' >&2
        return 1
    fi
    if [ "$MAFW_KIND" = install ]; then
        printf 'Installation log: %s\n' "$MAFW_LOG"
    else
        printf 'Bootstrap log: %s\n' "$MAFW_LOG"
    fi
    if command -v tee >/dev/null 2>&1; then
        # A pipeline alone reports tee's status, not the worker's. Save the
        # worker status inside the private directory; fail if it is missing.
        (
            "$@"
            MAFW_WORKER_RC=$?
            printf '%s\n' "$MAFW_WORKER_RC" > "$MAFW_WORK/exit-status"
        ) 2>&1 | tee -a "$MAFW_LOG"
        MAFW_TEE_RC=$?
        MAFW_RC=1
        if [ -f "$MAFW_WORK/exit-status" ]; then
            IFS= read -r MAFW_RC < "$MAFW_WORK/exit-status" || MAFW_RC=1
        fi
        case "$MAFW_RC" in ''|*[!0-9]*) MAFW_RC=1 ;; esac
        [ "$MAFW_RC" -le 255 ] 2>/dev/null || MAFW_RC=1
        rm -f "$MAFW_WORK/exit-status"
        if [ "$MAFW_TEE_RC" -ne 0 ]; then
            printf '%s\n' 'WARNING: Live logging failed; inspect the log and actual installation state.' >&2
            [ "$MAFW_RC" -ne 0 ] || MAFW_RC=1
        fi
    else
        # Minimal firmware without tee: retain output and replay it afterwards.
        printf '%s\n' 'Live logging is unavailable; output will be shown when this step finishes.'
        "$@" > "$MAFW_LOG" 2>&1
        MAFW_RC=$?
        cat "$MAFW_LOG" || :
    fi
    if [ "$MAFW_RC" -ne 0 ]; then
        if [ "$MAFW_KIND" = install ]; then
            printf 'Installation stopped (exit %s). Your SSH login shell was not instructed to exit.\n' "$MAFW_RC"
        else
            printf 'Bootstrap stopped (exit %s). Your SSH login shell was not instructed to exit.\n' "$MAFW_RC"
        fi
        printf "Read the error: cat '%s'\n" "$MAFW_LOG"
    else
        printf 'Completed. Log: %s\n' "$MAFW_LOG"
    fi
    # Keep the private directory and log for diagnostics. /tmp is cleared on
    # reboot. Do not recursively delete a path that could contain diagnostics.
    return "$MAFW_RC"
}
# END MAFW PORTABLE INSTALLER LOGGING

if [ "${1:-}" != --worker ]; then
    SELF=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/$(basename -- "$0")
    mafw_run_logged install sh "$SELF" --worker "$@"
    exit "$?"
fi
shift
set -eu
PHASE='starting'
trap 'rc=$?; if [ "$rc" -ne 0 ]; then printf "ERROR during %s (exit %s). No automatic reboot or firewall activation was requested.\n" "$PHASE" "$rc" >&2; fi' 0
COMMIT=
if [ "${1:-}" = --commit ] && [ "$#" = 2 ]; then
    COMMIT=$2
elif [ "$#" != 0 ]; then
    echo 'Usage: sh install.sh [--commit 40-character-commit-hash]' >&2
    exit 1
fi
PHASE='router prerequisites'
echo '[1/5] Checking router and Entware prerequisites...'
[ "$(id -u)" = 0 ] || { echo 'Run as the router administrator/root.' >&2; exit 1; }
command -v nvram >/dev/null || { echo 'This is not an Asuswrt-Merlin router: nvram is missing.' >&2; exit 1; }
[ "$(nvram get productid)" = GT-AX11000 ] || { echo 'This beta is prepared for the GT-AX11000 only.' >&2; exit 1; }
case "$(nvram get rc_support)" in *am_addons*) ;; *) echo 'Native Merlin Addons API missing.' >&2; exit 1 ;; esac
[ "$(nvram get jffs2_scripts)" = 1 ] || { echo 'Enable JFFS custom scripts and configs in Administration / System.' >&2; exit 1; }
[ -x /opt/bin/opkg ] && [ -d /jffs/scripts ] || { echo 'Working USB-mounted Entware and /jffs/scripts are required. Set up Entware using amtm first.' >&2; exit 1; }
[ -w /opt ] || { echo 'Entware /opt is not writable.' >&2; exit 1; }
PHASE='Python and curl dependencies'
echo '[2/5] Checking dependencies; installing missing packages only...'
NEEDED=
if ! /opt/bin/python3 -c 'import sys,ast,fcntl,resource,zipfile,hashlib,json,ipaddress,unicodedata; assert sys.version_info >= (3,9)' >/dev/null 2>&1; then NEEDED=python3; fi
if ! command -v curl >/dev/null 2>&1; then NEEDED="$NEEDED curl"; fi
if [ -n "$NEEDED" ]; then
    /opt/bin/opkg update
    # NEEDED contains fixed package names only, not user input.
    /opt/bin/opkg install $NEEDED
fi
/opt/bin/python3 -c 'import sys,ast,fcntl,resource,zipfile,hashlib,json,ipaddress,unicodedata; assert sys.version_info >= (3,9), "Python 3.9+ with the complete required standard library is needed"'
for c in iptables iptables-save iptables-restore ipset curl cru mount; do
    command -v "$c" >/dev/null || { echo "Required program missing: $c" >&2; exit 1; }
done
mkdir -p /opt/share /opt/var
[ -w /opt/share ] && [ -w /opt/var ] || { echo '/opt/share and /opt/var must be writable.' >&2; exit 1; }
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ "$SRC" != /opt/share/merlin-country-guard ] || { echo 'Install from a separate USB directory, not the live application directory.' >&2; exit 1; }
cd "$SRC"
PHASE='package verification'
echo '[3/5] Verifying the manifest, hashes and source syntax...'
/opt/bin/python3 -B tools/build_manifest.py --check
PHASE='application installation and native WebUI integration'
echo '[4/5] Backing up application files and installing the verified package...'
/opt/bin/python3 -B - "$SRC" "$COMMIT" <<'PY'
import sys
from pathlib import Path
import guard
import updater
guard.setup()
try:
    with guard.locked():
        result = updater.install_tree(Path(sys.argv[1]), commit=sys.argv[2] or None)
        print(result['message'])
        print('Application backup: ' + result['backup'])
        page = guard.DATA / 'page.txt'
        if page.exists():
            print('Web page: /' + page.read_text().strip() + ' on the existing router administration host and port.')
except Exception as exc:
    print('INSTALL ERROR: ' + str(exc), file=sys.stderr)
    sys.exit(1)
PY
PHASE='read-only post-install diagnostics'
echo '[5/5] Generating status and read-only preflight diagnostics...'
/jffs/scripts/mcg stats-refresh || echo 'WARNING: Initial statistics/status collection failed; inspect the error above.'
/jffs/scripts/mcg doctor || echo 'WARNING: Preflight command failed; inspect the error above.'
printf '\nInstalled MerlinWRT Advanced Firewall 0.3.1-beta. Fresh installation: filtering OFF.\n'
echo 'Existing confirmed policy, country choices, ports and private API key are preserved.'
echo 'Open Firewall / Advanced Firewall. Country and GitHub schedules are separate.'
echo 'Do not enable filtering unless preflight reports ready: true. Installation success is not proof of filtering coverage.'
echo 'No reboot, global firewall flush, IPv6 change or acceleration change was requested.'
