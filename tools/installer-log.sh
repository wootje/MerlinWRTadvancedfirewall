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
