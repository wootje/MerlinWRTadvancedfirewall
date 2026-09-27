#!/bin/sh
# Downloaded code runs as administrator. Trust this repository before running it.
# Execute with sh; do not source. Never disables TLS verification or firewall rules.
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
#!/usr/bin/env python3
"""Commit-pinned first installation. Run by tools/install-online.sh, not a daemon.

Unlike the software updater, this bootstrap cannot rely on a previously installed
trusted verifier. Its trust root is the explicitly selected repository over HTTPS.
The manifest is an integrity check, not an independent publisher signature.
"""
from pathlib import Path, PurePosixPath
import hashlib
import json
import os
import re
import resource
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

REPO = "wootje/MerlinWRTadvancedfirewall"
MAX_ARCHIVE = 12 * 1024**2
MAX_EXPANDED = 40 * 1024**2
MAX_FILES = 400


class BootstrapError(Exception):
    pass


def download(url, path, limit):
    if not re.fullmatch(r"https://(?:api\.github\.com|raw\.githubusercontent\.com|codeload\.github\.com)/[A-Za-z0-9_./-]+", url):
        raise BootstrapError("Unexpected bootstrap URL.")
    def file_limit():
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    args = ["curl", "--fail", "--silent", "--show-error", "--proto", "=https", "--connect-timeout", "10",
            "--max-time", "120", "--max-filesize", str(limit), "--user-agent", "MAFW-Bootstrap/0.3.1",
            "--url", url, "--output", str(path)]
    try:
        result = subprocess.run(args, stderr=subprocess.PIPE, timeout=130, preexec_fn=file_limit)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BootstrapError("Download unavailable or timed out; no TLS bypass was used.") from exc
    if result.returncode or not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise BootstrapError("Download failed: " + result.stderr.decode(errors="replace")[:350])


def safe_name(name):
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_./-]{1,220}", name):
        raise BootstrapError("Invalid manifest path.")
    p = PurePosixPath(name)
    if p.is_absolute() or any(x in ("", ".", "..") for x in name.split("/")):
        raise BootstrapError("Unsafe manifest path.")
    return name


def manifest_valid(manifest):
    if not isinstance(manifest, dict) or manifest.get("project") != "MerlinWRTadvancedfirewall" or manifest.get("schema") != 1 or manifest.get("install_protocol") != 1:
        raise BootstrapError("Missing or incompatible package manifest. Publish the extracted package at the repository root.")
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", str(manifest.get("version", ""))):
        raise BootstrapError("Invalid version.")
    files = manifest.get("files")
    if not isinstance(files, dict) or not 1 <= len(files) <= MAX_FILES:
        raise BootstrapError("Invalid manifest file count.")
    required = {"install.sh", "guard.py", "updater.py", "VERSION", "tools/install-online.sh"}
    if not required.issubset(files):
        raise BootstrapError("Publish version 0.3.0-beta or later, including tools/install-online.sh, before using this bootstrap.")
    for name, digest in files.items():
        safe_name(name)
        if name in ("manifest.json", "SHA256SUMS") or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise BootstrapError("Invalid checksum entry.")
    return files


def extract_checked(archive, destination, manifest):
    files = manifest_valid(manifest)
    allowed = set(files) | {"manifest.json", "SHA256SUMS"}
    seen, roots, total = set(), set(), 0
    with zipfile.ZipFile(archive) as z:
        infos = z.infolist()
        if len(infos) > MAX_FILES * 3:
            raise BootstrapError("Too many archive entries.")
        for entry in infos:
            raw = entry.filename.rstrip("/")
            safe_name(raw)
            parts = raw.split("/")
            roots.add(parts[0])
            kind = stat.S_IFMT(entry.external_attr >> 16)
            if entry.flag_bits & 1 or kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise BootstrapError("Encrypted or non-regular archive member refused.")
            if entry.is_dir(): continue
            if len(parts) < 2: raise BootstrapError("Missing enclosing archive directory.")
            relative = "/".join(parts[1:])
            if relative not in allowed or relative in seen:
                raise BootstrapError("Unlisted or duplicate package member: " + relative)
            seen.add(relative)
            total += entry.file_size
            if entry.file_size > MAX_ARCHIVE or total > MAX_EXPANDED:
                raise BootstrapError("Archive exceeds the size limit.")
        if len(roots) != 1 or not (set(files) | {"manifest.json"}).issubset(seen):
            raise BootstrapError("Archive is incomplete or has multiple roots.")
        destination.mkdir(exist_ok=False)
        for entry in infos:
            if entry.is_dir(): continue
            relative = "/".join(entry.filename.split("/")[1:])
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            copied = 0
            digest = hashlib.sha256()
            with z.open(entry) as source, target.open("xb") as out:
                while True:
                    chunk = source.read(65536)
                    if not chunk: break
                    copied += len(chunk)
                    if copied > entry.file_size or copied > MAX_ARCHIVE:
                        raise BootstrapError("Unexpected expanded file size.")
                    digest.update(chunk)
                    out.write(chunk)
            if relative in files and digest.hexdigest() != files[relative]:
                raise BootstrapError("Checksum mismatch: " + relative)
            target.chmod(0o600)
    if json.loads((destination / "manifest.json").read_text()) != manifest:
        raise BootstrapError("Archive manifest does not match the pinned manifest.")
    if (destination / "VERSION").read_text().strip() != manifest["version"]:
        raise BootstrapError("Package version mismatch.")


def main():
    if os.geteuid() != 0:
        raise BootstrapError("Run as the router administrator/root.")
    base = Path("/opt/tmp")
    base.mkdir(exist_ok=True)
    if shutil.disk_usage(base).free < 128 * 1024**2:
        raise BootstrapError("At least 128 MiB free Entware/USB storage is required.")
    mem = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        k, value = line.split(":", 1)
        mem[k] = int(value.split()[0]) * 1024
    available = mem.get("MemAvailable", mem.get("MemFree", 0) + mem.get("Buffers", 0) + mem.get("Cached", 0))
    if available < 96 * 1024**2:
        raise BootstrapError("At least 96 MiB available RAM is required for installation.")
    with tempfile.TemporaryDirectory(prefix="mafw-bootstrap-", dir=str(base)) as work:
        work = Path(work)
        print("[2/4] Resolving GitHub main to an immutable commit...", flush=True)
        download("https://api.github.com/repos/" + REPO + "/commits/main", work / "commit.json", 2 * 1024**2)
        sha = json.loads((work / "commit.json").read_text()).get("sha", "")
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise BootstrapError("GitHub returned no valid commit hash.")
        download("https://raw.githubusercontent.com/" + REPO + "/" + sha + "/manifest.json", work / "manifest.json", 200000)
        manifest = json.loads((work / "manifest.json").read_text())
        manifest_valid(manifest)
        print("[3/4] Downloading and verifying " + manifest["version"] + " / " + sha[:12] + "...", flush=True)
        download("https://codeload.github.com/" + REPO + "/zip/" + sha, work / "source.zip", MAX_ARCHIVE)
        extract_checked(work / "source.zip", work / "source", manifest)
        print("[4/4] Starting the verified local installer...", flush=True)
        return subprocess.call(["sh", str(work / "source/install.sh"), "--commit", sha], cwd=str(work / "source"))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("BOOTSTRAP ERROR: " + str(exc), file=sys.stderr)
        sys.exit(1)

MAFW_BOOTSTRAP_PY
