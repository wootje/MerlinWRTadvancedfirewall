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
