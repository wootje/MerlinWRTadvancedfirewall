#!/usr/bin/env python3
"""Bounded, commit-pinned GitHub updates. Downloading never executes new code.

All public entry points are called with guard.locked() held. Installation requires
an explicit request. Hashes detect corruption, NOT compromise of the repository.
"""
from __future__ import annotations
import ast
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
import guard as g

REPOSITORY = "wootje/MerlinWRTadvancedfirewall"
BRANCH = "main"
PROJECT = "MerlinWRTadvancedfirewall"
API = "https://api.github.com/repos/" + REPOSITORY
INSTALL_APP = Path("/opt/share/merlin-country-guard")
BACKUPS = Path("/opt/var/backups/merlin-country-guard")
LAUNCHER = Path("/jffs/scripts/mcg")
HOOK_DIR = Path("/jffs/scripts")
MAX_ARCHIVE = 12 * 1024 * 1024
MAX_EXPANDED = 40 * 1024 * 1024
MAX_FILES = 400
DEFAULT_SETTINGS = {"enabled": True, "auto_check": True, "auto_download": True, "interval_hours": 24}
REQUIRED = {"guard.py", "updater.py", "install_support.py", "install.sh", "mcg",
            "uninstall.sh", "countries.json", "web/guard.asp", "web/guard.js",
            "web/guard.css", "VERSION", "README.md", "LICENSE"}
EXECUTABLES = {"guard.py", "updater.py", "install_support.py", "install.sh", "mcg", "uninstall.sh"}
ALLOWED_TOP = REQUIRED | {"web", "docs", "tests", "tools", ".github", "manifest.json",
    "SHA256SUMS", "CHANGELOG.md", "SECURITY.md", "CONTRIBUTING.md", "THIRD_PARTY_NOTICES.md",
    "example-config.json", "build_preview.py", "preview.html", ".gitignore", ".gitattributes", ".editorconfig"}


def _path(name):
    return g.DATA / name


def normalize_settings(value):
    if not isinstance(value, dict) or set(value) - set(DEFAULT_SETTINGS):
        raise g.GuardError("Invalid updater settings.")
    # Only the exact 0.2.0 layout or the new complete layout is accepted.
    if set(value) not in ({"auto_check", "auto_download"}, set(DEFAULT_SETTINGS)):
        raise g.GuardError("Incomplete updater settings.")
    result = dict(DEFAULT_SETTINGS, **value)
    if any(type(result[k]) is not bool for k in ("enabled", "auto_check", "auto_download")):
        raise g.GuardError("Update switches must be true or false.")
    if type(result["interval_hours"]) is not int or not 1 <= result["interval_hours"] <= 720:
        raise g.GuardError("GitHub interval must be an integer from 1 to 720 hours.")
    if result["auto_download"] and not result["auto_check"]:
        raise g.GuardError("Automatic downloads require automatic checks.")
    return result


def settings():
    legacy = g.read_json(_path("update-settings.json"), {"auto_check": True, "auto_download": True})
    value = normalize_settings(legacy)
    policy = g.read_json(_path("update-policy.json"), {})
    if not isinstance(policy, dict) or set(policy) - {"enabled", "interval_hours"}:
        raise g.GuardError("Invalid GitHub update policy file.")
    value.update(policy)
    return normalize_settings(value)


def save_settings(value):
    value = normalize_settings(value)
    old = settings()
    # Retain the 0.2.0 file shape so application rollback can still read it.
    # Full disable also stops the older version's automatic network checks.
    if not value["enabled"]:
        value["auto_check"] = value["auto_download"] = False
    def persist(prefs):
        g.save_json(_path("update-settings.json"), {k: prefs[k] for k in ("auto_check", "auto_download")})
        g.save_json(_path("update-policy.json"), {k: prefs[k] for k in ("enabled", "interval_hours")})
    persist(value)
    try:
        from tools.maintenance import reconcile_schedule
        reconcile_schedule()
    except Exception:
        persist(old)
        raise
    return {"message": "GitHub preferences saved. Installation always requires confirmation.", "updates": status()}


def require_enabled():
    if not settings()["enabled"]:
        raise g.GuardError("GitHub updates are disabled. Enable them in Updates before checking, downloading or installing. Local rollback remains available.")


def valid_commit(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise g.GuardError("Invalid GitHub commit identifier.")
    return value


def safe_relative(name):
    if not isinstance(name, str) or not name or len(name) > 220 or "\\" in name or "\x00" in name:
        raise g.GuardError("Invalid package path.")
    p = PurePosixPath(name)
    if p.is_absolute() or any(x in ("", ".", "..") for x in name.split("/")):
        raise g.GuardError("Unsafe package path: " + name)
    if p.parts[0] not in ALLOWED_TOP or not re.fullmatch(r"[A-Za-z0-9_./-]+", name):
        raise g.GuardError("Unexpected package file: " + name)
    return p


def validate_manifest(obj):
    if not isinstance(obj, dict) or obj.get("schema") != 1 or obj.get("project") != PROJECT or obj.get("install_protocol") != 1:
        raise g.GuardError("Missing or incompatible manifest.json. Publish the complete package at the repository root.")
    if not isinstance(obj.get("version"), str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", obj["version"]):
        raise g.GuardError("Invalid package version.")
    if obj.get("min_python") != [3, 9]:
        raise g.GuardError("Unsupported Python compatibility declaration.")
    files = obj.get("files")
    if not isinstance(files, dict) or not REQUIRED.issubset(files) or not 1 <= len(files) <= MAX_FILES:
        raise g.GuardError("Incomplete or oversized package manifest.")
    for name, digest in files.items():
        safe_relative(name)
        if name in ("manifest.json", "SHA256SUMS") or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise g.GuardError("Invalid package checksum entry.")
    return obj


def verify_tree(root, expected=None):
    root = Path(root)
    obj = validate_manifest(g.read_json(root / "manifest.json", {}))
    if expected is not None and obj != expected:
        raise g.GuardError("Archive manifest differs from the commit-pinned manifest.")
    actual = set()
    for p in root.rglob("*"):
        if p.is_symlink():
            raise g.GuardError("Symlinks are not allowed in an update package.")
        if p.is_file():
            name = p.relative_to(root).as_posix()
            # Interpreter caches are local build products, never installed.
            if "__pycache__" in p.parts or p.suffix == ".pyc" or ".git" in p.parts:
                continue
            safe_relative(name)
            if name not in ("manifest.json", "SHA256SUMS"):
                actual.add(name)
    if actual != set(obj["files"]):
        raise g.GuardError("Package files do not match the manifest. Rebuild the manifest before publishing.")
    total = 0
    python_bytes = 0
    for name, digest in obj["files"].items():
        p = root / name
        total += p.stat().st_size
        if total > MAX_EXPANDED or p.stat().st_size > MAX_ARCHIVE:
            raise g.GuardError("Expanded package exceeds the resource limit.")
        if hashlib.sha256(p.read_bytes()).hexdigest() != digest:
            raise g.GuardError("Checksum mismatch: " + name)
        # Compile only: do not import or execute candidate Python code.
        if name.endswith(".py"):
            python_bytes += p.stat().st_size
            if p.stat().st_size > 512 * 1024 or python_bytes > 2 * 1024**2:
                raise g.GuardError("Python source exceeds the bounded syntax-check budget.")
            try:
                tree = ast.parse(p.read_text(encoding="utf-8"), filename=name, feature_version=(3, 9))
                compile(tree, name, "exec")
            except (SyntaxError, UnicodeError, ValueError) as exc:
                raise g.GuardError("Python syntax check failed: " + name) from exc
    if (root / "VERSION").read_text().strip() != obj["version"]:
        raise g.GuardError("VERSION does not match manifest.json.")
    tree = ast.parse((root / "guard.py").read_text())
    versions = [ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "VERSION" for t in n.targets)]
    if versions != [obj["version"]]:
        raise g.GuardError("guard.py version does not match the package manifest.")
    for name in obj["files"]:
        if name.endswith(".sh") or name == "mcg":
            g.command(["sh", "-n", str(root / name)])
    return obj


def extract_archive(archive, destination, expected):
    """Extract regular manifest-listed files only; reject traversal and zip bombs."""
    validate_manifest(expected)
    wanted = set(expected["files"]) | {"manifest.json", "SHA256SUMS"}
    total = 0
    roots = set()
    seen = set()
    destination = Path(destination)
    with zipfile.ZipFile(archive) as z:
        entries = z.infolist()
        if len(entries) > MAX_FILES * 3:
            raise g.GuardError("Too many archive entries.")
        for info in entries:
            name = info.filename
            if "\\" in name or name.startswith("/") or any(x in (".", "..") for x in name.rstrip("/").split("/")):
                raise g.GuardError("Unsafe archive path.")
            parts = name.rstrip("/").split("/")
            if not parts or not re.fullmatch(r"[A-Za-z0-9_.-]+", parts[0]):
                raise g.GuardError("Invalid archive root.")
            roots.add(parts[0])
            mode = info.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if info.flag_bits & 1 or kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise g.GuardError("Encrypted or non-regular archive entry rejected.")
            if info.is_dir():
                continue
            if len(parts) < 2:
                raise g.GuardError("Expected a GitHub archive with one enclosing directory.")
            relative = "/".join(parts[1:])
            safe_relative(relative)
            if relative not in wanted or relative in seen:
                raise g.GuardError("Unlisted or duplicate archive file: " + relative)
            seen.add(relative)
            total += info.file_size
            if info.file_size > MAX_ARCHIVE or total > MAX_EXPANDED:
                raise g.GuardError("Expanded archive exceeds the resource limit.")
        if len(roots) != 1 or not (set(expected["files"]) | {"manifest.json"}).issubset(seen):
            raise g.GuardError("Incomplete archive or multiple archive roots.")
        destination.mkdir(parents=True, exist_ok=False)
        for info in entries:
            if info.is_dir():
                continue
            relative = "/".join(info.filename.split("/")[1:])
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            # ZipFile verifies CRCs. Actual bytes are bounded independently of headers.
            copied = 0
            with z.open(info) as src, target.open("xb") as out:
                while True:
                    chunk = src.read(64 * 1024)
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied > info.file_size or copied > MAX_ARCHIVE:
                        raise g.GuardError("Archive expanded beyond its declared size.")
                    out.write(chunk)
            os.chmod(target, 0o755 if relative in EXECUTABLES else 0o644)
    verify_tree(destination, expected)


def download_archive(sha, target):
    """Fixed host, verified TLS, timeout and OS-enforced output-file size limit."""
    valid_commit(sha)
    url = "https://codeload.github.com/" + REPOSITORY + "/zip/" + sha
    args = ["curl", "--fail", "--silent", "--show-error", "--proto", "=https",
            "--connect-timeout", "10", "--max-time", "100", "--max-filesize", str(MAX_ARCHIVE),
            "--user-agent", "MerlinWRT-Advanced-Firewall/" + g.VERSION,
            "--output", str(target), "--url", url]
    def file_limit():
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_ARCHIVE, MAX_ARCHIVE))
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=110, check=False, preexec_fn=file_limit)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise g.GuardError("GitHub archive download failed or timed out.") from exc
    if p.returncode or not Path(target).is_file() or not 0 < Path(target).stat().st_size <= MAX_ARCHIVE:
        raise g.GuardError("GitHub archive download failed: " + p.stderr.decode(errors="replace")[:250])


def resource_check(install=False):
    if g.read_json(g.RUN / "pending.json", None):
        raise g.GuardError("Finish the pending firewall policy test before updating software.")
    if g.memory().get("MemAvailable", 0) < (96 if install else 64) * 1024**2:
        raise g.GuardError("Update deferred: insufficient available RAM.")
    if os.getloadavg()[0] > (os.cpu_count() or 1) * 1.5:
        raise g.GuardError("Update deferred: router load is too high.")
    g.DATA.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(g.DATA).free < 128 * 1024**2:
        raise g.GuardError("At least 128 MiB of free USB space is required for software updates.")


def status():
    s = g.read_json(_path("update-state.json"), {})
    installed = g.read_json(_path("installed.json"), {})
    staged = g.read_json(_path("updates/staged.json"), {})
    result = {"repository": REPOSITORY, "branch": BRANCH, "version": installed.get("version", g.VERSION),
              "installed_commit": installed.get("commit"), "settings": settings(),
              "last_check": s.get("last_check"), "latest_commit": s.get("latest_commit"),
              "latest_version": s.get("latest_version"), "available": s.get("available", False),
              "message": s.get("message", "No GitHub check has been completed."),
              "error": s.get("error"), "staged": staged or None,
              "backup": installed.get("backup"), "last_install": installed.get("at")}
    prefs = result["settings"]
    result["last_attempt"] = s.get("last_attempt")
    result["next_check"] = ((s.get("last_attempt") or time.time()) + prefs["interval_hours"] * 3600
                            if s.get("last_attempt") else time.time()) if prefs["enabled"] and prefs["auto_check"] else None
    result["schedule_note"] = "Elapsed-hour schedule, evaluated every five minutes; busy or resource-limited runs may be deferred."
    if s.get("latest_commit"):
        result["commit_url"] = "https://github.com/" + REPOSITORY + "/commit/" + valid_commit(s["latest_commit"])
    return result


def check(download=None, scheduled=False):
    prefs = settings()
    state = g.read_json(_path("update-state.json"), {})
    if scheduled and (not prefs["enabled"] or not prefs["auto_check"]):
        return {"message": "Automatic update checks are disabled.", "updates": status()}
    require_enabled()
    delay = prefs["interval_hours"] * 3600 if scheduled else 60
    if time.time() - state.get("last_attempt", 0) < delay:
        return {"message": "Using the recent update result; repeated checks are rate-limited.", "updates": status()}
    state["last_attempt"] = time.time()
    g.save_json(_path("update-state.json"), state)
    try:
        resource_check()
        commit = json.loads(g.fetch(API + "/commits/" + BRANCH, maxbytes=2 * 1024**2)[0])
        sha = valid_commit(commit.get("sha"))
        installed = g.read_json(_path("installed.json"), {})
        state.update(last_check=time.time(), latest_commit=sha, error=None)
        if sha == installed.get("commit"):
            state.update(available=False, latest_version=g.VERSION, message="The installed commit matches GitHub main.")
        else:
            url = "https://raw.githubusercontent.com/" + REPOSITORY + "/" + sha + "/manifest.json"
            manifest = validate_manifest(json.loads(g.fetch(url, maxbytes=200000)[0]))
            state.update(available=True, latest_version=manifest["version"], message="Repository changes are available.")
            # A manually installed ZIP can adopt the first identical published commit.
            local = g.read_json(INSTALL_APP / "manifest.json", {})
            if local == manifest:
                try:
                    verify_tree(INSTALL_APP, manifest)
                except g.GuardError:
                    pass
                else:
                    installed.update(commit=sha, version=manifest["version"])
                    g.save_json(_path("installed.json"), installed)
                    state.update(available=False, message="Local files match the published commit; baseline recorded.")
            g.save_json(_path("update-state.json"), state)
            if state["available"] and (prefs["auto_download"] if download is None else download):
                stage_download(sha, manifest)
                state["message"] = "Changes downloaded and verified. Installation requires confirmation."
        g.save_json(_path("update-state.json"), state)
        return {"message": state["message"], "updates": status()}
    except Exception as exc:
        state.update(error=str(exc), message="Update check/download failed. Installed software and firewall rules are unchanged.")
        g.save_json(_path("update-state.json"), state)
        raise g.GuardError(state["message"] + " " + str(exc)) from exc


def stage_download(sha, manifest):
    valid_commit(sha)
    resource_check()
    base = _path("updates")
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    previous = g.read_json(base / "staged.json", {})
    if previous.get("commit") == sha and (base / "staged").is_dir():
        verify_tree(base / "staged", manifest)
        return
    with tempfile.TemporaryDirectory(prefix="incoming-", dir=str(base)) as temp:
        temp = Path(temp)
        archive = temp / "source.zip"
        download_archive(sha, archive)
        extract_archive(archive, temp / "source", manifest)
        dest = base / "staged"
        old = base / "previous-stage"
        if old.exists():
            shutil.rmtree(old)
        if dest.exists():
            dest.rename(old)
        try:
            (temp / "source").rename(dest)
            g.save_json(base / "staged.json", {"commit": sha, "version": manifest["version"], "at": time.time(),
                         "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                         "manifest_sha256": hashlib.sha256((dest / "manifest.json").read_bytes()).hexdigest()})
        except Exception:
            if dest.exists():
                shutil.rmtree(dest)
            if old.exists():
                old.rename(dest)
            raise
        if old.exists():
            shutil.rmtree(old)


def download_latest():
    require_enabled()
    state = g.read_json(_path("update-state.json"), {})
    if not state.get("available"):
        return check(download=True)
    if time.time() - state.get("last_download_attempt", 0) < 60:
        raise g.GuardError("Wait 60 seconds between manual download attempts.")
    state["last_download_attempt"] = time.time()
    g.save_json(_path("update-state.json"), state)
    sha = valid_commit(state.get("latest_commit"))
    manifest = validate_manifest(json.loads(g.fetch("https://raw.githubusercontent.com/" + REPOSITORY + "/" + sha + "/manifest.json", maxbytes=200000)[0]))
    stage_download(sha, manifest)
    return {"message": "The checked commit is downloaded and verified. Installation requires confirmation.", "updates": status()}


def _integrate():
    # The caller owns the global lock. The child must not reacquire it. Only runs
    # after explicit installation approval; candidate code is trusted at this point.
    # Also remove the new cron name when restoring a pre-updater legacy version.
    for name in ("MCG_Updates", "MCG_Maintenance"):
        g.command(["cru", "d", name], check=False)
    code = "import install_support as i; i.guard.setup(); i.hooks(); i.cron(); i.mount_ui()"
    return g.command([sys.executable, "-B", "-c", "import sys; sys.path.insert(0, " + repr(str(INSTALL_APP)) + "); " + code], timeout=45)


def _unintegrate_fresh(source):
    # First-install failure has no previous integration to restore. Remove only
    # this add-on's schedules/links/menu marker, using the approved source copy.
    code = ("import sys; from pathlib import Path; sys.path.insert(0, " + repr(str(source)) + "); "
            "import install_support as i; i.guard.APP=Path(" + repr(str(INSTALL_APP)) + "); "
            "i.cron(False); i.mount_ui(True)")
    g.command([sys.executable, "-B", "-c", code], timeout=45)


def _validate_legacy(root):
    if not (root / "guard.py").is_file() or not (root / "mcg").is_file():
        raise g.GuardError("Incomplete legacy backup.")
    if 'VERSION = "0.1.0-beta"' not in (root / "guard.py").read_text():
        raise g.GuardError("Only the known 0.1.0-beta backup format is supported.")
    return {"version": "0.1.0-beta"}


def install_tree(source, commit=None, legacy=False):
    """Transactional file replacement with exception rollback; never changes rules.

    A power loss or failed filesystem can still require manual recovery. The journal
    records both paths; this is not a promise of crash-proof filesystem transactions.
    """
    if Path(source).is_symlink():
        raise g.GuardError("Refusing a symlinked installation source.")
    source = Path(source).resolve()
    if source == INSTALL_APP.resolve():
        raise g.GuardError("Install from a separate staging directory, not the live application directory.")
    resource_check(install=True)
    if source.is_symlink() or INSTALL_APP.is_symlink() or LAUNCHER.is_symlink():
        raise g.GuardError("Refusing symlinked installation paths.")
    manifest = _validate_legacy(source) if legacy else verify_tree(source)
    if commit is not None:
        valid_commit(commit)
    if LAUNCHER.exists() and "# MCG-ADDON launcher" not in LAUNCHER.read_text():
        raise g.GuardError("An unrelated /jffs/scripts/mcg already exists; it will not be overwritten.")
    token = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
    backup = BACKUPS / token
    backup.mkdir(parents=True, mode=0o700)
    os.chmod(backup, 0o700)
    INSTALL_APP.parent.mkdir(parents=True, exist_ok=True)
    new = INSTALL_APP.parent / (".mcg-new-" + token)
    previous = g.read_json(_path("installed.json"), {})
    g.save_json(backup / "metadata.json", {"installed": previous, "version": previous.get("version"), "at": time.time()})
    tracked = [LAUNCHER] + [HOOK_DIR / n for n in ("firewall-start", "services-start", "service-event")]
    snapshots = {}
    for i, p in enumerate(tracked):
        if p.is_symlink():
            raise g.GuardError("Refusing a symlinked launcher or hook: " + str(p))
        snapshots[p] = (p.read_bytes(), stat.S_IMODE(p.stat().st_mode)) if p.exists() else None
        if p.exists():
            shutil.copy2(p, backup / ("hook-" + p.name))
    for name in ("confirmed.json", "update-settings.json", "country-settings.json", "stats-settings.json", "update-policy.json", "installed.json"):
        if _path(name).exists():
            shutil.copy2(_path(name), backup / name)
    old_moved = False
    new_live = False
    integration_started = False
    g.save_json(_path("update-journal.json"), {"backup": str(backup), "destination": str(INSTALL_APP), "at": time.time(), "phase": "preparing"})
    try:
        shutil.copytree(source, new, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        for p in new.rglob("*"):
            if p.is_symlink():
                raise g.GuardError("Symlink in installation source.")
            os.chmod(p, 0o755 if p.is_dir() or p.relative_to(new).as_posix() in EXECUTABLES else 0o644)
        if not legacy:
            verify_tree(new, manifest)
        if INSTALL_APP.exists():
            INSTALL_APP.rename(backup / "app")
            old_moved = True
        new.rename(INSTALL_APP)
        new_live = True
        g.save_json(_path("update-journal.json"), {"backup": str(backup), "destination": str(INSTALL_APP), "at": time.time(), "phase": "integrating"})
        g.atomic(LAUNCHER, (INSTALL_APP / "mcg").read_text(), 0o755)
        integration_started = True
        _integrate()
        g.save_json(_path("installed.json"), {"version": manifest["version"], "commit": commit,
                    "at": time.time(), "backup": str(backup) if old_moved else None})
        _path("update-journal.json").unlink(missing_ok=True)
    except Exception as exc:
        recovery_error = None
        try:
            if new_live and INSTALL_APP.exists():
                shutil.rmtree(INSTALL_APP)
            if old_moved:
                (backup / "app").rename(INSTALL_APP)
            for p, value in snapshots.items():
                if value is None:
                    p.unlink(missing_ok=True)
                else:
                    p.write_bytes(value[0]); os.chmod(p, value[1])
            g.save_json(_path("installed.json"), previous)
            if old_moved:
                _integrate()
            elif integration_started:
                _unintegrate_fresh(source)
            _path("update-journal.json").unlink(missing_ok=True)
        except Exception as recovery:
            recovery_error = str(recovery)
        if recovery_error:
            raise g.GuardError("Installation failed and automatic file recovery was incomplete. Backup: " + str(backup) + ". " + recovery_error) from exc
        raise g.GuardError("Installation failed; previous application files were restored. " + str(exc)) from exc
    finally:
        if new.exists():
            shutil.rmtree(new)
    return {"message": "Application " + manifest["version"] + " installed. Firewall rules and private settings were not replaced. Reload the web page.", "backup": str(backup)}


def install_staged(sha):
    require_enabled()
    valid_commit(sha)
    staged = g.read_json(_path("updates/staged.json"), {})
    if staged.get("commit") != sha:
        raise g.GuardError("The downloaded commit changed or is missing. Review Updates again.")
    manifest_path = _path("updates/staged/manifest.json")
    if not manifest_path.is_file() or staged.get("manifest_sha256") != hashlib.sha256(manifest_path.read_bytes()).hexdigest():
        raise g.GuardError("Staged package metadata does not match its manifest. Download it again.")
    result = install_tree(_path("updates/staged"), commit=sha)
    state = g.read_json(_path("update-state.json"), {})
    state.update(available=state.get("latest_commit") != sha, error=None, message=result["message"])
    g.save_json(_path("update-state.json"), state)
    _path("updates/staged.json").unlink(missing_ok=True)
    shutil.rmtree(_path("updates/staged"), ignore_errors=True)
    return result


def rollback():
    installed = g.read_json(_path("installed.json"), {})
    value = installed.get("backup")
    if not value:
        raise g.GuardError("No previous application backup is available.")
    backup = Path(value).resolve()
    if backup.parent != BACKUPS.resolve() or not (backup / "app").is_dir():
        raise g.GuardError("The recorded backup is missing or outside the backup directory.")
    meta = g.read_json(backup / "metadata.json", {}).get("installed", {})
    return install_tree(backup / "app", commit=meta.get("commit"), legacy=not (backup / "app/manifest.json").exists())
