"""Offline updater tests. No router writes and no live GitHub requests."""
from pathlib import Path
import copy
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import guard as g
import updater as u

SHA = "a" * 40
OTHER = "b" * 40


def package(root):
    root.mkdir(parents=True, exist_ok=True)
    files = {name: "test\n" for name in u.REQUIRED}
    files.update({"guard.py": 'VERSION = "0.2.0-beta"\n', "updater.py": '"""Fixture."""\n',
                  "install_support.py": '"""Fixture."""\n', "install.sh": "#!/bin/sh\ntrue\n",
                  "uninstall.sh": "#!/bin/sh\ntrue\n", "mcg": "#!/bin/sh\n# MCG-ADDON launcher\ntrue\n",
                  "VERSION": "0.2.0-beta\n", "countries.json": "{}\n"})
    for name, text in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    manifest = {"schema": 1, "project": u.PROJECT, "install_protocol": 1, "version": "0.2.0-beta",
                "min_python": [3, 9], "files": {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in sorted(files)}}
    (root / "manifest.json").write_text(json.dumps(manifest))
    return manifest


def archive(source, target, extra=None):
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
        for p in source.rglob("*"):
            if p.is_file():
                z.write(p, "MerlinWRTadvancedfirewall-" + SHA + "/" + p.relative_to(source).as_posix())
        if extra:
            z.writestr(*extra)


class UpdaterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patches = [patch.object(g, "DATA", self.root / "data"), patch.object(g, "RUN", self.root / "run"),
                        patch.object(g, "PUBLIC", self.root / "run/public"),
                        patch.object(u, "INSTALL_APP", self.root / "opt/share/app"),
                        patch.object(u, "BACKUPS", self.root / "backups"),
                        patch.object(u, "LAUNCHER", self.root / "jffs/scripts/mcg"),
                        patch.object(u, "HOOK_DIR", self.root / "jffs/scripts"),
                        patch.object(g, "memory", return_value={"MemAvailable": 512 * 1024**2}),
                        patch.object(u.os, "getloadavg", return_value=(0, 0, 0)),
                        patch.object(u.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(10**9, 0, 10**9))]
        for p in self.patches:
            p.start()
        g.setup()
        u.HOOK_DIR.mkdir(parents=True)
        self.source = self.root / "source"
        self.manifest = package(self.source)

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def test_default_daily_check_and_download_no_install_setting(self):
        self.assertEqual(u.settings(), {"enabled": True, "auto_check": True, "auto_download": True, "interval_hours": 24})
        self.assertNotIn("auto_install", u.DEFAULT_SETTINGS)

    def test_invalid_preferences_refused(self):
        for value in ({"auto_check": "true", "auto_download": True}, {"auto_check": False, "auto_download": True}, {"auto_install": True}):
            with self.subTest(value=value), self.assertRaises(g.GuardError):
                u.save_settings(value)

    def test_save_valid_preferences(self):
        u.save_settings({"auto_check": False, "auto_download": False})
        self.assertFalse(u.settings()["auto_check"])

    def test_disabled_scheduled_check_never_contacts_github(self):
        u.save_settings({"auto_check": False, "auto_download": False})
        with patch.object(g, "fetch") as fetch:
            u.check(scheduled=True)
        fetch.assert_not_called()

    def test_commit_validation(self):
        self.assertEqual(u.valid_commit(SHA), SHA)
        for value in ("main", "../x", SHA + ";reboot", None):
            with self.subTest(value=value), self.assertRaises(g.GuardError):
                u.valid_commit(value)

    def test_manifest_wrong_project_or_protocol(self):
        for key, value in (("project", "other"), ("schema", 2), ("install_protocol", 2), ("min_python", [3, 8])):
            m = copy.deepcopy(self.manifest);m[key] = value
            with self.subTest(key=key), self.assertRaises(g.GuardError):
                u.validate_manifest(m)

    def test_manifest_missing_required_file(self):
        m = copy.deepcopy(self.manifest);del m["files"]["guard.py"]
        with self.assertRaises(g.GuardError):u.validate_manifest(m)

    def test_unsafe_manifest_paths(self):
        for name in ("../passwd", "/etc/passwd", "web/../../x", "web\\x", "secret.key", "web//x", "web/./x"):
            m = copy.deepcopy(self.manifest);m["files"][name] = "0" * 64
            with self.subTest(name=name), self.assertRaises(g.GuardError):u.validate_manifest(m)

    def test_valid_tree_checks_without_executing_candidate(self):
        self.assertEqual(u.verify_tree(self.source), self.manifest)

    def test_modified_file_refused(self):
        (self.source / "web/guard.js").write_text("modified")
        with self.assertRaisesRegex(g.GuardError, "Checksum"):u.verify_tree(self.source)

    def test_unlisted_file_refused(self):
        (self.source / "web/extra.js").write_text("unexpected")
        with self.assertRaisesRegex(g.GuardError, "do not match"):u.verify_tree(self.source)

    def test_symlink_in_tree_refused(self):
        p = self.source / "web/link.js";p.symlink_to(self.source / "web/guard.js")
        with self.assertRaisesRegex(g.GuardError, "Symlinks"):u.verify_tree(self.source)

    def test_changed_version_refused_even_with_updated_file_hash(self):
        (self.source / "VERSION").write_text("9.0.0\n")
        m = copy.deepcopy(self.manifest);m["files"]["VERSION"] = hashlib.sha256((self.source / "VERSION").read_bytes()).hexdigest()
        (self.source / "manifest.json").write_text(json.dumps(m))
        with self.assertRaisesRegex(g.GuardError, "VERSION"):u.verify_tree(self.source)

    def test_python_syntax_checked_without_execution(self):
        text = 'raise RuntimeError("must never execute during verification")\n'
        (self.source / "updater.py").write_text(text)
        m = copy.deepcopy(self.manifest);m["files"]["updater.py"] = hashlib.sha256(text.encode()).hexdigest()
        (self.source / "manifest.json").write_text(json.dumps(m))
        self.assertEqual(u.verify_tree(self.source), m)
        (self.source / "updater.py").write_text("def broken(:\n")
        m["files"]["updater.py"] = hashlib.sha256((self.source / "updater.py").read_bytes()).hexdigest()
        (self.source / "manifest.json").write_text(json.dumps(m))
        with self.assertRaisesRegex(g.GuardError, "syntax"):u.verify_tree(self.source)

    def test_valid_commit_archive(self):
        a = self.root / "valid.zip";archive(self.source, a)
        dest = self.root / "unpacked"
        u.extract_archive(a, dest, self.manifest)
        self.assertEqual(u.verify_tree(dest), self.manifest)

    def test_zip_traversal_refused(self):
        a = self.root / "bad.zip";archive(self.source, a, ("../outside.txt", "bad"))
        with self.assertRaises(g.GuardError):u.extract_archive(a, self.root / "out", self.manifest)
        self.assertFalse((self.root / "outside.txt").exists())

    def test_zip_symlink_refused(self):
        a = self.root / "bad.zip";info = zipfile.ZipInfo("root/web/link")
        info.create_system = 3;info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive(self.source, a, (info, "/etc/passwd"))
        with self.assertRaisesRegex(g.GuardError, "non-regular"):u.extract_archive(a, self.root / "out", self.manifest)

    def test_zip_duplicate_refused(self):
        a = self.root / "bad.zip"
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            archive(self.source, a, ("MerlinWRTadvancedfirewall-" + SHA + "/README.md", "duplicate"))
        with self.assertRaisesRegex(g.GuardError, "duplicate"):u.extract_archive(a, self.root / "out", self.manifest)

    def test_expansion_limit(self):
        a = self.root / "bad.zip";archive(self.source, a)
        with patch.object(u, "MAX_EXPANDED", 1), self.assertRaisesRegex(g.GuardError, "resource limit"):
            u.extract_archive(a, self.root / "out", self.manifest)

    def test_mismatching_archive_manifest(self):
        a = self.root / "bad.zip";archive(self.source, a)
        m = copy.deepcopy(self.manifest);m["version"] = "0.2.1-beta"
        with self.assertRaisesRegex(g.GuardError, "manifest differs"):u.extract_archive(a, self.root / "out", m)

    def test_low_memory_high_load_low_disk_refused(self):
        with patch.object(g, "memory", return_value={"MemAvailable": 1}), self.assertRaises(g.GuardError):u.resource_check()
        with patch.object(u.os, "getloadavg", return_value=(1000, 0, 0)), self.assertRaises(g.GuardError):u.resource_check()
        with patch.object(u.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(1, 1, 0)), self.assertRaises(g.GuardError):u.resource_check()

    def test_pending_policy_prevents_update(self):
        g.save_json(g.RUN / "pending.json", {"token": "test"})
        with self.assertRaisesRegex(g.GuardError, "policy test"):u.resource_check()

    def test_status_does_not_contact_github(self):
        with patch.object(g, "fetch") as fetch, patch.object(u, "download_archive") as down:
            u.status()
        fetch.assert_not_called();down.assert_not_called()

    def test_changed_commit_same_version_detected_and_staged(self):
        g.save_json(g.DATA / "installed.json", {"commit": OTHER, "version": "0.2.0-beta"})
        with patch.object(g, "fetch", side_effect=[(json.dumps({"sha": SHA}), ""), (json.dumps(self.manifest), "")]), patch.object(u, "stage_download") as stage, patch.object(u, "install_tree") as install:
            result = u.check()
        stage.assert_called_once_with(SHA, self.manifest);install.assert_not_called()
        self.assertTrue(result["updates"]["available"])

    def test_unchanged_commit_avoids_download(self):
        g.save_json(g.DATA / "installed.json", {"commit": SHA})
        with patch.object(g, "fetch", return_value=(json.dumps({"sha": SHA}), "")) as fetch, patch.object(u, "stage_download") as stage:
            result = u.check()
        self.assertEqual(fetch.call_count, 1);stage.assert_not_called();self.assertFalse(result["updates"]["available"])

    def test_identical_manual_install_adopts_commit_without_download(self):
        shutil.copytree(self.source, u.INSTALL_APP)
        with patch.object(g, "fetch", side_effect=[(json.dumps({"sha": SHA}), ""), (json.dumps(self.manifest), "")]), patch.object(u, "stage_download") as stage:
            result = u.check()
        self.assertFalse(result["updates"]["available"]);stage.assert_not_called()
        self.assertEqual(g.read_json(g.DATA / "installed.json")["commit"], SHA)

    def test_github_error_does_not_install_or_replace_policy(self):
        g.save_json(g.DATA / "confirmed.json", {"important": "retain"})
        with patch.object(g, "fetch", side_effect=g.GuardError("HTTP 403")), patch.object(u, "install_tree") as install, self.assertRaises(g.GuardError):u.check()
        install.assert_not_called();self.assertEqual(g.read_json(g.DATA / "confirmed.json"), {"important": "retain"})
        self.assertIn("HTTP 403", u.status()["error"])

    def test_manual_cooldown(self):
        g.save_json(g.DATA / "update-state.json", {"last_attempt": time.time()})
        with patch.object(g, "fetch") as fetch:u.check()
        fetch.assert_not_called()

    def test_successful_stage_preserves_settings_and_executes_no_candidate(self):
        def download(sha, target):archive(self.source, target)
        with patch.object(u, "download_archive", side_effect=download), patch.object(u, "install_tree") as install:
            u.stage_download(SHA, self.manifest)
        install.assert_not_called()
        self.assertEqual(g.read_json(g.DATA / "updates/staged.json")["commit"], SHA)
        self.assertFalse(u.INSTALL_APP.exists())

    def test_failed_stage_retains_previous_stage(self):
        base = g.DATA / "updates";base.mkdir();shutil.copytree(self.source, base / "staged")
        g.save_json(base / "staged.json", {"commit": OTHER})
        with patch.object(u, "download_archive", side_effect=g.GuardError("network")), self.assertRaises(g.GuardError):u.stage_download(SHA, self.manifest)
        self.assertEqual(g.read_json(base / "staged.json")["commit"], OTHER)
        self.assertTrue((base / "staged/guard.py").exists())

    def test_stale_install_commit_refused(self):
        g.save_json(g.DATA / "updates/staged.json", {"commit": OTHER})
        with patch.object(u, "install_tree") as install, self.assertRaises(g.GuardError):u.install_staged(SHA)
        install.assert_not_called()

    def test_install_preserves_private_config_and_avoids_rule_switch(self):
        g.save_json(g.DATA / "confirmed.json", {"important": "retain"})
        (g.DATA / "abuseipdb.key").write_text("private-secret")
        with patch.object(u, "_integrate"), patch.object(g, "switch_generation") as switch:
            result = u.install_tree(self.source, commit=SHA)
        switch.assert_not_called();self.assertTrue(u.INSTALL_APP.exists())
        self.assertEqual(g.read_json(g.DATA / "confirmed.json"), {"important": "retain"})
        self.assertEqual((g.DATA / "abuseipdb.key").read_text(), "private-secret")
        self.assertEqual(g.read_json(g.DATA / "installed.json")["commit"], SHA)
        self.assertIn("installed", result["message"])

    def test_install_creates_application_backup(self):
        shutil.copytree(self.source, u.INSTALL_APP)
        (u.INSTALL_APP / "README.md").write_text("old application")
        with patch.object(u, "_integrate"):
            result = u.install_tree(self.source, commit=SHA)
        self.assertEqual((Path(result["backup"]) / "app/README.md").read_text(), "old application")
        self.assertTrue(u.LAUNCHER.exists())

    def test_integration_failure_restores_previous_files_and_hooks(self):
        shutil.copytree(self.source, u.INSTALL_APP)
        (u.INSTALL_APP / "README.md").write_text("old application")
        u.LAUNCHER.write_text("#!/bin/sh\n# MCG-ADDON launcher\necho old\n")
        hook = u.HOOK_DIR / "service-event";hook.write_text("#!/bin/sh\necho keep\n")
        def integrate():
            hook.write_text("changed")
            raise g.GuardError("simulated mount failure")
        with patch.object(u, "_integrate", side_effect=[g.GuardError("simulated mount failure"), None]), self.assertRaisesRegex(g.GuardError, "restored"):
            u.install_tree(self.source, commit=SHA)
        self.assertEqual((u.INSTALL_APP / "README.md").read_text(), "old application")
        self.assertIn("echo old", u.LAUNCHER.read_text())
        self.assertIn("echo keep", hook.read_text())

    def test_unrelated_launcher_never_overwritten(self):
        u.LAUNCHER.write_text("#!/bin/sh\necho unrelated\n")
        with self.assertRaisesRegex(g.GuardError, "unrelated"):u.install_tree(self.source)
        self.assertIn("unrelated", u.LAUNCHER.read_text())

    def test_missing_backup_refused(self):
        with self.assertRaisesRegex(g.GuardError, "No previous"):u.rollback()

    def test_backup_outside_private_root_refused(self):
        g.save_json(g.DATA / "installed.json", {"backup": str(self.root)})
        with self.assertRaisesRegex(g.GuardError, "outside"):u.rollback()

    def test_download_url_fixed_to_verified_commit(self):
        target = self.root / "archive.zip"
        def run(args, **kw):
            target.write_bytes(b"PK fixture")
            self.assertIn("https://codeload.github.com/" + u.REPOSITORY + "/zip/" + SHA, args)
            self.assertNotIn("--insecure", args);self.assertNotIn("--location", args)
            self.assertIsNotNone(kw.get("preexec_fn"))
            return subprocess.CompletedProcess(args, 0, b"", b"")
        with patch.object(u.subprocess, "run", side_effect=run):u.download_archive(SHA, target)


    def test_failed_stage_metadata_write_restores_previous_tree(self):
        base = g.DATA / "updates";base.mkdir();shutil.copytree(self.source, base / "staged")
        (base / "staged/README.md").write_text("previous stage")
        g.save_json(base / "staged.json", {"commit": OTHER})
        def download(sha, target):archive(self.source, target)
        real_save = g.save_json
        def fail_metadata(path, value, *args, **kwargs):
            if path == base / "staged.json":raise OSError("simulated disk full")
            return real_save(path, value, *args, **kwargs)
        with patch.object(u, "download_archive", side_effect=download), patch.object(g, "save_json", side_effect=fail_metadata), self.assertRaises(OSError):
            u.stage_download(SHA, self.manifest)
        self.assertEqual((base / "staged/README.md").read_text(), "previous stage")
        self.assertEqual(g.read_json(base / "staged.json")["commit"], OTHER)

    def test_install_rejects_stage_manifest_metadata_mismatch(self):
        base = g.DATA / "updates";base.mkdir();shutil.copytree(self.source, base / "staged")
        g.save_json(base / "staged.json", {"commit": SHA, "manifest_sha256": "0" * 64})
        with patch.object(u, "install_tree") as install, self.assertRaisesRegex(g.GuardError, "metadata"):
            u.install_staged(SHA)
        install.assert_not_called()

    def test_fresh_install_failure_removes_only_new_integration(self):
        with patch.object(u, "_integrate", side_effect=g.GuardError("failure")), patch.object(u, "_unintegrate_fresh") as cleanup, self.assertRaises(g.GuardError):
            u.install_tree(self.source)
        cleanup.assert_called_once_with(self.source.resolve())
        self.assertFalse(u.INSTALL_APP.exists())
        self.assertFalse(u.LAUNCHER.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
