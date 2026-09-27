"""Offline installer regressions. No router, network or live firewall changes.

Common logging runs with a reduced applet PATH. Full entry points additionally
run unchanged inside a minimal chroot where permitted. BusyBox is from the test
host, not the user's exact firmware build.
"""
from pathlib import Path
import os
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BUSYBOX = shutil.which('busybox')
COMMON = (ROOT / 'tools/installer-log.sh').read_text()


@unittest.skipUnless(BUSYBOX, 'A local BusyBox is required for these shell regressions')
class PortableLoggingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mafw-shell-test-')
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for name in ('sh', 'mkdir', 'rmdir', 'rm', 'cat', 'tee', 'ln'):
            (self.bin / name).symlink_to(BUSYBOX)
        self.logdirs = set()

    def tearDown(self):
        for directory in self.logdirs:
            # Only our test-created private directories are collected from output.
            if re.fullmatch(r'/tmp/mafw-(?:install|bootstrap)\.[0-9]+\.[0-9]+', str(directory)):
                shutil.rmtree(directory, ignore_errors=True)
        self.temp.cleanup()

    def run_script(self, body):
        script = self.root / 'test.sh'
        script.write_text('PATH=' + shlex.quote(str(self.bin)) + '\nexport PATH\numask 077\n' + COMMON + '\n' + body)
        result = subprocess.run([BUSYBOX, 'ash', str(script)], capture_output=True, text=True, timeout=15)
        self.logdirs.update(Path(x).parent for x in re.findall(r'/tmp/mafw-(?:install|bootstrap)\.[0-9]+\.[0-9]+/output.log', result.stdout + result.stderr))
        return result

    def last_log(self, result):
        names = re.findall(r'/tmp/mafw-(?:install|bootstrap)\.[0-9]+\.[0-9]+/output.log', result.stdout)
        self.assertTrue(names, result.stdout + result.stderr)
        return Path(names[0])

    def test_reduced_path_has_no_missing_utilities(self):
        result = self.run_script('command -v mktemp && exit 88\ncommand -v mkfifo && exit 89\nmafw_run_logged install sh -c "echo WORKER_RAN"\n')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('WORKER_RAN', self.last_log(result).read_text())

    def test_worker_failure_not_hidden_by_successful_tee(self):
        result = self.run_script('mafw_run_logged install sh -c "echo EXPECTED_FAILURE; exit 17"\n')
        self.assertEqual(result.returncode, 17, result.stdout + result.stderr)
        self.assertIn('EXPECTED_FAILURE', self.last_log(result).read_text())

    def test_private_log_permissions(self):
        result = self.run_script('mafw_run_logged bootstrap sh -c "echo PRIVATE_LOG"\n')
        self.assertEqual(result.returncode, 0)
        log = self.last_log(result)
        self.assertEqual(stat.S_IMODE(log.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)
        self.assertFalse((log.parent / 'exit-status').exists())

    def test_stdout_and_stderr_are_logged(self):
        result = self.run_script('mafw_run_logged install sh -c "echo OUT; echo ERR >&2"\n')
        text = self.last_log(result).read_text()
        self.assertIn('OUT', text)
        self.assertIn('ERR', text)

    def test_failure_keeps_calling_shell_alive(self):
        result = self.run_script('mafw_run_logged install sh -c "exit 19"; r=$?; printf "CALLER_ALIVE:%s\\n" "$r"\n')
        self.assertEqual(result.returncode, 0)
        self.assertIn('CALLER_ALIVE:19', result.stdout)

    def test_logging_without_tee(self):
        (self.bin / 'tee').unlink()
        result = self.run_script('mafw_run_logged install sh -c "echo BUFFERED; exit 9"\n')
        self.assertEqual(result.returncode, 9)
        self.assertIn('Live logging is unavailable', result.stdout)
        self.assertIn('BUFFERED', self.last_log(result).read_text())

    def test_logger_failure_does_not_report_success(self):
        (self.bin / 'tee').unlink()
        (self.bin / 'tee').write_text('#!' + str(self.bin / 'sh') + '\ncat >/dev/null\nexit 2\n')
        (self.bin / 'tee').chmod(0o700)
        result = self.run_script('mafw_run_logged install sh -c "echo SUCCESSFUL_WORKER"\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Live logging failed', result.stderr)

    def test_existing_directory_is_not_reused(self):
        result = self.run_script('''reserved="/tmp/mafw-install.$$.0"
mkdir "$reserved" || exit 90
printf '%s\\n' 'DO_NOT_TOUCH' > "$reserved/sentinel"
mafw_run_logged install sh -c 'echo NEW_DIRECTORY'
r=$?
[ "$(cat "$reserved/sentinel")" = DO_NOT_TOUCH ] || exit 91
[ ! -f "$reserved/output.log" ] || exit 92
rm "$reserved/sentinel"; rmdir "$reserved"
exit "$r"
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertRegex(str(self.last_log(result)), r'\.1/output\.log$')

    def test_existing_symlink_is_not_followed(self):
        target = self.root / 'untouched'
        target.mkdir()
        result = self.run_script('reserved="/tmp/mafw-bootstrap.$$.0"\nln -s ' + shlex.quote(str(target)) + ''' "$reserved" || exit 90
mafw_run_logged bootstrap sh -c 'echo NO_SYMLINK_REUSE'
r=$?
rm "$reserved"
exit "$r"
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(list(target.iterdir()), [])
        self.assertRegex(str(self.last_log(result)), r'\.1/output\.log$')

    def test_no_private_directory_means_no_worker(self):
        marker = self.root / 'must-not-run'
        (self.bin / 'mkdir').unlink()
        (self.bin / 'mkdir').write_text('#!' + str(self.bin / 'sh') + '\nexit 1\n')
        (self.bin / 'mkdir').chmod(0o700)
        result = self.run_script('mafw_run_logged install sh -c ' + shlex.quote('echo BAD > ' + shlex.quote(str(marker))) + '\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Cannot create a private', result.stderr)
        self.assertFalse(marker.exists())

    def test_bootstrap_generator_is_reproducible(self):
        import sys
        paths = [ROOT / 'install.sh', ROOT / 'tools/install-online.sh']
        before = [p.read_bytes() for p in paths]
        result = subprocess.run([sys.executable, str(ROOT / 'tools/build_installer.py')], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(before, [p.read_bytes() for p in paths])


@unittest.skipUnless(BUSYBOX and os.geteuid() == 0 and shutil.which('chroot'), 'Full-script minimal chroot needs BusyBox and root')
class MinimalFirmwareEntryPointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='mafw-chroot-')
        cls.root = Path(cls.temp.name)
        for name in ('bin', 'tmp', 'pkg/tools', 'dev'):
            (cls.root / name).mkdir(parents=True, exist_ok=True)
        # chroot availability varies even for UID 0 in restricted containers.
        shutil.copy2(BUSYBOX, cls.root / 'bin/busybox')
        dependencies = subprocess.run(['ldd', BUSYBOX], capture_output=True, text=True, timeout=10)
        for name in re.findall(r'(/[A-Za-z0-9_./+-]+)', dependencies.stdout):
            p = Path(name)
            if p.is_file():
                dest = cls.root / name.lstrip('/')
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(p, dest)
        for name in ('sh', 'mkdir', 'rmdir', 'rm', 'cat', 'tee', 'id', 'dirname', 'basename'):
            (cls.root / 'bin' / name).symlink_to('busybox')
        # A harmless regular sink suffices; tests never read entropy/devices.
        (cls.root / 'dev/null').touch()
        for name in ('install.sh', 'tools/install-online.sh'):
            shutil.copy2(ROOT / name, cls.root / 'pkg' / name)
        probe = subprocess.run(['chroot', str(cls.root), '/bin/sh', '-c', ':'], capture_output=True, text=True, timeout=10)
        if probe.returncode:
            cls.temp.cleanup()
            raise unittest.SkipTest('Chroot unavailable: ' + probe.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_chroot(self, body):
        return subprocess.run(['chroot', str(self.root), '/bin/sh', '-c', body], capture_output=True, text=True, timeout=15)

    def test_real_local_installer_runs_without_mktemp_or_mkfifo(self):
        result = self.run_chroot('command -v mktemp && exit 88; command -v mkfifo && exit 89; sh /pkg/install.sh --invalid; r=$?; echo CALLER_ALIVE:$r')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('CALLER_ALIVE:1', result.stdout)
        self.assertIn('Usage:', result.stdout)
        self.assertIn('Installation stopped', result.stdout)
        self.assertNotIn('mktemp: not found', result.stdout + result.stderr)

    def test_real_bootstrap_reaches_readonly_prerequisites(self):
        result = self.run_chroot('sh /pkg/tools/install-online.sh; r=$?; echo CALLER_ALIVE:$r')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('CALLER_ALIVE:1', result.stdout)
        self.assertIn('Merlin nvram is missing', result.stdout)
        self.assertIn('Bootstrap stopped', result.stdout)

    def mock_curl(self, text):
        p = self.root / 'bin/curl'
        p.write_text('#!/bin/sh\n' + text)
        p.chmod(0o700)

    def test_documented_command_does_not_run_a_failed_download(self):
        self.mock_curl('exit 22\n')
        command = (ROOT / 'tools/install-command.txt').read_text().strip()
        result = self.run_chroot(command + '; r=$?; echo CALLER_ALIVE:$r')
        self.assertEqual(result.returncode, 0)
        self.assertIn('CALLER_ALIVE:22', result.stdout)
        self.assertEqual(list((self.root / 'tmp').glob('mafw-online.*')), [])
        self.assertNotIn('Bootstrap log:', result.stdout)

    def test_documented_command_calls_successful_download_and_cleans_up(self):
        self.mock_curl('''out=
while [ "$#" -gt 0 ]; do
    if [ "$1" = --output ]; then shift; out=$1; fi
    shift
done
[ -n "$out" ] || exit 91
printf '%s\\n' '#!/bin/sh' 'echo DOWNLOADED_CHILD_RAN' 'exit 7' > "$out"
''')
        command = (ROOT / 'tools/install-command.txt').read_text().strip()
        result = self.run_chroot(command + '; r=$?; echo CALLER_ALIVE:$r')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('DOWNLOADED_CHILD_RAN', result.stdout)
        self.assertIn('CALLER_ALIVE:7', result.stdout)
        self.assertEqual(list((self.root / 'tmp').glob('mafw-online.*')), [])


if __name__ == '__main__':
    unittest.main()
