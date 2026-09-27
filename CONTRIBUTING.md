# Development and contribution

Keep visible text/docs in English and retain the `mcg` launcher/private paths unless
a reviewed migration is implemented. Never add automatic software installation,
arbitrary shell rules, secret country-policy bypasses or unbounded packet logging.

Use Linux/WSL and Python 3.9+ for backend tests (`fcntl` and `resource` are Unix
modules). The router needs no third-party Python modules. The manifest builder
alone is portable to Windows. Test on the real supported firmware separately;
mocked unit tests do not establish actual packet coverage or safe throughput.

## Build and checks

```sh
python3 tools/build_installer.py
python3 build_preview.py
python3 -m unittest discover -s tests -v
python3 guard.py dry-run example-config.json
node --check web/guard.js
sh -n install.sh
sh -n tools/install-online.sh
sh -n uninstall.sh
sh -n mcg
```

The standalone bootstrap embeds tools/bootstrap.py; update both through the builder.
Keep new top-level files compatible with the previous updater's allowed paths or
provide a deliberate staged migration. The 0.3.0 support modules use tools/ so the
0.2.0 verifier accepts them. Maintain backwards-readable preferences for rollback.

For optional browser checks, use development Playwright and Chromium, never the
router. The test prefers `/usr/bin/chromium` or Playwright's downloaded browser:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install playwright
python3 -m playwright install chromium
python3 tests/browser_preview.py
```

This test exercises only the self-contained demo. It does not test Merlin session
handling, native submission/mounts, cron, live downloads or kernel firewall rules.
Its screenshots contain synthetic traffic and update outcomes.

## Package last

After **all** source, documentation, generated UI/screenshot and evidence changes:

```sh
python3 tools/build_manifest.py
python3 tools/build_manifest.py --check
python3 -c 'import updater; updater.verify_tree("."); print("Package verified")'
```

Do not change the demo, docs or logs after this without rebuilding the manifest.
Use LF line endings. Commit the entire consistent package to the repository root
on main, excluding keys, private runtime data, virtual environments and build ZIPs.
Check all additions before publishing. A failed integrity check must not be bypassed
by rebuilding the manifest on a user's router.

Document exactly which tests ran. Do not reuse old reports as fresh evidence or
label a simulated UI screenshot as an installed router. Prefer small, independently
reviewable changes; keep the global lock, policy-trial safeguards, resource bounds,
IPv4-only activation requirements and disable/rollback behavior covered by tests.

## Portable installer logging

Edit `tools/installer-log.sh` for the shared POSIX shell helper and
`tools/bootstrap.py` for the embedded online bootstrap. Run:

```sh
python3 tools/build_installer.py
python3 tools/build_manifest.py
```

The builder embeds the helper into both standalone entry points. The helper uses
private `mkdir` directories, not an external temporary-file utility or FIFO.
Changes to generated installers and the source must be committed together.
`tests/test_install_compat.py` exercises a deliberately reduced BusyBox command
environment; its full-entry-point chroot checks require root and may skip in CI.
