#!/usr/bin/env python3
"""Build or verify the reproducible package manifest; standard library only.

Run after ALL source/documentation/generated-file changes and before committing.
Does not modify the repository in --check mode. Works on Windows as well as Unix.
"""
from pathlib import Path
import argparse
import hashlib
import json
import sys
ROOT = Path(__file__).resolve().parents[1]
SKIP = {".git", "__pycache__", ".pytest_cache", ".venv", "node_modules"}

def documents():
    hashes = {}
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        if any(part in SKIP for part in relative.parts) or path.suffix == ".pyc":
            continue
        if path.is_symlink():
            raise ValueError("Package symlinks are not allowed: " + str(relative))
        if path.is_file() and relative.as_posix() not in ("manifest.json", "SHA256SUMS"):
            hashes[relative.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = {"schema": 1, "project": "MerlinWRTadvancedfirewall", "install_protocol": 1,
                "version": (ROOT / "VERSION").read_text().strip(), "min_python": [3, 9], "files": hashes}
    text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    sums = dict(hashes)
    sums["manifest.json"] = hashlib.sha256(text.encode()).hexdigest()
    checksums = "".join(digest + "  " + name + "\n" for name, digest in sorted(sums.items()))
    return text, checksums

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    manifest, checksums = documents()
    for name, value in (("manifest.json", manifest), ("SHA256SUMS", checksums)):
        path = ROOT / name
        if args.check:
            if not path.exists() or path.read_text() != value:
                print(name + " is stale or the package is incomplete. Router users: obtain a consistent release; do not rebuild to bypass verification. Maintainers: rebuild with python3 tools/build_manifest.py before publishing.", file=sys.stderr)
                return 1
        else:
            path.write_text(value, encoding="utf-8", newline="\n") if sys.version_info >= (3, 10) else path.write_text(value, encoding="utf-8")
    print("Manifest and checksums verified." if args.check else "Manifest and checksums rebuilt.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
