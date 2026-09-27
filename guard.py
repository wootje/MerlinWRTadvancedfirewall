#!/usr/bin/env python3
"""MerlinWRT Advanced Firewall 0.3.1-beta. Control plane only; no per-packet Python.

Independent, drop-only extension for the Skynet/Merlin native add-on interface.
All mutation uses validated argument arrays, never a user-supplied shell command.
See README.md and docs/SAFETY.md before using on a live router.
"""
from __future__ import annotations
import argparse
import base64
import collections
import contextlib
import copy
import fcntl
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unicodedata
import urllib.parse

VERSION = "0.3.1-beta"
APP = Path(__file__).resolve().parent
DATA = Path(os.environ.get("MCG_DATA", "/opt/var/lib/merlin-country-guard"))
RUN = Path(os.environ.get("MCG_RUN", "/tmp/merlin-country-guard"))
PUBLIC = RUN / "public"
COUNTRY_REPO = "https://api.github.com/repos/ebrasha/cidr-ip-ranges-by-country"
ABUSE_API = "https://api.abuseipdb.com/api/v2/"
MAX_NETWORKS = 200_000
MAX_FILE = 12 * 1024 * 1024
PENDING_SECONDS = 120
EMERGENCY = Path("/tmp/mcg-emergency-off")
# Special-use IPv4 is left to the existing router firewall, NOT accepted globally.
SPECIAL = ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
           "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
           "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
           "224.0.0.0/4", "240.0.0.0/4")
SPECIAL_NETS = tuple(ipaddress.ip_network(x) for x in SPECIAL)
MIRROR_SETS = ("Skynet-Blacklist", "Skynet-BlockedRanges", "Skynet-BlacklistDomains",
               "Skynet-UserBans")
DEFAULT = {"enabled": False, "country_enabled": False, "countries": [],
           "skynet": True, "abuse": False, "score": 90, "ports": [],
           "extra_rules": "", "max_rows": 3000}

class GuardError(Exception):
    pass

def read_json(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return copy.deepcopy(default)
    except (ValueError, UnicodeError) as exc:
        raise GuardError(f"Invalid JSON file: {path.name}") from exc

def atomic(path: Path, content: str, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".mcg-", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def save_json(path, value, public=False):
    atomic(path, json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n",
           0o644 if public else 0o600)

def setup():
    for p in (DATA, DATA / "cache", RUN, PUBLIC):
        p.mkdir(parents=True, exist_ok=True)
    os.chmod(DATA, 0o700)
    # Public files are exposed individually, never the private data directory.
    os.chmod(RUN, 0o755)
    os.chmod(PUBLIC, 0o755)

@contextlib.contextmanager
def locked(wait=False):
    setup()
    with open(RUN / "control.lock", "a", encoding="ascii") as f:
        os.chmod(RUN / "control.lock", 0o600)
        try:
            fcntl.flock(f, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
        except BlockingIOError as exc:
            raise GuardError("Another management operation is in progress. Try again afterwards.") from exc
        yield

def command(args, input_text=None, timeout=30, check=True):
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["PATH"] = "/sbin:/bin:/usr/sbin:/usr/bin:/opt/sbin:/opt/bin"
    try:
        p = subprocess.run([str(x) for x in args], input=input_text, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GuardError(f"Command unavailable or timed out: {args[0]}") from exc
    if check and p.returncode:
        # Commands never contain API keys; curl credentials go into a 0600 config.
        raise GuardError(f"{args[0]} failed: {p.stderr.strip()[:350] or p.stdout.strip()[:350]}")
    return p

def nv(key):
    try:
        return command(["nvram", "get", key], timeout=5).stdout.strip()
    except GuardError:
        return ""

def kernel(table, *args, check=True):
    return command(["iptables", "-t", table, *args], check=check)

def country_names():
    return read_json(APP / "countries.json", {})

def as_network(value, public=False):
    if not isinstance(value, str) or len(value) > 32:
        raise GuardError("Invalid IPv4 address or subnet.")
    try:
        n = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise GuardError(f"Invalid IPv4 address/subnet: {value}") from exc
    if n.version != 4:
        raise GuardError("This version processes IPv4 only.")
    if public and (n.prefixlen < 4 or any(n.overlaps(s) for s in SPECIAL_NETS)):
        raise GuardError(f"Not a usable public IPv4 network: {value}")
    return str(n)

def port_range(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,5}(?:[-:][0-9]{1,5})?", value):
        raise GuardError("Enter a port or range, for example 443 or 1000-2000.")
    pair = re.split("[-:]", value)
    lo, hi = int(pair[0]), int(pair[-1])
    if not 1 <= lo <= hi <= 65535:
        raise GuardError("Ports must be between 1 and 65535; start must not exceed end.")
    return str(lo) if lo == hi else f"{lo}:{hi}"

def parse_extra(text):
    """Restricted iptables rule bodies, not shell or full-table replacement.
    Example: out -p tcp -d 8.8.8.8/32 --dport 853 -j DROP
    Country and reputation checks ALWAYS precede these extra rules.
    """
    if not isinstance(text, str) or len(text) > 2200:
        raise GuardError("Extra rules: maximum 2200 characters.")
    result = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if len(result) >= 12:
            raise GuardError("This lightweight version supports up to 12 extra rules.")
        try:
            tokens = shlex.split(line)
        except ValueError as exc:
            raise GuardError("Invalid quotation marks in an extra rule.") from exc
        if not tokens or tokens[0] not in ("in", "out", "both"):
            raise GuardError("Start an extra rule with in, out or both.")
        direction, tokens = tokens[0], tokens[1:]
        fields = {}
        if len(tokens) % 2:
            raise GuardError("Use only option/value pairs in extra rules.")
        for flag, val in zip(tokens[::2], tokens[1::2]):
            if flag not in ("-p", "-s", "-d", "--sport", "--dport", "-j") or flag in fields:
                raise GuardError(f"Disallowed or duplicate option: {flag}")
            fields[flag] = val
        if fields.get("-j") != "DROP":
            raise GuardError("Extra rules support DROP only, not ACCEPT, RETURN or shell commands.")
        if fields.get("-p", "all") not in ("all", "tcp", "udp", "icmp"):
            raise GuardError("Protocol: all, tcp, udp or icmp.")
        for key in ("-s", "-d"):
            if key in fields:
                fields[key] = as_network(fields[key])
        for key in ("--sport", "--dport"):
            if key in fields:
                if fields.get("-p") not in ("tcp", "udp"):
                    raise GuardError("A port requires the tcp or udp protocol.")
                fields[key] = port_range(fields[key])
        args = []
        for key in ("-p", "-s", "-d", "--sport", "--dport"):
            if key in fields:
                args += [key, fields[key]]
        result.append((direction, args))
    return result

def validate_config(value):
    if not isinstance(value, dict) or set(value) - set(DEFAULT):
        raise GuardError("Unknown settings or invalid configuration format.")
    c = copy.deepcopy(DEFAULT)
    c.update(value)
    for key in ("enabled", "country_enabled", "skynet", "abuse"):
        if type(c[key]) is not bool:
            raise GuardError(f"{key}: expected true or false.")
    if not isinstance(c["countries"], list) or any(not isinstance(v, str) for v in c["countries"]):
        raise GuardError("Countries must be a list of country codes.")
    c["countries"] = sorted(set(v.upper() for v in c["countries"]))
    if any(v not in country_names() for v in c["countries"]):
        raise GuardError("Unknown country code.")
    if c["country_enabled"] and not c["countries"]:
        raise GuardError("Select at least one allowed country first, or disable the country filter.")
    if c["enabled"] and not (c["skynet"] or c["abuse"]):
        raise GuardError("Select at least one reputation source before enabling the firewall add-on.")
    if type(c["score"]) is not int or not 25 <= c["score"] <= 100:
        raise GuardError("The AbuseIPDB threshold must be 25-100; higher means more evidence of abuse.")
    if type(c["max_rows"]) is not int or not 100 <= c["max_rows"] <= 5000:
        raise GuardError("Connection details: at least 100 and at most 5000 rows.")
    if not isinstance(c["ports"], list) or len(c["ports"]) > 24:
        raise GuardError("Maximum 24 port rules.")
    ports = []
    for row in c["ports"]:
        if not isinstance(row, dict) or set(row) != {"direction", "protocol", "ports", "side"}:
            raise GuardError("Invalid port rule.")
        r = dict(row)
        if r["direction"] not in ("in", "out", "both") or r["protocol"] not in ("tcp", "udp", "both"):
            raise GuardError("Invalid direction or protocol.")
        if r["side"] not in ("remote", "destination", "either"):
            raise GuardError("Port side must be remote, destination or either.")
        r["ports"] = port_range(r["ports"])
        ports.append(r)
    c["ports"] = ports
    parse_extra(c["extra_rules"])
    return c

def parse_network_lines(text, public=True):
    result = set()
    for line in text.splitlines():
        line = re.split(r"[;#]", line, maxsplit=1)[0].strip()
        if not line:
            continue
        result.add(as_network(line, public=public))
        if len(result) > MAX_NETWORKS:
            raise GuardError("Memory limit reached: no list was truncated or applied.")
    if not result:
        raise GuardError("The downloaded list is empty; existing data is retained.")
    return sorted(result)

def extract_skynet(text):
    result = set()
    for line in text.splitlines():
        if not line.startswith("add "):
            continue
        # Never evaluate comments/commands from an ipset save document.
        fields = line.split()
        if len(fields) < 3 or fields[1] not in MIRROR_SETS:
            continue
        try:
            result.add(as_network(fields[2], public=True))
        except GuardError:
            # Private user bans are still enforced by Skynet itself.
            continue
        if len(result) > MAX_NETWORKS:
            raise GuardError("The Skynet copy exceeds the memory limit; the source was not truncated.")
    return sorted(result)

def parse_abuse_blacklist(text, threshold):
    try:
        obj = json.loads(text)
        rows = obj["data"]
        if not isinstance(rows, list) or len(rows) > 10000:
            raise ValueError("data")
        networks = set()
        for row in rows:
            score = row.get("abuseConfidenceScore")
            if type(score) is not int or not 0 <= score <= 100:
                raise ValueError("score")
            if score >= threshold:
                networks.add(as_network(row["ipAddress"], public=True))
        if not networks:
            raise ValueError("empty")
        return sorted(networks), obj.get("meta", {})
    except (KeyError, TypeError, ValueError) as exc:
        raise GuardError("AbuseIPDB did not return a valid, non-empty list with scores.") from exc

def fetch(url, key=None, maxbytes=MAX_FILE):
    u = urllib.parse.urlsplit(url)
    allowed = {"api.github.com", "raw.githubusercontent.com", "api.abuseipdb.com"}
    if u.scheme != "https" or u.hostname not in allowed or u.username or u.port:
        raise GuardError("The download URL is not allowed.")
    setup()
    with tempfile.TemporaryDirectory(prefix="download-", dir=str(RUN)) as temp:
        tmp = Path(temp)
        cfg = 'silent\nshow-error\nfail\nconnect-timeout = 10\nmax-time = 60\n'
        cfg += f'max-filesize = {maxbytes}\nproto = "=https"\n'
        cfg += 'user-agent = "Merlin-Country-Guard/0.3.1-beta"\n'
        cfg += 'header = "Accept: application/json"\n'
        if key:
            if not re.fullmatch(r"[A-Za-z0-9_-]{16,256}", key):
                raise GuardError("Invalid API key format.")
            cfg += f'header = "Key: {key}"\n'
        atomic(tmp / "curl.conf", cfg)
        command(["curl", "--config", str(tmp / "curl.conf"), "--output", str(tmp / "body"),
                 "--dump-header", str(tmp / "headers"), "--url", url], timeout=65)
        if (tmp / "body").stat().st_size > maxbytes:
            raise GuardError("Download too large; existing data is retained.")
        raw = (tmp / "body").read_text(encoding="utf-8")
        headers = (tmp / "headers").read_text(encoding="utf-8", errors="replace")
        return raw, headers

def norm(s):
    return re.sub(r"[^a-z0-9]", "", unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode().lower())

def map_country_paths(paths, names):
    aliases = {}
    for cc, info in names.items():
        for name in [cc, info["name"], *info.get("aliases", [])]:
            aliases[norm(name)] = cc
    found = {}
    for path in paths:
        if not isinstance(path, str) or not path.startswith("CIDR/") or ".." in Path(path).parts:
            continue
        if not path.lower().endswith("-ipv4-hackers.zone.txt"):
            continue
        base = re.sub(r"-ipv4-hackers\.zone\.txt$", "", Path(path).name, flags=re.I)
        candidates = [base, Path(path).parent.name]
        matches = {aliases[norm(v)] for v in candidates if norm(v) in aliases}
        if len(matches) == 1:
            cc = matches.pop()
            if cc in found and found[cc] != path:
                raise GuardError(f"Duplicate source for {cc}; no arbitrary source was selected.")
            found[cc] = path
    if not found:
        raise GuardError("Country files not recognized. The source layout may have changed.")
    return found

def country_index(force=False):
    cached = read_json(DATA / "cache/country-index.json", {})
    if cached and not force and time.time() - cached["fetched"] < 7 * 86400:
        return cached
    commit = json.loads(fetch(COUNTRY_REPO + "/commits/master", maxbytes=2*1024*1024)[0])
    sha, tree = commit.get("sha", ""), commit.get("commit", {}).get("tree", {}).get("sha", "")
    if not re.fullmatch("[0-9a-f]{40}", sha) or not re.fullmatch("[0-9a-f]{40}", tree):
        raise GuardError("GitHub did not return a valid commit/tree hash.")
    obj = json.loads(fetch(COUNTRY_REPO + "/git/trees/" + tree + "?recursive=1")[0])
    if obj.get("truncated"):
        raise GuardError("The GitHub file list is truncated; no partial country list was applied.")
    mapping = map_country_paths([r.get("path") for r in obj.get("tree", []) if r.get("type") == "blob"], country_names())
    result = {"commit": sha, "paths": mapping, "fetched": time.time()}
    save_json(DATA / "cache/country-index.json", result)
    return result

def load_key():
    try:
        return (DATA / "abuseipdb.key").read_text(encoding="ascii").strip()
    except FileNotFoundError:
        raise GuardError("Set the AbuseIPDB key over SSH: /jffs/scripts/mcg key")

def snapshot_skynet(reject_countries=False):
    pieces = []
    missing = []
    for name in MIRROR_SETS:
        p = command(["ipset", "save", name], check=False)
        if p.returncode == 0:
            if reject_countries and re.search(r'comment\s+"Country:\s*[A-Za-z]{2}', p.stdout):
                raise GuardError("Skynet still contains country blocks; remove those in Skynet first.")
            pieces.append(p.stdout)
        else:
            missing.append(name)
    if "Skynet-Blacklist" in missing or "Skynet-BlockedRanges" in missing:
        raise GuardError("Skynet is not fully running: the blacklist/ranges set is missing.")
    values = extract_skynet("\n".join(pieces))
    if not values:
        raise GuardError("The Skynet reputation copy is empty; check the Skynet feeds.")
    return values

def old_country_policy():
    # Literal parsing only; do not source/evaluate another add-on's config.
    candidates = list(Path("/opt").glob("share/skynet/skynet.cfg"))
    hook = Path("/jffs/scripts/firewall-start")
    if hook.exists():
        text = hook.read_text(errors="replace")
        for loc in re.findall(r"skynetloc=([/A-Za-z0-9_.-]+)", text):
            candidates.append(Path(loc) / "skynet.cfg")
    for p in candidates:
        if p.is_file():
            m = re.search(r"^countrylist=['\"]?([^'\"\n]*)", p.read_text(errors="replace"), re.M)
            if m and m.group(1).strip():
                return m.group(1).strip()
    return ""

def country_bundle(countries, refresh=False):
    """Download only selected countries. A refresh checks the commit, not every file.

    Cache writes are allowed before completion; live sets are not touched here.
    """
    bundle = {"geo": [], "meta": {}}
    idx = country_index(force=refresh)
    values = set()
    for cc in countries:
        path = idx["paths"].get(cc)
        if not path:
            raise GuardError(f"No recognized IPv4 file is available for {cc} in the selected source.")
        cachefile = DATA / "cache" / ("country-" + cc + ".json")
        cache = read_json(cachefile, {})
        if cache.get("commit") == idx["commit"]:
            entries = cache["entries"]
        else:
            url = "https://raw.githubusercontent.com/ebrasha/cidr-ip-ranges-by-country/" + idx["commit"] + "/" + urllib.parse.quote(path, safe="/")
            entries = parse_network_lines(fetch(url)[0])
            cache = {"commit": idx["commit"], "entries": entries, "fetched": time.time(), "url": url}
            save_json(cachefile, cache)
        values.update(entries)
        if len(values) > MAX_NETWORKS:
            raise GuardError("The selected countries exceed the configured memory limit.")
        bundle["meta"][cc] = {"entries": len(entries), "fetched": cache["fetched"], "checked": idx["fetched"], "commit": idx["commit"]}
    bundle["geo"] = sorted(values)
    return bundle

def collect_sources(c, refresh=False):
    """All sources are prepared before any active kernel policy is modified."""
    bundle = {"geo": [], "skynet": [], "abuse": [], "meta": {}, "created": time.time()}
    if c["country_enabled"]:
        geo = country_bundle(c["countries"], refresh)
        bundle["geo"] = geo["geo"]
        bundle["meta"].update(geo["meta"])
    if c["skynet"]:
        old = old_country_policy()
        if old and c["country_enabled"]:
            raise GuardError("Skynet still has country blocks: " + old + ". Remove those in Skynet first to avoid conflicts.")
        bundle["skynet"] = snapshot_skynet(reject_countries=c["country_enabled"])
        bundle["meta"]["skynet"] = {"entries": len(bundle["skynet"]), "fetched": time.time()}
    if c["abuse"]:
        cache = read_json(DATA / "cache/abuse.json", {})
        if not cache or time.time() - cache.get("fetched", 0) >= 86400 or cache.get("score") != c["score"]:
            # At most one successful fetch per 24h for an unchanged threshold.
            rate = read_json(DATA / "cache/abuse-attempt.json", {})
            if time.time() - rate.get("at", 0) < 3600:
                raise GuardError("AbuseIPDB was queried less than an hour ago; try again later.")
            save_json(DATA / "cache/abuse-attempt.json", {"at": time.time()})
            query = urllib.parse.urlencode({"confidenceMinimum": c["score"], "limit": 10000, "ipVersion": 4})
            raw, headers = fetch(ABUSE_API + "blacklist?" + query, key=load_key())
            entries, meta = parse_abuse_blacklist(raw, c["score"])
            cache = {"entries": entries, "meta": meta, "score": c["score"], "fetched": time.time()}
            save_json(DATA / "cache/abuse.json", cache)
        bundle["abuse"] = cache["entries"]
        bundle["meta"]["abuse"] = {"entries": len(cache["entries"]), "fetched": cache["fetched"], "score": cache["score"], "limit": 10000}
    if sum(len(bundle[k]) for k in ("geo", "skynet", "abuse")) > MAX_NETWORKS:
        raise GuardError("More than 200,000 CIDR entries in total; the existing configuration remains active.")
    return bundle

def acceleration(text):
    found = {}
    for line in text.splitlines():
        if re.search(r"\bFlow (?:Ucast )?Learning\b", line, re.I):
            found["flow"] = "disabled" if re.search(r"\bDisabled\b", line, re.I) else "enabled" if re.search(r"\bEnabled\b", line, re.I) else "unknown"
        if "hw acceleration" in line.lower():
            found["hardware"] = "disabled" if re.search(r"\bDisabled\b", line, re.I) else "enabled" if re.search(r"\bEnabled\b", line, re.I) else "unknown"
    return {"flow": found.get("flow", "unknown"), "hardware": found.get("hardware", "unknown"),
            "verified_off": found.get("flow") == found.get("hardware") == "disabled", "raw": text[:4000]}

def memory():
    values = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, rest = line.split(":", 1)
            values[key] = int(rest.split()[0]) * 1024
    except (OSError, ValueError):
        pass
    values.setdefault("MemAvailable", values.get("MemFree", 0) + values.get("Buffers", 0) + values.get("Cached", 0))
    return values

def doctor():
    try:
        fc = acceleration(command(["/bin/fc", "status"], timeout=8).stdout)
    except GuardError:
        fc = acceleration("")
    warnings = []
    model = nv("productid") or nv("odmpid")
    if model != "GT-AX11000":
        warnings.append("This beta is prepared for the GT-AX11000 only.")
    if nv("ipv6_service") != "disabled":
        warnings.append("IPv6 is enabled or its disabled status is unknown; only explicit disabled status is supported.")
    if not fc["verified_off"]:
        warnings.append("Flow Cache/Runner are active or cannot be read reliably. Full inspection is not confirmed.")
    if memory().get("MemAvailable", 0) < 96 * 1024**2:
        warnings.append("Less than 96 MiB of available RAM.")
    if nv("misc_http_x") == "1":
        warnings.append("WAN router administration is enabled. Disable it before activating this beta.")
    if nv("sw_mode") not in ("1",):
        warnings.append("The router must be in router mode, not AP, bridge or repeater mode.")
    if EMERGENCY.exists():
        warnings.append("Emergency shutdown is active. Resuming requires /jffs/scripts/mcg clear-emergency and a new policy test.")
    for program in ("ipset", "iptables", "iptables-save", "iptables-restore", "curl"):
        if not shutil.which(program):
            warnings.append("Required program missing: " + program)
    if "am_addons" not in nv("rc_support"):
        warnings.append("The native Merlin Addons API was not found.")
    return {"model": model, "firmware": ".".join([nv("firmver"), nv("buildno"), nv("extendno")]),
            "acceleration": fc, "ipv6": nv("ipv6_service") or "unknown", "warnings": warnings,
            "ready": not warnings, "memory": memory()}

def interfaces():
    # Only exact WAN interface names; do not guess from a remote hostname.
    out = []
    for unit in (0, 1):
        if unit == 1 and nv("wans_dualwan") in ("", "wan none"):
            continue
        keys = [f"wan{unit}_gw_ifname"]
        if nv(f"wan{unit}_proto") in ("pppoe", "pptp", "l2tp"):
            keys.append(f"wan{unit}_pppoe_ifname")
        else:
            keys.append(f"wan{unit}_ifname")
        for key in keys:
            val = nv(key)
            if val and re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", val):
                out.append(val)
    if not out:
        raise GuardError("The WAN interface could not be detected reliably.")
    return sorted(set(out))

def generation_name():
    return "MCG" + secrets.token_hex(3)

def compile_rules(c, gen, wan):
    if not re.fullmatch(r"MCG[0-9a-f]{6}", gen):
        raise GuardError("Invalid generation ID.")
    if not wan or any(not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", i) for i in wan):
        raise GuardError("Invalid WAN interface.")
    lines = ["*raw"]
    for suffix in ("I", "O", "P"):
        lines.append(f":{gen}{suffix} - [0:0]")
    for direction, suffix, remote in (("in", "I", "src"), ("out", "O", "dst")):
        chain = gen + suffix
        def add(match, label, target):
            lines.append(" ".join(["-A", chain, *match, "-m", "comment", "--comment", f"mcg:{direction}:{label}", "-j", target]))
        # RETURN is scoped to our chain; the original router firewall still runs.
        add(["-m", "set", "--match-set", gen + "L", remote], "local", "RETURN")
        if c["country_enabled"]:
            add(["-m", "set", "!", "--match-set", gen + "G", remote], "country", "DROP")
        if c["skynet"]:
            add(["-m", "set", "--match-set", gen + "S", remote], "skynet", "DROP")
        if c["abuse"]:
            add(["-m", "set", "--match-set", gen + "A", remote], "abuse", "DROP")
        for idx, row in enumerate(c["ports"]):
            if row["direction"] not in (direction, "both"):
                continue
            protocols = ("tcp", "udp") if row["protocol"] == "both" else (row["protocol"],)
            for proto in protocols:
                if row["side"] == "either":
                    match = ["-p", proto, "-m", "multiport", "--ports", row["ports"]]
                else:
                    flag = "--sport" if row["side"] == "remote" and direction == "in" else "--dport"
                    match = ["-p", proto, flag, row["ports"]]
                add(match, "port" + str(idx + 1), "DROP")
        for idx, (scope, match) in enumerate(parse_extra(c["extra_rules"])):
            if scope in (direction, "both"):
                add(match, "extra" + str(idx + 1), "DROP")
        add([], "passed", "RETURN")
    for iface in wan:
        lines.append(f"-A {gen}P -i {iface} -j {gen}I")
        # The generation's inbound chain returns here after passing; do not reclassify as outbound.
        lines.append(f"-A {gen}P -i {iface} -j RETURN")
    # Decrypted VPN inbound: public peer and private/local destination.
    lines += [f"-A {gen}P -m set ! --match-set {gen}L src -m set --match-set {gen}L dst -j {gen}I",
              f"-A {gen}P -m set ! --match-set {gen}L src -m set --match-set {gen}L dst -j RETURN",
              f"-A {gen}P -j {gen}O", "COMMIT"]
    return "\n".join(lines) + "\n"

def build_generation(c, bundle):
    gen = generation_name()
    total = sum(len(bundle[k]) for k in ("geo", "skynet", "abuse"))
    if memory().get("MemAvailable", 0) < 80 * 1024**2 + total * 250:
        raise GuardError("Insufficient memory for a new generation alongside the existing sets.")
    try:
        for suffix, entries in (("L", SPECIAL), ("G", bundle["geo"]), ("S", bundle["skynet"]), ("A", bundle["abuse"])):
            name = gen + suffix
            cap = max(1024, len(entries) + 1024)
            lines = [f"create {name} hash:net family inet hashsize 4096 maxelem {cap}"]
            lines += [f"add {name} {as_network(n)}" for n in entries]
            command(["ipset", "restore"], input_text="\n".join(lines) + "\n", timeout=120)
        text = compile_rules(c, gen, interfaces())
        command(["iptables-restore", "--noflush"], input_text=text)
        return {"gen": gen, "config": c, "bundle": bundle, "started": time.time()}
    except Exception:
        cleanup_generation(gen)
        raise

def cleanup_generation(gen):
    if not isinstance(gen, str) or not re.fullmatch(r"MCG[0-9a-f]{6}", gen):
        return
    for suffix in ("P", "I", "O"):
        kernel("raw", "-F", gen + suffix, check=False)
    for suffix in ("P", "I", "O"):
        kernel("raw", "-X", gen + suffix, check=False)
    for suffix in ("L", "G", "S", "A"):
        command(["ipset", "destroy", gen + suffix], check=False)

def ensure_anchor(chain, target):
    kernel("raw", "-N", target, check=False)
    # Delete ONLY our exact hook, never unrelated rules or a whole table.
    # Insertion before deleting duplicates avoids a first-install gap on subsequent repairs.
    kernel("raw", "-I", chain, "1", "-j", target)
    rules = kernel("raw", "-S", chain).stdout.splitlines()
    positions = []
    pos = 0
    for line in rules:
        if not line.startswith("-A "):
            continue
        pos += 1
        if line == f"-A {chain} -j {target}" and pos != 1:
            positions.append(pos)
    for pos in reversed(positions):
        kernel("raw", "-D", chain, str(pos))

def switch_generation(active):
    for name in ("MCG_PRE", "MCG_OUT"):
        kernel("raw", "-N", name, check=False)
    lines = ["*raw", "-F MCG_PRE", "-F MCG_OUT"]
    if active:
        gen = active["gen"]
        if not re.fullmatch(r"MCG[0-9a-f]{6}", gen):
            raise GuardError("Invalid active generation.")
        lines += [f"-A MCG_PRE -j {gen}P", f"-A MCG_OUT -j {gen}O"]
    lines += ["COMMIT"]
    # One raw-table commit changes both dispatchers. Other chains are retained.
    command(["iptables-restore", "--noflush"], input_text="\n".join(lines) + "\n")
    ensure_anchor("PREROUTING", "MCG_PRE")
    ensure_anchor("OUTPUT", "MCG_OUT")
    # Runtime status does not duplicate hundreds of thousands of network strings.
    summary = None
    if active:
        summary = {k: active[k] for k in ("gen", "config", "started")}
        summary["bundle"] = {k: active["bundle"].get(k, {}) for k in ("meta", "created")}
    save_json(RUN / "active.json", summary)

def pending_expired(p):
    # A clock/NTP adjustment must not extend the live rollback window.
    if "monotonic_expires" in p:
        return time.monotonic() >= p["monotonic_expires"]
    return time.time() >= p["expires"]

def stage(c):
    if read_json(RUN / "pending.json", None):
        raise GuardError("Confirm or roll back the previous change first.")
    c = validate_config(c)
    preparation_started = time.monotonic()
    old = read_json(RUN / "active.json", None)
    bundle = None
    new = None
    if c["enabled"]:
        check = doctor()
        if not check["ready"]:
            raise GuardError("Activation refused: " + " ".join(check["warnings"]))
        bundle = collect_sources(c)
        new = build_generation(c, bundle)
    if time.monotonic() - preparation_started > 180:
        if new:
            cleanup_generation(new["gen"])
        raise GuardError("Preparation took over 180 seconds; nothing was activated. Select fewer countries or retry with the prepared cache.")
    token = secrets.token_hex(16)
    pending = {"token": token, "expires": time.time() + PENDING_SECONDS, "old": old, "new": new, "config": c, "monotonic_expires": time.monotonic() + PENDING_SECONDS}
    save_json(RUN / "pending.json", pending)
    save_json(RUN / "pending-timer.json", {"token": token, "expires": pending["expires"], "monotonic_expires": pending["monotonic_expires"]})
    # Arm rollback BEFORE installing the candidate. A reboot also restores only the confirmed config.
    try:
        with open(RUN / "watchdog.log", "a") as out:
            subprocess.Popen([sys.executable, str(APP / "guard.py"), "watchdog", token],
                             stdin=subprocess.DEVNULL, stdout=out, stderr=out, start_new_session=True, close_fds=True)
    except Exception:
        (RUN / "pending.json").unlink(missing_ok=True)
        (RUN / "pending-timer.json").unlink(missing_ok=True)
        if new:
            cleanup_generation(new["gen"])
        raise GuardError("The rollback watchdog could not start; the candidate policy was NOT activated.")
    try:
        switch_generation(new)
    except Exception:
        try:
            switch_generation(old)
        finally:
            if new:
                cleanup_generation(new["gen"])
            (RUN / "pending.json").unlink(missing_ok=True)
            (RUN / "pending-timer.json").unlink(missing_ok=True)
        raise
    return {"pending": True, "token": token, "expires": pending["expires"],
            "message": "Test policy active. Check internet and administration access, then confirm within 120 seconds to prevent rollback."}

def rollback(token=None):
    p = read_json(RUN / "pending.json", None)
    if not p:
        return {"message": "No pending change."}
    if token and not secrets.compare_digest(token, p["token"]):
        raise GuardError("Incorrect rollback token.")
    switch_generation(None if EMERGENCY.exists() else p["old"])
    if p["new"]:
        cleanup_generation(p["new"]["gen"])
    (RUN / "pending.json").unlink(missing_ok=True)
    (RUN / "pending-timer.json").unlink(missing_ok=True)
    return {"message": "Previous configuration restored."}

def confirm(token):
    p = read_json(RUN / "pending.json", None)
    if not p or not secrets.compare_digest(str(token), p["token"]):
        raise GuardError("No matching pending change.")
    if pending_expired(p):
        rollback(p["token"])
        raise GuardError("Confirmation arrived too late; the previous configuration was restored.")
    # One durable document contains both config and the exact validated lists for offline boot.
    confirmed = {"config": p["config"], "bundle": p["new"]["bundle"] if p["new"] else None, "confirmed": time.time()}
    save_json(DATA / "confirmed.json", confirmed)
    (RUN / "pending.json").unlink(missing_ok=True)
    (RUN / "pending-timer.json").unlink(missing_ok=True)
    if p["old"]:
        cleanup_generation(p["old"]["gen"])
    return {"message": "Configuration confirmed and saved."}

def disable():
    p = read_json(RUN / "pending.json", None)
    a = read_json(RUN / "active.json", None)
    # Emergency switch does not require feeds, doctor, or working acceleration queries.
    switch_generation(None)
    if a:
        cleanup_generation(a["gen"])
    if p and p.get("old") and (not a or p["old"]["gen"] != a["gen"]):
        cleanup_generation(p["old"]["gen"])
    (RUN / "pending.json").unlink(missing_ok=True)
    (RUN / "pending-timer.json").unlink(missing_ok=True)
    saved = read_json(DATA / "confirmed.json", {"config": copy.deepcopy(DEFAULT)})
    saved["config"]["enabled"] = False
    save_json(DATA / "confirmed.json", saved)
    return {"message": "The firewall add-on is disabled. The original Merlin/Skynet firewall is unchanged."}

def refresh_sources(mirror_only=False):
    if read_json(RUN / "pending.json", None):
        raise GuardError("Source refresh is blocked while a policy change awaits confirmation.")
    saved = read_json(DATA / "confirmed.json", {"config": copy.deepcopy(DEFAULT)})
    c = validate_config(saved["config"])
    if not c["enabled"]:
        return {"message": "No active confirmed policy; no sources downloaded."}
    check = doctor()
    if not check["ready"]:
        raise GuardError("Source refresh postponed: " + " ".join(check["warnings"]))
    if mirror_only:
        if not c["skynet"]:
            return {"message": "Skynet mirroring is not configured."}
        entries = snapshot_skynet(reject_countries=c["country_enabled"])
        bundle = copy.deepcopy(saved.get("bundle"))
        if not bundle:
            raise GuardError("The saved source copy is missing.")
        if entries == bundle["skynet"]:
            return {"message": "The Skynet set is unchanged; no kernel rebuild is needed."}
        bundle["skynet"] = entries
        bundle["meta"]["skynet"] = {"entries": len(entries), "fetched": time.time()}
        if sum(len(bundle[k]) for k in ("geo", "skynet", "abuse")) > MAX_NETWORKS:
            raise GuardError("The new Skynet copy exceeds the memory limit.")
    else:
        bundle = copy.deepcopy(saved.get("bundle"))
        if not bundle:
            raise GuardError("The saved source copy is missing.")
        reputation_config = dict(c, country_enabled=False)
        reputations = collect_sources(reputation_config)
        for key in ("skynet", "abuse"):
            bundle[key] = reputations[key]
            if key in reputations["meta"]:
                bundle["meta"][key] = reputations["meta"][key]
        if sum(len(bundle[k]) for k in ("geo", "skynet", "abuse")) > MAX_NETWORKS:
            raise GuardError("The refreshed sources exceed the memory limit.")
    new = build_generation(c, bundle)
    old = read_json(RUN / "active.json", None)
    try:
        switch_generation(new)
        save_json(DATA / "confirmed.json", {"config": c, "bundle": bundle, "confirmed": saved.get("confirmed"), "refreshed": time.time()})
    except Exception:
        switch_generation(old)
        cleanup_generation(new["gen"])
        raise
    if old:
        cleanup_generation(old["gen"])
    return {"message": "Skynet mirror updated." if mirror_only else "Reputation sources refreshed. Country data and its schedule were not changed."}

def ip_lookup(value, online=False):
    n = as_network(value, public=True)
    ip = str(ipaddress.ip_network(n).network_address)
    if "/" in value:
        raise GuardError("Enter a single IPv4 address, not a subnet.")
    active = read_json(RUN / "active.json", None)
    answer = {"ip": ip, "otx": "https://otx.alienvault.com/indicator/ip/" + ip,
              "abuse_url": "https://www.abuseipdb.com/check/" + ip, "findings": []}
    if not active:
        answer["verdict"] = "The firewall add-on is inactive; no active local sets are available to query."
    else:
        gen, c = active["gen"], active["config"]

        def contains(suffix):
            p = command(["ipset", "test", gen + suffix, ip], check=False)
            if p.returncode not in (0, 1):
                raise GuardError("The IP set could not be checked.")
            return p.returncode == 0
        if c["country_enabled"] and not contains("G"):
            answer["verdict"] = "Country not allowed or not present in the loaded country data; reputation check skipped."
            answer["blocked_by_country"] = True
            return answer
        for enabled, suffix, label in ((c["skynet"], "S", "Skynet"), (c["abuse"], "A", "AbuseIPDB")):
            if enabled:
                answer["findings"].append({"source": label, "listed": contains(suffix)})
        listed = any(r["listed"] for r in answer["findings"])
        answer["verdict"] = "Listed in an active blocklist." if listed else "Not found in the active blocklists; not proven safe."
    if online:
        cachepath = DATA / "cache" / ("lookup-" + ip + ".json")
        cache = read_json(cachepath, {})
        if cache and time.time() - cache.get("fetched", 0) < 86400:
            answer["online"] = cache
        else:
            rate = read_json(RUN / "lookup-rate.json", {})
            if time.time() - rate.get("at", 0) < 10:
                raise GuardError("Wait ten seconds between online detail checks.")
            save_json(RUN / "lookup-rate.json", {"at": time.time()})
            query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
            raw, headers = fetch(ABUSE_API + "check?" + query, key=load_key())
            obj = json.loads(raw).get("data", {})
            score = obj.get("abuseConfidenceScore")
            if type(score) is not int or not 0 <= score <= 100:
                raise GuardError("The online response does not contain a valid abuse score.")
            cache = {"fetched": time.time(), "score": score, "reports": obj.get("totalReports"),
                     "country": obj.get("countryCode"), "isp": obj.get("isp"), "domain": obj.get("domain")}
            save_json(cachepath, cache)
            # Bound the optional lookup cache to 200 addresses.
            files = sorted((DATA / "cache").glob("lookup-*.json"), key=lambda p: p.stat().st_mtime)
            for p in files[:-200]:
                p.unlink(missing_ok=True)
            answer["online"] = cache
        answer["online_note"] = "Detail information: this lookup does not automatically change the firewall policy. Automatic blocking uses the loaded lists."
    return answer

def parse_counters(text):
    result = []
    for line in text.splitlines():
        m = re.match(r"\[(\d+):(\d+)\] -A (\S+) .*--comment \"?(mcg:([^ :\"]+):([^ \"\n]+))\"? .*?-j (\S+)", line)
        if m:
            result.append({"packets": int(m[1]), "bytes": int(m[2]), "chain": m[3],
                           "direction": m[5], "reason": m[6], "target": m[7]})
    return result

def parse_connection(line):
    if "ipv6" in line:
        return None
    proto = next((v for v in line.split()[:5] if v in ("tcp", "udp", "icmp")), "other")
    src = re.findall(r"\bsrc=([0-9.]+)", line)
    dst = re.findall(r"\bdst=([0-9.]+)", line)
    if not src or not dst:
        return None
    try:
        ipaddress.IPv4Address(src[0]); ipaddress.IPv4Address(dst[0])
    except ValueError:
        return None
    sports = re.findall(r"\bsport=(\d+)", line)
    dports = re.findall(r"\bdport=(\d+)", line)
    values = re.findall(r"\bbytes=(\d+)", line)
    state = next((s for s in ("ESTABLISHED", "SYN_SENT", "SYN_RECV", "TIME_WAIT", "CLOSE_WAIT", "UNREPLIED", "ASSURED") if s in line), "")
    return {"source": src[0], "destination": dst[0], "sport": int(sports[0]) if sports else None,
            "dport": int(dports[0]) if dports else None, "protocol": proto, "state": state,
            "bytes": sum(int(x) for x in values[:2]) if values else None,
            "original_bytes": int(values[0]) if values else None,
            "reply_bytes": int(values[1]) if len(values) > 1 else None,
            "reply_source": src[1] if len(src) > 1 else None,
            "reply_destination": dst[1] if len(dst) > 1 else None}

def connection_snapshot(limit):
    rows, seen = [], 0
    paths = (Path("/proc/net/nf_conntrack"), Path("/proc/net/ip_conntrack"))
    path = next((p for p in paths if p.is_file()), None)
    started = time.monotonic()
    budget_exceeded = False
    if path:
        with path.open(errors="replace") as f:
            for line in f:
                seen += 1
                if len(rows) < limit:
                    row = parse_connection(line)
                    if row:
                        rows.append(row)
                # Prevent huge tables from consuming a control-plane worker indefinitely.
                if seen >= 100_000 or (seen % 256 == 0 and time.monotonic() - started >= 3):
                    budget_exceeded = True
                    break
    return {"rows": rows, "read_records": seen, "shown": len(rows),
            "scan_limited": budget_exceeded, "truncated": seen > len(rows) or budget_exceeded,
            "available": path is not None,
            "note": "Snapshot, not a complete connection log. Short connections may be missing; filtering runs independently in the kernel."}

def interface_bytes():
    result = {}
    try:
        for line in Path("/proc/net/dev").read_text().splitlines()[2:]:
            name, rest = line.split(":", 1)
            v = rest.split()
            result[name.strip()] = {"rx": int(v[0]), "tx": int(v[8])}
    except (OSError, ValueError, IndexError):
        pass
    return result

def hooks_healthy(raw, active):
    """Verify exact owned chain targets and ordering, not mere substring presence."""
    if not active:
        return False
    rules = collections.defaultdict(list)
    declared = set()
    for line in raw.splitlines():
        line = re.sub(r"^\[\d+:\d+\] ", "", line)
        if line.startswith(":"):
            declared.add(line.split()[0][1:])
        if line.startswith("-A "):
            fields = line.split()
            if len(fields) >= 4:
                rules[fields[1]].append(line)
    g = active["gen"]
    if any(g + suffix not in declared for suffix in ("I", "O", "P")):
        return False
    for chain, target in (("PREROUTING", "MCG_PRE"), ("OUTPUT", "MCG_OUT"),
                          ("MCG_PRE", g + "P"), ("MCG_OUT", g + "O")):
        if not rules[chain] or rules[chain][0] != f"-A {chain} -j {target}":
            return False
    return not EMERGENCY.exists()

def status(detailed=True):
    active = read_json(RUN / "active.json", None)
    pending = read_json(RUN / "pending.json", None)
    saved = read_json(DATA / "confirmed.json", {"config": copy.deepcopy(DEFAULT)})
    c = pending["config"] if pending else saved["config"]
    d = doctor()
    raw = command(["iptables-save", "-c", "-t", "raw"], check=False).stdout if shutil.which("iptables-save") else ""
    counters = parse_counters(raw)
    if active:
        counters = [x for x in counters if x["chain"].startswith(active["gen"])]
    else:
        counters = []
    # A green configured switch is never used as proof of enforcement.
    hooks = hooks_healthy(raw, active)
    healthy = bool(active and hooks and d["ready"])
    warnings = list(d["warnings"])
    if c["enabled"] and not active:
        warnings.append("The policy is saved as enabled but there is no active generation: NOT PROTECTED by this add-on.")
    if active and not hooks:
        warnings.append("An anchor, chain order or generation is missing or incorrect; filtering is NOT confirmed.")
    if active:
        for name, meta in active["bundle"].get("meta", {}).items():
            limit = 2 * 86400 if name == "abuse" else 7 * 86400
            if time.time() - meta.get("checked", meta.get("fetched", 0)) > limit:
                warnings.append("Source " + name + " is outdated; check updates. Existing rules remain active.")
    for fname in ("boot-error.json", "background-error.json"):
        error = read_json(RUN / fname, {})
        if error:
            warnings.append(error.get("message", "A scheduled operation failed."))
    result = {"version": VERSION, "at": time.time(), "config": c, "active": bool(active), "healthy": healthy,
              "generation": active["gen"] if active else None, "counters": counters,
              "doctor": d, "warnings": warnings, "sources": active["bundle"]["meta"] if active else {},
              "pending": {k: pending[k] for k in ("token", "expires")} if pending else None,
              "interfaces": interface_bytes(), "load": list(os.getloadavg()),
              "history": read_json(RUN / "history.json", []),
              "key_configured": (DATA / "abuseipdb.key").exists()}
    import updater
    from tools import maintenance, telemetry
    result["updates"] = updater.status()
    result["country_updates"] = maintenance.status()
    telemetry.attach(result)
    save_json(PUBLIC / "status.json", result, public=True)
    return result

def collect_tick():
    pending = read_json(RUN / "pending.json", None)
    if pending and pending_expired(pending):
        rollback(pending["token"])
    active = read_json(RUN / "active.json", None)
    if active and not EMERGENCY.exists():
        # Repair only missing/moved owned entry points, not another add-on's rules.
        for chain, target in (("PREROUTING", "MCG_PRE"), ("OUTPUT", "MCG_OUT")):
            rules = kernel("raw", "-S", chain).stdout.splitlines()
            first = next((r for r in rules if r.startswith("-A ")), "")
            if first != f"-A {chain} -j {target}":
                ensure_anchor(chain, target)
    s = status(detailed=False)
    from tools import telemetry
    telemetry.collect(s)
    telemetry.attach(s)
    save_json(PUBLIC / "status.json", s, public=True)
    return {"message": "Status refreshed; statistics sampled when due."}

def boot():
    saved = read_json(DATA / "confirmed.json", {"config": copy.deepcopy(DEFAULT)})
    c = validate_config(saved["config"])
    (RUN / "pending.json").unlink(missing_ok=True)
    (RUN / "pending-timer.json").unlink(missing_ok=True)
    old = read_json(RUN / "active.json", None)
    if c["enabled"]:
        d = doctor()
        if not d["ready"]:
            # Do not claim that merely installing rules disables a hardware fastpath.
            save_json(RUN / "boot-error.json", {"at": time.time(), "message": "Boot preflight failed: " + " ".join(d["warnings"])})
            raise GuardError("Boot preflight failed: " + " ".join(d["warnings"]))
        if not saved.get("bundle"):
            raise GuardError("The confirmed source copy is missing; the policy cannot be restored.")
        new = build_generation(c, saved["bundle"])
        switch_generation(new)
    else:
        switch_generation(None)
    if old:
        cleanup_generation(old["gen"])
    if not (RUN / "history.json").exists():
        save_json(RUN / "history.json", read_json(DATA / "history.json", []))
    (RUN / "boot-error.json").unlink(missing_ok=True)
    return {"message": "Confirmed configuration restored without a network download."}

def dump_tables():
    pieces = []
    for name in ("raw", "mangle", "nat", "filter"):
        p = command(["iptables-save", "-c", "-t", name], check=False)
        pieces.append(f"# TABLE {name}\n" + (p.stdout if p.returncode == 0 else p.stderr))
    result = "\n".join(pieces)
    atomic(PUBLIC / "iptables.txt", result, 0o644)
    return {"text": result[:1_000_000], "truncated": len(result) > 1_000_000}

def handle(payload):
    if not isinstance(payload, dict) or set(payload) - {"action", "config", "ip", "online", "token", "settings", "commit", "countries"}:
        raise GuardError("Invalid request.")
    action = payload.get("action")
    if isinstance(action, str) and action.startswith("update-"):
        import updater
        if action == "update-check": return updater.check()
        if action == "update-download": return updater.download_latest()
        if action == "update-install": return updater.install_staged(payload.get("commit"))
        if action == "update-settings": return updater.save_settings(payload.get("settings"))
        if action == "update-rollback": return updater.rollback()
        raise GuardError("Unknown update action.")
    if action in ("country-refresh", "country-settings"):
        from tools import maintenance
        if action == "country-settings": return maintenance.save_settings(payload.get("settings"))
        return maintenance.refresh_countries(payload.get("countries"))
    if action in ("stats-settings", "stats-refresh"):
        from tools import telemetry
        if action == "stats-settings": return telemetry.save_settings(payload.get("settings"))
        state = status(detailed=False)
        return telemetry.collect(state, force=True)
    if action == "status":
        return status()
    if action == "apply":
        return stage(payload.get("config"))
    if action == "confirm":
        return confirm(str(payload.get("token", "")))
    if action == "rollback":
        return rollback(str(payload.get("token", "")))
    if action == "disable":
        return disable()
    if action == "lookup":
        if type(payload.get("online", False)) is not bool:
            raise GuardError("Invalid online option.")
        return ip_lookup(payload.get("ip", ""), payload.get("online", False))
    if action == "refresh":
        return refresh_sources()
    if action == "tables":
        return dump_tables()
    if action == "doctor":
        return doctor()
    raise GuardError("Unknown management action.")

def web_request(request_id):
    if not re.fullmatch(r"[0-9]{20,32}", request_id):
        raise GuardError("Invalid request identifier.")
    # Fixed shell program, no interpolated user text; use Merlin's own settings reader.
    rawid = command(["sh", "-c", ". /usr/sbin/helper.sh; am_settings_get mcg_request"]).stdout.strip()
    if rawid != request_id:
        raise GuardError("This web request was superseded by a newer request.")
    encoded = command(["sh", "-c", ". /usr/sbin/helper.sh; am_settings_get mcg_payload"]).stdout.strip()
    finalid = command(["sh", "-c", ". /usr/sbin/helper.sh; am_settings_get mcg_request"]).stdout.strip()
    if finalid != request_id:
        raise GuardError("The request changed while being read; nothing was applied.")
    if len(encoded) > 7000:
        raise GuardError("The request is too large for the Merlin Addons API.")
    try:
        payload = json.loads(base64.b64decode(encoded, validate=True).decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise GuardError("Invalid encoded request.") from exc
    previous = read_json(RUN / "last-request.json", {})
    if previous.get("id") == request_id:
        raise GuardError("This request has already been processed; reload and submit again.")
    save_json(RUN / "last-request.json", {"id": request_id})
    result = handle(payload)
    if payload.get("action") != "status":
        status()
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("doctor", "status", "tick", "boot", "refresh", "mirror", "disable", "tables", "key", "web", "watchdog", "dry-run", "update-check", "update-download", "update-install", "update-rollback", "update-scheduled", "country-refresh", "maintenance", "stats-refresh"))
    parser.add_argument("argument", nargs="?")
    args = parser.parse_args()
    if args.action == "dry-run":
        if not args.argument:
            parser.error("dry-run requires a configuration file")
        c = validate_config(read_json(Path(args.argument)))
        print(compile_rules(c, "MCG000001", ["eth0"]))
        return 0
    if os.geteuid() != 0:
        raise GuardError("Run as the router administrator/root.")
    setup()
    if args.action == "watchdog":
        token = args.argument or ""
        if not re.fullmatch("[0-9a-f]{32}", token):
            raise GuardError("Invalid watchdog token.")
        # Wakes regularly; only this short-lived rollback worker is resident.
        for _ in range(PENDING_SECONDS + 5):
            p = read_json(RUN / "pending-timer.json", None)
            if not p or p["token"] != token:
                return 0
            if pending_expired(p):
                with locked(wait=True):
                    rollback(token)
                    status()
                return 0
            time.sleep(1)
        return 0
    try:
        with locked():
            if args.action == "web":
                result = web_request(args.argument or "")
            elif args.action.startswith("update-"):
                import updater
                if args.action == "update-scheduled": result = updater.check(scheduled=True)
                elif args.action == "update-check": result = updater.check()
                elif args.action == "update-download": result = updater.download_latest()
                elif args.action == "update-install": result = updater.install_staged(args.argument)
                else: result = updater.rollback()
                status()
            elif args.action in ("country-refresh", "maintenance", "stats-refresh"):
                from tools import maintenance, telemetry
                if args.action == "country-refresh": result = maintenance.refresh_countries()
                elif args.action == "maintenance": result = maintenance.run_scheduled()
                else: result = telemetry.collect(status(detailed=False), force=True)
                status()
            elif args.action == "key":
                key = getpass.getpass("AbuseIPDB API key (hidden input): ").strip()
                if not re.fullmatch(r"[A-Za-z0-9_-]{16,256}", key):
                    raise GuardError("Invalid key format.")
                atomic(DATA / "abuseipdb.key", key + "\n")
                result = {"message": "Key saved with permissions 0600 outside the web directory."}
            else:
                result = {"doctor": doctor, "status": status, "tick": collect_tick, "boot": boot,
                          "refresh": refresh_sources, "mirror": lambda: refresh_sources(mirror_only=True), "disable": disable, "tables": dump_tables}[args.action]()
            if args.action in ("boot", "refresh", "mirror"):
                (RUN / "background-error.json").unlink(missing_ok=True)
            if args.action == "web":
                save_json(PUBLIC / "result.json", {"id": args.argument, "ok": True, "data": result, "at": time.time()}, public=True)
            print(json.dumps(result, ensure_ascii=False, indent=2))
    except Exception as exc:
        # Errors are explicit. We do not substitute an empty country/reputation database.
        message = str(exc)
        if args.action in ("boot", "refresh", "mirror"):
            save_json(RUN / "background-error.json", {"at": time.time(), "message": args.action + ": " + message})
        if args.action == "web":
            save_json(PUBLIC / "result.json", {"id": args.argument, "ok": False, "error": message, "at": time.time()}, public=True)
        print("ERROR: " + message, file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except GuardError as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        sys.exit(1)
