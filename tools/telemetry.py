"""Bounded, sampled telemetry. No packet capture, per-IP API calls or resident worker.

Connection totals are current conntrack observations, not completed-flow accounting.
Rule counters and interface counters have explicitly different scopes.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from pathlib import Path
import math
import time
import guard as g

DEFAULT_SETTINGS = {"interval_minutes": 1, "retention_hours": 24, "top_n": 20}
MAX_HISTORY = 10080


def validate_settings(value):
    if not isinstance(value, dict) or set(value) != set(DEFAULT_SETTINGS):
        raise g.GuardError("Statistics preferences require interval_minutes, retention_hours and top_n.")
    for key, low, high in (("interval_minutes", 1, 60), ("retention_hours", 1, 168), ("top_n", 5, 50)):
        if type(value[key]) is not int or not low <= value[key] <= high:
            raise g.GuardError(key + f" must be an integer from {low} to {high}.")
    return dict(value)


def settings():
    return validate_settings(g.read_json(g.DATA / "stats-settings.json", DEFAULT_SETTINGS))


def save_settings(value):
    value = validate_settings(value)
    g.save_json(g.DATA / "stats-settings.json", value)
    return {"message": "Statistics preferences saved. Sampling is independent of per-packet firewall checks."}


def read_int(path):
    try:
        return int(Path(path).read_text().strip())
    except (OSError, ValueError):
        return None


def cpu_ticks():
    try:
        with Path("/proc/stat").open() as source:
            values = [int(x) for x in source.readline().split()[1:9]]
        if len(values) < 4:
            return None
        return {"total": sum(values), "idle": values[3] + (values[4] if len(values) > 4 else 0)}
    except (OSError, ValueError):
        return None


def boot_id():
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return None


def cpu_percent(current, previous):
    if not current or not previous:
        return None
    total = current["total"] - previous["total"]
    idle = current["idle"] - previous["idle"]
    if total <= 0 or not 0 <= idle <= total:
        return None
    return round(100 * (total - idle) / total, 2)


def local_ip(value):
    try:
        ip = g.ipaddress.IPv4Address(value)
        return (int(ip) >> 24 == 10 or int(ip) >> 20 == 0xac1 or
                int(ip) >> 16 == 0xc0a8 or int(ip) >> 16 == 0xa9fe or int(ip) >> 24 == 127)
    except (ValueError, TypeError):
        return False


def endpoints(row):
    src, dst = row["source"], row["destination"]
    if local_ip(src) and not local_ip(dst):
        return src, dst, "out"
    if not local_ip(src) and local_ip(dst):
        return dst, src, "in"
    if local_ip(src) and local_ip(dst):
        return src, None, "local"
    # Incoming DNAT: original destination is public, reply source is the LAN server.
    if local_ip(row.get("reply_source")):
        return row["reply_source"], src, "in"
    if local_ip(row.get("reply_destination")):
        return row["reply_destination"], dst, "out"
    return None, dst, "public/router"


def summarize(rows, limit):
    groups = {key: defaultdict(lambda: {"connections": 0, "known_bytes": 0, "accounted_rows": 0})
              for key in ("local_ips", "remote_ips", "ports", "protocols", "states")}
    local, remote = set(), set()
    directions = Counter()
    accounted = 0
    for row in rows:
        host, peer, direction = endpoints(row)
        row.update(local_ip=host, remote_ip=peer, direction=direction)
        if host: local.add(host)
        if peer: remote.add(peer)
        directions[direction] += 1
        if row.get("bytes") is not None: accounted += 1
        labels = {"local_ips": host, "remote_ips": peer,
                  "ports": row["protocol"] + "/" + str(row.get("dport") or "—"),
                  "protocols": row["protocol"], "states": row.get("state") or "not reported"}
        for group, key in labels.items():
            if key is None: continue
            item = groups[group][key]
            item["connections"] += 1
            if row.get("bytes") is not None:
                item["known_bytes"] += row["bytes"]
                item["accounted_rows"] += 1
    output = {group: sorted((dict(value, label=key) for key, value in values.items()),
                           key=lambda r: (-r["connections"], -r["known_bytes"], r["label"]))[:limit]
              for group, values in groups.items()}
    return dict(output, unique_local=len(local), unique_remote=len(remote), directions=dict(directions),
                accounted_rows=accounted, shown_rows=len(rows))


def rule_totals(counters):
    result = defaultdict(lambda: {"packets": 0, "bytes": 0})
    for row in counters:
        key = ":".join((row["direction"], row["reason"], row["target"]))
        result[key]["packets"] += row["packets"]
        result[key]["bytes"] += row["bytes"]
    return dict(result)


def rule_deltas(current, previous, continuous, seconds):
    rows = []
    for key, value in current.items():
        old = previous.get(key)
        valid = bool(continuous and old and seconds > 0 and all(value[x] >= old[x] for x in ("packets", "bytes")))
        direction, reason, target = key.split(":")
        packets = value["packets"] - old["packets"] if valid else None
        size = value["bytes"] - old["bytes"] if valid else None
        rows.append(dict(direction=direction, reason=reason, target=target, packets=packets,
                         bytes=size, pps=round(packets / seconds, 3) if valid else None))
    return rows


def interface_rates(current, previous, continuous, seconds):
    result = {}
    for name, value in current.items():
        old = previous.get(name)
        valid = bool(continuous and old and seconds > 0 and value["rx"] >= old["rx"] and value["tx"] >= old["tx"])
        rx = value["rx"] - old["rx"] if valid else None
        tx = value["tx"] - old["tx"] if valid else None
        result[name] = dict(value, rx_delta=rx, tx_delta=tx,
                            rx_bps=round(rx * 8 / seconds, 1) if valid else None,
                            tx_bps=round(tx * 8 / seconds, 1) if valid else None)
    return result


def keep_history(history, now, prefs):
    cutoff = now - prefs["retention_hours"] * 3600
    return [r for r in history if cutoff <= r.get("at", 0) <= now + 60][-MAX_HISTORY:]


def collect(state, force=False):
    prefs = settings()
    now, mono, boot = time.time(), time.monotonic(), boot_id()
    previous = g.read_json(g.RUN / "telemetry-baseline.json", {})
    same_boot = bool(boot and boot == previous.get("boot"))
    elapsed = mono - previous.get("monotonic", mono)
    if same_boot and 0 <= elapsed < (10 if force else prefs["interval_minutes"] * 60 - 1):
        return {"message": "Statistics sample is not due yet; cached figures retained."}
    if state["doctor"]["memory"].get("MemAvailable", 0) < 64 * 1024**2 or state["load"][0] > (g.os.cpu_count() or 1) * 1.5:
        g.save_json(g.RUN / "telemetry-health.json", {"at": now, "message": "Sampling deferred due to memory pressure or high load; existing sample retained. Kernel filtering is independent."})
        return {"message": "Statistics deferred to keep router load bounded."}
    started = time.monotonic()
    snap = g.connection_snapshot(state["config"].get("max_rows", 3000))
    summary = summarize(snap["rows"], prefs["top_n"])
    current_cpu = cpu_ticks()
    counters = rule_totals(state["counters"])
    same_generation = same_boot and state["generation"] is not None and state["generation"] == previous.get("generation")
    deltas = rule_deltas(counters, previous.get("rules", {}), same_generation, elapsed)
    interfaces = interface_rates(state["interfaces"], previous.get("interfaces", {}), same_boot, elapsed)
    percent = cpu_percent(current_cpu, previous.get("cpu")) if same_boot else None
    drop_rows = [r for r in deltas if r["target"] == "DROP"]
    valid_drops = bool(same_generation and elapsed > 0 and all(r["packets"] is not None for r in drop_rows))
    blocked = sum(r["packets"] for r in drop_rows) if valid_drops else None
    blocked_bytes = sum(r["bytes"] for r in drop_rows) if valid_drops else None
    conn_count = read_int("/proc/sys/net/netfilter/nf_conntrack_count")
    conn_max = read_int("/proc/sys/net/netfilter/nf_conntrack_max")
    mem = state["doctor"]["memory"]
    sample = {"at": now, "duration_ms": round((time.monotonic() - started) * 1000, 2),
              "interval_seconds": round(elapsed, 2) if same_boot else None,
              "generation": state["generation"], "cpu_percent": percent, "load": state["load"][0],
              "free": mem.get("MemAvailable"), "total_memory": mem.get("MemTotal"),
              "conntrack_count": conn_count, "conntrack_max": conn_max,
              "connections": snap["read_records"], "shown": snap["shown"],
              "blocked_packets": blocked, "blocked_bytes": blocked_bytes,
              "blocked_pps": round(blocked / elapsed, 3) if valid_drops else None,
              "counter_gap": not same_generation, "interfaces": interfaces,
              "rule_deltas": deltas, "summary": summary}
    notes = ["IP, port, protocol and state rankings cover the displayed IPv4 snapshot only, not all lifetime traffic.",
             "Conntrack bytes, where available, are cumulative bytes of still-present flows, not transferred bytes during this sample.",
             "Blocked packets are dropped before conntrack and do not appear as a list of blocked connections.",
             "Passed means passed this add-on, not accepted by all other router/firewall rules.",
             "Interface counters are shown separately. Do not sum bridged/VLAN/WAN interfaces: the same traffic can be counted more than once."]
    if snap.get("truncated"): notes.append("Connection detail rows or scan time are capped. Rankings are partial.")
    if summary["accounted_rows"] < len(snap["rows"]): notes.append("Some or all connection byte counters are unavailable. Conntrack accounting is not enabled automatically.")
    if not same_generation: notes.append("No rule-rate baseline or a policy/reboot boundary: interval rule totals are unavailable, not zero.")
    snapshot = {"sample": sample, "connections": snap, "notes": notes}
    history = g.read_json(g.RUN / "telemetry-history.json", None)
    if history is None:
        history = g.read_json(g.DATA / "telemetry-history.json", [])
    small = {k: v for k, v in sample.items() if k not in ("summary", "rule_deltas", "interfaces")}
    small["interfaces"] = {name: {k: values[k] for k in ("rx_bps", "tx_bps")} for name, values in interfaces.items()}
    history.append(small)
    history = keep_history(history, now, prefs)
    g.save_json(g.RUN / "telemetry-snapshot.json", snapshot)
    g.save_json(g.RUN / "telemetry-history.json", history)
    g.save_json(g.RUN / "telemetry-baseline.json", {"at": now, "monotonic": mono, "boot": boot,
                "generation": state["generation"], "cpu": current_cpu, "rules": counters, "interfaces": state["interfaces"]})
    g.save_json(g.RUN / "telemetry-health.json", {})
    checkpoint = g.DATA / "telemetry-history.json"
    if not checkpoint.exists() or now - checkpoint.stat().st_mtime >= 3600:
        g.save_json(checkpoint, history)
    return {"message": "Statistics sampled. No online reputation lookups or packet captures were performed."}


def attach(state):
    prefs = settings()
    snap = g.read_json(g.RUN / "telemetry-snapshot.json", {})
    history_path = g.RUN / "telemetry-history.json"
    history = g.read_json(history_path, None)
    if history is None:
        history = g.read_json(g.DATA / "telemetry-history.json", [])
    history = keep_history(history, time.time(), prefs)
    sample = snap.get("sample")
    state["telemetry"] = {"settings": prefs, "sample": sample, "history": history,
                          "notes": snap.get("notes", []), "health": g.read_json(g.RUN / "telemetry-health.json", {}),
                          "next_sample": sample["at"] + prefs["interval_minutes"] * 60 if sample else None}
    state["connections"] = snap.get("connections", {"rows": [], "available": False, "note": "Waiting for the first scheduled statistics sample."})
    # The legacy overview graph needs only a small load series. Avoid duplicating
    # full interface/history data in every public status JSON payload.
    state["history"] = [{"at": row["at"], "load": row.get("load")} for row in history[-180:]]
