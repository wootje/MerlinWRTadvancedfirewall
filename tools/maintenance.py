"""Independent country refreshes and elapsed-hour scheduling; no resident daemon.

Public entry points run under guard.locked(). Network work never runs in status().
"""
from __future__ import annotations
import copy
import shutil
import time
import guard as g

DEFAULT_SETTINGS = {"auto_update": True, "interval_hours": 24}


def validate_settings(value):
    if not isinstance(value, dict) or set(value) != set(DEFAULT_SETTINGS):
        raise g.GuardError("Country preferences require auto_update and interval_hours.")
    if type(value["auto_update"]) is not bool:
        raise g.GuardError("Automatic country updates must be true or false.")
    if type(value["interval_hours"]) is not int or not 1 <= value["interval_hours"] <= 720:
        raise g.GuardError("Country update interval must be an integer from 1 to 720 hours.")
    return dict(value)


def settings():
    return validate_settings(g.read_json(g.DATA / "country-settings.json", DEFAULT_SETTINGS))


def reconcile_schedule():
    # No shell/cron on a workstation. On a supported router, cru is required by
    # installation; failures propagate rather than claiming a schedule was saved.
    if shutil.which("cru"):
        import install_support
        install_support.maintenance_cron()


def save_settings(value):
    value = validate_settings(value)
    old = settings()
    g.save_json(g.DATA / "country-settings.json", value)
    try:
        reconcile_schedule()
    except Exception:
        g.save_json(g.DATA / "country-settings.json", old)
        raise
    return {"message": "Country update preferences saved. Manual refresh remains available.", "country_updates": status()}


def status():
    state = g.read_json(g.DATA / "country-update-state.json", {})
    prefs = settings()
    result = dict(state, settings=prefs)
    result["next_check"] = ((state.get("last_attempt") or time.time()) + prefs["interval_hours"] * 3600
                            if state.get("last_attempt") else time.time()) if prefs["auto_update"] else None
    result["message"] = state.get("message", "No dedicated country refresh has completed yet.")
    result["note"] = "Only selected IPv4 country files are downloaded; unchanged commit-pinned files are reused. Schedules use elapsed hours and are evaluated every five minutes."
    return result


def validate_countries(countries):
    c = g.validate_config(dict(g.DEFAULT, countries=countries))
    if not c["countries"]:
        raise g.GuardError("Select at least one country before refreshing its IPv4 data.")
    return c["countries"]


def apply_bundle(saved, geo):
    """Apply all prepared country data together; preserve reputation/port policy."""
    c = saved["config"]
    old = g.read_json(g.RUN / "active.json", None)
    if not old or old.get("config") != c:
        raise g.GuardError("Active/confirmed policy mismatch. Country files are cached, but no live policy was replaced.")
    report = g.doctor()
    if not report["ready"]:
        raise g.GuardError("Country application deferred: " + " ".join(report["warnings"]))
    bundle = copy.deepcopy(saved.get("bundle"))
    if not bundle:
        raise g.GuardError("The confirmed source copy is missing; existing rules were retained.")
    bundle["geo"] = geo["geo"]
    for cc in c["countries"]:
        bundle["meta"][cc] = geo["meta"][cc]
    if sum(len(bundle[k]) for k in ("geo", "skynet", "abuse")) > g.MAX_NETWORKS:
        raise g.GuardError("Country and reputation data exceed the 200,000-entry limit.")
    changed = bundle["geo"] != saved["bundle"]["geo"]
    record = dict(saved, bundle=bundle, refreshed=time.time())
    if not changed:
        active = copy.deepcopy(old)
        active["bundle"] = bundle
        g.save_json(g.DATA / "confirmed.json", record)
        g.save_json(g.RUN / "active.json", active)
        return False
    new = g.build_generation(c, bundle)
    try:
        g.switch_generation(new)
        g.save_json(g.DATA / "confirmed.json", record)
    except Exception:
        g.switch_generation(old)
        g.cleanup_generation(new["gen"])
        raise
    g.cleanup_generation(old["gen"])
    return True


def refresh_countries(countries=None, scheduled=False):
    prefs = settings()
    state_path = g.DATA / "country-update-state.json"
    state = g.read_json(state_path, {})
    now = time.time()
    if scheduled and not prefs["auto_update"]:
        return {"message": "Automatic country updates are disabled."}
    interval = prefs["interval_hours"] * 3600 if scheduled else 60
    if state.get("last_attempt") and now - state["last_attempt"] < interval:
        return {"message": "Country refresh not due yet; recent result retained.", "country_updates": status()}
    saved = g.read_json(g.DATA / "confirmed.json", {"config": copy.deepcopy(g.DEFAULT)})
    c = g.validate_config(saved["config"])
    selected = c["countries"] if countries is None else countries
    if not selected and scheduled:
        state.update(last_attempt=now, error=None, message="No confirmed countries selected; no country download needed.")
        g.save_json(state_path, state)
        return {"message": state["message"]}
    selected = validate_countries(selected)
    state.update(last_attempt=now, requested_countries=selected)
    g.save_json(state_path, state)
    try:
        import updater
        updater.resource_check()
        geo = g.country_bundle(selected, refresh=True)
        apply_live = c["enabled"] and c["country_enabled"] and selected == c["countries"]
        changed = apply_bundle(saved, geo) if apply_live else False
        state.update(last_success=time.time(), error=None, entries=len(geo["geo"]),
                     countries=geo["meta"], applied=bool(apply_live), rebuilt=changed)
        if changed:
            state["last_change"] = time.time()
        state["message"] = ("Selected country data updated and applied; reputation and port settings unchanged."
                            if changed else "Country data checked; networks unchanged, so no kernel rebuild was needed."
                            if apply_live else "Selected country data cached. No live country policy was changed; draft country choices still require a policy test.")
        g.save_json(state_path, state)
        return {"message": state["message"], "country_updates": status()}
    except Exception as exc:
        state.update(error=str(exc)[:600], message="Country refresh failed or was deferred. No partial country list was activated.")
        g.save_json(state_path, state)
        raise


def run_scheduled():
    """One bounded worker handles independently due jobs; one error doesn't hide the other."""
    import updater
    results = {}
    for name, callback in (("countries", lambda: refresh_countries(scheduled=True)),
                           ("github", lambda: updater.check(scheduled=True))):
        try:
            result = callback()
            results[name] = {"ok": True, "message": result.get("message", "Checked due time.")}
        except Exception as exc:
            results[name] = {"ok": False, "error": str(exc)[:600]}
    return {"message": "Scheduled maintenance evaluated.", "jobs": results}
