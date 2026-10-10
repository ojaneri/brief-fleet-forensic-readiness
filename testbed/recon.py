"""Blast-radius reconstruction (BRIEF component R).

Inputs: the preserved log files of ONE profile, the organizational inventory snapshot, the suspect account and the
timestamp of the seed event (the event that raised the alert). No access to the ground truth or to campaign data.

The rule that turns records into affected objects is the same for both profiles: an object is affected when a
successful (2xx) access is attributed to the suspect session. What differs is what the log lets R attribute:
  * complete profile (token and device fields present): the session is every token issued to the suspect account
    from the seed's device since `lookback` before the seed, with the identity-provider events of that account and
    device; R has no containment time, so later activity of the same account and device is attributed as well;
  * access-log profile (source address and user-agent class, no token or device; added 2026-10-10): the session
    is every record of the suspect account with the seed's source address and user-agent class since `lookback`
    before the seed, plus the identity-provider events with the same origin; fleet pages are resolved to vehicles
    from the concrete path (offset and limit) through the inventory;
  * minimal profile: the session cannot be separated, so R takes every record of the suspect account from
    `lookback` before the seed onward.
Object granularity follows the schema too: with per-object vehicle records R reads vehicles directly; without
them R expands a fleet identifier to the fleet's vehicles through the inventory.
"""
import json
import os
import time
from urllib.parse import parse_qs, urlsplit

from config import UNIVERSAL_FIELDS

LAYERS = ("gateway", "idp", "service")


def ms(ts: str) -> int:
    """Milliseconds since the start of the simulated month from 'YYYY-MM-DDTHH:MM:SS.mmmZ'."""
    return ((int(ts[8:10]) - 1) * 86_400_000 + int(ts[11:13]) * 3_600_000 + int(ts[14:16]) * 60_000
            + int(ts[17:19]) * 1000 + int(ts[20:23]))


def classify(vehicles, tenants, campaigns, inv) -> str:
    """Impact class of the earlier work: systemic, fleet-level or user-level."""
    if len(tenants) >= 2 or campaigns:
        return "systemic"
    fleets = {inv["vehicles"][v]["fleet"] for v in vehicles if v in inv["vehicles"]}
    if len(vehicles) >= 2 or len(fleets) >= 2:
        return "fleet"
    return "user"


def _load(profile_dir):
    records = []
    for layer in LAYERS:
        with open(os.path.join(profile_dir, f"{layer}.jsonl"), "rb") as fh:
            for line in fh:
                rec = json.loads(line)
                rec["_l"] = layer
                records.append(rec)
    return records


def reconstruct(profile_dir, inventory, suspect, seed_ts, lookback_ms):
    t0 = time.perf_counter()
    records = _load(profile_dir)
    read = len(records)
    inv = inventory

    gw_keys = set()
    for r in records:
        if r["_l"] == "gateway":
            gw_keys.update(k for k in r if k != "_l")
    gaps = sorted(f for f in UNIVERSAL_FIELDS if f not in gw_keys)
    rich = "token_id" in gw_keys and "device_id" in gw_keys
    origin = not rich and "src_ip_pseudo" in gw_keys and "user_agent_class" in gw_keys

    seed = next((r for r in records if r.get("account_id") == suspect and r["ts"] == seed_ts
                 and r["_l"] in ("gateway", "service")), None)
    if seed is None:
        seed = next((r for r in records if r.get("account_id") == suspect and r["ts"] == seed_ts), None)
    session = []
    if seed is not None:
        seed_ms = ms(seed["ts"])
        if rich and seed.get("token_id"):
            # the session is every token issued to the suspect account from the seed's device since
            # `lookback` before the seed, plus the identity-provider events of that account and device
            dev = seed.get("device_id")
            lo = seed_ms - lookback_ms
            tokens = {seed["token_id"]} | {r["token_id"] for r in records
                                           if r["_l"] == "idp" and r.get("auth_event") == "token_issue"
                                           and r.get("account_id") == suspect and r.get("device_id") == dev
                                           and ms(r["ts"]) >= lo}
            session = [r for r in records if r.get("token_id") in tokens]
            session += [r for r in records if r["_l"] == "idp" and r.get("account_id") == suspect
                        and r.get("device_id") == dev and r.get("token_id") is None and ms(r["ts"]) >= lo]
        elif origin and seed.get("src_ip_pseudo"):
            lo = seed_ms - lookback_ms
            o = (seed.get("src_ip_pseudo"), seed.get("user_agent_class"))
            session = [r for r in records if r.get("account_id") == suspect and ms(r["ts"]) >= lo
                       and (r.get("src_ip_pseudo"), r.get("user_agent_class")) == o]
        else:
            lo = seed_ms - lookback_ms
            session = [r for r in records if r.get("account_id") == suspect and ms(r["ts"]) >= lo]

    veh, camps, creds = set(), set(), set()
    per_object = any(r.get("vehicle_id") for r in records if r["_l"] == "service")
    has_path = "path" in gw_keys   # access-log profile: the gateway path is the precise source for fleet pages
    for r in session:
        ok = 200 <= r.get("outcome", 0) < 300
        if not ok:
            continue
        if r["_l"] == "idp":
            if r.get("auth_event") in ("login_success", "token_issue") and r.get("credential_id"):
                creds.add(r["credential_id"])
            continue
        if r.get("credential_id"):
            creds.add(r["credential_id"])
        if per_object:
            if r["_l"] == "service" and r.get("vehicle_id"):
                veh.add(r["vehicle_id"])
            if r.get("campaign_id"):
                camps.add(r["campaign_id"])
        oid = r.get("object_id") or ""
        if oid.startswith("cmp-"):
            camps.add(oid)
        if not per_object:
            if oid.startswith("veh-"):
                veh.add(oid)
            elif oid.startswith("flt-") and oid in inv["fleets"]:
                if has_path and r["_l"] != "gateway":
                    continue
                fv = inv["fleets"][oid]["vehicles"]
                qs = parse_qs(urlsplit(r["path"]).query) if r.get("path") else {}
                if "offset" in qs or "limit" in qs:
                    off = int(qs.get("offset", ["0"])[0])
                    lim = int(qs.get("limit", ["10"])[0])
                    veh.update(fv[off:off + lim])
                else:
                    veh.update(fv)
    veh = {v for v in veh if v in inv["vehicles"]}
    accounts = {inv["vehicles"][v]["driver"] for v in veh}
    tenants = {inv["vehicles"][v]["tenant"] for v in veh}

    entry_route = entry_auth = None
    window = None
    attributed = set()
    if session:
        session.sort(key=lambda r: r["ts"])
        window = (session[0]["ts"], session[-1]["ts"])
        attributed = {r["ts"] for r in session}
        first = next((r for r in session if r.get("route")), None)
        if first is not None:
            entry_route = first["route"]
            if first.get("auth_method"):
                entry_auth = first["auth_method"]
            elif first.get("token_id"):
                issue_rec = next((r for r in records if r["_l"] == "idp" and r.get("token_id") == first["token_id"]
                                  and r.get("auth_method")), None)
                entry_auth = issue_rec["auth_method"] if issue_rec else None
    elapsed = time.perf_counter() - t0
    routes = {r["route"] for r in session if r.get("route") and 200 <= r.get("outcome", 0) < 300}
    return {"routes": routes, "vehicles": sorted(veh), "accounts": sorted(accounts), "tenants": sorted(tenants),
            "campaigns": sorted(camps), "credentials": sorted(creds),
            "impact": classify(veh, tenants, camps, inv), "window": window, "attributed": attributed,
            "entry_route": entry_route, "entry_auth": entry_auth, "gaps": gaps,
            "seconds": elapsed, "records_read": read}
