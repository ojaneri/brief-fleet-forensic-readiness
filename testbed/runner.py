"""One experimental run: build a population, replay background and attack traffic against the backend, keep both
profiles' logs, record the ground truth, verify custody, reconstruct from each profile, and compute the metrics."""
import argparse
import asyncio
import gzip
import hashlib
import json
import math
import os
import random
import re
import shutil
import statistics
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor

import httpx

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from app import Ctx, build_app  # noqa: E402
from config import ACCESS_FIELDS, CFG, MINIMAL_FIELDS, SCENARIOS, UNIVERSAL_FIELDS  # noqa: E402
from logsink import LAYERS, RunSinks, iso, verify_chain  # noqa: E402
from population import build_population, inventory_snapshot  # noqa: E402
from recon import classify, reconstruct  # noqa: E402
from traffic import attack, background  # noqa: E402

CLASSES = ("V", "A", "T", "K", "C")
AUTH_BY_TYPE = {"operator": "password+mfa", "driver": "password", "partner": "api_key", "ci": "api_key"}


def _schedule(scenario, rng, pop, noise=True, traffic_source="deterministic", spoof=False):
    atk, meta = attack(scenario, rng, pop, CFG)
    if spoof:
        # robustness variant (2026-10-10): the attacker presents the victim account's device id and user-agent
        # class; the source address stays the attacker's. Applied after the draws, so the run is otherwise paired.
        acct = pop["accounts"][meta["actor"]]
        for e in atk:
            e["dev"], e["ua"] = acct["device"], acct["ua"]
    if traffic_source == "genai" and noise:
        csv_path = os.path.join(os.path.dirname(__file__), "..", "data", "genai_sessions_clean.csv")
        bg_events = _load_genai_background(csv_path, rng)
    else:
        bg_events = background(rng, pop, CFG) if noise else []
    events = bg_events + atk
    events.sort(key=lambda e: (e["t"], 0 if e["attack"] else 1))
    prev = -1
    for e in events:
        e["t"] = max(e["t"], prev + 1)
        prev = e["t"]
    return events, meta


async def _execute(events, app, ctx):
    state = {}
    log = []
    sent = 0
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://backend") as client:
        for e in events:
            st = state.setdefault(e["sess"], {"token": None, "challenge": None, "campaign": None, "dead": False})
            headers = {"x-forwarded-for": e["ip"], "x-device-id": e["dev"], "user-agent": e["ua"]}
            if e["attack"]:
                headers["x-sim-attack"] = "1"
                headers["x-sim-trace"] = e["trace"]
            ctx.now_ms = e["t"]
            if e["kind"] == "login":
                r = await client.post("/idp/login", json={"account_id": e["actor"], "credential_id": e["cred"]},
                                      headers=headers)
                sent += 1
                body = r.json()
                if r.status_code == 200 and "token" in body:
                    st["token"] = body["token"]
                elif r.status_code == 200 and "challenge" in body:
                    st["challenge"] = body["challenge"]
                else:
                    st["dead"] = True
                log.append({"e": e, "status": r.status_code, "body": None})
            elif e["kind"] == "mfa":
                if st["dead"] or not st["challenge"]:
                    continue
                r = await client.post("/idp/mfa", json={"challenge": st["challenge"], "ok": True}, headers=headers)
                sent += 1
                if r.status_code == 200:
                    st["token"] = r.json()["token"]
                else:
                    st["dead"] = True
                log.append({"e": e, "status": r.status_code, "body": None})
            else:
                if st["dead"] or not st["token"]:
                    continue
                path = e["path"].replace("{LAST_CAMPAIGN}", st["campaign"] or "cmp-0000")
                headers["authorization"] = "Bearer " + st["token"]
                r = await client.request(e["method"], path, json=e["json"], headers=headers)
                sent += 1
                body = r.json() if r.status_code == 200 else None
                if body and "campaign" in body and e["path"] == "/campaigns":
                    st["campaign"] = body["campaign"]
                log.append({"e": e, "status": r.status_code, "body": body, "path": path})
    return log, sent


_IDS = [(re.compile(r"/veh-[^/?]+"), "/{vid}"), (re.compile(r"/flt-[^/?]+"), "/{fid}"),
        (re.compile(r"/cmp-[^/?]+"), "/{cid}")]


def _template(item):
    """Route template of a logged request, e.g. 'GET /vehicles/{vid}' (for the exploited-route predicate)."""
    path = item["path"].split("?")[0]
    for rx, rep in _IDS:
        path = rx.sub(rep, path)
    return f"{item['e'].get('method', item.get('method', 'GET'))} {path}"


def _ground_truth(scenario, meta, log, pop):
    inv_v = pop["vehicles"]
    V, K, C = set(), set(), set()
    seed_ts = None
    exploited = None
    attack_events = []
    actor = meta["actor"]
    contract = pop["accounts"][actor]["tenant"] if pop["accounts"][actor]["type"] == "partner" else None
    for item in log:
        e = item["e"]
        if not e["attack"]:
            continue
        ts = iso(e["t"])
        attack_events.append(ts)
        ok = 200 <= item["status"] < 300
        if e["kind"] == "login" and ok:
            C.add(e["cred"])
        if e["kind"] != "req" or not ok:
            continue
        body, path, gained = item["body"], item["path"], set()
        if scenario == "s1_takeover" and path.startswith("/vehicles/"):
            gained.add(path.split("/")[2])
        elif scenario == "s2_bola_probing" and path.startswith("/vehicles/"):
            vid = path.split("/")[2]
            if inv_v[vid]["driver"] != actor:
                gained.add(vid)
        elif scenario == "s3_bulk_location" and path.startswith("/fleets/"):
            fid = path.split("/")[2]
            if pop["fleets"][fid]["tenant"] != meta["tenant_of_actor"]:
                gained.update(body["vehicles"])
        elif scenario == "s4_ota_anomaly" and path.endswith("/launch"):
            gained.update(body["targets"])
            K.add(body["campaign"])
        elif scenario == "s5_supplier_abuse" and path.startswith("/partner/diagnostics/"):
            vid = path.split("/")[3]
            if inv_v[vid]["tenant"] != contract:
                gained.add(vid)
        if gained or (scenario == "s4_ota_anomaly" and path.endswith("/launch")):
            V.update(gained)
            if seed_ts is None:
                seed_ts = ts
                exploited = _template(item)
    A = {inv_v[v]["driver"] for v in V}
    T = {inv_v[v]["tenant"] for v in V}
    inv = inventory_snapshot(pop)
    gt = {"V": sorted(V), "A": sorted(A), "T": sorted(T), "K": sorted(K), "C": sorted(C),
          "impact": classify(V, T, K, inv), "attack_events": attack_events, "seed_ts": seed_ts, "actor": actor,
          "entry_route": "POST /idp/login", "entry_auth": AUTH_BY_TYPE[pop["accounts"][actor]["type"]],
          "exploited_route": exploited}
    return gt, inv


def _rate(truth, rec):
    t, r = set(truth), set(rec)
    recall = len(t & r) / len(t)
    precision = (len(t & r) / len(r)) if r else float("nan")
    return recall, precision


def _profile_metrics(gt, rec, profile, sinks, sizes, n_requests):
    out = {}
    recalls, precisions = [], []
    present = [c for c in CLASSES if gt[c]]
    truth_sets = {"V": gt["V"], "A": gt["A"], "T": gt["T"], "K": gt["K"], "C": gt["C"]}
    rec_sets = {"V": rec["vehicles"], "A": rec["accounts"], "T": rec["tenants"], "K": rec["campaigns"],
                "C": rec["credentials"]}
    for c in CLASSES:
        if c in present:
            r, p = _rate(truth_sets[c], rec_sets[c])
            out[f"recall_{c}"], out[f"precision_{c}"] = r, p
            recalls.append(r)
            if not math.isnan(p):
                precisions.append(p)
        else:
            out[f"recall_{c}"] = out[f"precision_{c}"] = float("nan")
    out["recall_mean"] = statistics.fmean(recalls)
    out["precision_mean"] = statistics.fmean(precisions) if precisions else float("nan")
    ev = set(gt["attack_events"])
    attributed = ev <= rec["attributed"]
    w = rec["window"]
    q = {}
    q["q1"] = set(gt["C"]) <= set(rec["credentials"]) and attributed
    q["q2"] = all(set(truth_sets[c]) <= set(rec_sets[c]) for c in present if c != "C")
    q["q3"] = bool(w) and w[0] <= min(ev) and w[1] >= max(ev) and attributed
    q["q4"] = rec["entry_route"] == gt["entry_route"] and rec["entry_auth"] == gt["entry_auth"]
    q["q5"] = rec["impact"] == gt["impact"] and all(len(truth_sets[c]) == len(rec_sets[c])
                                                    for c in present if c != "C")
    kept = {"minimal": MINIMAL_FIELDS, "access": ACCESS_FIELDS}.get(profile, UNIVERSAL_FIELDS)
    manifest = sorted(f for f in UNIVERSAL_FIELDS if f not in kept)
    q["q6"] = sorted(rec["gaps"]) == manifest
    # secondary, stricter predicates (CAPTOR review, 2026-10-10); not part of the pre-specified six
    q["q2x"] = "V" in present and set(truth_sets["V"]) == set(rec_sets["V"])
    q["q4x"] = gt.get("exploited_route") is not None and gt["exploited_route"] in rec.get("routes", ())
    out.update({k: int(v) for k, v in q.items()})
    out["unanswered"] = 6 - sum(q[k] for k in ("q1", "q2", "q3", "q4", "q5", "q6"))
    cov = [v[profile] for v in sinks.coverage.values() if profile in v]
    out["coverage"] = sum(cov) / len(cov) if cov else float("nan")
    logs = {layer: sizes[(profile, layer, "log")] for layer in LAYERS}
    chain = sum(sizes[(profile, layer, "chain")] for layer in LAYERS)
    total = sum(logs.values())
    out.update({"bytes_gateway": logs["gateway"], "bytes_idp": logs["idp"], "bytes_service": logs["service"],
                "bytes_total": total, "bytes_chain": chain, "bytes_per_1000": total * 1000 / n_requests,
                "seconds": rec["seconds"], "records_read": rec["records_read"]})
    return out


def _load_genai_background(csv_path, rng):
    """Convert cleaned GenAI CSV rows to background event dicts compatible with _execute()."""
    import pandas as pd
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"GenAI sessions file not found: {csv_path}")
    df = pd.read_csv(csv_path)
    events = []
    t = 0
    for i, row in df.iterrows():
        gap = rng.randint(500, 5000)
        t += gap
        e = {"t": t, "sess": f"genai-{i}", "kind": "req", "actor": row.get("account_type", "driver"),
             "attack": False, "dev": "dev-genai", "ip": "10.0.0.99", "ua": "genai-client", "tag": "genai"}
        path = str(row.get("path_template", "/vehicles/veh-00001"))
        method = str(row.get("method", "GET"))
        e["method"] = method
        e["path"] = path
        e["json"] = None
        events.append(e)
    return events


def run_one(scenario, seed, phase="confirmatory", keep_dir=None, noise=True, ablation=None, traffic_source="deterministic",
            access=False, spoof=False, seed_mode="first"):
    """access: also log the access-log baseline profile. spoof: attacker presents the victim's device id and
    user-agent class. seed_mode 'early': the alert points at the suspect account's last successful legitimate request
    within the lookback window before the first attack effect (robustness variants, 2026-10-10)."""
    rng = random.Random(f"{scenario}|{seed}")
    pop = build_population(rng, CFG)
    events, meta = _schedule(scenario, rng, pop, noise, traffic_source=traffic_source, spoof=spoof)
    prefix = f"run-{scenario}-{seed}-" if ablation is None else f"abl-{ablation}-{scenario}-{seed}-"
    run_dir = tempfile.mkdtemp(prefix=prefix, dir=os.path.join(os.path.dirname(__file__), "runs"))
    try:
        sinks = RunSinks(run_dir, ablation=ablation, access=access)
        ctx = Ctx(pop, sinks)
        app = build_app(ctx)
        log, n_requests = asyncio.run(_execute(events, app, ctx))
        sinks.close()
        gt, inv = _ground_truth(scenario, meta, log, pop)
        base = {"phase": phase, "scenario": scenario, "seed": seed, "n_requests": n_requests,
                "n_attack_events": len(gt["attack_events"]), "gt_V": len(gt["V"]), "gt_A": len(gt["A"]),
                "gt_T": len(gt["T"]), "gt_K": len(gt["K"]), "gt_C": len(gt["C"]), "impact_truth": gt["impact"]}
        profiles = sinks.profiles
        if gt["seed_ts"] is None:
            return [dict(base, profile=p, valid=0) for p in profiles]
        base["seed_shifted"] = 0
        if seed_mode == "early":
            first = ms_of(gt["seed_ts"])
            prior = [it for it in log if not it["e"]["attack"] and it["e"]["actor"] == gt["actor"]
                     and it.get("path") and 200 <= it["status"] < 300
                     and first - CFG["lookback_ms"] <= it["e"]["t"] < first]
            if prior:
                gt["seed_ts"] = iso(prior[-1]["e"]["t"])
                base["seed_shifted"] = 1
        gt_bytes = json.dumps(gt, sort_keys=True).encode()
        with open(os.path.join(run_dir, "ground_truth.json"), "wb") as fh:
            fh.write(gt_bytes)
        base["gt_sha256"] = hashlib.sha256(gt_bytes).hexdigest()      # fixed BEFORE any reconstruction
        with open(os.path.join(run_dir, "inventory.json"), "w") as fh:
            json.dump(inv, fh)
        sizes = sinks.sizes()
        rows = []
        for profile in profiles:
            pdir = os.path.join(run_dir, profile)
            custody = all(verify_chain(os.path.join(pdir, f"{l}.jsonl"), os.path.join(pdir, f"{l}.chain"),
                                       sinks.public_key)[0] for l in LAYERS)
            best = None
            times = []
            for _ in range(3):
                rec = reconstruct(pdir, inv, gt["actor"], gt["seed_ts"], CFG["lookback_ms"])
                times.append(rec["seconds"])
            rec["seconds"] = statistics.median(times)
            m = _profile_metrics(gt, rec, profile, sinks, sizes, n_requests)
            blob = b""
            for l in LAYERS:
                with open(os.path.join(pdir, f"{l}.jsonl"), "rb") as fh:
                    blob += fh.read()
            gz = gzip.compress(blob)
            rows.append(dict(base, profile=profile, valid=1, custody_ok=int(custody), gz_bytes=len(gz), **m))
        if keep_dir:
            shutil.copytree(run_dir, os.path.join(keep_dir, os.path.basename(run_dir)))
        return rows
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)


def ms_of(ts):
    from recon import ms
    return ms(ts)


def _job(args):
    scenario, seed, phase, traffic_source = args
    return run_one(scenario, seed, phase=phase, traffic_source=traffic_source)


def run_batch(scenarios, seeds, phase, workers, out_csv, traffic_source="deterministic"):
    import pandas as pd
    os.makedirs(os.path.join(os.path.dirname(__file__), "runs"), exist_ok=True)
    jobs = [(s, seed, phase, traffic_source) for s in scenarios for seed in seeds]
    rows = []
    with ProcessPoolExecutor(max_workers=workers) as pool:
        for i, res in enumerate(pool.map(_job, jobs), 1):
            rows.extend(res)
            if i % 10 == 0 or i == len(jobs):
                print(f"  {i}/{len(jobs)} runs (traffic={traffic_source})", flush=True)
    df = pd.DataFrame(rows)
    df.to_csv(out_csv, index=False)
    return df


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--phase", default="pilot")
    ap.add_argument("--seeds", type=int, nargs=2, required=True, help="first seed and count")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--out", required=True)
    ap.add_argument("--scenarios", nargs="*", default=list(SCENARIOS))
    ap.add_argument("--traffic-source", choices=["deterministic", "genai"], default="deterministic",
                    help="Traffic generator: deterministic (default) or genai (CTGAN-synthesized background)")
    a = ap.parse_args()
    run_batch(a.scenarios, range(a.seeds[0], a.seeds[0] + a.seeds[1]), a.phase, a.workers, a.out,
              traffic_source=a.traffic_source)
