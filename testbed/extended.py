"""Extended experiments added after the adversarial review of 2026-10-10 (CAPTOR).

E1  three profiles (minimal, access-log baseline, complete) on the confirmatory seeds 10000-10099;
    the minimal and complete rows must reproduce data/confirmatory_metrics.csv (regression check).
E2  spoofed device: the attacker presents the victim account's device id and user-agent class (S1, S4, S5; S2 and S3 use the account's own device).
E3  early alert: the seed is the suspect account's last legitimate request before the attack (all scenarios).
E4  ablation by field group with the current reconstruction on fresh seeds 20000-20099.

Usage: python3 testbed/extended.py --exp E1 --out data/extended_e1.csv
"""
import argparse
import os
import sys
from concurrent.futures import ProcessPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pandas as pd  # noqa: E402

import runner  # noqa: E402
from config import ABLATION_PROFILES, SCENARIOS  # noqa: E402

CONF = range(10000, 10100)
FRESH = range(20000, 20100)


def _job(a):
    exp, sc, seed, abl = a
    if exp == "E1":
        rows = runner.run_one(sc, seed, phase="extended", access=True)
    elif exp == "E2":
        rows = runner.run_one(sc, seed, phase="robust_spoof", access=True, spoof=True)
    elif exp == "E3":
        rows = runner.run_one(sc, seed, phase="robust_early", access=True, seed_mode="early")
    else:
        rows = runner.run_one(sc, seed, phase="ablation_v2", ablation=abl)
    for r in rows:
        r["ablation"] = abl or "none"
    return rows


def jobs(exp):
    if exp == "E1" or exp == "E3":
        return [(exp, s, seed, None) for s in SCENARIOS for seed in CONF]
    if exp == "E2":
        return [(exp, s, seed, None) for s in ("s1_takeover", "s4_ota_anomaly", "s5_supplier_abuse") for seed in CONF]
    return [(exp, s, seed, a) for a in [None, *ABLATION_PROFILES] for s in SCENARIOS for seed in FRESH]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp", choices=["E1", "E2", "E3", "E4"], required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()
    os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), "runs"), exist_ok=True)
    rows = []
    js = jobs(a.exp)
    with ProcessPoolExecutor(max_workers=a.workers) as pool:
        for i, res in enumerate(pool.map(_job, js), 1):
            rows.extend(res)
            if i % 50 == 0 or i == len(js):
                print(f"{a.exp}: {i}/{len(js)}", flush=True)
    pd.DataFrame(rows).to_csv(a.out, index=False)
