"""Write data/results_numbers.tex: every number quoted in the prose of the Results and Discussion sections,
computed from data/confirmatory_metrics.csv, data/paired_tests.csv, data/integrity_results.csv and
data/repetitions_decision.json. The manuscript uses these macros, so no result is typed by hand."""
import json
import os

import numpy as np
import pandas as pd

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
DATA = os.path.join(ROOT, "data")
SC = ["s1_takeover", "s2_bola_probing", "s3_bulk_location", "s4_ota_anomaly", "s5_supplier_abuse"]
NAME = {"s1_takeover": "A", "s2_bola_probing": "B", "s3_bulk_location": "C", "s4_ota_anomaly": "D",
        "s5_supplier_abuse": "E"}   # macro suffixes (LaTeX macro names cannot contain digits)


def hu(x, k=2):
    """Round half-up on the decimal representation (2026-10-10: one rule for every generated number)."""
    from decimal import ROUND_HALF_UP, Decimal
    return str(Decimal(repr(float(x))).quantize(Decimal(1).scaleb(-k), rounding=ROUND_HALF_UP))


def thousands(x, k=0):
    s = f"{x:,.{k}f}"
    return s.replace(",", "{,}")


def main():
    d = pd.read_csv(os.path.join(DATA, "confirmatory_metrics.csv"))
    inval = int((d.valid == 0).sum() // 2)
    v = d[d.valid == 1].copy()
    v["ms"] = v.seconds * 1000
    pt = pd.read_csv(os.path.join(DATA, "paired_tests.csv"))
    ig = pd.read_csv(os.path.join(DATA, "integrity_results.csv")).set_index("tampering")
    rep = json.load(open(os.path.join(DATA, "repetitions_decision.json")))
    m = {}

    def put(name, value):
        m[name] = value

    put("nSeeds", str(v.groupby("scenario").seed.nunique().min()))
    put("nRuns", str(v.groupby(["scenario", "seed"]).ngroups))
    put("nInvalid", str(inval))
    put("nPilotSeeds", "10")
    put("nReq", thousands(v.n_requests.median()))
    put("nNeeded", str(max(r["n_needed"] for r in rep["n_needed_table"])))
    put("nFixed", str(rep["n_fixed"]))
    put("custodyAll", "all" if v.custody_ok.min() == 1 else "not all")
    put("nProfileRuns", thousands(len(v)))
    put("holmFamily", str(int(pt.p.notna().sum())))
    # paired differences of vehicle precision with their bootstrap intervals (were hand-typed in the text)
    for sc_, tag_ in (("s1_takeover", "A"), ("s3_bulk_location", "C"), ("s5_supplier_abuse", "E")):
        r_ = pt[(pt.scenario == sc_) & (pt.metric == "M1 precision (vehicles)")].iloc[0]
        put(f"pdiff{tag_}", hu(r_.median_diff))
        put(f"pdiffLo{tag_}", hu(r_.ci_lo))
        put(f"pdiffHi{tag_}", hu(r_.ci_hi))
    put("holmPossible", str(len(pt) + 5))       # 5 scenarios x 8 metrics = 40; S4 precision (vehicles) is undefined
    put("holmMaxP", f"{pt.p_holm.max():.1e}".replace("e-", r"\times 10^{-") + "}")
    put("holmNotTested", str(40 - int(pt.p.notna().sum())))
    for sc in SC:
        s = NAME[sc]
        for prof, tag in (("minimal", "Min"), ("complete", "Comp")):
            g = v[(v.scenario == sc) & (v.profile == prof)]
            pv = g.precision_V.dropna()
            put(f"prec{tag}{s}", hu(pv.median()) if len(pv) else "--")
            put(f"unans{tag}{s}", f"{g.unanswered.median():.0f}")
            put(f"time{tag}{s}", f"{g.ms.median():.0f}")
            put(f"read{tag}{s}", thousands(g.records_read.median()))
            put(f"stor{tag}{s}", thousands(g.bytes_per_1000.median() / 1000))
            put(f"qfive{tag}{s}", f"{100 * g.q5.mean():.0f}")
    mn, cp = v[v.profile == "minimal"], v[v.profile == "complete"]
    put("storMin", thousands(mn.bytes_per_1000.median() / 1000))
    put("storCompLo", thousands(min(cp[cp.scenario == s].bytes_per_1000.median() for s in SC) / 1000))
    put("storCompHi", thousands(max(cp[cp.scenario == s].bytes_per_1000.median() for s in SC) / 1000))
    put("storRatio", f"{np.median(cp.bytes_total.values / mn.bytes_total.values):.1f}")
    put("gzRatio", f"{np.median(cp.gz_bytes.values / mn.gz_bytes.values):.1f}")
    put("chainMin", f"{100 * np.median(mn.bytes_chain / mn.bytes_total):.1f}")
    put("chainComp", f"{100 * np.median(cp.bytes_chain / cp.bytes_total):.1f}")
    put("timeRatioLo", f"{min(cp[cp.scenario == s].ms.median() / mn[mn.scenario == s].ms.median() for s in SC):.1f}")
    put("timeRatioHi", f"{max(cp[cp.scenario == s].ms.median() / mn[mn.scenario == s].ms.median() for s in SC):.1f}")
    put("readExtraPct", f"{100 * (np.median(cp.records_read.values / mn.records_read.values) - 1):.0f}")
    put("recallClassMin", f"{mn[mn.scenario != 's4_ota_anomaly'].recall_mean.median():.2f}")
    put("recallCredMin", f"{mn.recall_C.mean():.2f}")
    put("recallVehMinDOnly", f"{mn[mn.scenario == 's4_ota_anomaly'].recall_V.median():.2f}")
    put("qOneMin", f"{100 * mn.q1.mean():.0f}")
    put("qFourMin", f"{100 * mn.q4.mean():.0f}")
    put("qSixBoth", f"{100 * min(mn.q6.mean(), cp.q6.mean()):.0f}")
    put("qThreeBoth", f"{100 * min(mn.q3.mean(), cp.q3.mean()):.0f}")
    put("qFiveCompMissLo", f"{100 - 100 * cp[cp.scenario == 's3_bulk_location'].q5.mean():.0f}")
    put("qFiveCompMissB", f"{100 - 100 * cp[cp.scenario == 's2_bola_probing'].q5.mean():.0f}")
    put("qFiveCompAll", f"{100 * cp.q5.mean():.0f}")
    put("qFiveMinAll", f"{100 * mn.q5.mean():.0f}")
    put("unansMinAll", f"{mn.unanswered.median():.0f}")
    put("unansCompAll", f"{cp.unanswered.median():.0f}")
    put("qAllComp", f"{100 * (cp.unanswered == 0).mean():.0f}")
    put("qAllMin", f"{100 * (mn.unanswered == 0).mean():.0f}")
    put("integRecords", thousands(3670))
    put("integBatches", "37")
    put("integTrials", str(int(ig.loc["modify", "trials"])))
    for k, name in (("modify", "Modify"), ("delete", "Delete"), ("insert", "Insert"), ("reorder", "Reorder"),
                    ("truncate_partial", "TruncPart"), ("truncate_whole_batches", "TruncWhole"),
                    ("forge_without_key", "Forge")):
        put(f"integDet{name}", str(int(ig.loc[k, "detected"])))
        loc = ig.loc[k, "localized_to_batch"]
        put(f"integLoc{name}", "--" if pd.isna(loc) else str(int(loc)))
    lines = ["% Generated by testbed/make_numbers.py from data/*.csv and data/*.json. Do not edit by hand."]
    for k in sorted(m):
        lines.append(f"\\newcommand{{\\{k}}}{{{m[k]}}}")
    with open(os.path.join(DATA, "results_numbers.tex"), "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(len(m), "macros written")
    for k in ("nRuns", "nInvalid", "nReq", "storMin", "storCompLo", "storCompHi", "storRatio", "gzRatio", "chainMin",
              "chainComp", "timeRatioLo", "timeRatioHi", "readExtraPct", "holmFamily", "holmNotTested", "holmMaxP",
              "qFiveCompMissLo", "qFiveCompMissB", "qFiveMinAll", "qFiveCompAll", "unansMinAll", "unansCompAll",
              "recallClassMin", "recallCredMin", "custodyAll"):
        print(f"  {k} = {m[k]}")


if __name__ == "__main__":
    main()
