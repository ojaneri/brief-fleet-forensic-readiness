"""Analysis of the confirmatory runs, following experiments/metrics-protocol.md (d-0012).

Descriptive: median and interquartile range per scenario, profile and metric.
Paired comparison (complete minus minimal, paired by seed): median difference with a 95% percentile bootstrap
interval, Wilcoxon signed-rank test, Holm correction over the family of scenario-by-metric comparisons.
"""
import json
import os
import sys

import numpy as np
import pandas as pd
from scipy import stats

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
DATA = os.path.join(ROOT, "data")
FIG = os.path.join(ROOT, "figures")
SC = ["s1_takeover", "s2_bola_probing", "s3_bulk_location", "s4_ota_anomaly", "s5_supplier_abuse"]
LABEL = {"s1_takeover": "Account takeover", "s2_bola_probing": "Authorization probing",
         "s3_bulk_location": "Bulk location", "s4_ota_anomaly": "OTA anomaly",
         "s5_supplier_abuse": "Supplier abuse"}
METRICS = [("recall_mean", "M1 recall (class mean)"), ("recall_V", "M1 recall (vehicles)"),
           ("precision_V", "M1 precision (vehicles)"), ("seconds_ms", "M2 time (ms)"),
           ("records_read", "M2 records read"), ("unanswered", "M3 unanswered"), ("coverage", "M3 event coverage"),
           ("kb_per_1000", "M4 KB per 1,000 requests")]
BOOT = 10_000


def load(path):
    d = pd.read_csv(path)
    n_all = d[["scenario", "seed"]].drop_duplicates().shape[0]
    d = d[d.valid == 1].copy()
    d["seconds_ms"] = d["seconds"] * 1000
    d["kb_per_1000"] = d["bytes_per_1000"] / 1000
    return d, n_all


def paired(d):
    rng = np.random.default_rng(20260919)
    rows = []
    for sc in SC:
        g = d[d.scenario == sc]
        m = g[g.profile == "minimal"].set_index("seed")
        c = g[g.profile == "complete"].set_index("seed")
        for col, name in METRICS:
            diff = (c[col] - m[col]).dropna()
            n = len(diff)
            if n == 0:
                continue
            boots = np.median(rng.choice(diff.values, size=(BOOT, n), replace=True), axis=1)
            lo, hi = np.percentile(boots, [2.5, 97.5])
            if np.allclose(diff.values, 0):
                p = np.nan
            else:
                try:
                    p = float(stats.wilcoxon(diff.values, zero_method="wilcox").pvalue)
                except ValueError:
                    p = np.nan
            rows.append({"scenario": sc, "metric": name, "n": n, "median_min": float(np.median(m[col].dropna())),
                         "median_comp": float(np.median(c[col].dropna())), "median_diff": float(np.median(diff)),
                         "ci_lo": float(lo), "ci_hi": float(hi), "p": p})
    t = pd.DataFrame(rows)
    ok = t.p.notna()
    k = int(ok.sum())
    order = t.loc[ok, "p"].sort_values().index
    adj = {}
    running = 0.0
    for rank, idx in enumerate(order):
        val = min(1.0, (k - rank) * t.loc[idx, "p"])
        running = max(running, val)
        adj[idx] = running
    t["p_holm"] = pd.Series(adj)
    t.attrs["family_size"] = k
    return t


def question_rates(d):
    rows = []
    for sc in SC:
        for prof in ("minimal", "complete"):
            g = d[(d.scenario == sc) & (d.profile == prof)]
            rows.append({"scenario": sc, "profile": prof, "n": len(g),
                         **{f"q{i}": float(g[f"q{i}"].mean()) for i in range(1, 7)}})
    return pd.DataFrame(rows)


def iqr(x):
    x = np.asarray(x, dtype=float)
    x = x[~np.isnan(x)]
    return np.percentile(x, 25), np.median(x), np.percentile(x, 75)


def fmt(x, k=2):
    return f"{x:.{k}f}"


def tables(d, qr, pt):
    lines = []
    # Table: M1
    lines.append(r"\begin{table*}[t]\centering\footnotesize")
    lines.append(r"\caption{Reconstruction completeness (M1): median [interquartile range] per scenario and profile. "
                 r"Recall is the mean over the object classes present; precision is that of the recovered vehicles "
                 r"(--: no vehicle recovered).}")
    lines.append(r"\label{tab:m1}")
    lines.append(r"\begin{tabular}{@{}p{1.5in}lccc@{}}\toprule")
    lines.append(r"Scenario & Profile & Recall (mean) & Recall (veh.) & Precision (veh.) \\\midrule")
    for sc in SC:
        for i, prof in enumerate(("minimal", "complete")):
            g = d[(d.scenario == sc) & (d.profile == prof)]
            r = iqr(g.recall_mean)
            rv = iqr(g.recall_V)
            pv = g.precision_V.dropna()
            pcell = "--" if len(pv) == 0 else (lambda q: f"{fmt(q[1])} [{fmt(q[0])}--{fmt(q[2])}]")(iqr(pv))
            name = LABEL[sc] if i == 0 else ""
            lines.append(f"{name} & {prof} & {fmt(r[1])} & {fmt(rv[1])} & {pcell} \\\\")
    lines.append(r"\bottomrule\end{tabular}\end{table*}")
    # Table: questions
    lines.append(r"\begin{table*}[t]\centering\footnotesize")
    lines.append(r"\caption{Share of runs, in percent, in which each investigation question was answered, "
                 r"minimal / complete profile.}")
    lines.append(r"\label{tab:questions}")
    lines.append(r"\begin{tabular}{@{}p{1.5in}cccccc@{}}\toprule")
    lines.append(r"Scenario & Q1 & Q2 & Q3 & Q4 & Q5 & Q6 \\\midrule")
    for sc in SC:
        a = qr[(qr.scenario == sc) & (qr.profile == "minimal")].iloc[0]
        b = qr[(qr.scenario == sc) & (qr.profile == "complete")].iloc[0]
        cells = " & ".join(f"{100 * a[f'q{i}']:.0f}/{100 * b[f'q{i}']:.0f}" for i in range(1, 7))
        lines.append(f"{LABEL[sc]} & {cells} \\\\")
    lines.append(r"\bottomrule\end{tabular}\end{table*}")
    # Table: cost
    lines.append(r"\begin{table*}[t]\centering\footnotesize")
    lines.append(r"\caption{Cost of reconstruction (M2) and storage (M4), median per run and profile.}")
    lines.append(r"\label{tab:cost}")
    lines.append(r"\begin{tabular}{@{}p{1.5in}lrrr@{}}\toprule")
    lines.append(r"Scenario & Profile & Records read & Time (ms) & KB / 1,000 req. \\\midrule")
    for sc in SC:
        for i, prof in enumerate(("minimal", "complete")):
            g = d[(d.scenario == sc) & (d.profile == prof)]
            name = LABEL[sc] if i == 0 else ""
            lines.append(f"{name} & {prof} & {g.records_read.median():,.0f} & {g.seconds_ms.median():.0f} & "
                         f"{g.kb_per_1000.median():,.0f} \\\\")
    lines.append(r"\bottomrule\end{tabular}\end{table*}")
    return "\n".join(lines) + "\n"


def figure(d):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.family": "serif", "font.size": 8, "axes.linewidth": 0.6,
                         "pdf.fonttype": 42, "ps.fonttype": 42})   # TrueType: IEEE rejects Type 3 fonts
    fig, ax = plt.subplots(1, 2, figsize=(7.2, 2.5))
    pos, data, cols = [], [], []
    for i, sc in enumerate(SC):
        for j, prof in enumerate(("minimal", "complete")):
            g = d[(d.scenario == sc) & (d.profile == prof)].precision_V.dropna()
            data.append(g.values if len(g) else np.array([np.nan]))
            pos.append(i * 3 + j)
            cols.append("#bbbbbb" if prof == "minimal" else "#444444")
    bp = ax[0].boxplot(data, positions=pos, widths=0.8, patch_artist=True, showfliers=True,
                       flierprops={"markersize": 2}, medianprops={"color": "black"})
    for patch, c in zip(bp["boxes"], cols):
        patch.set_facecolor(c)
    ax[0].set_xticks([i * 3 + 0.5 for i in range(len(SC))])
    ax[0].set_xticklabels(["S1", "S2", "S3", "S4", "S5"])
    ax[0].set_ylabel("Precision (vehicles)")
    ax[0].set_ylim(0, 1.05)
    ax[0].set_title("(a) Precision of the recovered vehicles", fontsize=8)
    ax[0].legend([bp["boxes"][0], bp["boxes"][1]], ["minimal", "complete"], loc="lower right", fontsize=7, frameon=False)
    width = 0.38
    xs = np.arange(len(SC))
    for j, prof in enumerate(("minimal", "complete")):
        med, lo, hi = [], [], []
        for sc in SC:
            q = iqr(d[(d.scenario == sc) & (d.profile == prof)].kb_per_1000)
            lo.append(q[1] - q[0]); med.append(q[1]); hi.append(q[2] - q[1])
        ax[1].bar(xs + (j - 0.5) * width, med, width, yerr=[lo, hi], color="#bbbbbb" if j == 0 else "#444444",
                  error_kw={"lw": 0.6}, label=prof)
    ax[1].set_yscale("log")
    from matplotlib.ticker import FixedLocator, NullLocator, ScalarFormatter
    ax[1].yaxis.set_major_locator(FixedLocator([200, 500, 1000, 2000]))
    ax[1].yaxis.set_major_formatter(ScalarFormatter())
    ax[1].yaxis.set_minor_locator(NullLocator())
    ax[1].set_ylim(150, 2600)
    ax[1].set_xticks(xs)
    ax[1].set_xticklabels(["S1", "S2", "S3", "S4", "S5"])
    ax[1].set_ylabel("KB per 1,000 requests")
    ax[1].set_title("(b) Storage cost", fontsize=8)
    fig.tight_layout()
    os.makedirs(FIG, exist_ok=True)
    fig.savefig(os.path.join(FIG, "results.pdf"))
    plt.close(fig)


def main(path=os.path.join(DATA, "confirmatory_metrics.csv")):
    d, n_all = load(path)
    pt = paired(d)
    qr = question_rates(d)
    pt.to_csv(os.path.join(DATA, "paired_tests.csv"), index=False)
    qr.to_csv(os.path.join(DATA, "question_rates.csv"), index=False)
    with open(os.path.join(DATA, "results_tables.tex"), "w") as fh:
        fh.write(tables(d, qr, pt))
    figure(d)
    per = {}
    for sc in SC:
        for prof in ("minimal", "complete"):
            g = d[(d.scenario == sc) & (d.profile == prof)]
            per[f"{sc}|{prof}"] = {k: iqr(g[k]) for k in ("recall_mean", "recall_V", "unanswered", "seconds_ms",
                                                          "records_read", "kb_per_1000")}
            pvv = g.precision_V.dropna()
            per[f"{sc}|{prof}"]["precision_V"] = list(iqr(pvv)) if len(pvv) else None
            per[f"{sc}|{prof}"]["custody_ok_share"] = float(g.custody_ok.mean())
            per[f"{sc}|{prof}"]["n"] = len(g)
    summary = {"runs_total_pairs": int(n_all), "runs_valid_pairs": int(d.groupby(["scenario", "seed"]).ngroups),
               "holm_family_size": pt.attrs["family_size"], "per": per,
               "median_storage_ratio": float(np.median(d[d.profile == "complete"].bytes_total.values /
                                                       d[d.profile == "minimal"].bytes_total.values)),
               "chain_bytes_share_minimal": float((d[d.profile == "minimal"].bytes_chain /
                                                   d[d.profile == "minimal"].bytes_total).median()),
               "chain_bytes_share_complete": float((d[d.profile == "complete"].bytes_chain /
                                                    d[d.profile == "complete"].bytes_total).median()),
               "gz_ratio_median": float(np.median(d[d.profile == "complete"].gz_bytes.values /
                                                  d[d.profile == "minimal"].gz_bytes.values)),
               "n_requests_median": float(d.n_requests.median())}
    with open(os.path.join(DATA, "results_summary.json"), "w") as fh:
        json.dump(summary, fh, indent=1, default=float)
    print(pt.round(4).to_string(index=False))
    print(qr.round(2).to_string(index=False))
    print(json.dumps({k: v for k, v in summary.items() if k != "per"}, indent=1))


if __name__ == "__main__":
    main(*sys.argv[1:])
