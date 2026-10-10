"""Macros and tables for the extended experiments (testbed/extended.py). Generated; do not edit the outputs by hand.

Reads data/extended_e1.csv .. extended_e4.csv; writes data/extended_numbers.tex and data/extended_tables.tex.
"""
import os

import pandas as pd

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
SC = ["s1_takeover", "s2_bola_probing", "s3_bulk_location", "s4_ota_anomaly", "s5_supplier_abuse"]
L = dict(zip(SC, "ABCDE"))
NAME = {"s1_takeover": "Account takeover", "s2_bola_probing": "Authorization probing",
        "s3_bulk_location": "Bulk location", "s4_ota_anomaly": "OTA anomaly", "s5_supplier_abuse": "Supplier abuse"}
out = {}


def put(k, v):
    out[k] = v


def f2(x):
    from decimal import ROUND_HALF_UP, Decimal
    return "--" if pd.isna(x) else str(Decimal(repr(float(x))).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def pct(x):
    return f"{100 * x:.0f}"


def kb(x):
    return f"{x / 1000:,.0f}".replace(",", "{,}")


e1 = pd.read_csv(os.path.join(DATA, "extended_e1.csv"))
e2 = pd.read_csv(os.path.join(DATA, "extended_e2.csv"))
e3 = pd.read_csv(os.path.join(DATA, "extended_e3.csv"))
e4 = pd.read_csv(os.path.join(DATA, "extended_e4.csv"))
for d in (e1, e2, e3, e4):
    assert d.valid.all() and d.custody_ok.all()

# E1: three profiles on the confirmatory seeds
g = e1.groupby(["scenario", "profile"])
prec = g.precision_V.median()
q5 = g.q5.mean()
stor = e1.groupby("profile").bytes_per_1000.median()
for s in SC:
    for p, t in (("minimal", "Min"), ("access", "Acc"), ("complete", "Comp")):
        put(f"xPrec{t}{L[s]}", f2(prec[(s, p)]))
        put(f"xQfive{t}{L[s]}", pct(q5[(s, p)]))
for p, t in (("minimal", "Min"), ("access", "Acc"), ("complete", "Comp")):
    put(f"xQfive{t}All", pct(e1[e1.profile == p].q5.mean()))
    put(f"xStor{t}", kb(stor[p]))
    put(f"xQOne{t}", pct(e1[e1.profile == p].q1.mean()))
    put(f"xQFour{t}", pct(e1[e1.profile == p].q4.mean()))
put("xStorAccShare", f"{100 * stor['access'] / stor['complete']:.0f}")
gz = e1.groupby("profile").gz_bytes.median()
put("xGzAccShare", f"{100 * gz['access'] / gz['complete']:.0f}")
put("xStorAccRatioMin", f"{stor['access'] / stor['minimal']:.1f}")
put("xRuns", f"{e1.drop_duplicates(['scenario', 'seed']).shape[0]}")

# E2: spoofed device id and user-agent class (S1, S4)
g2 = e2.groupby(["scenario", "profile"])
for s in ("s1_takeover", "s4_ota_anomaly", "s5_supplier_abuse"):
    for p, t in (("minimal", "Min"), ("access", "Acc"), ("complete", "Comp")):
        put(f"spPrec{t}{L[s]}", f2(g2.precision_V.median()[(s, p)]))
        put(f"spQfive{t}{L[s]}", pct(g2.q5.mean()[(s, p)]))
put("spRuns", f"{e2.drop_duplicates(['scenario', 'seed']).shape[0]}")

# E3: early alert
sh = e3[e3.seed_shifted == 1]
put("eaRuns", f"{e3.drop_duplicates(['scenario', 'seed']).shape[0]}")
put("eaShifted", f"{sh.drop_duplicates(['scenario', 'seed']).shape[0]}")
for p, t in (("minimal", "Min"), ("access", "Acc"), ("complete", "Comp")):
    put(f"eaRecall{t}", f2(sh[sh.profile == p].recall_V.mean()))
for s in SC:
    ss = sh[sh.scenario == s]
    put(f"eaShifted{L[s]}", f"{ss.drop_duplicates('seed').shape[0]}")
    for p, t in (("minimal", "Min"), ("access", "Acc"), ("complete", "Comp")):
        sp = ss[ss.profile == p]
        put(f"eaRecall{t}{L[s]}", f2(sp.recall_V.mean()) if len(sp) else "--")
        put(f"eaPrec{t}{L[s]}", f2(sp.precision_V.median()) if len(sp) else "--")
# E1: runs in which access and complete recover different vehicle sets (scenarios other than S4)
pv = e1[e1.scenario != "s4_ota_anomaly"].pivot_table(index=["scenario", "seed"], columns="profile", values="precision_V")
put("xAccDiffRuns", f"{int((pv['access'].round(9) != pv['complete'].round(9)).sum())}")
put("xAccCmpRuns", f"{len(pv)}")

# E3, OTA scenario: campaign recall in the shifted runs
sd = sh[sh.scenario == "s4_ota_anomaly"]
for p, t in (("minimal", "Min"), ("access", "Acc"), ("complete", "Comp")):
    sp = sd[sd.profile == p]
    put(f"eaCamp{t}D", f2(sp.recall_K.mean()) if len(sp) else "--")
# E2: spoofed runs where complete equals minimal
put("spQfiveMinA", pct(g2.q5.mean()[("s1_takeover", "minimal")]))

# E4: ablation with the current reconstruction, fresh seeds
c4 = e4[e4.profile == "complete"]
b = c4.groupby("ablation").bytes_per_1000.median()
for a, t in (("none", "None"), ("abl_no_session", "Sess"), ("abl_no_object", "Obj"), ("abl_no_campaign", "Camp")):
    sub = c4[c4.ablation == a]
    put(f"ab{t}Qfive", pct(sub.q5.mean()))
    put(f"ab{t}PrecC", f2(sub[sub.scenario == "s3_bulk_location"].precision_V.median()))
    if a != "none":
        put(f"ab{t}Save", f"{100 * (1 - b[a] / b['none']):.1f}")
put("abRuns", f"{c4.drop_duplicates(['ablation', 'scenario', 'seed']).shape[0]:,}".replace(",", "{,}"))
s3 = c4[c4.scenario == "s3_bulk_location"]
put("abNoneQfiveC", pct(s3[s3.ablation == "none"].q5.mean()))
put("abObjQfiveC", pct(s3[s3.ablation == "abl_no_object"].q5.mean()))
put("abSeedLo", f"{e4.seed.min()}")
put("abSeedHi", f"{e4.seed.max()}")
changed = {a: bool((c4[c4.ablation == a].set_index(["scenario", "seed"])[["q1", "q2", "q3", "q4", "q5", "precision_V"]]
                    .fillna(-1)
                    != c4[c4.ablation == "none"].set_index(["scenario", "seed"])[["q1", "q2", "q3", "q4", "q5",
                                                                                     "precision_V"]].fillna(-1))
                   .any().any()) for a in ("abl_no_session", "abl_no_campaign")}
put("abSessChanged", "yes" if changed["abl_no_session"] else "no")
put("abCampChanged", "yes" if changed["abl_no_campaign"] else "no")

with open(os.path.join(DATA, "extended_numbers.tex"), "w") as fh:
    fh.write("% Generated by testbed/make_extended.py from data/extended_e*.csv. Do not edit by hand.\n")
    for k in sorted(out):
        fh.write(f"\\newcommand{{\\{k}}}{{{out[k]}}}\n")

rows = []
for s in SC:
    rows.append(f"{NAME[s]} & " + " & ".join(f2(prec[(s, p)]) for p in ("minimal", "access", "complete")) + " & "
                + " & ".join(pct(q5[(s, p)]) for p in ("minimal", "access", "complete")) + r" \\")
tab = (r"""\begin{table}[t]\centering\footnotesize
\caption{Minimal, access-log and complete profiles on the confirmatory seeds (E1): median vehicle precision and share of runs (\%) answering Q5 (--: no vehicle recovered).}
\label{tab:three}
\begin{tabular}{@{}l@{\hspace{4pt}}ccc@{\hspace{6pt}}ccc@{}}\toprule
 & \multicolumn{3}{c}{Precision (veh.)} & \multicolumn{3}{c}{Q5 (\%)} \\
Scenario & Min. & Acc. & Comp. & Min. & Acc. & Comp. \\\midrule
""" + "\n".join(rows) + "\n" + r"""\midrule
KB / 1,000 req. & """ + " & ".join(kb(stor[p]) for p in ("minimal", "access", "complete")) + r""" & & & \\
\bottomrule\end{tabular}\end{table}
""")
with open(os.path.join(DATA, "extended_tables.tex"), "w") as fh:
    fh.write("% Generated by testbed/make_extended.py. Do not edit by hand.\n" + tab)
print(len(out), "macros")


def figure_precision():
    """Single-panel figure: vehicle precision per scenario for the three profiles of E1 (2026-10-10)."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    plt.rcParams.update({"font.family": "serif", "font.serif": ["DejaVu Serif"],
                         "font.size": 8, "axes.linewidth": 0.6, "pdf.fonttype": 42, "ps.fonttype": 42})
    profs = (("minimal", "#d0d0d0"), ("access", "#8c8c8c"), ("complete", "#3a3a3a"))
    fig, ax = plt.subplots(figsize=(3.45, 1.9))
    data, pos, cols = [], [], []
    for i, s in enumerate(SC):
        for j, (p, c) in enumerate(profs):
            g = e1[(e1.scenario == s) & (e1.profile == p)].precision_V.dropna()
            data.append(g.values if len(g) else np.array([np.nan]))
            pos.append(i * 4 + j)
            cols.append(c)
    bp = ax.boxplot(data, positions=pos, widths=0.8, patch_artist=True, showfliers=True,
                    flierprops={"markersize": 1.5}, medianprops={"color": "black", "linewidth": 0.8})
    for patch, c in zip(bp["boxes"], cols):
        patch.set_facecolor(c)
        patch.set_linewidth(0.5)
    ax.set_xticks([i * 4 + 1 for i in range(len(SC))])
    ax.set_xticklabels(["S1", "S2", "S3", "S4", "S5"])
    ax.set_ylabel("Vehicle precision")
    ax.set_ylim(0, 1.05)
    ax.legend([bp["boxes"][k] for k in range(3)], ["minimal", "access log", "complete"], loc="lower left",
              fontsize=6.5, frameon=False, ncol=3, bbox_to_anchor=(0.0, -0.02))
    fig.tight_layout(pad=0.3)
    fig.savefig(os.path.join(DATA, "..", "figures", "precision_three.pdf"))
    plt.close(fig)


figure_precision()
