# BRIEF: forensic readiness of connected-fleet backends — testbed, data and analysis

Code and recorded results for the paper *Connected-Fleet Forensic Readiness: Tracing the Impact of Mass API Attacks*
(O. Janeri Filho, R. Santos Dominguez, J. J. de Lima, M. M. Dias Santos; Federal Technological University of Paraná,
Ponta Grossa, Brazil).

The testbed is a software emulation of a connected-fleet backend (identity provider, API gateway, fleet services) with
**synthetic data only**: no real vehicle, fleet or personal data. It replays five mass-API attack scenarios among
background traffic, writes the same requests to several logging profiles under a hash-chained, Ed25519-signed log
envelope, and reconstructs the blast radius from the preserved logs (BRIEF component R). The attacks are executed only
against the in-process emulation; no operational tooling is included. The keys in `testbed/config.py` are synthetic
and protect nothing.

## Layout
- `testbed/` — emulation (`app.py`, `population.py`, `traffic.py`, `logsink.py`), reconstruction (`recon.py`), runs and
  metrics (`runner.py`), confirmatory analysis (`analysis.py`, `make_numbers.py`), integrity trials
  (`integrity_experiment.py`), extended experiments (`extended.py`, `make_extended.py`), tests (`tests/`), vehicle
  positions (`geo/`). See `testbed/README.md`.
- `data/` — recorded results: pilot and confirmatory runs (`pilot_metrics.csv`, `confirmatory_metrics.csv`), paired tests,
  integrity trials, extended experiments E1–E4 (`extended_e1.csv` … `extended_e4.csv`), the LaTeX macros and tables
  generated from them, and `run_manifest.json` with package versions and SHA-256 digests.
- `figures/` — figures generated from the data.

## Reproduce
Python 3.12 and `pip install -r requirements.txt`.
```bash
python3 -m unittest discover -s testbed/tests
python3 testbed/runner.py --phase confirmatory --seeds 10000 100 --workers 6 --out data/confirmatory_metrics.csv
python3 testbed/analysis.py            # paired tests, tables, figure
python3 testbed/make_numbers.py        # data/results_numbers.tex
python3 testbed/integrity_experiment.py
python3 testbed/extended.py --exp E1 --out data/extended_e1.csv   # likewise E2, E3, E4
python3 testbed/make_extended.py       # data/extended_numbers.tex, extended_tables.tex, figures/precision_three.pdf
```
Every metric except wall-clock time is deterministic for a given seed. E1 reproduces the minimal and complete rows of
the confirmatory runs in every column except time and the ground-truth digest (which in E1 also records the exploited
route). The GenAI background-traffic option in `runner.py` belongs to other work; its data are not included.

## Licenses
Code: MIT (`LICENSE`). Data and figures: CC BY 4.0. Vehicle positions contain data © OpenStreetMap contributors,
licensed under the Open Database License (ODbL).
