# Testbed: emulated fleet backend for the BRIEF evaluation

Software-only, synthetic data, no real vehicle or personal data.

## What it is
- `app.py`: FastAPI services, an ASGI gateway middleware and an identity provider issuing PyJWT tokens. Three
  deliberate defects make the attacks possible (legacy vehicles skip the object check, an over-scoped operator role,
  a partner diagnostics route without the contract check).
- `logsink.py`: the logging profiles (minimal, complete and, in the extended experiments, access-log) written in parallel from the same requests, each through
  the same integrity envelope (batches of 100 records, SHA-256 hash chain, Ed25519 signature) and `verify_chain`.
- `traffic.py`: background traffic and the five attack scenarios. `population.py`: tenants, fleets, vehicles, accounts.
- `recon.py`: the reconstruction procedure R. It reads only one profile's log files and an organizational inventory.
- `runner.py`: one experimental run and batches of runs; computes the four metrics (M1 to M4).
- `analysis.py`: descriptive statistics, paired bootstrap, Wilcoxon signed-rank, Holm correction, tables, figure.
- `integrity_experiment.py`: tamper-detection trials on the integrity envelope.
- `tests/test_testbed.py`: unit tests, including the protocol's sanity control (complete profile, no background
  noise: recall and precision equal 1).

## Vehicle positions
`geo/positions.json` holds one synthetic position per vehicle, generated with trip-simulator 3.0.1 (MIT) on an OpenStreetMap
extract of Curitiba (BBBike). Positions appear only in API responses and are never logged. Generation needs Docker and network:
`geo/make_positions.sh` and `geo/extract_positions.py`. Attribution: Contains data (c) OpenStreetMap contributors, licensed under the
Open Database License (ODbL).

## Reproduce
```bash
python3 -m unittest discover -s testbed/tests            # tests
python3 testbed/runner.py --phase pilot --seeds 1000 10 --workers 6 --out data/pilot_metrics.csv
python3 testbed/runner.py --phase confirmatory --seeds 10000 100 --workers 6 --out data/confirmatory_metrics.csv
python3 testbed/analysis.py                              # tables, figure, paired tests
python3 testbed/integrity_experiment.py                  # tamper detection
```
Runs are deterministic given the scenario and seed (the test suite checks that the logs are byte-identical).

## Limits to keep in mind
The population, traffic and attacks are the authors' design, not field data. R is automated and has no containment
time. Requests go through an in-process ASGI transport, with a single simulated clock.
