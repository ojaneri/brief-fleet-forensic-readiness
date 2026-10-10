#!/usr/bin/env bash
# Reproduces testbed/geo/positions.json. Needs Docker and network. The trip-simulator depends on the native
# module `osrm`, which has no binary for the server's Node 24; it runs in a Node 12 container on Debian 11.
set -euo pipefail
W=${1:-/tmp/trip}; mkdir -p "$W"; cd "$W"
curl -sL -A "Mozilla/5.0" -o Curitiba.osm.pbf "https://download.bbbike.org/osm/bbbike/Curitiba/Curitiba.osm.pbf"
docker run --rm -v "$W":/work -w /work node:12-bullseye-slim sh -c '
  npm install trip-simulator --no-audit --no-fund
  B=node_modules/osrm/lib/binding; export LD_LIBRARY_PATH=/work/$B
  $B/osrm-extract -p node_modules/osrm/profiles/car.lua Curitiba.osm.pbf
  $B/osrm-contract Curitiba.osrm
  node node_modules/trip-simulator/src/cli.js --config car --pbf Curitiba.osm.pbf --graph Curitiba.osrm \
    --agents 800 --start 1767225600000 --seconds 300 --probes probes.json --trips trips.json -q'
# then take the last probe of each agent and assign it to veh-00001..veh-00800 (see the repository history for the script)
