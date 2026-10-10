"""Take the last probe of each simulated agent from trip-simulator's probes.json and assign it to
veh-00001..veh-00800 in order of first appearance. Usage: extract_positions.py probes.json out.json"""
import hashlib, json, sys
last, order, n = {}, [], 0
with open(sys.argv[1]) as fh:
    for l in fh:
        l = l.strip()
        if not l:
            continue
        f = json.loads(l)
        n += 1
        i = f["properties"]["id"]
        if i not in last:
            order.append(i)
        last[i] = f["geometry"]["coordinates"]
pos = {f"veh-{k + 1:05d}": [round(last[a][1], 6), round(last[a][0], 6)] for k, a in enumerate(order)}   # [lat, lon]
json.dump({"positions": pos, "probes": n, "probes_sha256": hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest()},
          open(sys.argv[2], "w"))
