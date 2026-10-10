"""Synthetic population: tenants, fleets, vehicles, drivers, operators, partners and a CI account."""
import random


def _ip(a, b, c, d):
    return f"{a}.{b}.{c}.{d}"


def build_population(rng: random.Random, cfg: dict) -> dict:
    tenants, fleets, vehicles, accounts = {}, {}, {}, {}
    vnum = 0
    dnum = 0
    for ti in range(1, cfg["tenants"] + 1):
        tid = f"tnt-{ti:02d}"
        tenants[tid] = {"fleets": [], "operators": []}
        for fi in range(1, cfg["fleets_per_tenant"] + 1):
            fid = f"flt-{ti:02d}{fi}"
            fleets[fid] = {"tenant": tid, "vehicles": []}
            tenants[tid]["fleets"].append(fid)
            for _ in range(cfg["vehicles_per_fleet"]):
                vnum += 1
                dnum += 1
                vid = f"veh-{vnum:05d}"
                did = f"acc-d{dnum:05d}"
                vehicles[vid] = {"fleet": fid, "tenant": tid, "driver": did,
                                 "legacy": rng.random() < cfg["legacy_share"]}
                fleets[fid]["vehicles"].append(vid)
                accounts[did] = {"type": "driver", "tenant": tid, "credential": f"cred-d{dnum:05d}",
                                 "mfa": False, "scope": ["vehicle:read", "vehicle:command"],
                                 "device": f"dev-{did[4:]}", "ip": _ip(10, ti, rng.randint(1, 250), rng.randint(1, 250)),
                                 "ua": "mobile"}
        for oi in range(1, cfg["operators_per_tenant"] + 1):
            oid = f"acc-o{ti:02d}{oi}"
            accounts[oid] = {"type": "operator", "tenant": tid, "credential": f"cred-o{ti:02d}{oi}",
                             "mfa": True, "scope": ["vehicle:read", "vehicle:command", "location:read"],
                             "device": f"dev-o{ti:02d}{oi}", "ip": _ip(10, ti, 250, oi), "ua": "web"}
            tenants[tid]["operators"].append(oid)
    partner_tenants = {}
    for pi in range(1, cfg["partners"] + 1):
        pid = f"acc-p{pi:02d}"
        contract = f"tnt-{((pi - 1) % cfg['tenants']) + 1:02d}"
        partner_tenants[pid] = contract
        accounts[pid] = {"type": "partner", "tenant": contract, "credential": f"key-p{pi:02d}", "mfa": False,
                         "scope": ["diag:read"], "device": f"dev-p{pi:02d}", "ip": _ip(172, 16, pi, 10), "ua": "api"}
    accounts["acc-ci01"] = {"type": "ci", "tenant": None, "credential": "key-ci01", "mfa": False,
                            "scope": ["campaign:create", "campaign:launch"], "device": "dev-ci01",
                            "ip": _ip(172, 20, 0, 5), "ua": "api"}
    return {"tenants": tenants, "fleets": fleets, "vehicles": vehicles, "accounts": accounts,
            "partner_tenants": partner_tenants}


def inventory_snapshot(pop: dict) -> dict:
    """What the investigator may read besides the logs: the organizational inventory only.

    It has tenants, fleets, vehicles, driver accounts and each account's tenant. It has no campaign targets,
    no location data and no responses.
    """
    return {
        "vehicles": {v: {"fleet": d["fleet"], "tenant": d["tenant"], "driver": d["driver"]}
                     for v, d in pop["vehicles"].items()},
        "fleets": {f: {"tenant": d["tenant"], "vehicles": d["vehicles"]} for f, d in pop["fleets"].items()},
        "accounts": {a: {"type": d["type"], "tenant": d["tenant"]} for a, d in pop["accounts"].items()},
    }
