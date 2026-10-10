"""Background traffic and the five attack scenarios, as time-stamped request schedules.

An event is a dict: t (ms), sess, kind (login | mfa | req), actor, attack, dev, ip, ua, and for requests
method, path, json. Attack events carry a hidden trace id used only by the evaluation harness.
"""
import random

FOREIGN_IP = "203.0.113."


def _sess(ev, rng, sess, actor, acct, t0, reqs, *, attack=False, cred=None, dev=None, ip=None, ua=None,
          gaps=(1000, 30000), tag="", trace_prefix=None, counter=None):
    cred = cred or acct["credential"]
    dev = dev or acct["device"]
    ip = ip or acct["ip"]
    ua = ua or acct["ua"]

    def add(t, **kw):
        e = {"t": t, "sess": sess, "actor": actor, "attack": attack, "dev": dev, "ip": ip, "ua": ua, "tag": tag}
        e.update(kw)
        if attack:
            counter[0] += 1
            e["trace"] = f"{trace_prefix}-{counter[0]:05d}"
        ev.append(e)

    t = t0
    add(t, kind="login", cred=cred)
    if acct["mfa"]:
        t += rng.randint(2000, 8000)
        add(t, kind="mfa")
    for method, path, body in reqs:
        t += rng.randint(*gaps)
        add(t, kind="req", method=method, path=path, json=body)
    return t


def background(rng: random.Random, pop: dict, cfg: dict) -> list:
    ev = []
    day = cfg["day_ms"] - 600_000
    vehicles = pop["vehicles"]
    all_v = list(vehicles)
    n = 0
    for vid, v in vehicles.items():
        if rng.random() > cfg["driver_active_prob"]:
            continue
        did = v["driver"]
        acct = pop["accounts"][did]
        reqs = []
        for _ in range(rng.randint(*cfg["driver_requests"])):
            r = rng.random()
            if r < 0.01:
                reqs.append(("GET", f"/vehicles/veh-9{rng.randint(1000, 9999)}", None))   # mistyped id
            elif r < 0.41:
                reqs.append(("GET", f"/vehicles/{vid}", None))
            elif r < 0.81:
                reqs.append(("GET", f"/vehicles/{vid}/location", None))
            else:
                reqs.append(("POST", f"/vehicles/{vid}/commands", {"cmd": rng.choice(["lock", "unlock"])}))
        n += 1
        _sess(ev, rng, f"bg-d{n}", did, acct, rng.randint(0, day), reqs)
    for tid, t in pop["tenants"].items():
        tvs = [v for f in t["fleets"] for v in pop["fleets"][f]["vehicles"]]
        for oid in t["operators"]:
            acct = pop["accounts"][oid]
            for k in range(cfg["operator_sessions"]):
                reqs = []
                for _ in range(rng.randint(*cfg["operator_requests"])):
                    r = rng.random()
                    if r < 0.5:
                        fid = rng.choice(t["fleets"])
                        reqs.append(("GET", f"/fleets/{fid}/locations?limit=10&offset={rng.choice([0, 10, 20])}", None))
                    elif r < 0.8:
                        reqs.append(("GET", f"/vehicles/{rng.choice(tvs)}", None))
                    else:
                        reqs.append(("POST", f"/vehicles/{rng.choice(tvs)}/commands",
                                     {"cmd": rng.choice(["lock", "unlock"])}))
                _sess(ev, rng, f"bg-{oid}-{k}", oid, acct, rng.randint(0, day), reqs)
    for pid, contract in pop["partner_tenants"].items():
        acct = pop["accounts"][pid]
        cvs = [v for f in pop["tenants"][contract]["fleets"] for v in pop["fleets"][f]["vehicles"]]
        total = rng.randint(*cfg["partner_polls"])
        for k in range(4):
            reqs = [("GET", f"/partner/diagnostics/{rng.choice(cvs)}", None) for _ in range(total // 4)]
            _sess(ev, rng, f"bg-{pid}-{k}", pid, acct, rng.randint(0, day), reqs, gaps=(2000, 60000))
    ci = pop["accounts"]["acc-ci01"]
    for k in range(cfg["ci_campaigns"]):
        tid = rng.choice(list(pop["tenants"]))
        fleets = rng.sample(pop["tenants"][tid]["fleets"], rng.randint(1, 2))
        approver = rng.choice(pop["tenants"][tid]["operators"])
        reqs = [("POST", "/campaigns", {"artifact_id": f"art-ok{k}", "signature_ok": True, "target_fleets": fleets,
                                        "approver_id": approver}),
                ("POST", "/campaigns/{LAST_CAMPAIGN}/launch", {"window_ok": True})]
        _sess(ev, rng, f"bg-ci-{k}", "acc-ci01", ci, rng.randint(0, day), reqs, gaps=(5000, 60000))
    return ev


def _atk_sess(ev, rng, actor, acct, t0, reqs, **kw):
    """Attack session; in half of the cases (with at least four requests) the attacker reconnects once."""
    if len(reqs) >= 4 and rng.random() < 0.5:
        k = rng.randint(1, len(reqs) - 1)
        t = _sess(ev, rng, "atk", actor, acct, t0, reqs[:k], **kw)
        return _sess(ev, rng, "atk2", actor, acct, t + rng.randint(5000, 30000), reqs[k:], **kw)
    return _sess(ev, rng, "atk", actor, acct, t0, reqs, **kw)


def _foreign_fleets(pop, tenant):
    return [f for f, d in pop["fleets"].items() if d["tenant"] != tenant]


def attack(scenario: str, rng: random.Random, pop: dict, cfg: dict) -> tuple:
    """Return (events, meta). meta describes the suspect account and, for evaluation, how to read the effects."""
    ev = []
    counter = [0]
    t0 = rng.randint(2 * 3_600_000, 22 * 3_600_000)
    pref = scenario[:2]
    accounts = pop["accounts"]
    meta = {"scenario": scenario}

    if scenario == "s1_takeover":
        victim = rng.choice([a for a, d in accounts.items() if d["type"] == "operator"])
        va = accounts[victim]
        tvs = [v for f in pop["tenants"][va["tenant"]]["fleets"] for v in pop["fleets"][f]["vehicles"]]
        dev, ip = "dev-atk-01", FOREIGN_IP + str(rng.randint(2, 250))
        t = t0
        for i in range(rng.randint(*cfg["s1_failed_logins"])):
            _sess(ev, rng, f"atk-f{i}", victim, va, t, [], attack=True, cred=f"cred-guess-{rng.randint(1000, 9999)}",
                  dev=dev, ip=ip, ua="other", tag=pref, trace_prefix=pref, counter=counter)
            t += rng.randint(500, 3000)
        reqs = []
        for _ in range(rng.randint(*cfg["s1_commands"])):
            reqs.append(("POST", f"/vehicles/{rng.choice(tvs)}/commands", {"cmd": "unlock"}))
        for _ in range(rng.randint(*cfg["s1_location_reads"])):
            reqs.append(("GET", f"/vehicles/{rng.choice(tvs)}/location", None))
        rng.shuffle(reqs)
        _atk_sess(ev, rng, victim, va, t, reqs, attack=True, dev=dev, ip=ip, ua="other", gaps=(300, 1500),
                  tag=pref, trace_prefix=pref, counter=counter)
        meta.update(actor=victim, tenant_of_actor=va["tenant"], stolen=True)

    elif scenario == "s2_bola_probing":
        drivers = [a for a, d in accounts.items() if d["type"] == "driver"]
        actor = rng.choice(drivers)
        n = len(pop["vehicles"])
        start = rng.randint(1, n)
        k = rng.randint(*cfg["s2_probes"])
        reqs = [("GET", f"/vehicles/veh-{((start + i - 1) % n) + 1:05d}", None) for i in range(k)]
        _atk_sess(ev, rng, actor, accounts[actor], t0, reqs, attack=True, gaps=(200, 800), tag=pref,
                  trace_prefix=pref, counter=counter)
        meta.update(actor=actor, tenant_of_actor=accounts[actor]["tenant"], stolen=False)

    elif scenario == "s3_bulk_location":
        actor = rng.choice([a for a, d in accounts.items() if d["type"] == "operator"])
        accounts[actor]["scope"] = accounts[actor]["scope"] + ["location:read:all"]   # misconfigured scope
        foreign = _foreign_fleets(pop, accounts[actor]["tenant"])
        pages = [(f, off) for f in foreign for off in (0, 10, 20)]
        chosen = sorted(rng.sample(pages, min(len(pages), rng.randint(*cfg["s3_pages"]))))
        reqs = [("GET", f"/fleets/{f}/locations?limit={cfg['s3_limit']}&offset={off}", None) for f, off in chosen]
        _atk_sess(ev, rng, actor, accounts[actor], t0, reqs, attack=True, gaps=(300, 1200), tag=pref,
                  trace_prefix=pref, counter=counter)
        meta.update(actor=actor, tenant_of_actor=accounts[actor]["tenant"], stolen=False)

    elif scenario == "s4_ota_anomaly":
        ci = accounts["acc-ci01"]
        fleets = rng.sample(list(pop["fleets"]), rng.randint(*cfg["s4_target_fleets"]))
        reqs = [("POST", "/campaigns", {"artifact_id": "art-evil", "signature_ok": False, "target_fleets": fleets,
                                        "approver_id": None}),
                ("POST", "/campaigns/{LAST_CAMPAIGN}/launch", {"window_ok": False})]
        _sess(ev, rng, "atk", "acc-ci01", ci, t0, reqs, attack=True, dev="dev-atk-04",
              ip=FOREIGN_IP + str(rng.randint(2, 250)), ua="other", gaps=(2000, 15000), tag=pref, trace_prefix=pref,
              counter=counter)
        meta.update(actor="acc-ci01", tenant_of_actor=None, stolen=True)

    elif scenario == "s5_supplier_abuse":
        actor = rng.choice([a for a, d in accounts.items() if d["type"] == "partner"])
        contract = accounts[actor]["tenant"]
        outside = [v for v, d in pop["vehicles"].items() if d["tenant"] != contract]
        reqs = []
        for _ in range(rng.randint(*cfg["s5_reads"])):
            reqs.append(("GET", f"/partner/diagnostics/{rng.choice(outside)}", None))
        for _ in range(5):
            reqs.insert(rng.randint(0, len(reqs)), ("GET", f"/vehicles/{rng.choice(outside)}/location", None))
        _atk_sess(ev, rng, actor, accounts[actor], t0, reqs, attack=True, dev="dev-atk-05",
                  ip=FOREIGN_IP + str(rng.randint(2, 250)), ua="other", gaps=(100, 500), tag=pref,
                  trace_prefix=pref, counter=counter)
        meta.update(actor=actor, tenant_of_actor=contract, stolen=True)
    else:
        raise ValueError(scenario)
    return ev, meta
