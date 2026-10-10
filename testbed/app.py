"""The emulated fleet backend: identity provider, API gateway (ASGI middleware) and fleet services.

Deliberate defects (they make the attack scenarios possible and are part of the test design):
  * GET /vehicles/{vid} skips the object-level check for vehicles flagged `legacy`;
  * an operator holding the scope `location:read:all` can read any fleet's locations;
  * GET /partner/diagnostics/{vid} does not enforce the partner's contract tenant.
"""
import json
import os

import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from config import CFG
from logsink import geo_region, iso, pseudo_ip


class Ctx:
    def __init__(self, pop, sinks):
        self.pop = pop
        self.sinks = sinks
        self.now_ms = 0
        self.corr_seq = 0
        self.tok_seq = 0
        self.chal_seq = 0
        self.camp_seq = 0
        self.challenges = {}
        self.campaigns = {}
        # synthetic vehicle positions from trip-simulator (response payloads only; never written to the logs)
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "geo", "positions.json")
        self.positions = json.load(open(path))["positions"] if os.path.exists(path) else {}


def _origin(request: Request):
    ip = request.headers.get("x-forwarded-for", "0.0.0.0")
    return {"src_ip_pseudo": pseudo_ip(ip), "device_id": request.headers.get("x-device-id"),
            "user_agent_class": request.headers.get("user-agent", "other"), "geo_region": geo_region(ip)}


def _claims_fields(c):
    if not c:
        return {}
    return {"account_id": c.get("sub"), "credential_id": c.get("cid"), "token_id": c.get("jti"),
            "client_id": c.get("cli"), "subject_type": c.get("typ"), "scope": c.get("scope")}


def build_app(ctx: Ctx) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    pop = ctx.pop
    sinks = ctx.sinks

    def trace_of(request):
        return request.headers.get("x-sim-trace")

    def attack_of(request):
        return request.headers.get("x-sim-attack") == "1"

    # ------------------------------------------------------------------ gateway
    @app.middleware("http")
    async def gateway(request: Request, call_next):
        path = request.url.path
        ctx.corr_seq += 1
        request.state.corr = f"c{ctx.corr_seq:07d}"
        request.state.claims = None
        request.state.meta = {}
        if path.startswith("/idp/"):
            return await call_next(request)
        reason = None
        auth = request.headers.get("authorization", "")
        claims = None
        if auth.startswith("Bearer "):
            try:
                claims = jwt.decode(auth[7:], CFG["jwt_key"], algorithms=["HS256"], options={"verify_exp": False})
                if claims["exp"] * 1000 < ctx.now_ms:
                    claims, reason = None, "expired"
            except Exception:  # noqa: BLE001
                claims, reason = None, "invalid_token"
        else:
            reason = "no_token"
        request.state.claims = claims
        if claims is None:
            resp = JSONResponse({"error": reason}, status_code=401)
            status = 401
        else:
            resp = await call_next(request)
            status = resp.status_code
        meta = request.state.meta
        route = request.scope.get("route")
        template = getattr(route, "path", path)
        rec = {"ts": iso(ctx.now_ms), "layer": "gateway", "component": "gw-1", "corr_id": request.state.corr}
        rec.update(_claims_fields(claims))
        rec.update({
            "object_type": meta.get("otype"), "object_id": meta.get("oid"),
            "route": f"{request.method} {template}", "action": meta.get("action", request.method.lower()),
            "decision": "allow" if claims is not None else "deny",
            "policy_id": "gw-authn", "reason": None if claims is not None else reason,
            "result_count": meta.get("count"), "outcome": status})
        rec.update(_origin(request))
        q = request.url.query
        rec["_path"] = path + ("?" + q if q else "")   # access-log profile only
        sinks.emit("gateway", rec, "both", trace_of(request), attack_of(request))
        return resp

    # ------------------------------------------------------------------ helpers for services
    def svc(request, *, action, otype, oid, status, decision, policy, reason=None, vehicle=None, fleet=None,
            purpose=None, count=None, scope="both", **extra):
        c = request.state.claims
        v = pop["vehicles"].get(vehicle) if vehicle else None
        f = fleet or (v["fleet"] if v else None)
        tenant = v["tenant"] if v else (pop["fleets"][f]["tenant"] if f in pop["fleets"] else None)
        rec = {"ts": iso(ctx.now_ms), "layer": "service", "component": "svc-1", "corr_id": request.state.corr}
        rec.update(_claims_fields(c))
        rec.update({"object_type": otype, "object_id": oid, "action": action,
                    "route": f"{request.method} {request.scope['route'].path}",
                    "tenant_id": tenant, "fleet_id": f, "vehicle_id": vehicle, "purpose": purpose,
                    "decision": decision, "policy_id": policy, "reason": reason, "result_count": count,
                    "outcome": status})
        rec.update(extra)
        rec.update(_origin(request))
        sinks.emit("service", rec, scope, trace_of(request), attack_of(request))

    def idp(request, account, cred, *, action, event, status, token=None, mfa="not_required"):
        a = pop["accounts"].get(account)
        rec = {"ts": iso(ctx.now_ms), "layer": "idp", "component": "idp-1", "corr_id": request.state.corr,
               "account_id": account, "credential_id": cred, "token_id": token,
               "client_id": "app-" + (a["ua"] if a else "other"), "subject_type": a["type"] if a else None,
               "object_type": "account", "object_id": account, "action": action,
               "route": f"{request.method} {request.url.path}", "auth_event": event,
               "auth_method": ("password+mfa" if a and a["mfa"] else ("api_key" if a and a["type"] in ("partner", "ci")
                                                                      else "password")),
               "mfa_result": mfa, "outcome": status}
        rec.update(_origin(request))
        sinks.emit("idp", rec, "both", trace_of(request), attack_of(request))

    def issue(request, account, cred):
        a = pop["accounts"][account]
        ctx.tok_seq += 1
        jti = f"tok-{ctx.tok_seq:06d}"
        payload = {"sub": account, "jti": jti, "cid": cred, "scope": a["scope"], "typ": a["type"], "tid": a["tenant"],
                   "cli": "app-" + a["ua"], "exp": (ctx.now_ms + CFG["token_ttl_ms"]) / 1000}
        return jti, jwt.encode(payload, CFG["jwt_key"], algorithm="HS256")

    # ------------------------------------------------------------------ identity provider
    @app.post("/idp/login")
    async def login(request: Request):
        body = await request.json()
        account, cred = body["account_id"], body["credential_id"]
        a = pop["accounts"].get(account)
        if a is None or a["credential"] != cred:
            idp(request, account, cred, action="login", event="login_failure", status=401)
            return JSONResponse({"error": "invalid_credentials"}, status_code=401)
        if a["mfa"]:
            ctx.chal_seq += 1
            chal = f"ch-{ctx.chal_seq:06d}"
            ctx.challenges[chal] = (account, cred)
            idp(request, account, cred, action="login", event="mfa_required", status=200, mfa="required")
            return {"status": "mfa_required", "challenge": chal}
        idp(request, account, cred, action="login", event="login_success", status=200)
        jti, tok = issue(request, account, cred)
        idp(request, account, cred, action="token_issue", event="token_issue", status=200, token=jti)
        return {"token": tok}

    @app.post("/idp/mfa")
    async def mfa(request: Request):
        body = await request.json()
        account, cred = ctx.challenges.pop(body["challenge"], (None, None))
        if account is None or not body.get("ok", False):
            idp(request, account, cred, action="mfa", event="mfa", status=401, mfa="failed")
            return JSONResponse({"error": "mfa_failed"}, status_code=401)
        idp(request, account, cred, action="mfa", event="mfa", status=200, mfa="passed")
        jti, tok = issue(request, account, cred)
        idp(request, account, cred, action="token_issue", event="token_issue", status=200, token=jti, mfa="passed")
        return {"token": tok}

    # ------------------------------------------------------------------ authorization policies
    def authz_vehicle(c, v, legacy_defect):
        t = c["typ"]
        if t == "driver":
            ok = v["driver"] == c["sub"]
            pol = "pol-driver-own"
            reason = "ok" if ok else "not_owner"
        elif t == "operator":
            ok = v["tenant"] == c["tid"]
            pol = "pol-operator-tenant"
            reason = "ok" if ok else "tenant_mismatch"
        else:
            ok, pol, reason = False, "pol-deny-type", "scope_missing"
        if not ok and legacy_defect and v["legacy"]:
            return True, "pol-legacy-open", "ok"
        return ok, pol, reason

    async def vehicle_read(request, vid, what, legacy_defect):
        c = request.state.claims
        v = pop["vehicles"].get(vid)
        meta = request.state.meta
        meta.update({"otype": "vehicle", "oid": vid, "action": "read"})
        if v is None:
            svc(request, action="read", otype="vehicle", oid=vid, status=404, decision="deny", policy="pol-lookup",
                reason="not_found", purpose=what)
            return JSONResponse({"error": "not_found"}, status_code=404)
        ok, pol, reason = authz_vehicle(c, v, legacy_defect)
        status = 200 if ok else 403
        svc(request, action="read", otype="vehicle", oid=vid, status=status, decision="allow" if ok else "deny",
            policy=pol, reason=reason, vehicle=vid, purpose=what)
        if not ok:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        if what == "location" and vid in ctx.positions:
            lat, lon = ctx.positions[vid]
            return {"vehicle": vid, "data": what, "lat": lat, "lon": lon}
        return {"vehicle": vid, "data": what}

    @app.get("/vehicles/{vid}")
    async def get_vehicle(request: Request, vid: str):
        return await vehicle_read(request, vid, "vehicle_status", True)

    @app.get("/vehicles/{vid}/location")
    async def get_location(request: Request, vid: str):
        return await vehicle_read(request, vid, "location", False)

    @app.post("/vehicles/{vid}/commands")
    async def command(request: Request, vid: str):
        body = await request.json()
        c = request.state.claims
        v = pop["vehicles"].get(vid)
        request.state.meta.update({"otype": "vehicle", "oid": vid, "action": "command"})
        if v is None:
            svc(request, action="command", otype="vehicle", oid=vid, status=404, decision="deny", policy="pol-lookup",
                reason="not_found", purpose="command")
            return JSONResponse({"error": "not_found"}, status_code=404)
        ok, pol, reason = authz_vehicle(c, v, False)
        status = 200 if ok else 403
        svc(request, action="command", otype="vehicle", oid=vid, status=status, decision="allow" if ok else "deny",
            policy=pol, reason=reason, vehicle=vid, purpose="command")
        if not ok:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        return {"ok": True, "vehicle": vid, "cmd": body.get("cmd")}

    @app.get("/fleets/{fid}/locations")
    async def fleet_locations(request: Request, fid: str, limit: int = 10, offset: int = 0):
        c = request.state.claims
        f = pop["fleets"].get(fid)
        request.state.meta.update({"otype": "fleet", "oid": fid, "action": "read"})
        if f is None:
            svc(request, action="read", otype="fleet", oid=fid, status=404, decision="deny", policy="pol-lookup",
                reason="not_found", purpose="fleet_locations")
            return JSONResponse({"error": "not_found"}, status_code=404)
        if c["typ"] != "operator":
            ok, pol, reason = False, "pol-deny-type", "scope_missing"
        elif "location:read:all" in c["scope"]:
            ok, pol, reason = True, "pol-operator-all", "ok"
        else:
            ok = f["tenant"] == c["tid"]
            pol, reason = "pol-operator-tenant", "ok" if ok else "tenant_mismatch"
        if not ok:
            svc(request, action="read", otype="fleet", oid=fid, status=403, decision="deny", policy=pol, reason=reason,
                fleet=fid, purpose="fleet_locations")
            return JSONResponse({"error": "forbidden"}, status_code=403)
        page = f["vehicles"][offset:offset + limit]
        request.state.meta["count"] = len(page)
        svc(request, action="read", otype="fleet", oid=fid, status=200, decision="allow", policy=pol, reason=reason,
            fleet=fid, purpose="fleet_locations", count=len(page))
        for vid in page:
            svc(request, action="read", otype="vehicle", oid=vid, status=200, decision="allow", policy=pol,
                reason=reason, vehicle=vid, purpose="fleet_locations", scope="complete")
        return {"fleet": fid, "vehicles": page, "locations": {v: ctx.positions[v] for v in page if v in ctx.positions}}

    @app.get("/partner/diagnostics/{vid}")
    async def diagnostics(request: Request, vid: str):
        c = request.state.claims
        v = pop["vehicles"].get(vid)
        request.state.meta.update({"otype": "vehicle", "oid": vid, "action": "read"})
        if v is None:
            svc(request, action="read", otype="vehicle", oid=vid, status=404, decision="deny", policy="pol-lookup",
                reason="not_found", purpose="diagnostics")
            return JSONResponse({"error": "not_found"}, status_code=404)
        ok = c["typ"] == "partner" and "diag:read" in c["scope"]
        svc(request, action="read", otype="vehicle", oid=vid, status=200 if ok else 403,
            decision="allow" if ok else "deny", policy="pol-partner-diag", reason="ok" if ok else "scope_missing",
            vehicle=vid, purpose="diagnostics")
        if not ok:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        return {"vehicle": vid, "data": "diagnostics"}

    @app.post("/campaigns")
    async def create_campaign(request: Request):
        body = await request.json()
        c = request.state.claims
        request.state.meta.update({"otype": "campaign", "action": "create"})
        if not (c["typ"] == "ci" and "campaign:create" in c["scope"]):
            svc(request, action="create", otype="campaign", oid=None, status=403, decision="deny",
                policy="pol-ci-campaign", reason="scope_missing", purpose="ota")
            return JSONResponse({"error": "forbidden"}, status_code=403)
        ctx.camp_seq += 1
        cid = f"cmp-{ctx.camp_seq:04d}"
        targets = [v for fid in body["target_fleets"] if fid in pop["fleets"] for v in pop["fleets"][fid]["vehicles"]]
        ctx.campaigns[cid] = {"targets": targets, "artifact": body["artifact_id"], "sig_ok": body["signature_ok"],
                              "approver": body.get("approver_id")}
        request.state.meta.update({"oid": cid, "count": len(targets)})
        svc(request, action="create", otype="campaign", oid=cid, status=200, decision="allow",
            policy="pol-ci-campaign", reason="ok", purpose="ota", campaign_id=cid, artifact_id=body["artifact_id"],
            signature_result="valid" if body["signature_ok"] else "invalid", target_count=len(targets),
            approver_id=body.get("approver_id"))
        return {"campaign": cid}

    @app.post("/campaigns/{cid}/launch")
    async def launch_campaign(request: Request, cid: str):
        body = await request.json()
        c = request.state.claims
        camp = ctx.campaigns.get(cid)
        request.state.meta.update({"otype": "campaign", "oid": cid, "action": "launch"})
        if camp is None or not (c["typ"] == "ci" and "campaign:launch" in c["scope"]):
            svc(request, action="launch", otype="campaign", oid=cid, status=404 if camp is None else 403,
                decision="deny", policy="pol-ci-campaign", reason="not_found" if camp is None else "scope_missing",
                purpose="ota")
            return JSONResponse({"error": "denied"}, status_code=404 if camp is None else 403)
        request.state.meta["count"] = len(camp["targets"])
        svc(request, action="launch", otype="campaign", oid=cid, status=200, decision="allow",
            policy="pol-ci-campaign", reason="ok" if body.get("window_ok", True) else "outside_window",
            purpose="ota", campaign_id=cid, artifact_id=camp["artifact"],
            signature_result="valid" if camp["sig_ok"] else "invalid", target_count=len(camp["targets"]),
            approver_id=camp["approver"])
        for vid in camp["targets"]:
            svc(request, action="launch_target", otype="vehicle", oid=vid, status=200, decision="allow",
                policy="pol-ci-campaign", reason="ok", vehicle=vid, purpose="ota", campaign_id=cid,
                artifact_id=camp["artifact"], scope="complete")
        return {"campaign": cid, "targets": camp["targets"]}

    return app
