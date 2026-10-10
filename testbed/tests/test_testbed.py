import json, os, random, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.makedirs(os.path.join(os.path.dirname(__file__), "..", "runs"), exist_ok=True)
from config import CFG, MINIMAL_FIELDS, SCENARIOS
from logsink import ChainedWriter, verify_chain
from population import build_population
import runner
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def make_log(n=350):
    d = tempfile.mkdtemp()
    key = Ed25519PrivateKey.generate()
    lp, cp = os.path.join(d, "a.jsonl"), os.path.join(d, "a.chain")
    w = ChainedWriter(lp, cp, key, 100)
    for i in range(n):
        w.write((json.dumps({"i": i}) + "\n").encode())
    w.close()
    return lp, cp, key.public_key()


class Integrity(unittest.TestCase):
    def test_clean_log_verifies(self):
        lp, cp, pk = make_log()
        self.assertTrue(verify_chain(lp, cp, pk)[0])

    def test_modification_detected(self):
        lp, cp, pk = make_log()
        lines = open(lp, "rb").readlines()
        lines[120] = b'{"i":999}\n'
        open(lp, "wb").writelines(lines)
        self.assertFalse(verify_chain(lp, cp, pk)[0])

    def test_deletion_and_insertion_detected(self):
        lp, cp, pk = make_log()
        lines = open(lp, "rb").readlines()
        open(lp, "wb").writelines(lines[:50] + lines[51:])
        self.assertFalse(verify_chain(lp, cp, pk)[0])
        lp, cp, pk = make_log()
        lines = open(lp, "rb").readlines()
        open(lp, "wb").writelines(lines[:50] + [b'{"i":-1}\n'] + lines[50:])
        self.assertFalse(verify_chain(lp, cp, pk)[0])

    def test_reordering_detected(self):
        lp, cp, pk = make_log()
        lines = open(lp, "rb").readlines()
        lines[10], lines[20] = lines[20], lines[10]
        open(lp, "wb").writelines(lines)
        self.assertFalse(verify_chain(lp, cp, pk)[0])

    def test_tail_truncation_is_not_detected(self):
        """Documented limit: removing whole final batches leaves a valid prefix."""
        lp, cp, pk = make_log()
        lines = open(lp, "rb").readlines()
        open(lp, "wb").writelines(lines[:200])
        chain = open(cp, "rb").readlines()
        open(cp, "wb").writelines(chain[:2])
        self.assertTrue(verify_chain(lp, cp, pk)[0])


class Profiles(unittest.TestCase):
    def test_population_size(self):
        pop = build_population(random.Random(0), CFG)
        self.assertEqual(len(pop["vehicles"]), CFG["tenants"] * CFG["fleets_per_tenant"] * CFG["vehicles_per_fleet"])

    def test_minimal_is_projection_of_complete(self):
        keep = tempfile.mkdtemp()
        rows = runner.run_one("s2_bola_probing", 7, "test", keep_dir=keep, noise=False)
        run = os.path.join(keep, os.listdir(keep)[0])
        for layer in ("gateway", "idp", "service"):
            for line in open(os.path.join(run, "minimal", layer + ".jsonl")):
                self.assertTrue(set(json.loads(line)) <= set(MINIMAL_FIELDS))
        self.assertTrue(all(r["custody_ok"] == 1 for r in rows if r["valid"]))

    def test_deterministic_logs(self):
        outs = []
        for _ in range(2):
            keep = tempfile.mkdtemp()
            runner.run_one("s1_takeover", 3, "test", keep_dir=keep, noise=False)
            run = os.path.join(keep, os.listdir(keep)[0])
            outs.append(open(os.path.join(run, "complete", "gateway.jsonl"), "rb").read())
        self.assertEqual(outs[0], outs[1])

    def test_reconstruction_never_imports_ground_truth(self):
        src = open(os.path.join(os.path.dirname(__file__), "..", "recon.py")).read()
        self.assertNotIn("ground_truth", src)
        self.assertNotIn("from runner", src)


class Positions(unittest.TestCase):
    def test_positions_reach_responses_but_never_the_logs(self):
        import asyncio, httpx
        from app import Ctx, build_app
        from logsink import RunSinks
        rng = random.Random(0)
        pop = build_population(rng, CFG)
        d = tempfile.mkdtemp()
        sinks = RunSinks(d)
        ctx = Ctx(pop, sinks)
        self.assertEqual(len(ctx.positions), 800)
        app = build_app(ctx)
        acc = pop["accounts"]["acc-d00001"]
        H = {"x-forwarded-for": acc["ip"], "x-device-id": acc["device"], "user-agent": acc["ua"]}

        async def go():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as cl:
                r = await cl.post("/idp/login", json={"account_id": "acc-d00001", "credential_id": acc["credential"]}, headers=H)
                H2 = dict(H, authorization="Bearer " + r.json()["token"])
                return (await cl.get("/vehicles/veh-00001/location", headers=H2)).json()
        body = asyncio.run(go())
        sinks.close()
        self.assertIn("lat", body)
        for p in ("minimal", "complete"):
            for layer in ("gateway", "idp", "service"):
                text = open(os.path.join(d, p, layer + ".jsonl")).read()
                self.assertNotIn(str(body["lat"]), text)
                self.assertNotIn(str(body["lon"]), text)


class Sanity(unittest.TestCase):
    """Protocol control: with the complete profile and no background noise, recall and precision must be 1."""

    def test_complete_profile_noise_free(self):
        for sc in SCENARIOS:
            rows = runner.run_one(sc, 11, "test", noise=False)
            comp = [r for r in rows if r["profile"] == "complete"][0]
            self.assertEqual(comp["valid"], 1, sc)
            self.assertEqual(comp["recall_mean"], 1.0, sc)
            self.assertEqual(comp["precision_mean"], 1.0, sc)


if __name__ == "__main__":
    unittest.main()
