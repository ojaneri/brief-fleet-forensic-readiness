"""Tamper-detection experiment for the integrity envelope (BRIEF component C).

Takes the complete-profile gateway log of one realistic run, re-writes it through the same ChainedWriter, and applies
random tampering of each kind, then checks whether verify_chain detects it and, when it does, whether it points at
the batch that was actually changed. The number of trials per kind is a design choice of the agent (d-0015).
"""
import json
import os
import random
import shutil
import sys
import tempfile

import pandas as pd
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import runner  # noqa: E402
from config import CFG  # noqa: E402
from logsink import ChainedWriter, verify_chain  # noqa: E402

TRIALS = 200
DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")


def build(lines, workdir):
    key = Ed25519PrivateKey.generate()
    lp, cp = os.path.join(workdir, "log.jsonl"), os.path.join(workdir, "log.chain")
    w = ChainedWriter(lp, cp, key, CFG["batch_size"])
    for l in lines:
        w.write(l)
    w.close()
    return lp, cp, key.public_key()


def batch_of(pos, batch_size=CFG["batch_size"]):
    return pos // batch_size


def tamper(kind, lines, chain, rng):
    """Return (new_lines, new_chain, tampered_batch or None)."""
    lines, chain = list(lines), list(chain)
    bs = CFG["batch_size"]
    n = len(lines)
    if kind == "modify":
        i = rng.randrange(n)
        raw = bytearray(lines[i])
        j = rng.randrange(len(raw) - 1)
        raw[j] = (raw[j] + 1) % 256 if raw[j] != 10 else 32
        lines[i] = bytes(raw)
        return lines, chain, batch_of(i)
    if kind == "delete":
        i = rng.randrange(n)
        del lines[i]
        return lines, chain, batch_of(i)
    if kind == "insert":
        i = rng.randrange(n)
        lines.insert(i, lines[rng.randrange(n)])
        return lines, chain, batch_of(i)
    if kind == "reorder":
        i, j = rng.sample(range(n), 2)
        lines[i], lines[j] = lines[j], lines[i]
        return lines, chain, batch_of(min(i, j))
    if kind == "truncate_partial":
        k = rng.randint(1, bs - 1)
        return lines[:-k], chain, None
    if kind == "truncate_whole_batches":
        m = rng.randint(1, max(1, len(chain) - 1))
        keep = len(chain) - m
        return lines[:sum(json.loads(h)["n"] for h in chain[:keep])], chain[:keep], None
    if kind == "forge_without_key":
        i = rng.randrange(n)
        lines[i] = lines[i].replace(b"200", b"403", 1) if b"200" in lines[i] else lines[i] + b" "
        # recompute every batch hash from the tampered batch on, keeping the old signatures (no private key)
        import hashlib
        hdrs = [json.loads(h) for h in chain]
        prev = bytes.fromhex(hdrs[0]["prev"])
        pos = 0
        for h in hdrs:
            chunk = lines[pos:pos + h["n"]]
            digest = hashlib.sha256(prev + b"".join(chunk)).digest()
            h["prev"], h["h"] = prev.hex(), digest.hex()
            prev, pos = digest, pos + h["n"]
        chain = [(json.dumps(h, separators=(",", ":")) + "\n").encode() for h in hdrs]
        return lines, chain, batch_of(i)
    raise ValueError(kind)


def main():
    keep = tempfile.mkdtemp()
    os.makedirs(os.path.join(os.path.dirname(__file__), "runs"), exist_ok=True)
    runner.run_one("s5_supplier_abuse", 4242, "integrity", keep_dir=keep)
    run = os.path.join(keep, os.listdir(keep)[0])
    with open(os.path.join(run, "complete", "gateway.jsonl"), "rb") as fh:
        lines = fh.readlines()
    work = tempfile.mkdtemp()
    lp, cp, pk = build(lines, work)
    with open(cp, "rb") as fh:
        chain = fh.readlines()
    base_ok = verify_chain(lp, cp, pk)[0]
    rng = random.Random(20260919)
    rows = []
    for kind in ("modify", "delete", "insert", "reorder", "truncate_partial", "truncate_whole_batches",
                 "forge_without_key"):
        det = loc = 0
        for _ in range(TRIALS):
            nl, nc, b = tamper(kind, lines, chain, rng)
            tl, tc = os.path.join(work, "t.jsonl"), os.path.join(work, "t.chain")
            with open(tl, "wb") as fh:
                fh.writelines(nl)
            with open(tc, "wb") as fh:
                fh.writelines(nc)
            ok, reason = verify_chain(tl, tc, pk)
            if not ok:
                det += 1
                if b is not None and reason.startswith(f"batch {b}:"):
                    loc += 1
        rows.append({"tampering": kind, "trials": TRIALS, "detected": det,
                     "localized_to_batch": loc if kind in ("modify", "delete", "insert", "reorder",
                                                            "forge_without_key") else None})
    df = pd.DataFrame(rows)
    df.attrs["clean_log_verifies"] = base_ok
    df.to_csv(os.path.join(DATA, "integrity_results.csv"), index=False)
    print("log records:", len(lines), "| batches:", len(chain), "| clean log verifies:", base_ok)
    print(df.to_string(index=False))
    shutil.rmtree(keep, ignore_errors=True)
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
