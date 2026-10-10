"""Log records, the two profiles and the integrity envelope.

A component builds one *full* record. The sink projects it onto each profile and appends it to that profile's
per-layer file through a chained writer: records are grouped in batches; each batch carries the SHA-256 of
(previous batch hash + batch bytes) and an Ed25519 signature of that hash. Both profiles use the same envelope.
"""
import hashlib
import hmac
import json
import os
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from config import ABLATION_PROFILES, ACCESS_FIELDS, CFG, MINIMAL_FIELDS

_ZERO = b"\x00" * 32
LAYERS = ("gateway", "idp", "service")
_iso_cache = {}


def iso(ms: int) -> str:
    sec, milli = divmod(ms, 1000)
    base = _iso_cache.get(sec)
    if base is None:
        base = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(CFG["epoch_base"] + sec))
        _iso_cache[sec] = base
    return f"{base}.{milli:03d}Z"


def pseudo_ip(ip: str) -> str:
    return hmac.new(CFG["hmac_key"], ip.encode(), hashlib.sha256).hexdigest()[:12]


def geo_region(ip: str) -> str:
    return "r" + str(int(ip.split(".")[0]) % 7)


class ChainedWriter:
    def __init__(self, log_path, chain_path, key, batch_size):
        self.log = open(log_path, "ab")
        self.chain = open(chain_path, "ab")
        self.key = key
        self.batch_size = batch_size
        self.buf = []
        self.prev = _ZERO
        self.batch = 0
        self.records = 0

    def write(self, line: bytes):
        self.buf.append(line)
        self.records += 1
        if len(self.buf) >= self.batch_size:
            self._flush()

    def _flush(self):
        if not self.buf:
            return
        data = b"".join(self.buf)
        digest = hashlib.sha256(self.prev + data).digest()
        sig = self.key.sign(digest)
        self.log.write(data)
        header = {"b": self.batch, "n": len(self.buf), "prev": self.prev.hex(), "h": digest.hex(), "sig": sig.hex()}
        self.chain.write((json.dumps(header, separators=(",", ":")) + "\n").encode())
        self.prev = digest
        self.batch += 1
        self.buf = []

    def close(self):
        self._flush()
        self.log.close()
        self.chain.close()


def verify_chain(log_path, chain_path, public_key):
    """Return (ok, reason). Detects modification, insertion, deletion and reordering inside the chain.

    Removing the final batches (tail truncation) leaves a valid prefix and is NOT detected here; detecting it
    needs the last hash anchored outside the log store.
    """
    try:
        with open(chain_path, "rb") as fh:
            headers = [json.loads(l) for l in fh if l.strip()]
        with open(log_path, "rb") as fh:
            lines = fh.readlines()
    except Exception as exc:  # noqa: BLE001
        return False, f"unreadable: {exc}"
    prev = _ZERO
    pos = 0
    for i, h in enumerate(headers):
        if h["b"] != i:
            return False, f"batch {i}: index"
        if h["prev"] != prev.hex():
            return False, f"batch {i}: chain link"
        chunk = lines[pos:pos + h["n"]]
        if len(chunk) != h["n"]:
            return False, f"batch {i}: short"
        digest = hashlib.sha256(prev + b"".join(chunk)).digest()
        if digest.hex() != h["h"]:
            return False, f"batch {i}: hash"
        try:
            public_key.verify(bytes.fromhex(h["sig"]), digest)
        except InvalidSignature:
            return False, f"batch {i}: signature"
        prev = digest
        pos += h["n"]
    if pos != len(lines):
        return False, "extra records after the last batch"
    return True, "ok"


def _dumps(obj) -> bytes:
    return (json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


class RunSinks:
    """Writes both profiles in parallel from the same requests."""

    def __init__(self, run_dir: str, ablation: str = None, access: bool = False):
        """ablation: one of ABLATION_PROFILES keys, or None for the standard minimal+complete pair.
        access: also write the access-log baseline profile (ACCESS_FIELDS)."""
        self.key = Ed25519PrivateKey.generate()
        self.public_key = self.key.public_key()
        self.ablation = ablation
        if ablation and ablation in ABLATION_PROFILES:
            self.profiles = ("complete",)  # ablation runs only the projected complete profile
            self._drop_fields = ABLATION_PROFILES[ablation]
        else:
            self.profiles = ("minimal", "access", "complete") if access else ("minimal", "complete")
            self._drop_fields = set()
        self.writers = {}
        self.seq = {p: {layer: 0 for layer in LAYERS} for p in self.profiles}
        for p in self.profiles:
            d = os.path.join(run_dir, p)
            os.makedirs(d, exist_ok=True)
            for layer in LAYERS:
                self.writers[(p, layer)] = ChainedWriter(
                    os.path.join(d, f"{layer}.jsonl"), os.path.join(d, f"{layer}.chain"), self.key, CFG["batch_size"])
        self.run_dir = run_dir
        # evaluation-only side channel (never written to the logs): trace -> profile -> covered?
        self.coverage = {}

    def emit(self, layer: str, rec: dict, scope: str = "both", trace=None, attack=False):
        """rec is the full record. scope 'complete' means the minimal profile does not write it."""
        full = {k: v for k, v in rec.items() if v is not None and not k.startswith("_")}
        extra = {"path": rec["_path"]} if rec.get("_path") else {}
        for p in self.profiles:
            if p == "minimal":
                if scope == "complete":
                    continue
                out = {k: full[k] for k in MINIMAL_FIELDS if k in full}
            elif p == "access":
                if scope == "complete":
                    continue
                src = dict(full, **extra)
                out = {k: src[k] for k in ACCESS_FIELDS if k in src}
            else:
                self.seq[p][layer] += 1
                n = self.seq[p][layer]
                out = {"event_id": f"{layer[:3]}-{n}", "seq": n}
                out.update({k: v for k, v in full.items() if k not in self._drop_fields})
            if layer == "gateway" and attack and scope == "both":
                # covered when the profile keeps every non-null field of the complete record
                self.coverage.setdefault(trace, {})[p] = set(full) <= set(out)
            self.writers[(p, layer)].write(_dumps(out))

    def close(self):
        for w in self.writers.values():
            w.close()

    def sizes(self):
        """Bytes per profile and layer: logs and custody overhead (chain files)."""
        out = {}
        for p in self.profiles:
            for layer in LAYERS:
                d = os.path.join(self.run_dir, p)
                out[(p, layer, "log")] = os.path.getsize(os.path.join(d, f"{layer}.jsonl"))
                out[(p, layer, "chain")] = os.path.getsize(os.path.join(d, f"{layer}.chain"))
        return out
