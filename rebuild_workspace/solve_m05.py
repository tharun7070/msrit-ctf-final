#!/usr/bin/env python3
"""M05 reference solver - Debugging the Dispatch.

Peel order
----------
1. Repair the dispatcher: run the depot node with ONE lock guarding the ENTIRE
   critical section (the per-lane tally dict, the running ledger AND the running
   mix), so every clearance updates all three shared structures atomically.  A
   lock around only some of them still loses the others; the correct seal needs
   all three exact.
2. Decode ``out.bin`` / rebuild the sealed manifest: unmask BOTH embedded
   programs (stage2 and assemble) with the keystream keyed on the digest of the
   repaired (ledger, mix, dispatched) triple.
3. Repair stage 2's FOUR independent bugs:
     (a) the 32-bit rotate must mask its overflow back to 32 bits;
     (b) the length-prefixed record must be read big-endian at offset 2 (the
         shipped code reads little-endian at offset 3);
     (c) the trailer must be read at ``2 + n`` -- the shipped code adds a
         spurious byte whenever ``n`` is a multiple of 4, which every base64
         payload is, so a fix of (a)+(b) alone still trips the trailer check;
     (d) lane 1 must CONTINUE the signature produced by lane 0, but the shipped
         ``signature`` reseeds from the constant every call -- so a single run
         (lane 0) is fine and only the SECOND run is corrupt.
4. XOR the two lane payloads (the "two runs combined"), then ungated with the
   key derived from the sealed (ledger, mix, dispatched) triple.
5. Peel the extra final wrap (keyed on the same derived value), then the outer
   rotating-key base64 wrap, then the stage-3 stream (run-length collapse +
   per-index rotating XOR) to recover the flag bytes.

Traps avoided:
  * the shipped stage-2 falls through to ARCHIVED_VALUE plus a base64 blob that
    decodes to a well-formed DECOY flag -- any partial fix lands here;
  * running stage 2 without repairing bug (d) yields a wrong lane-1 payload and
    therefore structurally valid garbage after the combine;
  * recovery_note.txt advertises a wrong method (archived seed, single pass, OR)
    and carries another decoy flag.

Deterministic.
"""
import base64
import json
import queue
import sys
import threading
import zlib
from pathlib import Path

sys.dont_write_bytecode = True  # keep the participant dir pristine

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import lib_fta as L

MASK32 = 0xFFFFFFFF
MASK64 = (1 << 64) - 1
THIRD_KEY = bytes((0x5A, 0xC3, 0x77, 0x21))  # outer fixed rotating key
ROT_SEED = 0x9E3779B9                         # stage-3 rotating-XOR seed
MIX_SEED = 0x123456789ABCDEF0

M05_DIR = L.out_dir("M05")
sys.path.insert(0, str(M05_DIR))
import broken_dispatch as bd  # noqa: E402  (participant package; main() guarded)


# ---------------------------------------------------------------------------
# Primitive reimplementations (the corrected variants).
# ---------------------------------------------------------------------------
def splitmix64(x):
    x &= MASK64
    x = (x + 0x9E3779B97F4A7C15) & MASK64
    x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & MASK64
    return (x ^ (x >> 31)) & MASK64


def seal_digest(ledger, mix, dispatched):
    h = ledger & MASK64
    h ^= splitmix64((mix & MASK64) ^ 0xA5A5A5A5A5A5A5A5)
    h ^= splitmix64((dispatched & MASK64) ^ 0x5A5A5A5A5A5A5A5A)
    return splitmix64(h)


def derive_key(ledger, mix, dispatched):
    return splitmix64(seal_digest(ledger, mix, dispatched) ^ 0x0D15A7C4C0DE0000)


def ks64(seed, length):
    h = seed & MASK64
    out = bytearray()
    for _ in range(length):
        h = (h * 6364136223846793005 + 1442695040888963407) & MASK64
        out.append((h >> 33) & 0xFF)
    return bytes(out)


def dstream(seed, length):
    h = seed & MASK32
    out = bytearray()
    for _ in range(length):
        h = (h * 1664525 + 1013904223) & MASK32
        out.append((h >> 24) & 0xFF)
    return bytes(out)


def gate(data, key):
    ks = dstream(key ^ 0x61E7A11, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


def extra_unwrap(data, key):
    ks = dstream(key ^ 0xE47A5EED, len(data))
    out = bytearray(b ^ k for b, k in zip(data, ks))
    s = key & 0x7
    if s:
        out = out[-s:] + out[:-s]
    return bytes(out)


def rotl32(x, r, masked=True):
    if masked:
        x &= MASK32
    v = (x << r) | (x >> (32 - r))
    return v & MASK32 if masked else v


def fold(tags, start, masked=True):
    h = start
    for t in tags:
        h = (h + t) & MASK32
        h = rotl32(h, 7, masked)
        h ^= h >> 16
        h = (h * 0x9E3779B9) & MASK32
    return h & MASK32


def ks32(seed, length):
    h = seed & MASK32
    out = bytearray()
    for _ in range(length):
        h = (h * 1103515245 + 12345) & MASK32
        out.append((h >> 16) & 0xFF)
    return bytes(out)


def wrap_decode(payload):
    x = base64.b64decode(payload)
    return bytes(b ^ THIRD_KEY[i % 4] for i, b in enumerate(x))


def stage3_decode(data):
    rot = ROT_SEED
    expanded = bytearray(len(data))
    for k, b in enumerate(data):
        rot = ((rot << 1) | (rot >> 31)) & MASK32
        expanded[k] = b ^ ((rot >> 7) & 0xFF)
    fb = bytearray()
    k = 0
    while k < len(expanded):
        fb.extend([expanded[k]] * expanded[k + 1])
        k += 2
    return bytes(fb)


# ---------------------------------------------------------------------------
# The repaired node: one lock guarding all three shared structures.
# ---------------------------------------------------------------------------
class FixedDispatchNode:
    def __init__(self, packets, workers=8):
        self.packets = packets
        self.workers = workers
        self.lock = threading.Lock()
        self.ledger = 0
        self.mix = MIX_SEED
        self.lanes = {}
        self.queue = queue.Queue()
        for p in packets:
            self.queue.put(p)

    def clear_packet(self, pkt):
        with self.lock:
            lane = pkt["lane"]
            self.ledger = (self.ledger + pkt["tag"]) & MASK64
            self.mix = (self.mix + splitmix64(pkt["tag"])) & MASK64
            self.lanes[lane] = self.lanes.get(lane, 0) + 1

    def _worker(self):
        while True:
            try:
                pkt = self.queue.get_nowait()
            except queue.Empty:
                return
            self.clear_packet(pkt)

    def run(self):
        workers = [threading.Thread(target=self._worker)
                   for _ in range(self.workers)]
        for w in workers:
            w.start()
        for w in workers:
            w.join()


def load_packets():
    return json.loads((M05_DIR / "dispatch_packets.json").read_text(encoding="utf-8"))


def correct_triple():
    """Run the repaired node and cross-check against a direct sequential fold."""
    packets = load_packets()
    node = FixedDispatchNode(packets)
    node.run()
    assert sum(node.lanes.values()) == len(packets)
    assert node.ledger == sum(p["tag"] for p in packets) & MASK64
    m = MIX_SEED
    for p in packets:
        m = (m + splitmix64(p["tag"])) & MASK64
    assert node.mix == m
    return node.ledger, node.mix, len(packets)


def unmask_programs():
    ledger, mix, dispatched = correct_triple()
    digest = seal_digest(ledger, mix, dispatched)
    s2 = bytes(a ^ b for a, b in
               zip(base64.b64decode(bd.SEALED_STAGE2_B64),
                   bd.keystream(digest, len(base64.b64decode(bd.SEALED_STAGE2_B64)))))
    asm = bytes(a ^ b for a, b in
                zip(base64.b64decode(bd.SEALED_ASSEMBLE_B64),
                    bd.keystream(digest, len(base64.b64decode(bd.SEALED_ASSEMBLE_B64)))))
    return (ledger, mix, dispatched), s2.decode("utf-8"), asm.decode("utf-8")


# ---------------------------------------------------------------------------
# Stage 2, parametrised on which bugs remain (for the trap checks).
# ---------------------------------------------------------------------------
def stage2_lane(tags, sealed, salt, *, rot_masked=True, rec_buggy=False,
                align_buggy=False, start=0x1BADB002):
    h = fold(tags, start, rot_masked)
    plain = bytes(a ^ b for a, b in zip(sealed, ks32(h ^ salt, len(sealed))))
    n = (int.from_bytes(plain[0:2], "little") if rec_buggy
         else int.from_bytes(plain[0:2], "big"))
    body = plain[3:3 + n] if rec_buggy else plain[2:2 + n]
    span = n + 1 if (align_buggy and (n & 3) == 0) else n
    trailer = int.from_bytes(plain[2 + span:6 + span], "big")
    if (sum(body) & 0xFFFF) != trailer:
        raise ValueError("reconciliation record failed its trailer check")
    return body


def recover():
    """Repair everything up to (but not including) the final assemble peel."""
    (ledger, mix, dispatched), s2_src, asm_src = unmask_programs()
    assert "def signature" in s2_src and "def extract_record" in s2_src

    ns = {"__name__": "stage2_extracted"}
    exec(compile(s2_src, "<stage2>", "exec"), ns)
    tags = ns["TAGS"]

    # Correct repair: mask the rotate (a), big-endian @2 (b), trailer @2+n (c)
    # and CONTINUE the signature across lanes (d).
    h0 = fold(tags, 0x1BADB002, True)
    R0 = stage2_lane(tags, ns["SEALED0"], ns["SALT0"], start=0x1BADB002)
    R1 = stage2_lane(tags, ns["SEALED1"], ns["SALT1"], start=h0)
    key = derive_key(ledger, mix, dispatched)
    return {"ledger": ledger, "mix": mix, "dispatched": dispatched,
            "stage2_src": s2_src, "assemble_src": asm_src, "ns": ns,
            "R0": R0, "R1": R1, "key": key}


def assemble_peel(R0, R1, key):
    """Combine the two runs, ungate, then peel the extra wrap and below."""
    dispatch = bytes(a ^ b for a, b in zip(R0, R1))
    inner = gate(dispatch, key)
    wrapped = extra_unwrap(inner, key)
    return stage3_decode(wrap_decode(wrapped))


def solve():
    r = recover()
    ns = r["ns"]
    tags = ns["TAGS"]

    # Trap 1: the shipped stage-2 advertises a decoy plus a reward blob that
    # decodes to a well-formed (fake) flag.  Both are dead ends.
    decoy = ns["ARCHIVED_VALUE"]
    reward = base64.b64decode(ns["ARCHIVED_REWARD_B64"]).decode("ascii")
    assert decoy.startswith("FTA{") and reward.startswith("FTA{")
    assert decoy != L.FLAGS["M05"] and reward != L.FLAGS["M05"]

    # Trap 2: without repairing bug (d) lane 1 reseeds from the constant (no
    # chain), so the combined result is structurally valid garbage, never the
    # flag.
    try:
        bad = stage2_lane(tags, ns["SEALED1"], ns["SALT1"], start=0x1BADB002)
        badflag = assemble_peel(r["R0"], bad, r["key"])
    except Exception:
        badflag = None
    assert badflag != L.FLAGS["M05"].encode(), "unchained lane-1 yielded the flag"

    flag = assemble_peel(r["R0"], r["R1"], r["key"]).decode("ascii")
    verify(flag)
    print("[M05] PASS ->", flag)
    return flag


def verify(flag):
    assert flag == L.FLAGS["M05"], "wrong flag: %r" % flag
    return flag


if __name__ == "__main__":
    solve()
