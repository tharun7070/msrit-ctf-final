#!/usr/bin/env python3
"""M05 reference solver - Debugging the Dispatch.

Steps
-----
1. Repair the dispatcher: reimplement the depot node with a single
   ``threading.Lock`` guarding the ENTIRE critical section (both the per-lane
   tally dict and the running ledger), so every clearance updates both shared
   structures atomically.  A lock around only one of them still loses the
   other; the correct manifest needs both exact.
2. Decode ``out.bin`` = base85(zlib(json)) and unmask the embedded stage-2
   source with the keystream keyed on the repaired (ledger, dispatched) pair.
3. Repair stage 2's TWO independent bugs:
     (a) the 32-bit rotate must mask its overflow back to 32 bits, and
     (b) the length-prefixed record must be read big-endian at offset 2
         (the shipped code reads little-endian at offset 3).
4. The repaired record payload is one more reversible layer: base64 of the
   flag bytes XORed with a fixed rotating key.
5. Assert the result equals ``L.FLAGS["M05"]`` and print ``[M05] PASS -> ...``.

Self-contained and fully deterministic.
"""
import base64
import json
import queue
import sys
import threading
import zlib
from pathlib import Path

sys.dont_write_bytecode = True  # keep the participant dir pristine (no __pycache__)

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import lib_fta as L

MASK32 = 0xFFFFFFFF
MASK64 = (1 << 64) - 1
THIRD_KEY = bytes((0x5A, 0xC3, 0x77, 0x21))
M05_DIR = L.out_dir("M05")
sys.path.insert(0, str(M05_DIR))
import broken_dispatch as bd  # noqa: E402  (participant package; main() guarded)


class FixedDispatchNode:
    """The repaired node: the whole critical section runs under one lock, so
    both the lane tallies and the ledger stay exact."""

    def __init__(self, packets, workers=8):
        self.packets = packets
        self.workers = workers
        self.lock = threading.Lock()
        self.dispatched = 0
        self.ledger = 0
        self.lanes = {}
        self.queue = queue.Queue()
        for p in packets:
            self.queue.put(p)

    def clear_packet(self, pkt):
        with self.lock:
            lane = pkt["lane"]
            self.ledger = (self.ledger + pkt["tag"]) & MASK64
            self.lanes[lane] = self.lanes.get(lane, 0) + 1
            self.dispatched += 1

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


def build_correct_out_bin():
    """Repair the dispatcher and produce the deterministic correct out.bin."""
    packets = load_packets()
    node = FixedDispatchNode(packets)
    node.run()
    assert node.dispatched == len(packets), (node.dispatched, len(packets))
    assert sum(node.lanes.values()) == len(packets)

    sealed = base64.b64decode(bd.SEALED_MANIFEST_B64)
    key = bd.keystream(bd.seed_from(node.ledger, node.dispatched), len(sealed))
    source = bytes(a ^ b for a, b in zip(sealed, key))
    manifest = {
        "manifest": "DEPOT-DISPATCH-MANIFEST",
        "dispatched": node.dispatched,
        "ledger": node.ledger,
        "lane_counts": {str(k): node.lanes[k] for k in sorted(node.lanes)},
        "stage2_b64": base64.b64encode(source).decode(),
        "notes": bd.NOTES,
    }
    return base64.b85encode(zlib.compress(json.dumps(manifest).encode()))


def extract_stage2_source(blob):
    manifest = json.loads(zlib.decompress(base64.b85decode(blob)))
    assert manifest["dispatched"] == len(load_packets()), manifest["dispatched"]
    return base64.b64decode(manifest["stage2_b64"]).decode("utf-8")


def stage2_process(tags, sealed, rot_masked=True, rec_buggy=False):
    """Reimplementation of stage 2, parametrised on which bugs remain.

    rot_masked=False  -> the 32-bit rotate overflow is not masked (bug a)
    rec_buggy=True    -> the record length is read little-endian at offset 3
                         instead of big-endian at offset 2 (bug b)

    Raises ValueError when the record trailer rejects the parsed payload.
    """
    h = 0x1BADB002
    for t in tags:
        h = (h + t) & MASK32
        if rot_masked:
            v = h & MASK32
            h = ((v << 7) | (v >> 25)) & MASK32
        else:
            h = (h << 7) | (h >> 25)
        h ^= h >> 16
        h = (h * 0x9E3779B9) & MASK32
    seed = h & MASK32

    ks = bytearray()
    for _ in range(len(sealed)):
        seed = (seed * 1103515245 + 12345) & MASK32
        ks.append((seed >> 16) & 0xFF)
    plain = bytes(a ^ b for a, b in zip(sealed, ks))

    if rec_buggy:
        n = int.from_bytes(plain[0:2], "little")
        body = plain[3:3 + n]
    else:
        n = int.from_bytes(plain[0:2], "big")
        body = plain[2:2 + n]
    trailer = int.from_bytes(plain[2 + n:6 + n], "big")
    if (sum(body) & 0xFFFF) != trailer:
        raise ValueError("reconciliation record failed its trailer check")
    return body


def third_layer_decode(payload: bytes) -> str:
    x = base64.b64decode(payload)
    fb = bytes(b ^ THIRD_KEY[i % 4] for i, b in enumerate(x))
    return fb.decode("ascii")


def verify(flag: str):
    assert flag == L.FLAGS["M05"], "wrong flag: %r" % flag
    return flag


def solve():
    blob = build_correct_out_bin()
    source = extract_stage2_source(blob)

    ns = {"__name__": "stage2_extracted"}
    exec(compile(source, "<stage2>", "exec"), ns)
    tags, sealed = ns["TAGS"], ns["SEALED"]

    # Every variant of the shipped bug (and each partial fix) is rejected.
    for rot_masked, rec_buggy, label in (
            (False, True, "shipped (both bugs)"),
            (True, True, "rotate fixed only"),
            (False, False, "record fixed only")):
        try:
            stage2_process(tags, sealed, rot_masked, rec_buggy)
        except ValueError:
            continue
        raise AssertionError("stage-2 variant accepted: %s" % label)

    payload = stage2_process(tags, sealed, rot_masked=True, rec_buggy=False)
    flag = third_layer_decode(payload)

    verify(flag)
    print("[M05] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
