#!/usr/bin/env python3
"""M05 reference solver - Debugging the Dispatch.

Steps
-----
1. Repair the dispatcher: reimplement the depot node with a ``threading.Lock``
   so the shared counters update atomically, producing the deterministic
   sealed manifest.  (Equivalently the correct ledger is the modular sum of
   every packet tag.)
2. Decode ``out.bin`` = base85(zlib(json)) and unmask the embedded stage-2
   source.
3. Run the stage-2 checksum with the EXPLICIT 32-bit overflow masks
   (``& 0xFFFFFFFF``) that the shipped code omits.
4. Assert the result equals ``L.FLAGS["M05"]`` and print ``[M05] PASS -> ...``.

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
M05_DIR = L.out_dir("M05")
sys.path.insert(0, str(M05_DIR))
import broken_dispatch as bd  # noqa: E402  (participant package; main() guarded)


class FixedDispatchNode:
    """The repaired node: every shared-counter update happens under a lock."""

    def __init__(self, packets, workers=8):
        self.packets = packets
        self.workers = workers
        self.lock = threading.Lock()
        self.dispatched = 0
        self.ledger = 0
        self.queue = queue.Queue()
        for p in packets:
            self.queue.put(p)

    def clear_packet(self, pkt):
        with self.lock:
            self.ledger = (self.ledger + pkt["tag"]) & MASK64
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

    sealed = base64.b64decode(bd.SEALED_MANIFEST_B64)
    key = bd.keystream(bd.seed_from(node.ledger, node.dispatched), len(sealed))
    source = bytes(a ^ b for a, b in zip(sealed, key))
    manifest = {
        "manifest": "DEPOT-DISPATCH-MANIFEST",
        "dispatched": node.dispatched,
        "ledger": node.ledger,
        "stage2_b64": base64.b64encode(source).decode(),
    }
    return base64.b85encode(zlib.compress(json.dumps(manifest).encode()))


def extract_stage2_source(blob):
    manifest = json.loads(zlib.decompress(base64.b85decode(blob)))
    assert manifest["dispatched"] == len(load_packets()), manifest["dispatched"]
    return base64.b64decode(manifest["stage2_b64"]).decode("utf-8")


def run_stage2(source, masked=True):
    """Execute the extracted stage-2 script; fold with (or without) the
    32-bit overflow mask.  Returns the recovered manifest text."""
    ns = {"__name__": "stage2_extracted"}
    exec(compile(source, "<stage2>", "exec"), ns)
    tags, sealed = ns["TAGS"], ns["SEALED"]

    h = 0x1F2E3D4C
    for t in tags:
        h = h + t
        h = h * 1103515245
        if masked:
            h &= MASK32
        h = h ^ (h >> 15)
        h = h * 2246822519
        if masked:
            h &= MASK32
        h = h ^ (h >> 13)
    seed = h & MASK32 if masked else h

    out = bytearray()
    for b in sealed:
        seed = seed * 1664525 + 1013904223
        if masked:
            seed &= MASK32
        out.append(b ^ (seed & 0xFF))
    return bytes(out).decode("latin-1")


def verify(flag: str):
    assert flag == L.FLAGS["M05"], "wrong flag: %r" % flag
    return flag


def solve():
    blob = build_correct_out_bin()
    source = extract_stage2_source(blob)

    # The shipped stage-2 omits the masks -> wrong text; masking fixes it.
    assert run_stage2(source, masked=False) != L.FLAGS["M05"], "stage-2 not buggy"
    flag = run_stage2(source, masked=True)

    verify(flag)
    print("[M05] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
