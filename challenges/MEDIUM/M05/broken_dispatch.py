#!/usr/bin/env python3
"""Depot dispatch node - Los Santos freight relay.

Reads dispatch_packets.json, pushes every tagged packet through a pool of
worker threads, then seals an outbound manifest to out.bin.

Threading model
---------------
A single FIFO queue feeds 8 worker threads.  The node keeps THREE
shared process-wide structures: a per-lane tally of cleared packets, a running
64-bit ledger of cleared lane tags, and a running 64-bit mix (a hashed tally of
the cleared tags).  Each worker updates all three as it clears a packet; when
every worker has drained the queue the node seals its manifest and writes
out.bin.
"""
import base64
import json
import queue
import sys
import threading
import zlib
from pathlib import Path

sys.setswitchinterval(1e-6)

MASK64 = (1 << 64) - 1
WORKER_THREADS = 8
SEALED_STAGE2_B64 = "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"
SEALED_ASSEMBLE_B64 = "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"
NOTES = "FTA{v01d_s3gm3nt_n0t_d15p4tch3d}"


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


def keystream(seed, length):
    h = seed & MASK64
    out = bytearray()
    for _ in range(length):
        h = (h * 6364136223846793005 + 1442695040888963407) & MASK64
        out.append((h >> 33) & 0xFF)
    return bytes(out)


class DispatchNode:
    def __init__(self, packets):
        self.packets = packets
        self.ledger = 0
        self.mix = 0x123456789ABCDEF0
        self.lanes = {}
        self.trace = []
        self.queue = queue.Queue()
        for p in packets:
            self.queue.put(p)

    def publish(self, lane, pkt):
        # depot trace: note the clearance on the shared dispatch log
        self.trace.append((lane, pkt["id"]))

    def clear_packet(self, pkt):
        # snapshot all three shared structures, publish, then commit
        lane = pkt["lane"]
        seen = self.lanes.get(lane, 0)
        acc = self.ledger
        mx = self.mix
        self.publish(lane, pkt)
        self.ledger = (acc + pkt["tag"]) & MASK64
        self.mix = (mx + splitmix64(pkt["tag"])) & MASK64
        self.lanes[lane] = seen + 1

    def _worker(self):
        while True:
            try:
                pkt = self.queue.get_nowait()
            except queue.Empty:
                return
            self.clear_packet(pkt)

    def run(self):
        gate = threading.Barrier(WORKER_THREADS)

        def worker():
            gate.wait()
            self._worker()

        workers = [threading.Thread(target=worker)
                   for _ in range(WORKER_THREADS)]
        for w in workers:
            w.start()
        for w in workers:
            w.join()

    def dispatched(self):
        return sum(self.lanes.values())

    def seal(self):
        d = seal_digest(self.ledger, self.mix, self.dispatched())
        s2 = base64.b64decode(SEALED_STAGE2_B64)
        s2 = bytes(a ^ b for a, b in zip(s2, keystream(d, len(s2))))
        asm = base64.b64decode(SEALED_ASSEMBLE_B64)
        asm = bytes(a ^ b for a, b in zip(asm, keystream(d, len(asm))))
        return {
            "manifest": "DEPOT-DISPATCH-MANIFEST",
            "dispatched": self.dispatched(),
            "ledger": self.ledger,
            "mix": self.mix,
            "lane_counts": {str(k): self.lanes[k] for k in sorted(self.lanes)},
            "stage2_b64": base64.b64encode(s2).decode(),
            "assemble_b64": base64.b64encode(asm).decode(),
            "notes": NOTES,
        }


def main():
    here = Path(__file__).resolve().parent
    packets = json.loads((here / "dispatch_packets.json").read_text(encoding="utf-8"))
    node = DispatchNode(packets)
    node.run()
    manifest = node.seal()
    blob = base64.b85encode(zlib.compress(json.dumps(manifest).encode()))
    (here / "out.bin").write_bytes(blob)
    print("[depot] dispatched=%d ledger=%d mix=%d -> out.bin (%d bytes)"
          % (manifest["dispatched"], manifest["ledger"], manifest["mix"], len(blob)))


if __name__ == "__main__":
    main()
