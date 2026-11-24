#!/usr/bin/env python3
"""Depot dispatch node - Los Santos freight relay.

Reads dispatch_packets.json, pushes every tagged packet through a pool of
worker threads, then seals an outbound manifest to out.bin.

Threading model
---------------
A single FIFO queue feeds 8 worker threads.  The node keeps two
shared process-wide structures: a per-lane tally of cleared packets and a
running ledger of cleared lane tags.  Each worker updates both as it clears a
packet; when every worker has drained the queue the node seals its manifest
and writes out.bin.
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
SEALED_MANIFEST_B64 = "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"
NOTES = "FTA{v01d_s3gm3nt_n0t_d15p4tch3d}"


def seed_from(acc, n):
    h = (acc ^ (n * 0x9E3779B97F4A7C15)) & MASK64
    h = (h * 6364136223846793005 + 1442695040888963407) & MASK64
    h ^= (h >> 29)
    return h & MASK64


def keystream(seed, length):
    h = seed
    out = bytearray()
    for _ in range(length):
        h = (h * 6364136223846793005 + 1442695040888963407) & MASK64
        out.append((h >> 33) & 0xFF)
    return bytes(out)


class DispatchNode:
    def __init__(self, packets):
        self.packets = packets
        self.ledger = 0
        self.lanes = {}
        self.trace = []
        self.queue = queue.Queue()
        for p in packets:
            self.queue.put(p)

    def publish(self, lane, pkt):
        # depot trace: note the clearance on the shared dispatch log
        self.trace.append((lane, pkt["id"]))

    def clear_packet(self, pkt):
        # snapshot both shared structures, publish the clearance, then commit
        lane = pkt["lane"]
        seen = self.lanes.get(lane, 0)
        acc = self.ledger
        self.publish(lane, pkt)
        self.ledger = (acc + pkt["tag"]) & MASK64
        self.lanes[lane] = seen + 1

    def _worker(self):
        while True:
            try:
                pkt = self.queue.get_nowait()
            except queue.Empty:
                return
            self.clear_packet(pkt)

    def run(self):
        # release every worker at once so the whole pool contends for the queue
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
        sealed = base64.b64decode(SEALED_MANIFEST_B64)
        key = keystream(seed_from(self.ledger, self.dispatched()), len(sealed))
        source = bytes(a ^ b for a, b in zip(sealed, key))
        return {
            "manifest": "DEPOT-DISPATCH-MANIFEST",
            "dispatched": self.dispatched(),
            "ledger": self.ledger,
            "lane_counts": {str(k): self.lanes[k] for k in sorted(self.lanes)},
            "stage2_b64": base64.b64encode(source).decode(),
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
    print("[depot] dispatched=%d ledger=%d -> out.bin (%d bytes)"
          % (manifest["dispatched"], manifest["ledger"], len(blob)))


if __name__ == "__main__":
    main()
