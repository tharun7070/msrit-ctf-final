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
        workers = [threading.Thread(target=self._worker)
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
