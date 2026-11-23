#!/usr/bin/env python3
"""Depot dispatch node - Los Santos freight relay.

Reads dispatch_packets.json, pushes every tagged packet through a pool of
worker threads, then seals an outbound manifest to out.bin.

Threading model
---------------
A single FIFO queue feeds 8 worker threads.  The node keeps two
shared process-wide counters: the number of packets cleared and the running
ledger of packet tags.  Each worker updates both counters as it clears a
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
        self.dispatched = 0
        self.ledger = 0
        self.trace = []
        self.queue = queue.Queue()
        for p in packets:
            self.queue.put(p)

    def publish(self, seq, pkt):
        # depot trace: note the clearance on the shared dispatch log
        self.trace.append((seq, pkt["id"]))

    def clear_packet(self, pkt):
        # snapshot the node counters, publish the clearance, then commit
        seq = self.dispatched
        acc = self.ledger
        self.publish(seq, pkt)
        self.ledger = (acc + pkt["tag"]) & MASK64
        self.dispatched = seq + 1

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

    def seal(self):
        sealed = base64.b64decode(SEALED_MANIFEST_B64)
        key = keystream(seed_from(self.ledger, self.dispatched), len(sealed))
        source = bytes(a ^ b for a, b in zip(sealed, key))
        return {
            "manifest": "DEPOT-DISPATCH-MANIFEST",
            "dispatched": self.dispatched,
            "ledger": self.ledger,
            "stage2_b64": base64.b64encode(source).decode(),
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
          % (node.dispatched, node.ledger, len(blob)))


if __name__ == "__main__":
    main()
