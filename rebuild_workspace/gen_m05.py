#!/usr/bin/env python3
"""M05 - Debugging the Dispatch (concurrency race + 32-bit checksum overflow).

Builds the participant package for M05 in L.out_dir("M05"):

  * dispatch_packets.json - 1200 tagged freight packets.
  * broken_dispatch.py    - multithreaded depot node whose shared counters are
                            updated non-atomically, so the sealed manifest it
                            writes to out.bin is wrong.
  * README.txt            - threading model only (no spoiler).

The intended (lock-correct) behaviour seals
    out.bin = b85encode(zlib.compress(json.dumps(manifest)))
where the manifest embeds the *source of stage 2*.  Stage 2 computes a custom
32-bit checksum whose naive form forgets the `& 0xFFFFFFFF` overflow mask; the
corrected stage-2 output is exactly L.FLAGS["M05"].

Private organizer tooling.  The flag never appears in any shipped artifact.
"""
import base64
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

HERE = Path(__file__).resolve().parent
MASK32 = 0xFFFFFFFF
MASK64 = (1 << 64) - 1
PACKET_COUNT = 1200

# The dispatch node's two shared 32-bit lane constants (stage 2).
S2_TAGS = [random.Random(0xF7A50C11).getrandbits(32) for _ in range(40)]

# ----------------------------------------------------------------------------
# Stage 2 logic.  The variant embedded in the manifest OMITS the overflow mask
# (the shipped bug); the corrected variant inserts it (the solve).
# ----------------------------------------------------------------------------
def stage2_signature(tags, masked):
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
    return h & MASK32 if masked else h


def stage2_keystream(seed, length, masked):
    h = seed
    out = bytearray()
    for _ in range(length):
        h = h * 1664525 + 1013904223
        if masked:
            h &= MASK32
        out.append(h & 0xFF)
    return bytes(out)


def build_stage2_source(flag: str) -> str:
    """Return the stage-2 script text (naive / mask-free) that the manifest
    embeds.  Running the naive form yields garbage; masking the folds fixes it."""
    flag_bytes = flag.encode()
    seed = stage2_signature(S2_TAGS, masked=True)
    ks = stage2_keystream(seed, len(flag_bytes), masked=True)
    sealed = bytes(f ^ k for f, k in zip(flag_bytes, ks))

    tags_lines = []
    for i in range(0, len(S2_TAGS), 6):
        row = ", ".join(f"0x{v:08X}" for v in S2_TAGS[i:i + 6])
        tags_lines.append("    " + row + ",")
    sealed_lines = []
    for i in range(0, len(sealed), 12):
        row = ", ".join(f"0x{b:02X}" for b in sealed[i:i + 12])
        sealed_lines.append("    " + row + ",")

    return (
        '#!/usr/bin/env python3\n'
        '"""Stage 2 - depot reconciliation.\n'
        '\n'
        'Every packet that clears the gate leaves a 32-bit tag on the lane.\n'
        'This stage folds those tags into a rolling signature and uses the\n'
        'signature to unmask the sealed manifest text.  Lane arithmetic is\n'
        '32-bit unsigned.\n'
        '"""\n'
        'import sys\n'
        '\n'
        '# 32-bit tags observed on the dispatch lane, in arrival order.\n'
        'TAGS = [\n'
        + "\n".join(tags_lines) + '\n'
        ']\n'
        '\n'
        '# Sealed manifest text, each byte masked by the rolling lane signature.\n'
        'SEALED = [\n'
        + "\n".join(sealed_lines) + '\n'
        ']\n'
        '\n'
        '\n'
        'def signature(tags):\n'
        '    h = 0x1F2E3D4C\n'
        '    for t in tags:\n'
        '        h = h + t\n'
        '        h = h * 1103515245\n'
        '        h = h ^ (h >> 15)\n'
        '        h = h * 2246822519\n'
        '        h = h ^ (h >> 13)\n'
        '    return h\n'
        '\n'
        '\n'
        'def recover(blob, seed):\n'
        '    out = bytearray()\n'
        '    h = seed\n'
        '    for b in blob:\n'
        '        h = h * 1664525 + 1013904223\n'
        '        out.append(b ^ (h & 0xFF))\n'
        '    return bytes(out)\n'
        '\n'
        '\n'
        'def main():\n'
        '    text = recover(SEALED, signature(TAGS)).decode("latin-1")\n'
        '    sys.stdout.write(text + "\\n")\n'
        '\n'
        '\n'
        'if __name__ == "__main__":\n'
        '    main()\n'
    )


# ----------------------------------------------------------------------------
# Outer seal: the dispatch result keys the manifest that carries stage 2.
# ----------------------------------------------------------------------------
def seed_from(acc: int, n: int) -> int:
    h = (acc ^ (n * 0x9E3779B97F4A7C15)) & MASK64
    h = (h * 6364136223846793005 + 1442695040888963407) & MASK64
    h ^= (h >> 29)
    return h & MASK64


def keystream(seed: int, length: int) -> bytes:
    h = seed
    out = bytearray()
    for _ in range(length):
        h = (h * 6364136223846793005 + 1442695040888963407) & MASK64
        out.append((h >> 33) & 0xFF)
    return bytes(out)


BROKEN_DISPATCH_TEMPLATE = r'''#!/usr/bin/env python3
"""Depot dispatch node - Los Santos freight relay.

Reads dispatch_packets.json, pushes every tagged packet through a pool of
worker threads, then seals an outbound manifest to out.bin.

Threading model
---------------
A single FIFO queue feeds __WORKERS__ worker threads.  The node keeps two
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
WORKER_THREADS = __WORKERS__
SEALED_MANIFEST_B64 = "__SEALED__"


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
'''

README = """DEPOT DISPATCH NODE - field manual
=================================

dispatch_packets.json
    The outbound freight log.  Every entry is one tagged packet:
        { "id": <ordinal>, "tag": <64-bit lane tag> }
    Packets are delivered to the node in file order.

broken_dispatch.py
    The depot node binary.  Run it with:

        python broken_dispatch.py

    It reads dispatch_packets.json from its own directory and writes out.bin.

Threading model
---------------
    * One FIFO queue holds every packet.
    * WORKER_THREADS worker threads each pull packets until the queue drains.
    * The node maintains two process-wide counters: the number of cleared
      packets and the ledger of cleared tags.
    * Workers share those counters; each worker applies its own update as it
      clears a packet.
    * When every worker has drained the queue the node seals a manifest and
      writes it to out.bin.

    out.bin is base85(zlib(json)) of the sealed manifest.

Reconciliation
--------------
    The sealed manifest is only meaningful when the node reports that every
    packet in the log was cleared, and that the ledger balances against the
    tags recorded on the lane.  A node that prints a short count has not
    finished the run.
"""


def main():
    out = L.out_dir("M05")
    flag = L.FLAGS["M05"]

    # --- packets ---
    rnd = random.Random(0x44515350)  # "DQSP"
    packets = [{"id": i, "tag": rnd.getrandbits(64)} for i in range(PACKET_COUNT)]
    (out / "dispatch_packets.json").write_text(
        json.dumps(packets, indent=1), encoding="utf-8")
    acc_correct = sum(p["tag"] for p in packets) & MASK64

    # --- stage 2 source + outer seal ---
    stage2_src = build_stage2_source(flag).encode("utf-8")
    outer_key = keystream(seed_from(acc_correct, PACKET_COUNT), len(stage2_src))
    sealed_manifest = bytes(a ^ b for a, b in zip(stage2_src, outer_key))
    sealed_b64 = base64.b64encode(sealed_manifest).decode()

    # --- participant-facing dispatcher ---
    broken = (BROKEN_DISPATCH_TEMPLATE
              .replace("__WORKERS__", "8")
              .replace("__SEALED__", sealed_b64))
    (out / "broken_dispatch.py").write_text(broken, encoding="utf-8")
    (out / "README.txt").write_text(README, encoding="utf-8")

    # --- self-checks (organizer side) ---
    flag_bytes = flag.encode()
    sealed2 = bytes(
        f ^ k for f, k in
        zip(flag_bytes, stage2_keystream(stage2_signature(S2_TAGS, True),
                                         len(flag_bytes), True)))
    # corrected stage-2 masks -> recovers the flag exactly
    good_seed = stage2_signature(S2_TAGS, True)
    good_ks = stage2_keystream(good_seed, len(sealed2), True)
    recovered = bytes(s ^ k for s, k in zip(sealed2, good_ks)).decode("latin-1")
    assert recovered == flag, recovered
    # naive stage-2 (masks omitted) -> recovers something else
    naive_seed = stage2_signature(S2_TAGS, False)
    naive_ks = stage2_keystream(naive_seed, len(sealed2), False)
    naive_recovered = bytes(s ^ k for s, k in zip(sealed2, naive_ks))
    assert naive_recovered != flag_bytes, "naive stage-2 must be wrong"

    # correctness sanity on the dispatcher aggregation
    assert acc_correct == sum(p["tag"] for p in packets) % (1 << 64)

    # the flag must never appear in any shipped artifact
    for name in ("broken_dispatch.py", "dispatch_packets.json", "README.txt"):
        text = (out / name).read_text(encoding="utf-8")
        assert flag not in text, name

    print("[M05] wrote %s" % out)
    print("[M05] packets=%d stage2_src_bytes=%d correct_ledger=%d"
          % (PACKET_COUNT, len(stage2_src), acc_correct))


if __name__ == "__main__":
    main()
