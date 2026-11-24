#!/usr/bin/env python3
"""M05 - Debugging the Dispatch (stacked concurrency + multi-bug stage 2).

Builds the participant package for M05 in L.out_dir("M05"):

  * dispatch_packets.json - 1200 tagged freight packets.
  * broken_dispatch.py    - multithreaded depot node.  It clears packets across
                            a worker pool that updates TWO shared structures
                            (a per-lane tally dict and a running ledger) with a
                            non-atomic read-modify-write, so the sealed manifest
                            it writes to out.bin is wrong.
  * README.txt            - intended data flow only (no spoiler).

The intended (correct) behaviour seals

    out.bin = b85encode(zlib.compress(json.dumps(manifest)))

where the manifest carries the *source of stage 2* masked by a keystream keyed
on the node's final (ledger, dispatched) pair.  Stage 2 has TWO independent,
non-obvious bugs:

  (a) a fixed-width 32-bit rotate whose overflow mask is missing, and
  (b) a length-prefixed record parsed with the wrong endianness and an
      off-by-one field offset.

Fixing both lets stage 2 emit an outer payload that is itself one more
reversible layer (a base64 of the flag bytes XORed with a fixed key).  A
partial fix instead trips the record's trailer check and falls back to an
archived DECOY flag.

Private organizer tooling.  The flag never appears in any shipped artifact.
"""
import base64
import json
import random
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

HERE = Path(__file__).resolve().parent
MASK32 = 0xFFFFFFFF
MASK64 = (1 << 64) - 1
PACKET_COUNT = 1200
WORKER_THREADS = 8

# Fixed stage-2 lane tags and record geometry.
S2_TAGS = [random.Random(0xF7A50C11).getrandbits(32) for _ in range(40)]
RECORD_LEN = 96

# Third (outer) layer: fixed rotating key over the flag bytes, then base64.
THIRD_KEY = bytes((0x5A, 0xC3, 0x77, 0x21))

# Decoys: a plausible wrong flag reachable by a partial fix / a shallow grep.
DECOY_ARCHIVED = "FTA{d15p4tch_l3g4cy_p4th_d3c0y}"
DECOY_NOTES = "FTA{v01d_s3gm3nt_n0t_d15p4tch3d}"

# ----------------------------------------------------------------------------
# Stage 2 logic.  The variant embedded in the manifest omits the 32-bit rotate
# mask and mis-frames the record (the shipped bugs); the corrected variant
# restores both (the solve).
# ----------------------------------------------------------------------------
def _rotl32(x: int, r: int, masked: bool) -> int:
    if masked:
        x &= MASK32
    v = (x << r) | (x >> (32 - r))
    return v & MASK32 if masked else v


def s2_signature(tags, masked: bool) -> int:
    h = 0x1BADB002
    for t in tags:
        h = (h + t) & MASK32
        h = _rotl32(h, 7, masked)
        h ^= h >> 16
        h = (h * 0x9E3779B9) & MASK32
    return h & MASK32


def s2_keystream(seed: int, length: int) -> bytes:
    h = seed & MASK32
    out = bytearray()
    for _ in range(length):
        h = (h * 1103515245 + 12345) & MASK32
        out.append((h >> 16) & 0xFF)
    return bytes(out)


def s2_process(tags, sealed, rot_masked: bool, rec_buggy: bool) -> bytes:
    """Reimplementation of the shipped stage-2 program, parametrised on which
    bugs are present.  Raises ValueError when the record trailer rejects."""
    h = 0x1BADB002
    for t in tags:
        h = (h + t) & MASK32
        h = _rotl32(h, 7, rot_masked)
        h ^= h >> 16
        h = (h * 0x9E3779B9) & MASK32
    seed = h & MASK32
    ks = s2_keystream(seed, len(sealed))
    plain = bytes(a ^ b for a, b in zip(sealed, ks))
    if rec_buggy:
        n = int.from_bytes(plain[0:2], "little")   # wrong endianness
        body = plain[3:3 + n]                       # off-by-one offset
    else:
        n = int.from_bytes(plain[0:2], "big")
        body = plain[2:2 + n]
    trailer = int.from_bytes(plain[2 + n:6 + n], "big")
    if (sum(body) & 0xFFFF) != trailer:
        raise ValueError("reconciliation record failed its trailer check")
    return body


# ----------------------------------------------------------------------------
# Third (outer) layer.
# ----------------------------------------------------------------------------
def third_layer_encode(flag: str) -> bytes:
    fb = flag.encode()
    x = bytes(b ^ THIRD_KEY[i % 4] for i, b in enumerate(fb))
    return base64.b64encode(x)


def third_layer_decode(payload: bytes) -> str:
    x = base64.b64decode(payload)
    fb = bytes(b ^ THIRD_KEY[i % 4] for i, b in enumerate(x))
    return fb.decode("ascii")


# ----------------------------------------------------------------------------
# Record framing (what stage 2 unmasks): [>u16 length][payload][>u32 trailer]
# followed by zero padding to RECORD_LEN.
# ----------------------------------------------------------------------------
def build_record(payload: bytes) -> bytes:
    lb = len(payload)
    assert lb < 0x10000
    plain = bytearray(RECORD_LEN)
    plain[0:2] = struct.pack(">H", lb)
    plain[2:2 + lb] = payload
    plain[2 + lb:6 + lb] = struct.pack(">I", sum(payload) & 0xFFFF)
    return bytes(plain)


def build_stage2_source() -> str:
    """Return the stage-2 script text (buggy / shipped variant)."""
    payload = third_layer_encode(L.FLAGS["M05"])
    plain = build_record(payload)
    ks = s2_keystream(s2_signature(S2_TAGS, masked=True), len(plain))
    sealed = bytes(a ^ b for a, b in zip(plain, ks))

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
        'The dispatch node folds the lane tags below into a rolling 32-bit\n'
        'signature.  That signature keys a keystream which unmasks the sealed\n'
        'reconciliation record; the record is length-prefixed and carries a\n'
        'trailer that must agree with its payload, and the recovered payload is\n'
        'handed on unchanged.  Lane arithmetic is 32-bit unsigned.\n'
        '"""\n'
        'import sys\n'
        '\n'
        'MASK = 0xFFFFFFFF\n'
        '\n'
        '# Lane tags observed on the dispatch lane, in arrival order.\n'
        'TAGS = [\n'
        + "\n".join(tags_lines) + '\n'
        ']\n'
        '\n'
        '# Sealed reconciliation record, masked with the signature keystream.\n'
        'SEALED = [\n'
        + "\n".join(sealed_lines) + '\n'
        ']\n'
        '\n'
        '# Archived value from a retired build.  Reference only -- the current\n'
        '# record supersedes it on every clean run.\n'
        'ARCHIVED_VALUE = ' + repr(DECOY_ARCHIVED) + '\n'
        '\n'
        '\n'
        'def rotl32(x, r):\n'
        '    return (x << r) | (x >> (32 - r))\n'
        '\n'
        '\n'
        'def signature(tags):\n'
        '    h = 0x1BADB002\n'
        '    for t in tags:\n'
        '        h = (h + t) & MASK\n'
        '        h = rotl32(h, 7)\n'
        '        h ^= h >> 16\n'
        '        h = (h * 0x9E3779B9) & MASK\n'
        '    return h & MASK\n'
        '\n'
        '\n'
        'def keystream(seed, length):\n'
        '    h = seed & MASK\n'
        '    out = bytearray()\n'
        '    for _ in range(length):\n'
        '        h = (h * 1103515245 + 12345) & MASK\n'
        '        out.append((h >> 16) & 0xFF)\n'
        '    return bytes(out)\n'
        '\n'
        '\n'
        'def extract_record(plain):\n'
        '    n = int.from_bytes(plain[0:2], "little")\n'
        '    body = plain[3:3 + n]\n'
        '    trailer = int.from_bytes(plain[2 + n:6 + n], "big")\n'
        '    if (sum(body) & 0xFFFF) != trailer:\n'
        '        raise ValueError("reconciliation record failed its trailer check")\n'
        '    return body\n'
        '\n'
        '\n'
        'def main():\n'
        '    try:\n'
        '        seed = signature(TAGS)\n'
        '        ks = keystream(seed, len(SEALED))\n'
        '        plain = bytes(a ^ b for a, b in zip(SEALED, ks))\n'
        '        payload = extract_record(plain)\n'
        '    except ValueError:\n'
        '        sys.stdout.write(ARCHIVED_VALUE + "\\n")\n'
        '        return\n'
        '    sys.stdout.write(payload.decode("ascii") + "\\n")\n'
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
WORKER_THREADS = __WORKERS__
SEALED_MANIFEST_B64 = "__SEALED__"
NOTES = "__NOTES__"


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
'''

README = """DEPOT DISPATCH NODE - field manual
=================================

dispatch_packets.json
    The outbound freight log.  Every entry is one tagged packet:
        { "id": <ordinal>, "tag": <64-bit lane tag>, "lane": <lane index> }
    Packets are delivered to the node in file order.

broken_dispatch.py
    The depot node binary.  Run it with:

        python broken_dispatch.py

    It reads dispatch_packets.json from its own directory and writes out.bin.

Threading model
---------------
    * One FIFO queue holds every packet.
    * WORKER_THREADS worker threads each pull packets until the queue drains.
    * The node maintains two shared process-wide structures: a per-lane tally
      of cleared packets, and a running ledger of the cleared lane tags.
    * Every worker touches both structures as it clears a packet.
    * When every worker has drained the queue the node seals a manifest: the
      reported dispatch count is the sum of the lane tallies, and the ledger is
      the tagged total.  It writes that manifest to out.bin.

    out.bin is base85(zlib(json)) of the sealed manifest.  The manifest carries
    a stage-2 program masked by a keystream keyed on the node's final
    (ledger, dispatched) pair.

Reconciliation
--------------
    A clean run must clear every packet in the log exactly once: the tally
    totals and the ledger both have to balance against the freight on the lane.
    Numbers that drift between runs, or a run whose totals fall short of the
    log, are signs that the node has not finished the dispatch.

    The stage-2 program is not the answer.  It unmasks one further record whose
    trailer must agree with its own payload; the payload that survives is still
    wrapped exactly once more.
"""


def main():
    out = L.out_dir("M05")
    flag = L.FLAGS["M05"]

    # --- packets ---
    rnd = random.Random(0x44515350)  # "DQSP"
    packets = [{"id": i,
                "tag": rnd.getrandbits(64),
                "lane": rnd.randrange(8)} for i in range(PACKET_COUNT)]
    (out / "dispatch_packets.json").write_text(
        json.dumps(packets, indent=1), encoding="utf-8")
    acc_correct = sum(p["tag"] for p in packets) & MASK64

    # --- stage 2 source + outer seal ---
    stage2_src = build_stage2_source().encode("utf-8")
    outer_key = keystream(seed_from(acc_correct, PACKET_COUNT), len(stage2_src))
    sealed_manifest = bytes(a ^ b for a, b in zip(stage2_src, outer_key))
    sealed_b64 = base64.b64encode(sealed_manifest).decode()

    # --- participant-facing dispatcher ---
    broken = (BROKEN_DISPATCH_TEMPLATE
              .replace("__WORKERS__", str(WORKER_THREADS))
              .replace("__SEALED__", sealed_b64)
              .replace("__NOTES__", DECOY_NOTES))
    (out / "broken_dispatch.py").write_text(broken, encoding="utf-8")
    (out / "README.txt").write_text(README, encoding="utf-8")

    # --- organizer self-checks -------------------------------------------------
    # (1) the corrected stage-2 recovers the outer payload, which decodes to flag
    payload = third_layer_encode(flag)
    plain = build_record(payload)
    ks = s2_keystream(s2_signature(S2_TAGS, True), len(plain))
    sealed = bytes(a ^ b for a, b in zip(plain, ks))
    good = s2_process(S2_TAGS, sealed, rot_masked=True, rec_buggy=False)
    assert good == payload, "correct stage-2 payload mismatch"
    assert third_layer_decode(good) == flag, "third layer did not yield the flag"

    # (2) the two bugs are independent; each partial variant must be rejected
    assert s2_signature(S2_TAGS, False) != s2_signature(S2_TAGS, True), \
        "rotate mask must matter"
    for rot_masked, rec_buggy, label in (
            (True, True, "record bug only"),
            (False, False, "rotate bug only"),
            (False, True, "both bugs")):
        try:
            bad = s2_process(S2_TAGS, sealed, rot_masked, rec_buggy)
        except ValueError:
            continue  # fell through to the archived decoy -> good
        assert bad != payload and third_layer_decode(bad) != flag, label

    # (3) the shipped stage-2 program itself falls back to the decoy
    ns = {"__name__": "stage2_check"}
    exec(compile(build_stage2_source(), "<stage2>", "exec"), ns)
    h = 0x1BADB002
    for t in ns["TAGS"]:
        h = (h + t) & MASK32
        h = _rotl32(h, 7, False)
        h ^= h >> 16
        h = (h * 0x9E3779B9) & MASK32
    plain2 = bytes(a ^ b for a, b in
                   zip(ns["SEALED"], s2_keystream(h & MASK32, len(ns["SEALED"]))))
    try:
        ns["extract_record"](plain2)
        raise AssertionError("shipped stage-2 must not accept its own record")
    except ValueError:
        pass
    assert ns["ARCHIVED_VALUE"] == DECOY_ARCHIVED

    # (4) correctness sanity on the dispatcher aggregation
    assert acc_correct == sum(p["tag"] for p in packets) % (1 << 64)

    # (5) the flag must never appear in any shipped artifact
    for name in ("broken_dispatch.py", "dispatch_packets.json", "README.txt"):
        text = (out / name).read_text(encoding="utf-8")
        assert flag not in text, name

    print("[M05] wrote %s" % out)
    print("[M05] packets=%d stage2_src_bytes=%d correct_ledger=%d payload=%r"
          % (PACKET_COUNT, len(stage2_src), acc_correct, payload[:16]))


if __name__ == "__main__":
    main()
