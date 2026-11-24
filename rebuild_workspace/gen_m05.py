#!/usr/bin/env python3
"""M05 - Debugging the Dispatch (stacked concurrency + multi-bug stage 2 +
outer run-length / rotating-XOR layer).

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
on the node's final (ledger, dispatched) pair.

Recovering the flag is a three-layer peel:

  stage 2 (depot reconciliation) has THREE independent, non-obvious bugs:
    (a) a fixed-width 32-bit rotate whose overflow mask is missing;
    (b) a length-prefixed record parsed with the wrong endianness and an
        off-by-one field offset; and
    (c) an alignment "correction" that reads the record trailer one byte late
        whenever the record length is a multiple of 4 (which every base64
        payload is) -- a participant who unit-tests their fix on a short,
        non-aligned sample record will think stage 2 is repaired and still
        only recover the archived DECOY value.

  Once stage 2 is fully repaired its payload is itself a wrapped stream: the
  stage-3 transform (a run-length expansion followed by a per-index rotating
  XOR) under a fixed base64/rotating-key outer wrap.  A partial fix that only
  undoes the wrap stops at an unreadable stage-3 blob; a partial *script* fix
  trips stage 2's trailer check and falls back to the archived DECOY flag.

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
RECORD_LEN = 128

# Outer wrap: fixed rotating key over the stage-3 stream, then base64.
THIRD_KEY = bytes((0x5A, 0xC3, 0x77, 0x21))

# Stage-3: run-length expansion followed by a per-index rotating XOR.
ROT_SEED = 0x9E3779B9

# Decoys: a plausible wrong flag reachable by a partial fix / a shallow grep.
DECOY_ARCHIVED = "FTA{d15p4tch_l3g4cy_p4th_d3c0y}"
DECOY_NOTES = "FTA{v01d_s3gm3nt_n0t_d15p4tch3d}"

# ----------------------------------------------------------------------------
# Stage 2 logic.  The variant embedded in the manifest omits the 32-bit rotate
# mask, mis-frames the record AND mis-aligns the trailer (the shipped bugs);
# the corrected variant restores all three (the solve).
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


def s2_process(tags, sealed, rot_masked: bool = True, rec_buggy: bool = False,
               align_buggy: bool = False) -> bytes:
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
    # bug (c): the trailer is read one byte late for 4-byte-aligned records.
    span = n + 1 if (align_buggy and (n & 3) == 0) else n
    trailer = int.from_bytes(plain[2 + span:6 + span], "big")
    if (sum(body) & 0xFFFF) != trailer:
        raise ValueError("reconciliation record failed its trailer check")
    return body


# ----------------------------------------------------------------------------
# Stage 3 (outer payload layer): run-length expansion + per-index rotating XOR.
# ----------------------------------------------------------------------------
def stage3_encode(fb: bytes) -> bytes:
    """Run-length expand ``fb`` into (byte, run-length) pairs (runs capped at
    255), then XOR every byte with a key that rotates once per index."""
    expanded = bytearray()
    i, n = 0, len(fb)
    while i < n:
        j = i + 1
        while j < n and fb[j] == fb[i] and (j - i) < 255:
            j += 1
        expanded.append(fb[i])
        expanded.append(j - i)
        i = j
    rot = ROT_SEED
    out = bytearray(len(expanded))
    for k, b in enumerate(expanded):
        rot = ((rot << 1) | (rot >> 31)) & MASK32
        out[k] = b ^ ((rot >> 7) & 0xFF)
    return bytes(out)


def stage3_decode(data: bytes) -> bytes:
    """Inverse of :func:`stage3_encode`."""
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


def wrap_encode(data: bytes) -> bytes:
    """Fixed rotating-key XOR then base64 (keeps the record payload printable)."""
    x = bytes(b ^ THIRD_KEY[i % 4] for i, b in enumerate(data))
    return base64.b64encode(x)


def wrap_decode(payload: bytes) -> bytes:
    x = base64.b64decode(payload)
    return bytes(b ^ THIRD_KEY[i % 4] for i, b in enumerate(x))


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
    payload = wrap_encode(stage3_encode(L.FLAGS["M05"].encode()))
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
        '    span = n + 1 if (n & 3) == 0 else n\n'
        '    trailer = int.from_bytes(plain[2 + span:6 + span], "big")\n'
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
    wrapped by an additional reversible layer (a run-length stream under a
    rotating key) before the flag can be read.
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
    # (0) stage-3 round-trips and its wrapped output stays 4-byte aligned
    inner = stage3_encode(flag.encode())
    assert stage3_decode(inner) == flag.encode(), "stage-3 round-trip failed"
    payload = wrap_encode(inner)
    assert len(payload) % 4 == 0, "record payload must be 4-byte aligned"

    # (1) the corrected stage-2 recovers the outer payload, which decodes to flag
    plain = build_record(payload)
    ks = s2_keystream(s2_signature(S2_TAGS, True), len(plain))
    sealed = bytes(a ^ b for a, b in zip(plain, ks))
    good = s2_process(S2_TAGS, sealed, True, False, False)
    assert good == payload, "correct stage-2 payload mismatch"
    assert stage3_decode(wrap_decode(good)) == flag.encode(), \
        "outer layers did not yield the flag"

    # (2) the three bugs are independent; every wrong combination is rejected
    import itertools
    for rot_masked, rec_buggy, align_buggy in itertools.product((False, True),
                                                                repeat=3):
        if (rot_masked, rec_buggy, align_buggy) == (True, False, False):
            continue
        try:
            bad = s2_process(S2_TAGS, sealed, rot_masked, rec_buggy, align_buggy)
        except ValueError:
            continue  # fell through to the archived decoy -> good
        assert bad != payload, (rot_masked, rec_buggy, align_buggy)
        try:
            assert stage3_decode(wrap_decode(bad)) != flag.encode()
        except Exception:
            pass  # a wrong payload must never decode to the flag either

    # (2b) the "partial script fix" (bugs a+b repaired, alignment bug left in)
    # must trip the trailer check and fall through to ARCHIVED_VALUE
    try:
        s2_process(S2_TAGS, sealed, True, False, True)
        raise AssertionError("alignment bug must reject the shipped record")
    except ValueError:
        pass

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
    assert ns["ARCHIVED_VALUE"] != flag and DECOY_NOTES != flag

    # (4) correctness sanity on the dispatcher aggregation
    assert acc_correct == sum(p["tag"] for p in packets) % (1 << 64)

    # (5) the flag must never appear in any shipped artifact
    for name in ("broken_dispatch.py", "dispatch_packets.json", "README.txt"):
        text = (out / name).read_text(encoding="utf-8")
        assert flag not in text, name

    print("[M05] wrote %s" % out)
    print("[M05] packets=%d stage2_src_bytes=%d correct_ledger=%d payload_len=%d"
          % (PACKET_COUNT, len(stage2_src), acc_correct, len(payload)))


if __name__ == "__main__":
    main()
