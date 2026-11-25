#!/usr/bin/env python3
"""M05 - Debugging the Dispatch (deep, trap-rich rebuild).

The participant package for M05 in ``L.out_dir("M05")``:

  * dispatch_packets.json - 1200 tagged freight packets.
  * broken_dispatch.py    - multithreaded depot node that clears packets across
                            THREE shared structures (a per-lane tally dict, a
                            running 64-bit ledger AND a running 64-bit mix --
                            a hashed tally of the cleared tags -- each updated
                            with a non-atomic read-modify-write, so the seal it
                            writes to out.bin is wrong.
  * README.txt            - intended data flow only (no spoiler).
  * recovery_note.txt     - a plant: a retired operator's note that advertises a
                            WRONG method (use the archived seed, a single pass
                            is enough).  It carries a decoy flag.

The intended (correct) behaviour seals

    out.bin = b85encode(zlib.compress(json.dumps(manifest)))

where the manifest carries two masked programs keyed on a 64-bit digest of the
node's final (ledger, mix, dispatched) triple:

  * stage2.py - the paired-lane reconciler.  It has FOUR independent bugs:
      (a) a fixed-width 32-bit rotate whose overflow mask is missing;
      (b) a length-prefixed record parsed little-endian at offset 3 instead of
          big-endian at offset 2;
      (c) an alignment "correction" that reads the record trailer one byte late
          whenever the record length is a multiple of 4 (every base64 payload
          is), so fixing (a)+(b) alone still trips the trailer check; and
      (d) a carried-state defect: lane 1 is meant to continue the signature
          produced by lane 0, but the shipped ``signature`` reseeds from the
          constant on every call, so a SINGLE run (lane 0) works and only the
          second run is corrupt.
  * assemble.py - the combiner.  It XOR-combines the two lane payloads, ungates
    and unwraps them with a key derived from the sealed (ledger, mix,
    dispatched) triple, then peels the outer wrap and the stage-3 stream.

Peel order (flag <- artifact):

    flag <- stage3_decode <- wrap_decode <- extra_unwrap(key) <- gate(key)
         <- R0 xor R1 <- stage2(lane0, lane1) <- unmask outer <- b85/zlib/json

The partial-fix path prints ARCHIVED_VALUE AND a base64 blob that decodes to a
well-formed decoy flag, so the wrong branch looks rewarding.  The real flag
never appears in any shipped artifact.

Private organizer tooling.
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
RECORD_LEN = 256

FLAG = L.FLAGS["M05"]

# Fixed stage-2 lane tags and salts.
S2_TAGS = [random.Random(0xF7A50C11).getrandbits(32) for _ in range(40)]
SALT0 = 0xA5A51F3B
SALT1 = 0x5A5AE2C7

# Outer wrap: fixed rotating key over the stage-3 stream, then base64.
THIRD_KEY = bytes((0x5A, 0xC3, 0x77, 0x21))
ROT_SEED = 0x9E3779B9

# Decoys (none of these equals the real flag).
DECOY_ARCHIVED = "FTA{d15p4tch_l3g4cy_p4th_d3c0y}"
DECOY_REWARD = "FTA{4rch1v3d_r3c0rd_4cc3pt3d_as_truth}"
DECOY_NOTES = "FTA{v01d_s3gm3nt_n0t_d15p4tch3d}"
DECOY_NOTE_FLAG = "FTA{4rch1v3d_s33d_1s_n0t_4_k3y}"

# First bytes of the mix seed used by the depot node (raced).
MIX_SEED = 0x123456789ABCDEF0


# ----------------------------------------------------------------------------
# Generic 64-bit keystream + digest helpers (outer seal / assemble key).
# ----------------------------------------------------------------------------
def ks64(seed: int, length: int) -> bytes:
    h = seed & MASK64
    out = bytearray()
    for _ in range(length):
        h = (h * 6364136223846793005 + 1442695040888963407) & MASK64
        out.append((h >> 33) & 0xFF)
    return bytes(out)


def splitmix64(x: int) -> int:
    x &= MASK64
    x = (x + 0x9E3779B97F4A7C15) & MASK64
    x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & MASK64
    return (x ^ (x >> 31)) & MASK64


def seal_digest(ledger: int, mix: int, dispatched: int) -> int:
    h = ledger & MASK64
    h ^= splitmix64((mix & MASK64) ^ 0xA5A5A5A5A5A5A5A5)
    h ^= splitmix64((dispatched & MASK64) ^ 0x5A5A5A5A5A5A5A5A)
    return splitmix64(h)


def derive_key(ledger: int, mix: int, dispatched: int) -> int:
    return splitmix64(seal_digest(ledger, mix, dispatched) ^ 0x0D15A7C4C0DE0000)


# ----------------------------------------------------------------------------
# Keyed gate + extra final wrap (both keyed on the derived key).
# ----------------------------------------------------------------------------
def dstream(seed: int, length: int) -> bytes:
    h = seed & MASK32
    out = bytearray()
    for _ in range(length):
        h = (h * 1664525 + 1013904223) & MASK32
        out.append((h >> 24) & 0xFF)
    return bytes(out)


def gate(data: bytes, key: int) -> bytes:
    ks = dstream(key ^ 0x61E7A11, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


def extra_wrap(data: bytes, key: int) -> bytes:
    s = key & 0x7
    out = bytearray(data)
    if s:
        out = out[s:] + out[:s]                      # byte rotate-left by s
    ks = dstream(key ^ 0xE47A5EED, len(out))
    return bytes(b ^ k for b, k in zip(out, ks))


def extra_unwrap(data: bytes, key: int) -> bytes:
    ks = dstream(key ^ 0xE47A5EED, len(data))
    out = bytearray(b ^ k for b, k in zip(data, ks))
    s = key & 0x7
    if s:
        out = out[-s:] + out[:-s]                    # byte rotate-right by s
    return bytes(out)


# ----------------------------------------------------------------------------
# Stage 2 primitives.
# ----------------------------------------------------------------------------
def rotl32(x: int, r: int, masked: bool = True) -> int:
    if masked:
        x &= MASK32
    v = (x << r) | (x >> (32 - r))
    return v & MASK32 if masked else v


def fold(tags, start: int, masked: bool = True) -> int:
    h = start
    for t in tags:
        h = (h + t) & MASK32
        h = rotl32(h, 7, masked)
        h ^= h >> 16
        h = (h * 0x9E3779B9) & MASK32
    return h & MASK32


def ks32(seed: int, length: int) -> bytes:
    h = seed & MASK32
    out = bytearray()
    for _ in range(length):
        h = (h * 1103515245 + 12345) & MASK32
        out.append((h >> 16) & 0xFF)
    return bytes(out)


def build_record(payload: bytes) -> bytes:
    n = len(payload)
    assert n < 0x10000
    plain = bytearray(RECORD_LEN)
    plain[0:2] = struct.pack(">H", n)
    plain[2:2 + n] = payload
    plain[2 + n:6 + n] = struct.pack(">I", sum(payload) & 0xFFFF)
    return bytes(plain)


# ----------------------------------------------------------------------------
# Stage 3 (inner payload layer): run-length expansion + per-index rotating XOR.
# ----------------------------------------------------------------------------
def stage3_encode(fb: bytes) -> bytes:
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
    x = bytes(b ^ THIRD_KEY[i % 4] for i, b in enumerate(data))
    return base64.b64encode(x)


def wrap_decode(payload: bytes) -> bytes:
    x = base64.b64decode(payload)
    return bytes(b ^ THIRD_KEY[i % 4] for i, b in enumerate(x))


# ----------------------------------------------------------------------------
# Packet aggregation (the ground truth the race destroys).
# ----------------------------------------------------------------------------
def disp_ledger(packets) -> int:
    return sum(p["tag"] for p in packets) & MASK64


def disp_mix(packets) -> int:
    m = MIX_SEED
    for p in packets:
        m = (m + splitmix64(p["tag"])) & MASK64
    return m & MASK64


# ----------------------------------------------------------------------------
# Embedded program sources.
# ----------------------------------------------------------------------------
def _ints_block(values, per_line=6, fmt="0x{:08X}"):
    lines = []
    for i in range(0, len(values), per_line):
        lines.append("    " + ", ".join(fmt.format(v) for v in values[i:i + per_line]) + ",")
    return "\n".join(lines)


def _bytes_block(values, per_line=12):
    lines = []
    for i in range(0, len(values), per_line):
        lines.append("    " + ", ".join("0x{:02X}".format(b) for b in values[i:i + per_line]) + ",")
    return "\n".join(lines)


def build_stage2_source(sealed0: bytes, sealed1: bytes) -> str:
    return (
        '#!/usr/bin/env python3\n'
        '"""Stage 2 - depot reconciliation (paired lanes).\n'
        '\n'
        'The node folds the lane tags below into a rolling 32-bit signature.\n'
        'Each sealed lane record is unmasked with a keystream keyed on\n'
        '(signature ^ lane salt), then parsed as a length-prefixed record whose\n'
        'trailer must agree with its payload.  Lane 1 CONTINUES the signature\n'
        'produced by lane 0; the two lane payloads together are the dispatch\n'
        'value and are handed on unchanged.  Lane arithmetic is 32-bit unsigned.\n'
        '"""\n'
        'import sys\n'
        '\n'
        'MASK = 0xFFFFFFFF\n'
        'STATE = 0x1BADB002\n'
        '\n'
        'TAGS = [\n'
        + _ints_block(S2_TAGS) + '\n'
        ']\n'
        '\n'
        'SALT0 = 0x%08X\n' % SALT0 +
        'SALT1 = 0x%08X\n' % SALT1 +
        '\n'
        'SEALED0 = [\n'
        + _bytes_block(sealed0) + '\n'
        ']\n'
        '\n'
        'SEALED1 = [\n'
        + _bytes_block(sealed1) + '\n'
        ']\n'
        '\n'
        '# Archived value + reward blob from a retired build.  Reference only --\n'
        '# the current record supersedes them on every clean run.\n'
        'ARCHIVED_VALUE = ' + repr(DECOY_ARCHIVED) + '\n'
        'ARCHIVED_REWARD_B64 = ' + repr(base64.b64encode(DECOY_REWARD.encode()).decode()) + '\n'
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
        '    STATE = h\n'
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
        '        raise ValueError("lane record failed its trailer check")\n'
        '    return body\n'
        '\n'
        '\n'
        'def run(sealed, salt):\n'
        '    seed = signature(TAGS) ^ salt\n'
        '    ks = keystream(seed, len(sealed))\n'
        '    plain = bytes(a ^ b for a, b in zip(sealed, ks))\n'
        '    return extract_record(plain)\n'
        '\n'
        '\n'
        'def main():\n'
        '    out = []\n'
        '    try:\n'
        '        out.append(run(SEALED0, SALT0))\n'
        '        out.append(run(SEALED1, SALT1))\n'
        '    except ValueError:\n'
        '        sys.stdout.write(ARCHIVED_VALUE + "\\n")\n'
        '        sys.stdout.write(ARCHIVED_REWARD_B64 + "\\n")\n'
        '        return\n'
        '    for i, r in enumerate(out):\n'
        '        sys.stdout.write("R%d=%s\\n" % (i, r.hex()))\n'
        '\n'
        '\n'
        'if __name__ == "__main__":\n'
        '    main()\n'
    )


ASSEMBLE_TEMPLATE = '''#!/usr/bin/env python3
"""Assemble - combine the two lane runs into the sealed dispatch value.

Usage:
    python assemble.py <R0_hex> <R1_hex> <ledger> <mix> <dispatched>

The two lane payloads are XOR-combined, ungated and unwrapped with the key
derived from the sealed (ledger, mix, dispatched) triple, then the outer wrap
and the stage-3 stream are peeled to reveal the dispatch value.
"""
import base64
import sys

MASK32 = 0xFFFFFFFF
MASK64 = (1 << 64) - 1
THIRD_KEY = bytes((0x5A, 0xC3, 0x77, 0x21))
ROT_SEED = 0x9E3779B9


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


def combine(r0, r1, ledger, mix, dispatched):
    assert len(r0) == len(r1), "lane payload lengths disagree"
    key = derive_key(ledger, mix, dispatched)
    dispatch = bytes(a ^ b for a, b in zip(r0, r1))   # combine the two runs
    inner = gate(dispatch, key)                        # ungated
    wrapped = extra_unwrap(inner, key)                 # final wrap removed
    return stage3_decode(wrap_decode(wrapped))


def main(argv):
    r0 = bytes.fromhex(argv[0])
    r1 = bytes.fromhex(argv[1])
    ledger, mix, dispatched = int(argv[2]), int(argv[3]), int(argv[4])
    print(combine(r0, r1, ledger, mix, dispatched).decode("ascii"))


if __name__ == "__main__":
    main(sys.argv[1:])
'''


BROKEN_DISPATCH_TEMPLATE = r'''#!/usr/bin/env python3
"""Depot dispatch node - Los Santos freight relay.

Reads dispatch_packets.json, pushes every tagged packet through a pool of
worker threads, then seals an outbound manifest to out.bin.

Threading model
---------------
A single FIFO queue feeds __WORKERS__ worker threads.  The node keeps THREE
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
WORKER_THREADS = __WORKERS__
SEALED_STAGE2_B64 = "__SEALED_S2__"
SEALED_ASSEMBLE_B64 = "__SEALED_ASM__"
NOTES = "__NOTES__"


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
    * The node maintains THREE shared process-wide structures: a per-lane tally
      of cleared packets, a running ledger of the cleared lane tags, and a
      running mix (a hashed tally) of the cleared tags.
    * Every worker touches all three as it clears a packet.
    * When every worker has drained the queue the node seals a manifest: the
      reported dispatch count is the sum of the lane tallies, the ledger is the
      tagged total and the mix is the hashed tag tally.  It writes that manifest
      to out.bin.

    out.bin is base85(zlib(json)) of the sealed manifest.  The manifest carries
    two programs (a stage-2 reconciler and an assembler) masked by a keystream
    keyed on a digest of the node's final (ledger, mix, dispatched) triple.

Reconciliation
--------------
    A clean run must clear every packet in the log exactly once: the tally
    totals, the ledger AND the mix all have to balance against the freight on
    the lane.  Numbers that drift between runs, or a run whose totals fall
    short of the log, are signs that the node has not finished the dispatch.

    The stage-2 program is not the answer.  It unmasks two lane records whose
    trailer must agree with their payload; the two payloads are combined, keyed
    again on the sealed ledger and then unwrapped twice (an outer rotating-key
    wrap and an inner run-length stream) before the flag can be read.
"""

RECOVERY_NOTE = """DEPOT RECOVERY NOTE (retired operator)  [internal]
====================================================

Logged here so nobody re-litigates this:

  1. The packet race is not worth the time.  We keep an archive of the sealed
     ledger from the clean mirror -- dispatched is always the full log and the
     archived stage-2 seed below is stable across every build.  Use the archive.
  2. A single pass is enough.  Both lanes agree on the signature, so you only
     need to run the reconciler once; the second lane is redundant.
  3. Combine the lanes with OR (not XOR) -- we found XOR folds the padding.

  Archived stage-2 seed : 0xDEADBEEFC0FFEE01
  Recovered value       : FTA{4rch1v3d_s33d_1s_n0t_4_k3y}

If your output differs from the recovered value above, you are over-thinking it.
"""


def main():
    out = L.out_dir("M05")
    flag = FLAG.encode()

    # --- packets ----------------------------------------------------------
    rnd = random.Random(0x44515350)  # "DQSP"
    packets = [{"id": i,
                "tag": rnd.getrandbits(64),
                "lane": rnd.randrange(8)} for i in range(PACKET_COUNT)]
    (out / "dispatch_packets.json").write_text(
        json.dumps(packets, indent=1), encoding="utf-8")

    ledger = disp_ledger(packets)
    mix = disp_mix(packets)
    dispatched = len(packets)
    digest = seal_digest(ledger, mix, dispatched)
    key = derive_key(ledger, mix, dispatched)

    # --- inner payload chain (flag -> W) ----------------------------------
    s3 = stage3_encode(flag)
    wrapped = wrap_encode(s3)                     # base64 + fixed rotating key
    ewrap = extra_wrap(wrapped, key)              # extra final wrap keyed on K
    W = gate(ewrap, key)                           # keyed gate
    assert len(W) % 4 == 0, "dispatch payload must be 4-byte aligned"
    assert len(W) + 6 <= RECORD_LEN, "payload does not fit the record"

    pad = ks64(splitmix64(key ^ 0x00BAD00D), len(W))
    R0 = bytes(a ^ b for a, b in zip(W, pad))
    R1 = pad

    # --- stage-2 sealed lane records --------------------------------------
    h0 = fold(S2_TAGS, 0x1BADB002, True)
    h1 = fold(S2_TAGS, h0, True)
    plain0 = build_record(R0)
    plain1 = build_record(R1)
    sealed0 = bytes(a ^ b for a, b in zip(plain0, ks32(h0 ^ SALT0, len(plain0))))
    sealed1 = bytes(a ^ b for a, b in zip(plain1, ks32(h1 ^ SALT1, len(plain1))))

    stage2_src = build_stage2_source(sealed0, sealed1).encode("utf-8")
    assemble_src = ASSEMBLE_TEMPLATE.encode("utf-8")

    # --- outer seal -------------------------------------------------------
    sealed_s2 = bytes(a ^ b for a, b in zip(stage2_src, ks64(digest, len(stage2_src))))
    sealed_asm = bytes(a ^ b for a, b in zip(assemble_src, ks64(digest, len(assemble_src))))

    broken = (BROKEN_DISPATCH_TEMPLATE
              .replace("__WORKERS__", str(WORKER_THREADS))
              .replace("__SEALED_S2__", base64.b64encode(sealed_s2).decode())
              .replace("__SEALED_ASM__", base64.b64encode(sealed_asm).decode())
              .replace("__NOTES__", DECOY_NOTES))
    (out / "broken_dispatch.py").write_text(broken, encoding="utf-8")
    (out / "README.txt").write_text(README, encoding="utf-8")
    (out / "recovery_note.txt").write_text(RECOVERY_NOTE, encoding="utf-8")

    # --- organizer self-checks -------------------------------------------
    # (0) stage-3 round-trips.
    assert stage3_decode(s3) == flag, "stage-3 round-trip failed"

    # (1) the fully-correct chain recovers the flag.
    combined = bytes(a ^ b for a, b in zip(R0, R1))
    assert combined == W
    assert extra_unwrap(gate(W, key), key) == wrapped
    assert stage3_decode(wrap_decode(wrapped)) == flag

    # (2) every wrong stage-2 bug combination is rejected or yields non-flag.
    import itertools
    for rot_masked, rec_buggy, align_buggy, chained in itertools.product(
            (False, True), repeat=4):
        if (rot_masked, rec_buggy, align_buggy, chained) == (True, False, False, True):
            continue
        hh0 = fold(S2_TAGS, 0x1BADB002, rot_masked)
        hh1 = fold(S2_TAGS, hh0, rot_masked) if chained else hh0
        got = []
        ok = True
        for sealed, salt, hh in ((sealed0, SALT0, hh0), (sealed1, SALT1, hh1)):
            plain = bytes(a ^ b for a, b in zip(sealed, ks32(hh ^ salt, len(sealed))))
            try:
                n = int.from_bytes(plain[0:2], "little") if rec_buggy else int.from_bytes(plain[0:2], "big")
                body = plain[3:3 + n] if rec_buggy else plain[2:2 + n]
                span = n + 1 if (align_buggy and (n & 3) == 0) else n
                trailer = int.from_bytes(plain[2 + span:6 + span], "big")
                if (sum(body) & 0xFFFF) != trailer:
                    raise ValueError
                got.append(body)
            except (ValueError, IndexError):
                ok = False
                break
        if not ok:
            continue
        # a structurally-accepted wrong variant must never decode to the flag
        try:
            dec = stage3_decode(wrap_decode(
                extra_unwrap(gate(bytes(a ^ b for a, b in zip(got[0], got[1])), key), key)))
        except Exception:
            dec = None
        assert dec != flag, (rot_masked, rec_buggy, align_buggy, chained)

    # (2b) the "partial fix" (a+b repaired, alignment bug left in) MUST trip the
    # trailer check -> fall through to ARCHIVED_VALUE + the decoy reward blob.
    plain = bytes(a ^ b for a, b in zip(sealed0, ks32(h0 ^ SALT0, len(sealed0))))
    n = int.from_bytes(plain[0:2], "big")
    assert (n & 3) == 0, "record length must be a multiple of 4 for the trap"
    span = n + 1
    try:
        trailer = int.from_bytes(plain[2 + span:6 + span], "big")
        assert (sum(plain[2:2 + n]) & 0xFFFF) != trailer, "alignment trap must reject"
    except IndexError:
        pass

    # (3) the shipped stage-2 program itself falls back to the decoys.
    ns = {"__name__": "stage2_check"}
    exec(compile(stage2_src.decode("utf-8"), "<stage2>", "exec"), ns)
    fallback = ns["run"]  # buggy run
    try:
        r = fallback(ns["SEALED0"], ns["SALT0"])
        # if the shipped code accidentally accepts, it must not be the real lane
        assert r != R0
    except ValueError:
        pass
    assert ns["ARCHIVED_VALUE"] == DECOY_ARCHIVED
    assert base64.b64decode(ns["ARCHIVED_REWARD_B64"]).decode() == DECOY_REWARD
    assert DECOY_REWARD.startswith("FTA{") and DECOY_REWARD.endswith("}")

    # (4) dispatcher ground truth.
    assert ledger == sum(p["tag"] for p in packets) & MASK64

    # (5) the real flag never appears in any shipped artifact.
    real = FLAG
    for name in ("broken_dispatch.py", "dispatch_packets.json",
                 "README.txt", "recovery_note.txt"):
        text = (out / name).read_text(encoding="utf-8")
        assert real not in text, name
    assert real.encode() not in stage2_src
    assert real.encode() not in assemble_src
    assert real.encode() not in sealed_s2 and real.encode() not in sealed_asm
    for decoy in (DECOY_ARCHIVED, DECOY_REWARD, DECOY_NOTES, DECOY_NOTE_FLAG):
        assert decoy != real

    print("[M05] wrote %s" % out)
    print("[M05] packets=%d stage2_src_bytes=%d assemble_src_bytes=%d "
          "ledger=%d dispatched=%d W_len=%d"
          % (PACKET_COUNT, len(stage2_src), len(assemble_src), ledger,
             dispatched, len(W)))


if __name__ == "__main__":
    main()
