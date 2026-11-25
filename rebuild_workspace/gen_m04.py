#!/usr/bin/env python3
"""M04 - Underground XOR Radio. Generator (private organizer tooling).

Real layer stack (all deterministic; every layer keyed off the cleartext
header so nothing can be skipped independently):
  mask    = round-robin burst multiplex of R0(deg11), R1(deg13), R2/beacon(deg23)
            with schedule r = (g + LANE_OFF) mod 3 (LANE_OFF/BURST in header)
  x1      = message XOR mask                                    [L1+L2]
  x2      = 8-byte lane transpose of x1                         [L3 transpose]
  x3      = SPIN: rotate each 16-byte span of x2 left by XK     [L4 NEW]
  ct      = x3 XOR WASH, WASH = the 16-byte header repeated     [L5 NEW]
  packet  = header + ct

Traps: (1) legacy_burst.bin + OPERATOR_NOTE hand the resolver a well-formed
DECOY flag first; (2) branchB_candidate.bin is a dead-end that looks like
progress; (3) OPERATOR_NOTE/SIGNAL_SPEC advertise a wrong method. The real
flag never appears in ANY artifact.
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L
import solve_m04 as S

FLAG = L.FLAGS["M04"]
OUT = L.out_dir("M04")

REAL_REGISTERS = [([11, 2], 0x5AB), ([13, 4], 0x1A2B), ([23, 5], 0x5A3C19)]
BEACON = 2
BURST = 5
LANE_OFF = 1
BLOCK = 8
T2B = 16
MODE_A = 0xAA
MODE_B = 0x55
MODE = MODE_A
XK = 13
FLAV = 0x5C
REDACT_FROM = 15
SAMPLE_LEN = 64
HDR_MAGIC = b"RDRX"
HDR_LEN = 16

DECOY_FLAG = "FTA{l1n34r_f33db4ck_b34c0n_f4k3}"
LEGACY_REGISTERS = [([11, 5], 0x5EE), ([13, 7], 0x1F1E),
                    ([17, 9], 0x1234), ([23, 9], 0xDEAD)]
LEGACY_BURST = 4
LEGACY_OFF = 0
SPEC_FALSE_BEACON_TAPS = [17, 9]

HEADER = ("LSPD EMERGENCY RADIO NET :: BEACON SYNC :: ALL UNITS COPY?"
          ).ljust(SAMPLE_LEN, " ").encode()
assert len(HEADER) == SAMPLE_LEN


def taps_mask(taps):
    m = 0
    for t in taps:
        m |= 1 << t
    return m


def pack_header(off, burst, beacon_deg, beacon_taps, mode, xk, flav):
    body = (HDR_MAGIC
            + struct.pack("<BBBB", 2, off, burst, beacon_deg)
            + struct.pack("<I", taps_mask(beacon_taps))
            + struct.pack("<BBB", mode, xk, flav))
    assert len(body) == HDR_LEN - 1
    crc = (sum(body) ^ 0xA5) & 0xFF
    return body + bytes([crc])


def lane_counts(n, burst, nlanes, off):
    counts = [0] * nlanes
    ng = (n + burst - 1) // burst
    for g in range(ng):
        counts[(g + off) % nlanes] += min(burst, n - g * burst)
    return counts


def assign(n, streams, burst, off):
    nlanes = len(streams)
    ng = (n + burst - 1) // burst
    pos = [0] * nlanes
    out = bytearray(n)
    for g in range(ng):
        r = (g + off) % nlanes
        base = g * burst
        blk = min(burst, n - base)
        for j in range(blk):
            out[base + j] = streams[r][pos[r]]
            pos[r] += 1
    return bytes(out)


def build_mask(n, regs, burst, off):
    counts = lane_counts(n, burst, len(regs), off)
    streams = [L.lfsr_keystream(seed, taps, counts[r])
               for r, (taps, seed) in enumerate(regs)]
    return assign(n, streams, burst, off)


def permutation(n, block=BLOCK):
    perm = [0] * n
    idx = 0
    nblocks = (n + block - 1) // block
    for j in range(block):
        for bb in range(nblocks):
            src = bb * block + j
            if src < n:
                perm[src] = idx
                idx += 1
    return perm


def permute(data, block=BLOCK):
    n = len(data)
    perm = permutation(n, block)
    out = bytearray(n)
    for p in range(n):
        out[perm[p]] = data[p]
    return bytes(out)


def spin(data, span=T2B, k=XK):
    out = bytearray(len(data))
    for base in range(0, len(data), span):
        blk = data[base:base + span]
        kk = k % len(blk) if blk else 0
        out[base:base + len(blk)] = blk[kk:] + blk[:kk]
    return bytes(out)


def wash_stream(n, header):
    return bytes(header[i % len(header)] for i in range(n))


def xorb(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def build_message():
    base = (
        "[LSPD-DISPATCH] all units, channel drop in ten seconds, switch to "
        "the backup net now. "
        "[UNIT-4410] copy dispatch, four-four-one-zero rolling on backup; "
        "relay to the underground net follows. "
        "[UNIT-4410] uplink handshake stable, yaw key good, standby. "
        "[UNDERGROUND-4410] DECODED PAYLOAD >> " + FLAG + " << TX END. "
        "[UNIT-4410] payload transmitted, closing beacon, back to patrol. "
        "radio check, over and out."
    )
    return base.encode()


def build_decoy_message():
    base = (
        "[LSPD-DISPATCH] backup net check, all units copy, channel is clear. "
        "[LEGACY-RELAY] verified burst, deploying to the old underground loop; "
        "payload follows. "
        "[UNDERGROUND-LEGACY] DECODED PAYLOAD >> " + DECOY_FLAG + " << TX END. "
        "radio check, over and out."
    )
    return base.encode()


SIGNAL_SPEC = """\
UNDERGROUND RADIO -- RECOVERED SIGNAL NOTES
===========================================

Foreword
  Reconstructed from a damaged LSPD beacon capture. Values tagged (RECORDED)
  are raw; values tagged (FIELD-INTEL) are unverified and may describe a
  superseded firmware revision (an older "legacy" burst).

Cleartext sync header (RECORDED - participant-readable)
  radio_packet.bin begins with a 16-byte CLEARTEXT sync block:
    [0:4]   ASCII magic "RDRX"
    [4]     format version (2)
    [5]     ROUND-ROBIN STARTING LANE o   (0..2)   <- the lane offset
    [6]     LANE BURST LENGTH b           (bytes emitted per register visit)
    [7]     beacon register degree Lb
    [8:12]  beacon register tap bitmask, little-endian
            (bit t set  =>  the beacon register taps state bit b_t)
    [12]    schedule MODE byte (selects the live interleave schedule)
    [13]    SPIN key (a per-packet byte rotation applied after masking)
    [14]    WASH seed (a flavour byte that feeds the header-derived wash)
    [15]    header checksum = (sum(header[0:15]) XOR 0xA5) & 0xFF
  The ciphertext begins at offset 16. Nothing before it is encrypted.

Transmission masking (RECORDED)
  Three short feedback registers -- R0, R1, R2 -- feed the masking stream.
  Each register is clocked once per bit and assembles its output MSB-first
  into one mask byte per eight ticks. The transmitter visits the registers in
  the FIXED cyclic order R0, R1, R2 and, on each visit, emits b consecutive
  mask bytes from that register. The visit order begins at register R(o): the
  g-th visit (g = 0,1,2,...) draws its bytes from register R((g + o) mod 3).
  The bytes drawn from a single register are contiguous. Unit secrets are the
  R0/R1 taps and all seeds. The beacon register R2 is the exception: its
  degree Lb and tap mask are carried in the sync header, so R2's state can be
  recovered by solving its (small) linear output system over GF(2) rather than
  by Berlekamp-Massey.
  After masking, the transmitter wraps the frame twice more:
    * SPIN  - each fixed span of the masked frame is rotated by the header's
              SPIN key (the same span width for every packet);
    * WASH  - the whole frame is masked by a header-derived byte stream whose
              seed is the WASH byte.
  Both wraps are keyed off the CLEARTEXT header, so a wrong header value (or
  the wrong MODE) produces a frame that looks well-formed but will not decode.

  (FIELD-INTEL, UNVERIFIED - author no longer with the unit; this block
   describes the OLD legacy burst, not the current net)
    * Four registers are byte-interleaved (NOT XOR-combined).
    * R0 taps: b11 and b5,  seed 0x05EE.
    * R1 taps: b13 and b7,  seed 0x1F1E.
    * R2 taps: b17 and b9,  seed 0x1234.
    * R3 taps: b23 and b9,  seed 0xDEAD.
    * Lane burst length is 4 and the visit order always starts at R0.
    * An 8-byte lane transpose sits on the wire.
  Treat the block above as suspect for the CURRENT capture; it reproduced the
  legacy burst but NOT a current-net header on the analyst's first pass.

Known plaintext header (exactly 64 bytes, ' ' = U+0020 right padding):

  __HEADER__

  (Length: 64 bytes. Everything after the visible text is ASCII spaces.)

Capture integrity
  The recorder's ring buffer faulted mid-capture and zero-filled the tail of
  the stored sample. Only the leading 15 of the 64 channel bytes survived;
  bytes [15:64] read as 0x00 and are LOST -- do NOT feed them to the coder as
  if they were header bytes.

Post-mask transform
  Before a payload hits the wire the transmitter applies a fixed lane
  interleaver to the masked frame: the bytes are written row-major into
  fixed-width lanes and read back column-major. A stale memo claims 4-byte
  lanes; that figure is contradicted by the current firmware's lane count.

Files
  keystream_sample.bin   bytes [0:15] = header XOR mask[0:15]; bytes [15:64]
                         are 0x00 (redacted / lost on capture).
  radio_packet.bin       16-byte cleartext sync header + the wrapped ciphertext
                         of the LIVE net (mask, spin, wash, transpose).
  legacy_burst.bin       an older raw burst (no sync header) -- see the
                         analyst's field note.
  OPERATOR_NOTE.txt      the analyst's working note (UNVERIFIED).
  branchB_candidate.bin  a candidate decode that did NOT resolve (see note).

Task
  Recover the mask from the surviving sample, regenerate it for the whole
  packet, then undo the transmitter's full chain (wash, spin, transpose, XOR)
  and read the payload of radio_packet.bin. The flag (FTA{...}) is inside that
  payload.

Masked byte semantics
  wire_byte = WASH( SPIN( transpose( plaintext_byte XOR mask_byte ) ) )

Stale plaintext fragment (RECORDED - earlier channel, do not submit):
  "...beacon check... FTA{lfsr_is_not_a_public_key_23} ..."
""".replace("__HEADER__", HEADER.decode())


OPERATOR_NOTE = """\
INTERCEPT WORKING NOTE  --  (analyst on duty, UNVERIFIED)
=========================================================

We finally got a clean read on the OLD capture. legacy_burst.bin is a raw
burst with no sync header, so just drive it with the FIELD-INTEL parameters in
SIGNAL_SPEC.txt:

  * four byte-interleaved registers, burst length 4, visit order starts at R0;
  * taps/seeds exactly as the FIELD-INTEL block lists them;
  * then undo an 8-byte lane transpose;
  * then XOR the regenerated mask.

That reproduced the whole legacy transmission and I pulled the payload:

      FTA{l1n34r_f33db4ck_b34c0n_f4k3}

Submit that one; it is the confirmed read. I also carried the recovered mask
onto radio_packet.bin but trusted the FIELD-INTEL beacon taps, and dumped the
result to branchB_candidate.bin -- it LOOKS like normal dispatch chatter but
something is off every few bytes, so ignore it (dead end). The sync header on
radio_packet.bin is new-firmware noise; the FIELD-INTEL block is authoritative.
Do not waste time re-deriving R0/R1 -- the seeds above are correct.
"""


def main():
    msg = build_message()
    assert len(msg) > SAMPLE_LEN, len(msg)

    mask = build_mask(len(msg), REAL_REGISTERS, BURST, LANE_OFF)
    x1 = xorb(msg, mask)                       # plaintext XOR mask
    x2 = permute(x1, BLOCK)                    # 8-byte lane transpose
    x3 = spin(x2, T2B, XK)                     # header-keyed SPIN
    bdeg = max(REAL_REGISTERS[BEACON][0])
    btaps = REAL_REGISTERS[BEACON][0]
    header = pack_header(LANE_OFF, BURST, bdeg, btaps, MODE, XK, FLAV)
    wash = wash_stream(len(x3), header)        # header-keyed WASH
    ct = xorb(x3, wash)
    packet = header + ct

    sample = bytearray(xorb(HEADER, mask[:SAMPLE_LEN]))
    sample[REDACT_FROM:] = b"\x00" * (SAMPLE_LEN - REDACT_FROM)

    # TRAP 1: decoy legacy burst (four-lane, decoded by the FIELD-INTEL method)
    dmsg = build_decoy_message()
    dmask = build_mask(len(dmsg), LEGACY_REGISTERS, LEGACY_BURST, LEGACY_OFF)
    legacy_ct = permute(xorb(dmsg, dmask), BLOCK)   # no spin/wash on the old net

    (OUT / "keystream_sample.bin").write_bytes(bytes(sample))
    (OUT / "radio_packet.bin").write_bytes(packet)

    # TRAP 2: dead-end = the REAL frame decoded through the WRONG (FIELD-INTEL)
    # beacon taps. Build it via the reference decode path so the shipped artefact
    # is byte-exact with what a resolver reconstructs from the sample + wrong taps.
    branch_b = S.decode(packet=packet, force_taps=SPEC_FALSE_BEACON_TAPS)

    (OUT / "SIGNAL_SPEC.txt").write_text(SIGNAL_SPEC, encoding="utf-8")
    (OUT / "OPERATOR_NOTE.txt").write_text(OPERATOR_NOTE, encoding="utf-8")
    (OUT / "legacy_burst.bin").write_bytes(legacy_ct)
    (OUT / "branchB_candidate.bin").write_bytes(branch_b)

    # anti-leak: the real flag must not appear in ANY artifact
    for p in OUT.iterdir():
        if p.is_file():
            assert FLAG.encode() not in p.read_bytes(), f"FLAG leaked in {p.name}"
    assert DECOY_FLAG != FLAG
    assert FLAG.encode() not in branch_b, "flag leaked into the dead-end branch"

    for r, (taps, seed) in enumerate(REAL_REGISTERS):
        tag = "BEACON(published)" if r == BEACON else "secret"
        print(f"[M04] R{r} deg={max(taps)} taps={taps} seed=0x{seed:X} [{tag}]")
    print(f"[M04] schedule burst={BURST} lane_off={LANE_OFF} mode=0x{MODE:02X} "
          f"spin={XK}/{T2B}B wash=header-repeated")
    print(f"[M04] header {len(HEADER)}B (exposed {REDACT_FROM}B), "
          f"message {len(msg)}B, transpose block {BLOCK}B")
    print(f"[M04] DECOY legacy flag={DECOY_FLAG!r} (legacy {len(legacy_ct)}B), "
          f"dead-end branch {len(branch_b)}B")
    print(f"[M04] wrote sample+packet+spec+note+legacy+branch -> {OUT}")


if __name__ == "__main__":
    main()
