#!/usr/bin/env python3
"""M04 - Underground XOR Radio. Generator (private organizer tooling).

Produces, in challenges_rebuilt/MEDIUM/M04:
  * SIGNAL_SPEC.txt      -- participant-facing spec (with a deliberately wrong
                            "FIELD-INTEL" block and a decoy flag fragment)
  * keystream_sample.bin -- 64 bytes; ONLY the leading REDACT_FROM bytes are
                            header XOR mask[0:REDACT_FROM]; the tail is 0x00
                            (recorder ring-buffer fault / redacted).
  * radio_packet.bin     -- 12-byte CLEARTEXT sync header + lane_interleave(
                            message XOR mask).

Stacked layers (all deterministic, all invertible from the sample):
  L1  THREE Fibonacci LFSRs of different degree (R0 deg 11, R1 deg 13,
      R2/beacon deg 23). Output of each register is MSB-first, one mask byte
      per eight ticks.
  L2  Byte multiplexing, ROUND-ROBIN WITH BURST: the transmitter visits
      registers in the fixed cyclic order R0,R1,R2 and emits BURST consecutive
      mask bytes per visit. The very first visit is register R(LANE_OFF), i.e.
      the g-th visit draws from register R((g + LANE_OFF) mod 3). Because BURST
      > 1, a wrong lane offset genuinely re-groups the bytes (it is NOT a mere
      relabelling), so the participant must recover the offset from the sync
      header before de-multiplexing. (A decoy spec claims XOR-combined lanes.)
  L3  Partial known plaintext: only the leading REDACT_FROM=15 of 64 header
      bytes survive. With the round-robin this leaves only 5 bytes (40 bits)
      per register. R0/R1 are still Berlekamp-Massey recoverable, but the
      degree-23 beacon register cannot be BM-recovered from 40 < 2*23 bits --
      it must be recovered by solving its small GF(2) linear output system
      (taps carried in the cleartext sync header).
  L4  Post-XOR fixed 8-byte lane transpose (block interleave) of the payload.
  L5  Decoy parameters in SIGNAL_SPEC.txt (wrong taps/seed/lane size/burst and
      a stale plaintext fragment + decoy flag) -- real params are never stated.

Private organizer tooling. Never shipped verbatim.
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

FLAG = L.FLAGS["M04"]
OUT = L.out_dir("M04")

# --- Layer 1: three Fibonacci LFSRs of different degree ---------------------
# (taps, seed) per register; seeds nonzero and < 2**deg.
REGISTERS = [
    ([11, 2], 0x5AB),        # R0: degree 11
    ([13, 4], 0x1A2B),       # R1: degree 13
    ([23, 5], 0x5A3C19),     # R2 (BEACON): degree 23, taps published in header
]
BEACON = 2                   # register whose degree/taps the sync header carries

# --- Layer 2: round-robin burst multiplex -----------------------------------
BURST = 5                    # mask bytes emitted per register visit (decoy: 4)
LANE_OFF = 1                 # starting register of the visit schedule (0..2)

# --- Layer 3: partial known plaintext ---------------------------------------
REDACT_FROM = 15             # leading sample bytes that survive (of 64)
SAMPLE_LEN = 64

# --- Layer 4: lane transpose -------------------------------------------------
BLOCK = 8                    # real lane size (decoy claims 4)

# Cleartext sync header (12 bytes): magic, version, lane_off, burst, beacon_deg,
# beacon tap bitmask (LE, 4 bytes). Fields are individually addressable so the
# offset is trivially recoverable, but ONLY from the packet -- not the spec.
HDR_MAGIC = b"RDRX"
HDR_LEN = 12

HEADER = ("LSPD EMERGENCY RADIO NET :: BEACON SYNC :: ALL UNITS COPY?"
          ).ljust(SAMPLE_LEN, " ").encode()
assert len(HEADER) == SAMPLE_LEN


def taps_mask(taps):
    m = 0
    for t in taps:
        m |= 1 << t
    return m


def pack_header(lane_off, burst, beacon_deg, beacon_taps):
    return (HDR_MAGIC
            + struct.pack("<BBBB", 1, lane_off, burst, beacon_deg)
            + struct.pack("<I", taps_mask(beacon_taps)))


def lane_counts(n, burst, off):
    """How many mask bytes register r contributes for an n-byte mask."""
    counts = [0, 0, 0]
    ng = (n + burst - 1) // burst
    for g in range(ng):
        counts[(g + off) % 3] += min(burst, n - g * burst)
    return counts


def assign(n, streams, burst, off):
    """Layer 1+2: write register byte streams into the n-byte mask via the
    round-robin burst schedule."""
    ng = (n + burst - 1) // burst
    pos = [0, 0, 0]
    out = bytearray(n)
    for g in range(ng):
        r = (g + off) % 3
        base = g * burst
        blk = min(burst, n - base)
        for j in range(blk):
            out[base + j] = streams[r][pos[r]]
            pos[r] += 1
    return bytes(out)


def build_mask(n, burst=BURST, off=LANE_OFF):
    counts = lane_counts(n, burst, off)
    streams = [L.lfsr_keystream(seed, taps, counts[r])
               for r, (taps, seed) in enumerate(REGISTERS)]
    return assign(n, streams, burst, off)


def permutation(n, block=BLOCK):
    """Layer 4: lane transpose. Returns perm where payload[perm[p]] = masked[p]."""
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


SIGNAL_SPEC = """\
UNDERGROUND RADIO -- RECOVERED SIGNAL NOTES
===========================================

Foreword
  These notes were reconstructed from a damaged LSPD beacon capture. Values
  tagged (RECORDED) are raw; values tagged (FIELD-INTEL) are unverified and
  may describe a superseded firmware revision.

Cleartext sync header (RECORDED - participant-readable)
  radio_packet.bin begins with a 12-byte CLEARTEXT sync block:
    [0:4]   ASCII magic "RDRX"
    [4]     format version (1)
    [5]     ROUND-ROBIN STARTING LANE o   (0..2)   <- the lane offset
    [6]     LANE BURST LENGTH b           (bytes emitted per register visit)
    [7]     beacon register degree Lb
    [8:12]  beacon register tap bitmask, little-endian
            (bit t set  =>  the beacon register taps state bit b_t)
  The lane-interleaved ciphertext begins at offset 12.

Transmission masking (RECORDED)
  Three short feedback registers -- R0, R1, R2 -- feed the masking stream.
  Each register is clocked once per bit and assembles its output
  most-significant-bit first into one mask byte per eight ticks. The
  transmitter visits the registers in the FIXED cyclic order R0, R1, R2 and,
  on each visit, emits b consecutive mask bytes from that register. The visit
  order begins at register R(o): the g-th visit (g = 0,1,2,...) draws its bytes
  from register R((g + o) mod 3). The bytes drawn from any single register are
  therefore contiguous (the i-th byte drawn from a register is that register's
  i-th stream byte). b > 1, so choosing the wrong starting lane o re-groups the
  bytes into mixed streams -- find o in the sync header before de-multiplexing.
  Unit secrets are the R0/R1 taps and all seeds. The beacon register R2 is the
  exception: its degree Lb and tap mask are carried in the sync header, so R2's
  state can be recovered by solving its (small) linear output system over GF(2)
  rather than by Berlekamp-Massey.

  (FIELD-INTEL, UNVERIFIED - author no longer with the unit)
    * The three registers' byte outputs are XOR-combined into the mask.
    * R0 taps: b11 and b5,  seed 0x0BEEF.
    * R1 taps: b13 and b7,  seed 0x0F1E2D.
    * R2 taps: b17 and b9,  seed 0x01234.
    * Lane burst length is 4 and the visit order always starts at R0.
  Treat the whole block above as suspect; it did not reproduce a known header
  during the analyst's first pass.

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
  interleaver: the masked bytes are written row-major into fixed-width lanes
  and read back column-major. A stale memo claims 4-byte lanes; that figure
  is contradicted by the current firmware's lane count.

Files
  keystream_sample.bin   bytes [0:15] = header XOR mask[0:15]; bytes [15:64]
                         are 0x00 (redacted / lost on capture).
  radio_packet.bin       12-byte cleartext sync header + lane_interleave(message
                         XOR mask[0:len]).

Task
  Find the lane offset in the sync header, de-multiplex the surviving sample
  bytes into the three registers (two via Berlekamp-Massey, the degree-23
  beacon via its published taps + a tiny GF(2) solve), regenerate as much mask
  as the packet needs, undo the lane interleave, and read the payload. The flag
  (FTA{...}) is inside the decoded message.

Masked byte semantics
  masked_byte  = plaintext_byte XOR mask_byte    (bitwise XOR, 8 bits)
  payload_byte = lane_interleave(masked_byte)     (see "Post-mask transform")

Stale plaintext fragment (RECORDED - from an earlier channel, do not submit):
  "...beacon check... FTA{lfsr_is_not_a_public_key_23} ..."
""".replace("__HEADER__", HEADER.decode())


def main():
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
    msg = base.encode()
    assert len(msg) > SAMPLE_LEN, len(msg)

    mask = build_mask(len(msg))
    masked = bytes(m ^ k for m, k in zip(msg, mask))
    ct = permute(masked)                                        # Layer 4

    bdeg = max(REGISTERS[BEACON][0])
    header = pack_header(LANE_OFF, BURST, bdeg, REGISTERS[BEACON][0])
    packet = header + ct

    sample = bytearray(h ^ k for h, k in zip(HEADER, mask[:SAMPLE_LEN]))
    sample[REDACT_FROM:] = b"\x00" * (SAMPLE_LEN - REDACT_FROM)  # Layer 3

    (OUT / "keystream_sample.bin").write_bytes(bytes(sample))
    (OUT / "radio_packet.bin").write_bytes(packet)
    (OUT / "SIGNAL_SPEC.txt").write_text(SIGNAL_SPEC, encoding="utf-8")

    for r, (taps, seed) in enumerate(REGISTERS):
        tag = "BEACON(published)" if r == BEACON else "secret"
        print(f"[M04] R{r} deg={max(taps)} taps={taps} seed=0x{seed:X} [{tag}]")
    print(f"[M04] round-robin burst={BURST} lane_off={LANE_OFF} "
          f"-> visits {[ (g+LANE_OFF) % 3 for g in range(3) ]}")
    print(f"[M04] header {len(HEADER)}B (exposed {REDACT_FROM}B), "
          f"message {len(msg)}B, lane transpose block {BLOCK}B")
    print(f"[M04] wrote {len(sample)}B sample + {len(packet)}B packet "
          f"(={HDR_LEN}B sync header + {len(ct)}B ct) -> {OUT}")


if __name__ == "__main__":
    main()
