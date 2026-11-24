#!/usr/bin/env python3
"""M04 - Underground XOR Radio. Generator (private organizer tooling).

Produces, in challenges_rebuilt/MEDIUM/M04:
  * SIGNAL_SPEC.txt      -- participant-facing spec incl. the known header
  * keystream_sample.bin -- 64 bytes; ONLY the leading REDACT_FROM bytes are
                            header XOR mask[0:REDACT_FROM]; the tail is 0x00
                            (recorder ring-buffer fault / redacted).
  * radio_packet.bin     -- lane_interleave(message XOR mask)

Stacked layers (all deterministic, all invertible from the sample):
  L1  Two Fibonacci LFSRs of different degree (ALPHA deg 23, BRAVO deg 17).
  L2  Byte multiplexing: mask[even]=ALPHA byte stream, mask[odd]=BRAVO stream.
      (Not XOR-combined -- the decoy spec claims XOR. Multiplexing makes the
      combined bit sequence have large linear complexity, so a single
      Berlekamp-Massey pass over the whole sample does NOT converge.)
  L3  Partial known plaintext: the sample only exposes the leading
      REDACT_FROM=38 of 64 header bytes, so the raw mask is not fully revealed.
  L4  Post-XOR fixed 8-byte lane transpose (block interleave) of the payload.
  L5  Decoy parameters in SIGNAL_SPEC.txt (wrong taps/seed/lane size and a
      stale plaintext fragment) -- the real parameters are never stated.

Private organizer tooling. Never shipped verbatim.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

FLAG = L.FLAGS["M04"]
OUT = L.out_dir("M04")

# --- Layer 1: two Fibonacci LFSRs of different degree -----------------------
SEED_A = 0x5A3C19        # nonzero, < 2**23
TAPS_A = [23, 5]         # ALPHA: degree 23
SEED_B = 0x1552D         # nonzero, < 2**17
TAPS_B = [17, 3]         # BRAVO: degree 17

# --- Layer 3: partial known plaintext ---------------------------------------
REDACT_FROM = 38         # leading sample bytes that survive (of 64)
SAMPLE_LEN = 64

# --- Layer 4: lane transpose -------------------------------------------------
BLOCK = 8                # real lane size (decoy claims 4)

HEADER = ("LSPD EMERGENCY RADIO NET :: BEACON SYNC :: ALL UNITS COPY?"
          ).ljust(SAMPLE_LEN, " ").encode()
assert len(HEADER) == SAMPLE_LEN


def mask_lanes(n):
    """Layer 1+2: build an n-byte mask by multiplexing two LFSR byte streams."""
    a = L.lfsr_keystream(SEED_A, TAPS_A, (n + 1) // 2)
    b = L.lfsr_keystream(SEED_B, TAPS_B, n // 2)
    out = bytearray(n)
    for j in range(n):
        out[j] = a[j // 2] if j % 2 == 0 else b[j // 2]
    return bytes(out)


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

Transmission masking
  Two short feedback registers -- call them ALPHA and BRAVO -- feed the
  masking stream. Each register is clocked once per bit and assembles its
  output most-significant-bit first into one mask byte per eight ticks. The
  two registers' bytes are then combined into a single mask stream by the
  transmitter. Seeds and tap sets are unit secrets and are NOT recorded here.

  (FIELD-INTEL, UNVERIFIED - author no longer with the unit)
    * The two registers' byte outputs are XOR-combined into the mask.
    * ALPHA taps: b23 and b18, seed 0x00BEEF.
    * BRAVO taps: b19 and b6,  seed 0x0F1E2D.
  Treat the whole block above as suspect; it did not reproduce a known
  header during the analyst's first pass.

Known plaintext header (exactly 64 bytes, ' ' = U+0020 right padding):

  __HEADER__

  (Length: 64 bytes. Everything after the visible text is ASCII spaces.)

Capture integrity
  The recorder's ring buffer faulted mid-capture and zero-filled the tail of
  the stored sample. Only the leading 38 of the 64 channel bytes survived;
  bytes [38:64] read as 0x00 and are LOST -- do NOT feed them to the coder as
  if they were header bytes.

Post-mask transform
  Before a payload hits the wire the transmitter applies a fixed lane
  interleaver: the masked bytes are written row-major into fixed-width lanes
  and read back column-major. A stale memo claims 4-byte lanes; that figure
  is contradicted by the current firmware's lane count.

Files
  keystream_sample.bin   bytes [0:38] = header XOR mask[0:38]; bytes [38:64]
                         are 0x00 (redacted / lost on capture).
  radio_packet.bin       the intercepted payload = lane_interleave(message
                         XOR mask[0:len]).

Task
  Recover the mask generator structure from the surviving sample bytes,
  regenerate as much mask as the packet needs, undo the lane interleave, and
  read the payload. The flag (FTA{...}) is inside the decoded message.

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
    message = base
    msg = message.encode()
    assert len(msg) > SAMPLE_LEN, len(msg)

    mask = mask_lanes(len(msg))
    masked = bytes(m ^ k for m, k in zip(msg, mask))
    packet = permute(masked)                                   # Layer 4

    sample = bytearray(h ^ k for h, k in zip(HEADER, mask[:SAMPLE_LEN]))
    sample[REDACT_FROM:] = b"\x00" * (SAMPLE_LEN - REDACT_FROM)  # Layer 3

    (OUT / "keystream_sample.bin").write_bytes(bytes(sample))
    (OUT / "radio_packet.bin").write_bytes(packet)
    (OUT / "SIGNAL_SPEC.txt").write_text(SIGNAL_SPEC, encoding="utf-8")

    print(f"[M04] ALPHA deg={max(TAPS_A)} taps={TAPS_A} seed=0x{SEED_A:X}")
    print(f"[M04] BRAVO deg={max(TAPS_B)} taps={TAPS_B} seed=0x{SEED_B:X}")
    print(f"[M04] header {len(HEADER)}B (exposed {REDACT_FROM}B), "
          f"message {len(msg)}B, lane block {BLOCK}B")
    print(f"[M04] wrote {len(sample)}B sample + {len(packet)}B packet -> {OUT}")


if __name__ == "__main__":
    main()
