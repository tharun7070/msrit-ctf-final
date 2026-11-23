#!/usr/bin/env python3
"""M04 - Underground XOR Radio. Generator (private organizer tooling).

Produces, in challenges_rebuilt/MEDIUM/M04:
  * SIGNAL_SPEC.txt    -- participant-facing spec incl. the known 64-byte header
  * keystream_sample.bin -- header XOR keystream[0:64]  (64 bytes)
  * radio_packet.bin   -- message XOR keystream[0:len(message)]

Keystream is a degree-23 Fibonacci LFSR (taps [23, 5], fixed nonzero seed),
generated with lib_fta.lfsr_keystream (MSB-first within each byte). The
message embeds the flag and is longer than the 64-byte header, so the sample
alone does not reveal the whole keystream.

Private organizer tooling. Never shipped verbatim.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

FLAG = L.FLAGS["M04"]
OUT = L.out_dir("M04")

SEED = 0x5A3C19          # nonzero, < 2**23
TAPS = [23, 5]           # degree-23 Fibonacci LFSR

HEADER = "LSPD EMERGENCY RADIO NET :: CHANNEL 23 SYNC BEACON :: COPY?".ljust(64, " ")

SIGNAL_SPEC = """\
UNDERGROUND RADIO -- SIGNAL SPECIFICATION
=========================================

Keying
  Transmissions are masked with a deterministic keystream produced by a
  linear-feedback shift register of degree 23. The register is advanced once
  per bit; each byte of keystream is emitted most-significant-bit first. The
  register's seed and feedback taps are unit secrets and are NOT given here.

Known plaintext header (exactly 64 bytes, ' ' = U+0020 padding to the right):

  {header}

  (Length: 64 bytes. Everything after the visible text is ASCII spaces.)

Files
  keystream_sample.bin    64 bytes = header XOR keystream[0:64].
                          Because the header is known, this exposes the first
                          512 bits of the raw keystream.

  radio_packet.bin        the intercepted message XOR keystream[0:len]. The
                          message is longer than 64 bytes, so the captured
                          sample does not cover the whole transmission.

Task
  Recover the keystream generator from the exposed 512 bits, extend it as far
  as the packet needs, unmask the packet, and read the payload. The flag
  (FTA{{...}}) is inside the decoded message.

Masked byte semantics
  plaintext_byte = ciphertext_byte XOR keystream_byte   (bitwise XOR, 8 bits)
""".format(header=HEADER)


def main():
    message = ("[UNDERGROUND-4410] DECODED PAYLOAD >> " + FLAG + " << TX END.")
    msg = message.encode()
    assert len(HEADER) == 64, len(HEADER)
    assert len(msg) > 64, len(msg)

    ks = L.lfsr_keystream(SEED, TAPS, len(msg))
    sample = bytes(h ^ k for h, k in zip(HEADER.encode(), ks[:64]))
    packet = bytes(m ^ k for m, k in zip(msg, ks[:len(msg)]))

    (OUT / "keystream_sample.bin").write_bytes(sample)
    (OUT / "radio_packet.bin").write_bytes(packet)
    (OUT / "SIGNAL_SPEC.txt").write_text(SIGNAL_SPEC, encoding="utf-8")

    print(f"[M04] seed=0x{SEED:X} taps={TAPS}")
    print(f"[M04] header {len(HEADER)}B, message {len(msg)}B")
    print(f"[M04] wrote {len(sample)}B sample + {len(packet)}B packet -> {OUT}")


if __name__ == "__main__":
    main()
