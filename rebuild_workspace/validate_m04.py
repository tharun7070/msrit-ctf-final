#!/usr/bin/env python3
"""M04 - Underground XOR Radio. Validator (private).

  1. Runs the reference solver as a fresh process; it must print PASS + the
     canonical flag.
  2. Wrong-flag rejection: corrupt a ciphertext byte that maps (through wash,
     spin and the lane transpose) onto a byte inside the flag body; the decode
     must no longer carry the flag.
  3. The cleartext header fields must all matter -- a wrong lane offset, the
     FIELD-INTEL (wrong) beacon taps, or skipping either new header-keyed layer
     (WASH, SPIN) must NOT yield the flag.
  4. Trap checks: branchB_candidate.bin is exactly the genuine wrong-taps
     branch (a dead end that looks like progress) and carries no flag;
     legacy_burst.bin decodes (by the FIELD-INTEL method) to the DECOY flag.
  5. Anti-leak: the real flag appears in NO shipped artefact.
"""
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L
import solve_m04 as S

REAL_FLAG = L.FLAGS["M04"]
DECOY_FLAG = "FTA{l1n34r_f33db4ck_b34c0n_f4k3}"
SPEC_FALSE_BEACON_TAPS = [17, 9]
LEGACY_REGISTERS = [([11, 5], 0x5EE), ([13, 7], 0x1F1E),
                    ([17, 9], 0x1234), ([23, 9], 0xDEAD)]
LEGACY_BURST = 4
LEGACY_OFF = 0
BLOCK = 8


def decode_legacy(out):
    ct = (out / "legacy_burst.bin").read_bytes()
    mask = S.build_mask_from_regs(len(ct), LEGACY_REGISTERS, LEGACY_BURST, LEGACY_OFF)
    return bytes(c ^ k for c, k in zip(S.unpermute(ct, BLOCK), mask))


def has_flag(pt):
    m = re.search(rb"FTA\{[^}]+\}", pt)
    return m.group(0).decode() if m else None


def main():
    here = Path(__file__).resolve().parent

    # 1. run the solver as a fresh process
    r = subprocess.run([sys.executable, str(here / "solve_m04.py")],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"solver exited {r.returncode}\n{r.stderr}"
    assert f"[M04] PASS -> {REAL_FLAG}" in r.stdout, f"solver stdout: {r.stdout!r}"
    print(r.stdout.strip())

    out = L.out_dir("M04")
    packet = (out / "radio_packet.bin").read_bytes()
    h = S.parse_header(packet)
    assert h["crc_ok"], "sync header CRC did not verify"

    pt = S.decode(packet)
    good = has_flag(pt)
    assert good == REAL_FLAG, good
    off_pt = pt.index(b"FTA{")

    # 2. wrong-flag rejection: map a flag-body byte back to its ct index.
    perm = S.permutation(len(pt))                    # pt[p] <- transposed[perm[p]]
    t = perm[off_pt + 6]
    base = (t // 16) * 16
    j = t % 16
    m = min(16, len(pt) - base)
    spun_idx = base + ((j - h["xk"] % m) % m)         # ct[spun_idx] -> pt[off_pt+6]
    bad = bytearray(packet)
    bad[S.HDR_LEN + spun_idx] ^= 0x01
    wrong = has_flag(S.decode(bytes(bad)))
    assert wrong is not None, "no flag after corruption"
    assert wrong != REAL_FLAG, "wrong flag was NOT rejected"

    # 3. every header field must matter
    other = next(o for o in (0, 1, 2) if o != h["off"])
    assert has_flag(S.decode(packet, force_off=other)) != REAL_FLAG, "wrong lane offset"
    assert has_flag(S.decode(packet, force_taps=SPEC_FALSE_BEACON_TAPS)) != REAL_FLAG, \
        "wrong beacon taps decoded the flag"
    assert has_flag(S.decode(packet, skip_wash=True)) != REAL_FLAG, "skipping WASH worked"
    assert has_flag(S.decode(packet, skip_spin=True)) != REAL_FLAG, "skipping SPIN worked"
    assert has_flag(S.decode(packet, force_xk=(h["xk"] + 1) % 16)) != REAL_FLAG, \
        "wrong SPIN key worked"

    # 4a. dead-end trap = exactly the genuine wrong-taps branch, no flag
    branch = (out / "branchB_candidate.bin").read_bytes()
    branch_ref = S.decode(packet, force_taps=SPEC_FALSE_BEACON_TAPS)
    assert branch == branch_ref, "dead-end artefact != the genuine wrong-taps branch"
    assert REAL_FLAG.encode() not in branch
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in branch) / len(branch)
    assert printable > 0.5, f"dead-end does not look like progress ({printable:.2f})"

    # 4b. decoy flag found first via the legacy burst (the FIELD-INTEL method)
    lpt = decode_legacy(out)
    assert REAL_FLAG.encode() not in lpt
    assert DECOY_FLAG.encode() in lpt, "legacy burst did not yield the decoy flag"
    note = (out / "OPERATOR_NOTE.txt").read_text(encoding="utf-8")
    assert DECOY_FLAG in note, "operator note lost the decoy flag"

    # 5. anti-leak across every shipped artefact
    for p in out.iterdir():
        if p.is_file():
            assert REAL_FLAG.encode() not in p.read_bytes(), f"FLAG leaked in {p.name}"

    print(f"[M04] VALIDATE OK (lane_off={h['off']} burst={h['burst']} "
          f"beacon_deg={h['bdeg']}, good={good!r}, wrong rejected={wrong!r}, "
          f"offset {other}/wrong-taps/skip-wash/skip-spin/wrong-key rejected, "
          f"dead-end==wrong-taps (printable {printable:.0%}), "
          f"decoy={DECOY_FLAG!r} via legacy)")


if __name__ == "__main__":
    main()
