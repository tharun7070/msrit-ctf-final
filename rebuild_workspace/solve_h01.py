#!/usr/bin/env python3
"""H01 "Zancudo Deadbolt" -- reference solver (organizer / participant path).

Reverse-engineering path:
  1. ``zancudo_gate`` is a stripped Linux x86-64 ELF, so the tables are found by
     their content, not by symbols. The 256-byte SBOX is the unique window in the
     file that is a permutation of 0..255; its 4-byte little-endian length prefix
     marks the start of the embedded vault: [len][SBOX 256][K len][TARGET len].
  2. Reconstruct the constraint system: per byte i,
         (SBOX[in[i]] * K[i]) mod 251 == TARGET[i]
     With 251 prime and K[i] != 0, invert the multiplication via the modular
     inverse, then invert the SBOX (each residue has exactly one pre-image here).
  3. The recovered passphrase is the flag; confirm by executing the gate.
"""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, r"d:\ctf\FLAG_THEFT_AUTO_FINAL\rebuild_workspace")
import lib_fta as L

OUT = L.out_dir("H01")
GATE = OUT / "zancudo_gate"
MOD = 251
MAXLEN = 200
PERM = set(range(256))


def wsl_path(p) -> str:
    s = str(p).replace("\\", "/")
    return "/mnt/" + s[0].lower() + s[2:]


def find_vault(data: bytes):
    hits = []
    for i in range(4, len(data) - 256):
        w = data[i:i + 256]
        if set(w) == PERM:
            ln = int.from_bytes(data[i - 4:i], "little")
            if 1 <= ln <= MAXLEN:
                hits.append((i, ln))
    assert len(hits) == 1, f"expected exactly one vault candidate, got {hits}"
    i, ln = hits[0]
    sbox = data[i:i + 256]
    k = data[i + 256:i + 256 + ln]
    target = data[i + 256 + ln:i + 256 + 2 * ln]
    return list(sbox), list(k), list(target), ln


def recover(sbox, k, target, ln) -> str:
    # map residue (mod 251) -> unique pre-image byte
    preimage = {}
    for b, s in enumerate(sbox):
        r = s % MOD
        if r in preimage:
            preimage[r] = None          # ambiguous; keep as sentinel
        else:
            preimage[r] = b
    out = bytearray()
    for idx in range(ln):
        inv = pow(k[idx], -1, MOD)      # K[idx] != 0 and 251 prime
        r = (target[idx] * inv) % MOD
        b = preimage.get(r)
        assert b is not None, f"byte {idx}: residue {r} has no unique pre-image"
        out.append(b)
    return out.decode()


def solve():
    data = GATE.read_bytes()
    sbox, k, target, ln = find_vault(data)
    flag = recover(sbox, k, target, ln)
    assert flag == L.FLAGS["H01"], flag

    # confirm against the live binary
    r = subprocess.run(["wsl.exe", "-e", "bash", "-lc",
                        f"'{wsl_path(GATE)}' '{flag}'"],
                       capture_output=True, text=True)
    ok = "ZANCUDO DEADBOLT RELEASED" in r.stdout
    print(f"[H01] gate banner: {r.stdout.strip().splitlines()[0] if r.stdout else r.stderr.strip()}")
    assert ok and r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    print("[H01] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
