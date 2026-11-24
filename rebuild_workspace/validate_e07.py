#!/usr/bin/env python3
"""E07 - Wanted Poster. Validator (private).

  1. Runs the reference solver end to end as a fresh subprocess and checks it
     prints PASS + the canonical flag.
  2. NEGATIVE tests proving the traps do NOT yield the real flag:
       NEG 1 - the DECOY watchword advertised in DEPUTIZE.txt (FREEWAY);
       NEG 2 - the naive LSB decoy flag hidden in the poster's pixel data;
       NEG 3 - a wrong rail count.
  3. Anti-leak: the real flag never appears verbatim in the poster bytes.
"""
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L
import solve_e07 as S


def main():
    here = Path(__file__).resolve().parent

    # 1. run the solver as a fresh process
    r = subprocess.run([sys.executable, str(here / "solve_e07.py")],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"solver exited {r.returncode}\n{r.stderr}"
    expected = f"[E07] PASS -> {L.FLAGS['E07']}"
    assert expected in r.stdout, f"solver stdout: {r.stdout!r}"
    print(r.stdout.strip())

    out = L.out_dir("E07")
    poster = out / "wanted_poster.png"
    note = (out / "DEPUTIZE.txt").read_text(encoding="utf-8")

    V = S.read_ciphertext(poster)
    key = S.read_seal_key(poster)
    rails = S.parse_rails(note)
    good = S.rail_fence_decode(S.vigenere_decrypt(V, key), rails)
    assert good == L.FLAGS["E07"], good

    # NEG 1: the decoy watchword in DEPUTIZE.txt must not produce the real flag
    assert "FREEWAY" in note, "expected the decoy watchword in DEPUTIZE.txt"
    wrong_key = S.rail_fence_decode(S.vigenere_decrypt(V, "FREEWAY"), rails)
    assert wrong_key != L.FLAGS["E07"], "decoy watchword produced the real flag!"

    # NEG 2: the naive LSB decoy is a DIFFERENT flag
    lsb = S.read_lsb_payload(poster)
    m = re.search(rb"FTA\{[a-z0-9_]+\}", lsb)
    assert m, "LSB decoy flag not found"
    decoy = m.group(0).decode()
    assert decoy != L.FLAGS["E07"], "LSB decoy equals the real flag!"

    # NEG 3: a wrong rail count must not yield the flag
    wrong_rails = S.rail_fence_decode(S.vigenere_decrypt(V, key), rails + 1)
    assert wrong_rails != L.FLAGS["E07"], "wrong rail count accepted!"

    # anti-leak: the real flag is nowhere verbatim in the artifacts
    assert L.FLAGS["E07"].encode() not in poster.read_bytes(), "flag leaked!"

    print(f"[E07] VALIDATE OK (key={key!r}, neg_watchword={wrong_key!r}, "
          f"neg_lsb={decoy!r}, neg_rails={wrong_rails!r})")


if __name__ == "__main__":
    main()
