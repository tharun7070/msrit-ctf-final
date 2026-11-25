#!/usr/bin/env python3
"""M03 - LSPD Midnight Audit. Validator (private).

  1. Runs the reference solver end to end; checks it prints PASS + canonical flag.
  2. Independently bootstraps the salt schedule, verifies the keyed chain and
     every block root, confirms the forgeries span more than one checkpoint
     block, repairs them via region A, reads region B and re-derives the flag.
  3. Confirms the three trap families behave:
        T1  decoy flag  -- the contiguous _REACCEPT run collapses to a fake flag;
        T2  trap block  -- block 6 is INTACT (chain + root) yet its _ACCEPTED run
                           is a honeypot flag; a chain-only check stops there;
        T3  canary      -- OPS_NOTE.txt advertises a wrong method, and following
                           it (plain RLE on flash_backup.bin) yields a plausible
                           pseudo-log, never the originals or the flag.
        T4  dead end    -- decoding region A with the canary's key (0x0000) is
                           structurally valid but does not recover the originals.
  4. Asserts a WRONG flag is rejected, and that the real flag leaks into NO file.
"""
import hashlib
import re
import string
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L
import solve_m03 as S

OUT = L.out_dir("M03")
DECOY_CLASS = "REACCEPT"
HONEY_CLASS = "ACCEPTED"
TRAP_BLOCK = 6
BLOCK = 100


def read_text(name: str) -> str:
    return (OUT / name).read_text(encoding="utf-8")


def naive_run_flags(lines, token: str) -> str:
    """The naive shortcut: adjacent-XOR over contiguous "<c>_<token>" runs."""
    return S.run_flags(lines, token)


def flip_same_class(line: str) -> str:
    f = line.split("|")
    oc = f[2]
    cls = S.code_class(oc)
    for cand in string.ascii_letters + string.digits:
        if cand != oc[0] and S.code_class(f"{cand}_ACCEPT") == cls:
            f[2] = f"{cand}_ACCEPT"
            return "|".join(f)
    raise AssertionError("no same-class alternate found")


def main():
    here = Path(__file__).resolve().parent

    # ---- 1. run the solver as a fresh process ----------------------------
    r = subprocess.run([sys.executable, str(here / "solve_m03.py")],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"solver exited {r.returncode}\n{r.stderr}"
    expected = f"[M03] PASS -> {L.FLAGS['M03']}"
    assert expected in r.stdout, f"solver stdout: {r.stdout!r}"
    print(r.stdout.strip())

    # ---- 2. independent recomputation ------------------------------------
    lines = S.read_log()
    roots = S.read_roots()
    bootstrap = S.recover_bootstrap_salt(lines, roots[0])
    salts = S.derive_salts(roots, bootstrap)
    assert len(salts) == len(roots) == 10

    breaks = S.find_breaks(lines, salts)
    assert len(breaks) == 3, breaks
    broken_blocks = sorted({(i // BLOCK) + 1 for i in breaks})
    assert len(broken_blocks) >= 2, f"forgeries confined to one block: {broken_blocks}"
    roots_before = S.recompute_roots(lines, salts)
    assert roots_before != roots, "roots were not broken"

    delta = (OUT / "audit_delta.bin").read_bytes()
    originals, off = S.parse_region_a(delta, bootstrap, roots[-1])
    mask = S.parse_region_b(delta, off, roots[-1], originals[max(originals)])

    repaired = S.repair(lines, originals)
    assert S.find_breaks(repaired, salts) == [], "chain still broken after repair"
    assert S.recompute_roots(repaired, salts) == roots, "block roots still broken"

    token = S.predicate_token(repaired)
    good = bytes(ord(c) ^ m for c, m in zip(token, mask)).decode("latin-1")
    assert good == L.FLAGS["M03"], good

    # ---- 3a. T2: the trap block is INTACT but carries a honeypot ---------
    assert TRAP_BLOCK not in broken_blocks, "trap block must stay intact"
    assert roots_before[TRAP_BLOCK - 1] == roots[TRAP_BLOCK - 1], \
        "trap block root is broken (should be clean)"
    assert not any(TRAP_BLOCK * BLOCK >= i + 1 > (TRAP_BLOCK - 1) * BLOCK
                   for i in breaks), "trap block contains a chain break"
    honey = naive_run_flags(repaired, HONEY_CLASS)
    assert honey.startswith("FTA{"), honey
    assert honey != L.FLAGS["M03"], "honeypot collapsed onto the real flag"
    print(f"[M03] T2 trap block {TRAP_BLOCK} intact; honeypot -> {honey!r} (rejected)")

    # ---- 3b. T1: the head decoy run --------------------------------------
    decoy = naive_run_flags(repaired, DECOY_CLASS)
    assert decoy.startswith("FTA{"), decoy
    assert decoy != L.FLAGS["M03"], "decoy collapsed onto the real flag"
    print(f"[M03] T1 decoy run -> {decoy!r} (rejected)")

    # ---- 3c. T3: the canary advertises a wrong method --------------------
    note = read_text("OPS_NOTE.txt")
    assert re.search(r"0x0000", note), "canary no longer baits the salt"
    assert "SHA-256" in note and "RLE" in note, "canary no longer baits the method"
    assert L.FLAGS["M03"] not in note, "real flag leaked into the canary"
    flash = (OUT / "flash_backup.bin").read_bytes()
    pseudo = S.rle_decode(flash)          # the canary's promised "plain RLE"
    assert all(9 <= b < 127 for b in pseudo), "bait did not decode to text"
    pseudo_text = pseudo.decode()
    assert "restored-from-flash" in pseudo_text, "bait lost its bait text"
    assert L.FLAGS["M03"] not in pseudo_text, "real flag leaked into the bait"
    assert pseudo_text.encode() not in {o.encode() for o in originals.values()}, \
        "bait decoded to a real original"
    print(f"[M03] T3 canary followed -> {len(pseudo)}B pseudo-log dead end (no flag)")

    # ---- 3d. T4: region A under the canary key is a dead end -------------
    try:
        wrong_originals, _ = S.parse_region_a(delta, b"\x00\x00", roots[-1])
        wrong = set(wrong_originals.values())
    except Exception as exc:                       # unrecoverable debris is fine
        wrong = {f"<decode-error:{type(exc).__name__}>"}
    assert wrong != set(originals.values()), "canary key recovered region A?!"
    assert L.FLAGS["M03"] not in " ".join(wrong), "flag leaked via dead end"
    print("[M03] T4 region A under key 0x0000 -> structurally valid garbage (dead end)")

    # ---- 4. wrong-flag rejection -----------------------------------------
    bad = list(repaired)
    for i, ln in enumerate(bad):
        if ln.split("|")[2].endswith("_ACCEPT"):
            bad[i] = flip_same_class(ln)
            break
    wrong_token = S.predicate_token(bad)
    wrong_flag = bytes(ord(c) ^ m for c, m in zip(wrong_token, mask)).decode("latin-1")
    assert wrong_flag != L.FLAGS["M03"], "wrong flag was NOT rejected"

    # ---- anti-leak: flag appears in NO artifact --------------------------
    inner = L.FLAGS["M03"][4:-1]
    for p in sorted(OUT.iterdir()):
        if p.is_file():
            blob = p.read_bytes()
            assert L.FLAGS["M03"].encode() not in blob, f"flag leaked in {p.name}"
            assert inner.encode() not in blob, f"flag token leaked in {p.name}"

    print(f"[M03] VALIDATE OK (good={good!r}, wrong rejected={wrong_flag!r})")


if __name__ == "__main__":
    main()
