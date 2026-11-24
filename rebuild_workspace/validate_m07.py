#!/usr/bin/env python3
"""M07 validation harness.

Checks:
  1. solve_m07.py runs to completion and prints ``[M07] PASS -> <flag>``.
  2. The recovered C2 endpoint + session id are present and sane.
  3. Negative tests: the trap key does not open LIVE; a corrupted heap record
     trips the record check; a wrong token fails the tag gate.
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import lib_fta as L
import solve_m07

M07_DIR = L.out_dir("M07")


def main():
    expected = L.FLAGS["M07"]

    # 1. solver runs cleanly
    r = subprocess.run([sys.executable, str(HERE / "solve_m07.py")],
                       cwd=str(HERE), capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "[M07] PASS -> " + expected in r.stdout, r.stdout
    print("[validate] solver OK:", r.stdout.strip())

    # 2. endpoint + session id recovered
    flag, host, port, sid = solve_m07.recover()
    assert flag == expected and port > 0 and len(sid) == 16
    print("[validate] recovered C2 %s:%d sid=%s..." % (host, port, sid.hex()[:8]))

    cfg = (M07_DIR / "nightshift_config.bin").read_bytes()
    ram = (M07_DIR / "ram_slice.bin").read_bytes()

    # 3a. a corrupted heap record trips the record check
    bad = bytearray(ram)
    bad[10 + 5] ^= 0xFF
    try:
        solve_m07.recover_ram_key(bytes(bad))
        raise SystemExit("[validate] corrupted heap record was accepted!")
    except ValueError:
        pass

    # 3b. the trap key (shadow K2SH in place of KEY2) does not open LIVE
    _, token = solve_m07.solve_m06.recover()
    sec = solve_m07.parse_sections(cfg)
    recs = {name: (status, data) for name, status, data in solve_m07.parse_ram(ram)}
    trap_key = solve_m07.kdf(token, solve_m07.xor_all([
        recs[b"KEY0"][1], recs[b"KEY1"][1], recs[b"K2SH"][1], recs[b"KEY3"][1]]))
    try:
        solve_m07.dec_blob(trap_key, sec[b"LIVE"])
        raise SystemExit("[validate] trap key unexpectedly opened LIVE!")
    except ValueError:
        pass

    # 3c. a wrong token fails the tag gate
    try:
        solve_m07.recover(cfg_buf=cfg, ram_buf=ram)
    except Exception as ex:  # pragma: no cover - recover() should succeed
        raise SystemExit("[validate] genuine recover failed: %r" % (ex,))
    assert solve_m07.mac(b"\x00" * 16, b"ns-config-tag") != sec[b"TAGV"]

    print("[validate] negative routes rejected")
    print("[validate] M07 VALIDATE OK (flag=%s)" % expected)


if __name__ == "__main__":
    main()
