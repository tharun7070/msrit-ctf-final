#!/usr/bin/env python3
"""E11 reference solver.

The capture holds one relay burst. Reassembly:
  1. open the shipped capture (ghost_relay.pcap);
  2. walk Ethernet/IPv4/UDP to the COURIER RELAY PROTOCOL header;
  3. keep the genuine family (magic 0xCB01, session 0xC11A); CRC-gate the DATA
     fragments and merge the two sub-streams (udp/7001 even + udp/7002 odd) by
     their global SEQ;
  4. decode the control key from base64(rot13(hex(SK))), XOR the SHA256
     keystream and zlib-inflate.

The decoy family (magic 0xCB02 on udp/7003) is ignored here; the validator
inspects it separately to prove it never yields the real flag.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "relay"))
import lib_fta as L            # noqa: E402
import relay_proto as P        # noqa: E402


def collect(frames, magic, session):
    """Return (control_frag, {seq: fragment}) for the CRC-valid data frames."""
    ctrl, seqs = None, {}
    for eth in frames:
        if len(eth) < 14 or eth[12:14] != b"\x08\x00":
            continue
        _sport, _dport, payload = P.udp_payload(eth)
        if len(payload) < 8:
            continue
        m, sess, seq, crc, frag = P.parse_frame(payload)
        if m != magic or sess != session:
            continue
        if seq == P.SEQ_CONTROL:
            ctrl = frag
        elif P.crc16_ccitt_false(frag) == crc:
            seqs[seq] = frag
    return ctrl, seqs


def solve():
    raw = (L.out_dir("E11") / "ghost_relay.pcap").read_bytes()
    frames = P.parse_pcap(raw)

    ctrl, seqs = collect(frames, P.FRAME_MAGIC_GENUINE, P.SESSION_E11)
    assert ctrl is not None, "genuine CONTROL frame missing"
    text = P.decode_drop(ctrl, seqs)
    m = re.search(r"FTA\{[a-z0-9_]+\}", text)
    assert m and m.group(0) == L.FLAGS["E11"], ("unexpected flag", text)
    print("[E11] PASS ->", m.group(0))
    return m.group(0)


if __name__ == "__main__":
    solve()
