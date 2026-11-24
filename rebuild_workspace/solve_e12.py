#!/usr/bin/env python3
"""E12 reference solver.

Inverts the Relay Archive capture:
  1. parse the classic little-endian pcap into raw frames;
  2. walk Ethernet+IPv4+UDP to the COURIER RELAY PROTOCOL header;
  3. group magic-0xCB01 parcels by SESSION tag; the genuine one is the only
     parcel carried across BOTH data carriers (udp/7001 + udp/7002) -- the
     legacy replays ride a single carrier on udp/7003;
  4. confirm the tag matches the Ghost Relay (E11) capture session tag;
  5. CRC-gate, order by SEQ, decode the key from base64(rot13(hex(SK))), XOR the
     SHA256 keystream and zlib-inflate.

The single-carrier replays are deliberately ignored here; the validator inspects
them separately to prove they never yield the real flag.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "relay"))
import lib_fta as L            # noqa: E402
import relay_proto as P        # noqa: E402


def group(frames):
    """{session: {'ctrl': frag, 'frags': {seq: frag}, 'carriers': set}}."""
    sessions = {}
    for eth in frames:
        if len(eth) < 14 or eth[12:14] != b"\x08\x00":
            continue
        sport, _dport, payload = P.udp_payload(eth)
        if len(payload) < 8:
            continue
        magic, session, seq, crc, frag = P.parse_frame(payload)
        if magic != P.FRAME_MAGIC_GENUINE:
            continue
        ent = sessions.setdefault(session, {"ctrl": None, "frags": {}, "carriers": set()})
        if seq == P.SEQ_CONTROL:
            ent["ctrl"] = frag
        elif P.crc16_ccitt_false(frag) == crc:
            ent["frags"][seq] = frag
            ent["carriers"].add(sport)
    return sessions


def live_tag():
    """The session tag recovered from the Ghost Relay capture (E11)."""
    p = L.out_dir("E11") / "ghost_relay.pcap"
    if not p.is_file():
        return None
    for eth in P.parse_pcap(p.read_bytes()):
        _sport, _dport, payload = P.udp_payload(eth)
        magic, session, seq, _crc, _frag = P.parse_frame(payload)
        if magic == P.FRAME_MAGIC_GENUINE and seq != P.SEQ_CONTROL:
            return session
    return None


def solve():
    raw = (L.out_dir("E12") / "relay_archive.pcap").read_bytes()
    frames = P.parse_pcap(raw)
    sessions = group(frames)

    dual = P.PORT_DATA_A, P.PORT_DATA_B
    genuine = [s for s, e in sessions.items() if set(dual) <= e["carriers"]]
    assert len(genuine) == 1, f"expected exactly one dual-carrier parcel, got {genuine}"
    tag = genuine[0]

    note = live_tag()
    assert note is None or tag == note, \
        f"archive tag 0x{tag:04X} does not match the Ghost Relay (E11) tag 0x{note:04X}"

    ent = sessions[tag]
    assert ent["ctrl"] is not None, "genuine CONTROL frame missing"
    text = P.decode_drop(ent["ctrl"], ent["frags"])
    m = re.search(r"FTA\{[a-z0-9_]+\}", text)
    assert m and m.group(0) == L.FLAGS["E12"], ("unexpected flag", text)
    print("[E12] PASS ->", m.group(0))
    return m.group(0)


if __name__ == "__main__":
    solve()
