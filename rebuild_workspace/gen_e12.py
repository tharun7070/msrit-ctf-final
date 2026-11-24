#!/usr/bin/env python3
"""E12 - Relay Archive. Offline capture of the SAME relay as E11.

Produces the participant artefacts:
  * relay_archive.pcap   - the relay's buffered traffic, several parcels mixed.
  * COURIER_RELAY.txt    - field notes (the TRAP: it advertises the legacy
                           single-carrier udp/7003 replay path).

Structure: every parcel uses the COURIER RELAY PROTOCOL (magic 0xCB01, control
on udp/7000). The GENUINE archive parcel is the only one delivered across TWO
carriers (udp/7001 even + udp/7002 odd) and travels on session tag 0xC11A -- the
same tag the live Ghost Relay (E11) used. The decoys are legacy single-carrier
replays left on udp/7003; each reassembles to a bait flag.

The genuine parcel's plaintext (the E12 flag) never appears verbatim in any
artifact. Deterministic output. Private organizer tooling.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "relay"))
import lib_fta as L            # noqa: E402
import relay_proto as P        # noqa: E402

SRC_MAC = bytes.fromhex("02cb01000040")
DST_MAC = bytes.fromhex("02cb02000099")
SRC_IP = "10.20.30.40"
DST_IP = "10.20.30.99"

# legacy replay sessions (all share the genuine magic, differ by tag + carrier)
DECOY1 = dict(session=0xC0DE, key=P.DECOY_KEY, flag="FTA{l3g4cy_r3pl4y_p4th_b41t}")
DECOY2 = dict(session=0xD00D, key=bytes.fromhex("00112233445566778899aabbccddeeff"),
              flag="FTA{0ld_r3l4y_buff3r_b41t}")

SPEC = """\
COURIER RELAY - ARCHIVE NOTES (recovered from a dead relay's buffer)
====================================================================

The relay you sniffed live (GHOST RELAY) also buffers its parcels off-air for
crews working dark. This dump is that buffer. Nothing here talks; the parcels
sit still and wait to be reassembled.

FRAME (custom payload; begins immediately after the 8-byte UDP header)
---------------------------------------------------------------------
  MAGIC     2 bytes   big-endian   0xCB01
  SESSION   2 bytes   big-endian   drop session tag
  SEQ       2 bytes   big-endian   fragment index (0xFFFF = CONTROL)
  CRC16     2 bytes   big-endian   CRC-16/CCITT-FALSE over FRAGMENT
  FRAGMENT  (rest)                 opaque fragment bytes

  CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflection, xor-out
  0x0000. Drop any fragment that fails the check.

CARRIERS
  CONTROL   7000   the probe port; its FRAGMENT carries the session key
  REPLAY    7003   the legacy carrier the buffer was written to

KEY DELIVERY (CONTROL.fragment)
  base64( rot13( hex(SK) ) )  ->  16-byte session key SK

PARCEL REASSEMBLY
  Sort the session's fragments by SEQ, concatenate, XOR the whole buffer with
  the keystream = SHA256(SK) repeated, then zlib-inflate. The result is the
  parcel payload (a single ASCII line).

THE ARCHIVE'S OWN TAG
  Each parcel is stamped with its SESSION tag. The genuine archive parcel
  reuses the Ghost Relay (E11) capture's tag -- the one you noted there.
  Two old fragments in this dump are stamped as legacy replays left on the
  REPLAY carrier; they inflate to claws-marked bait:

        FTA{l3g4cy_r3pl4y_p4th_b41t}      <- DECOY
        FTA{0ld_r3l4y_buff3r_b41t}        <- DECOY

  Trust the tag and the carrier, not the port number these notes hand you.
"""


def main():
    out = L.out_dir("E12")
    flag = L.FLAGS["E12"]

    genuine_data = P.build_data_frames(flag, P.SESSION_E11, P.FRAME_MAGIC_GENUINE,
                                       P.SK_E12, two_streams=True)
    d1_data = P.build_data_frames(DECOY1["flag"], DECOY1["session"],
                                  P.FRAME_MAGIC_GENUINE, DECOY1["key"],
                                  two_streams=False)
    d2_data = P.build_data_frames(DECOY2["flag"], DECOY2["session"],
                                  P.FRAME_MAGIC_GENUINE, DECOY2["key"],
                                  two_streams=False)

    strays = [
        # genuine: control on the probe port, data split across 7001 + 7002
        (P.PORT_BEACON, P.build_control(P.SESSION_E11, P.FRAME_MAGIC_GENUINE, P.SK_E12)),
        # decoys: legacy single-carrier replays on the advertised REPLAY port
        (P.PORT_DECOY, P.build_control(DECOY1["session"], P.FRAME_MAGIC_GENUINE, DECOY1["key"])),
        (P.PORT_DECOY, P.build_control(DECOY2["session"], P.FRAME_MAGIC_GENUINE, DECOY2["key"])),
    ]

    packets = []

    def emit(sport, raw):
        packets.append(P.build_udp(SRC_MAC, DST_MAC, SRC_IP, DST_IP, sport, P.PORT_BEACON, raw))

    for sport, raw in strays:
        emit(sport, raw)

    # deterministic round-robin over the three parcels' data fragments
    g = genuine_data
    for i in range(max(len(g), len(d1_data), len(d2_data))):
        if i < len(g):
            lane, raw = g[i]
            emit(P.PORT_DATA_A if lane == 0 else P.PORT_DATA_B, raw)
        if i < len(d1_data):
            emit(P.PORT_DECOY, d1_data[i][1])
        if i < len(d2_data):
            emit(P.PORT_DECOY, d2_data[i][1])

    pcap_path = out / "relay_archive.pcap"
    P.write_pcap(pcap_path, packets)
    L.write_text("E12", "COURIER_RELAY.txt", SPEC)

    blob = pcap_path.read_bytes()
    assert flag.encode() not in blob, "REAL E12 flag leaked into the pcap!"
    assert flag.encode() not in SPEC.encode(), "REAL flag leaked into the notes!"
    assert DECOY1["flag"].encode() in SPEC.encode() and DECOY2["flag"].encode() in SPEC.encode()

    # verify the genuine parcel round-trips and the decoys never equal it
    def reassemble(frames, want_session, want_two_carrier):
        ctrl, seqs = None, {}
        carriers = set()
        for eth in frames:
            sport, _dport, payload = P.udp_payload(eth)
            magic, session, seq, crc, frag = P.parse_frame(payload)
            if magic != P.FRAME_MAGIC_GENUINE or session != want_session:
                continue
            if seq == P.SEQ_CONTROL:
                ctrl = frag
            elif P.crc16_ccitt_false(frag) == crc:
                seqs[seq] = frag
                carriers.add(sport)
        if want_two_carrier and not {P.PORT_DATA_A, P.PORT_DATA_B} <= carriers:
            raise AssertionError("genuine parcel is not dual-carrier")
        if not want_two_carrier and P.PORT_DATA_B in carriers:
            raise AssertionError("decoy parcel unexpectedly dual-carrier")
        return P.decode_drop(ctrl, seqs)

    frames = P.parse_pcap(blob)
    assert reassemble(frames, P.SESSION_E11, True) == flag
    assert reassemble(frames, DECOY1["session"], False) == DECOY1["flag"]
    assert reassemble(frames, DECOY2["session"], False) == DECOY2["flag"]

    print("wrote %s (%d frames)" % (pcap_path, len(packets)))
    print("wrote %s" % (out / "COURIER_RELAY.txt"))
    print("[E12] genuine tag=0x%04X dual-carrier udp/%d+%d | decoys 0x%04X,0x%04X on udp/%d"
          % (P.SESSION_E11, P.PORT_DATA_A, P.PORT_DATA_B,
             DECOY1["session"], DECOY2["session"], P.PORT_DECOY))


if __name__ == "__main__":
    main()
