#!/usr/bin/env python3
"""E11 - Ghost Relay. Offline capture challenge.

Produces the participant artefact `ghost_relay.pcap`: the single burst the
crew's courier relay threw back, captured on the wire. There is no live service
to stand up -- teams open the capture, find the relay's reply among the noise,
and reassemble the parcel.

Chain: this is the SAME parcel the relay emits, framed with the COURIER RELAY
PROTOCOL (magic 0xCB01, session 0xC11A, control on udp/7000, data split
across udp/7001+7002). A decoy replay parcel (magic 0xCB02) rides udp/7003.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "relay"))
import lib_fta as L            # noqa: E402
import relay_proto as P        # noqa: E402

RELAY_IP = "10.20.30.40"
CLIENT_IP = "10.20.30.99"
RELAY_MAC = bytes.fromhex("02cb01000040")
CLIENT_MAC = bytes.fromhex("02cb02000099")

DECOY_FLAG = "FTA{r3pl4y3d_r3l4y_b41t_d0_n0t_subm1t}"


def build_burst(flag: str):
    """(src_port, frame) burst identical to what the relay emitted on the wire."""
    genuine = P.build_data_frames(flag, P.SESSION_E11, P.FRAME_MAGIC_GENUINE,
                                  P.SK_E11, two_streams=True)
    decoy = P.build_data_frames(DECOY_FLAG, P.SESSION_DECOY, P.FRAME_MAGIC_DECOY,
                                P.DECOY_KEY, two_streams=True)
    burst = [(P.PORT_BEACON,
              P.build_control(P.SESSION_E11, P.FRAME_MAGIC_GENUINE, P.SK_E11))]
    for i in range(max(len(genuine), len(decoy))):
        if i < len(genuine):
            lane, raw = genuine[i]
            burst.append((P.PORT_DATA_A if lane == 0 else P.PORT_DATA_B, raw))
        if i < len(decoy):
            burst.append((P.PORT_DECOY, decoy[i][1]))
    burst.append((P.PORT_DECOY,
                  P.build_control(P.SESSION_DECOY, P.FRAME_MAGIC_DECOY, P.DECOY_KEY)))
    return burst


def main():
    out = L.out_dir("E11")
    flag = L.FLAGS["E11"]
    burst = build_burst(flag)

    packets = []
    for sport, raw in burst:
        # relay -> client; the client is the one doing the capturing
        packets.append(P.build_udp(RELAY_MAC, CLIENT_MAC, RELAY_IP, CLIENT_IP,
                                   sport, P.PORT_BEACON, raw))

    pcap_path = out / "ghost_relay.pcap"
    P.write_pcap(pcap_path, packets)

    blob = pcap_path.read_bytes()
    assert flag.encode() not in blob, "REAL E11 flag leaked into the capture!"
    assert DECOY_FLAG.encode() not in blob, "decoy flag leaked verbatim!"

    # end-to-end round trip of the genuine drop
    frames = P.parse_pcap(blob)
    ctrl, seqs = None, {}
    for eth in frames:
        sport, _dport, payload = P.udp_payload(eth)
        magic, session, seq, crc, frag = P.parse_frame(payload)
        if magic != P.FRAME_MAGIC_GENUINE or session != P.SESSION_E11:
            continue
        if seq == P.SEQ_CONTROL:
            ctrl = frag
        elif P.crc16_ccitt_false(frag) == crc:
            seqs[seq] = frag
    assert P.decode_drop(ctrl, seqs) == flag

    print("wrote %s (%d frames)" % (pcap_path, len(packets)))
    print("[E11] genuine session=0x%04X magic=0x%04X control=udp/%d data=udp/%d+%d"
          % (P.SESSION_E11, P.FRAME_MAGIC_GENUINE, P.PORT_BEACON,
             P.PORT_DATA_A, P.PORT_DATA_B))


if __name__ == "__main__":
    main()
