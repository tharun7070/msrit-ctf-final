#!/usr/bin/env python3
"""M08 - Nightshift C2 (Part 3 of 3): chained, HMAC-gated C2 transcript.

Ships a raw-IP/TCP capture (``nightshift_c2.pcap``) of the crew's C2 channel
plus a note.  The channel is a small stateful protocol:

    frame = magic "NC2\\x01" | ftype | seq(u32 LE) | nonce(16) | len(u16 LE)
            | ciphertext | mac(16)

  * every non-diagnostic frame is gated by HMAC-SHA256(mac_key, header+ct);
    mac_key is derived from Part 2's session id, so the frame that matters only
    authenticates once Part 2 is solved;
  * the keystream for a frame is chained: it mixes the *authenticated* previous
    frame's MAC, so frames must be walked in order and bad frames dropped;
  * the capture also carries plaintext ftype-0 diagnostic broadcasts (a plant
    bait flag) and a second flow to a decoy endpoint.

The genuine flow is only found via Part 2's C2 endpoint.  The exfil frame
yields the Part-3 flag.

Private organizer tooling.  The flag never appears in any shipped artifact.
"""
import hashlib
import hmac
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L
import gen_m07 as g7

MAGIC = b"NC2\x01"
SESSION_ID = g7.SESSION_ID
DECOY_SID = g7.DECOY_SID
C2_HOST, C2_PORT = g7.C2_HOST, g7.C2_PORT
DECOY_HOST, DECOY_PORT = "203.0.113.9", 4445

CLIENT = "10.60.4.11"
BAIT = "FTA{n1ghtsh1ft_c2_s3ss10n_b41t_d0_n0t_subm1t}"


def mac_key(sid: bytes) -> bytes:
    return hashlib.sha256(b"NS-C2-MAC" + sid).digest()


def keystream(prev: bytes, nonce: bytes, seq: int, n: int) -> bytes:
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(b"NS-C2-KS" + prev + nonce
                              + struct.pack("<I", seq) + struct.pack("<I", i)).digest()
        i += 1
    return bytes(out[:n])


def xor_key(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def header(ftype: int, seq: int, nonce: bytes, ct: bytes) -> bytes:
    return MAGIC + bytes([ftype]) + struct.pack("<I", seq) + nonce + struct.pack("<H", len(ct))


def frame_mac(sid: bytes, hv: bytes, ct: bytes) -> bytes:
    return hmac.new(mac_key(sid), hv + ct, hashlib.sha256).digest()[:16]


def build_notice(pt: bytes) -> bytes:
    """A plaintext diagnostic broadcast (ftype 0): not authenticated, not chained."""
    hv = header(0x00, 0, b"\x00" * 16, pt)
    return hv + pt + b"\x00" * 16


def genuine_items(flag: str):
    return [
        (0x01, b"NC2 HELLO client=NIGHT c2=" + f"{C2_HOST}:{C2_PORT}".encode() + b"\n"),
        (0x02, b"NC2 DATA stage=beacon ok\n"),
        (0x02, b"NC2 DATA stage=staging ok\n"),
        (0x03, b"NC2 EXFIL payload flag: " + flag.encode() + b"\n"),
    ]


def decoy_items():
    return [
        (0x01, b"NC2 HELLO client=GHOST c2=" + f"{DECOY_HOST}:{DECOY_PORT}".encode() + b"\n"),
        (0x03, b"NC2 EXFIL payload flag: " + BAIT.encode() + b"\n"),
    ]


def build_flow(frames_payloads, src, dst, sport, dport):
    """TCP handshake + one segment per payload."""
    pkts = []
    seq = 5000
    ack = 9000
    pkts.append(L.build_tcp_packet(src, dst, sport, dport, seq, 0, b"", 0x02))
    seq += 1
    pkts.append(L.build_tcp_packet(dst, src, dport, sport, ack, seq, b"", 0x12))
    ack += 1
    pkts.append(L.build_tcp_packet(src, dst, sport, dport, seq, ack, b"", 0x10))
    for p in frames_payloads:
        pkts.append(L.build_tcp_packet(src, dst, sport, dport, seq, ack, p, 0x18))
        seq += len(p)
    pkts.append(L.build_tcp_packet(src, dst, sport, dport, seq, ack, b"", 0x11))
    return pkts


NOTES = """NIGHTSHIFT C2 -- WIRE NOTE
==========================

This is the crew's command channel as it crossed the wire.  It is a small
stateful protocol, not HTTP: every real message is a frame, and the frames are
authenticated.  Do not trust a frame you cannot authenticate -- the channel is
salted with replays and a couple of tampered frames.

Our copy also picked up a plaintext diagnostic broadcast from the implant's
debug path.  It announces an "archived flag" -- do not hand that in; it is a
leftover from a build the crew retired.

The channel names multiple endpoints.  Only one of them is the live C2, and you
already have it from the config: use the endpoint AND the session id it gave
you.  The other flow on the wire belongs to a different (retired) session and
will not authenticate.

Deliverable: the exfiltrated flag.
"""


def main():
    out = L.out_dir("M08")
    flag = L.FLAGS["M08"]

    # ---- genuine flow to the live C2 -------------------------------------
    gen_list = _session_frames(SESSION_ID, genuine_items(flag))
    gen_blob = b"".join(gen_list)

    f1 = gen_list[1]
    tampered = bytearray(f1)
    tampered[30] ^= 0x01                                   # corrupt ciphertext byte
    tampered = bytes(tampered)
    replay = f1                                            # valid replay of seq 1
    notice = build_notice(b"NC2 NOTICE maintenance: archived flag "
                          + BAIT.encode() + b"\n")
    flow_a = [gen_list[0], notice, f1, tampered, replay, gen_list[2], gen_list[3]]

    # ---- decoy flow to the retired endpoint ------------------------------
    flow_b = _session_frames(DECOY_SID, decoy_items())

    packets = build_flow(flow_a, CLIENT, C2_HOST, 51552, C2_PORT)
    packets += build_flow(flow_b, CLIENT, DECOY_HOST, 51563, DECOY_PORT)
    pcap = out / "nightshift_c2.pcap"
    L.write_pcap(pcap, packets)
    (out / "C2_NOTES.txt").write_text(NOTES, encoding="utf-8")

    # ---- organizer self-checks -------------------------------------------
    # (1) genuine session decrypts (with the chain) to the Part-3 flag
    pt = _walk_chain(SESSION_ID, _parse_frames(gen_blob))
    assert flag.encode() in b"".join(pt), pt
    # (2) the decoy session decrypts (with its own sid) to the bait, not the flag
    ptb = _walk_chain(DECOY_SID, _parse_frames(b"".join(flow_b)))
    jb = b"".join(ptb)
    assert BAIT.encode() in jb and flag.encode() not in jb
    # (3) the notice is plaintext bait and never carries the real flag
    assert BAIT.encode() in notice and flag.encode() not in notice
    # (4) ignoring the chain yields no flag
    naive = _walk_chain(SESSION_ID, _parse_frames(gen_blob), chain=False)
    assert flag.encode() not in b"".join(naive), "naive route must not yield the flag"
    # (5) the tampered frame fails authentication
    tampered_fr = _parse_frames(tampered + gen_list[2])[0]
    assert not _mac_ok(SESSION_ID, tampered_fr)
    # (6) no shipped artifact leaks the flag
    assert flag.encode() not in pcap.read_bytes()
    assert flag.encode() not in (out / "C2_NOTES.txt").read_bytes()

    print("[M08] wrote %s" % out)
    print("[M08] packets=%d  genuine_frames=%d  decoy_frames=%d  bait=%s"
          % (len(packets), len(gen_list), len(flow_b), BAIT))


# ---------------------------------------------------------------------------
# parsing helpers (also exercised by the self-checks)
# ---------------------------------------------------------------------------
def _session_frames(sid, items):
    """Same as build_session but returns the list of individual frames."""
    prev = sid
    frames = []
    for seq, (ftype, pt) in enumerate(items):
        nonce = hashlib.sha256(b"NS-C2-NONCE" + sid + struct.pack("<I", seq)).digest()[:16]
        ct = xor_key(pt, keystream(prev, nonce, seq, len(pt)))
        hv = header(ftype, seq, nonce, ct)
        tag = frame_mac(sid, hv, ct)
        frames.append(hv + ct + tag)
        prev = tag
    return frames


def _parse_frames(blob: bytes):
    """Parse the concatenated frame stream into dicts."""
    out = []
    i, n = 0, len(blob)
    while i + 28 <= n:
        j = blob.find(MAGIC, i)
        if j < 0 or j + 28 > n:
            break
        ftype = blob[j + 4]
        seq = struct.unpack("<I", blob[j + 5:j + 9])[0]
        nonce = blob[j + 9:j + 25]
        ln = struct.unpack("<H", blob[j + 25:j + 27])[0]
        end = j + 27 + ln + 16
        if ln > 4096 or end > n:
            i = j + 1
            continue
        ct = blob[j + 27:j + 27 + ln]
        tag = blob[j + 27 + ln:end]
        out.append(dict(ftype=ftype, seq=seq, nonce=nonce, ct=ct, tag=tag,
                        hv=blob[j:j + 27]))
        i = end
    return out


def _mac_ok(sid, fr) -> bool:
    return hmac.compare_digest(frame_mac(sid, fr["hv"], fr["ct"]), fr["tag"])


def _walk_chain(sid, frames, chain=True):
    """MAC-gate, dedupe by seq, then walk in order returning plaintexts."""
    valid = sorted((f for f in frames if f["ftype"] != 0x00 and _mac_ok(sid, f)),
                   key=lambda f: f["seq"])
    prev = sid
    seen = set()
    pts = []
    for fr in valid:
        if fr["seq"] in seen:
            continue
        seen.add(fr["seq"])
        ks = keystream(prev if chain else sid, fr["nonce"], fr["seq"], len(fr["ct"]))
        pts.append(xor_key(fr["ct"], ks))
        prev = fr["tag"]
    return pts


if __name__ == "__main__":
    main()
