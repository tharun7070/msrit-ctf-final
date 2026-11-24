#!/usr/bin/env python3
"""Shared helpers for the FLAG THEFT AUTO rebuilt challenge generators.

Private organizer tooling. Never shipped to participants verbatim.
"""
import base64, hashlib, json, os, random, struct, zlib
from pathlib import Path

ROOT = Path("D:/ctf/FLAG_THEFT_AUTO_FINAL")
OUT = ROOT / "challenges_rebuilt"

# Canonical flags (participant-facing, CTFd-submitted). All match FTA\{[a-z0-9_]+\}.
FLAGS = {
    "E01": "FTA{41_c1ph3r_b4s3_cust0m_m0d_p4g3r_l3st3r_2026}",
    "E02": "FTA{4ff1n3_v1n3w00d_sh1ft_c0nv0y_99}",
    "E03": "FTA{ext2_st4sh_r3c0v3r3d_s4ndy_51}",
    "E04": "FTA{lsb_c0lumn_m4j0r_ut7_p13r}",
    "E05": "FTA{p0lygl0t_pdf_zip_aes_v4ult}",
    "M01": "FTA{s3c0nd_0rd3r_fl33c4_byp4ss}",
    "M02": "FTA{b1n_pr0t0_crc32_gh0st_fl1ght}",
    "M03": "FTA{h4sh_ch41n_t4mp3r_l5pd_aud1t}",
    "M04": "FTA{lfsr23_b3rl3k4mp_m4ss3y_r4d10}",
    "M05": "FTA{c0ncurr3ncy_r4c3_d15p4tch_f1x}",
    "H01": "FTA{z4nclud0_vm_d34db0lt_unl0ck}",
    "H02": "FTA{sp3ctr4l_fr33w4y_gr4ph_150m0rph}",
    "H03": "FTA{m4try0shk4_f1v3_l4y3rs_c4rv3d}",
    "H04": "FTA{rs4_crt_f4ult_l3g4l_r4gg1ng}",
    "H05": "FTA{mult1_p4rty_3sc4p3_pr0t0c0l}",
    # --- Wave 2 "namesake-easy" (labelled Easy, engineered to be brutal) ------
    "E06": "FTA{p4yph0n3_st4t1c_dtmf_tr4p}",
    "E07": "FTA{w4nt3d_p0st3r_hue_k3y_v1g3n3r3}",
    "E08": "FTA{d34d_dr0p_upl1nk_s3ss10n}",
    "E09": "FTA{ch0p_sh0p_t0k3n_f31st3l_r3v3rs3}",
    "E10": "FTA{t0w1ng_y4rd_byt3c0d3_1gn1t10n}",
    # --- Wave 3 "relay" pair (Easy, offline captures) --------------------------
    # E11 is a static wire capture; E12 is the same relay's offline archive
    # and chains back to the session tag recovered in E11.
    "E11": "FTA{gh0st_r3l4y_l1v3_c4ptur3}",
    "E12": "FTA{r3l4y_4rch1v3_m3rg3d_0ff4x}",
    # --- Wave 4 "Nightshift" malware-analysis trilogy (Medium, chained) --------
    # M06 -> M07 -> M08: each part derives a token the next part demands.
    "M06": "FTA{n1ghtsh1ft_l04d3r_unp4ck3d_t0k3n}",
    "M07": "FTA{n1ghtsh1ft_c2_c0nf1g_r4m_x0r}",
    "M08": "FTA{n1ghtsh1ft_c2_s3ss10n_ch41n3d_fr4m3s}",
}


def out_dir(cid):
    lvl = {"E": "EASY", "M": "MEDIUM", "H": "HARD"}[cid[0]]
    d = OUT / lvl / cid
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_bytes(cid, name, data: bytes):
    p = out_dir(cid) / name
    p.write_bytes(data)
    return p


def write_text(cid, name, text: str):
    p = out_dir(cid) / name
    p.write_text(text, encoding="utf-8")
    return p


# ----------------------------------------------------------------------------
# Custom base-N encoding (E01)
# ----------------------------------------------------------------------------
BASE41_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz_!@#$"
BASE41 = len(BASE41_ALPHABET)


def base41_encode(b: bytes) -> str:
    val = int.from_bytes(b, "big")
    if val == 0:
        return BASE41_ALPHABET[0]
    digs = []
    while val > 0:
        digs.append(BASE41_ALPHABET[val % BASE41])
        val //= BASE41
    return "".join(reversed(digs))


def base41_decode(s: str) -> bytes:
    val = 0
    for ch in s:
        val = val * BASE41 + BASE41_ALPHABET.index(ch)
    return val.to_bytes((val.bit_length() + 7) // 8, "big")


# ----------------------------------------------------------------------------
# Affine cipher (E02)
# ----------------------------------------------------------------------------
def affine_enc(text: str, a: int, b: int) -> str:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((a * (ord(ch) - 97) + b) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((a * (ord(ch) - 65) + b) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def affine_dec(text: str, a: int, b: int) -> str:
    ai = pow(a, -1, 26)
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ai * ((ord(ch) - 97) - b)) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ai * ((ord(ch) - 65) - b)) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def caesar_enc(text: str, shift: int) -> str:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + shift) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + shift) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


# ----------------------------------------------------------------------------
# pcap (classic, little endian) + custom binary frame (M02)
# ----------------------------------------------------------------------------
def _ip_checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_tcp_packet(src_ip, dst_ip, sport, dport, seq, ack, payload, flags=0x18):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    pseudo = (
        bytes(int(x) for x in src_ip.split("."))
        + bytes(int(x) for x in dst_ip.split("."))
        + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    )
    csum = _ip_checksum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack("!H", csum) + tcp[18:]
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH", 0x45, 0, total, 0x1A2B, 0x4000, 64, 6, 0)
    ip += bytes(int(x) for x in src_ip.split(".")) + bytes(int(x) for x in dst_ip.split("."))
    ip = ip[:10] + struct.pack("!H", _ip_checksum(ip)) + ip[12:]
    return ip + tcp + payload


FRAME_MAGIC = 0xDEAD1A70


def frame(ftype: int, payload: bytes, corrupt_crc=False) -> bytes:
    body = struct.pack("<IHH", FRAME_MAGIC, ftype, len(payload)) + payload
    crc = zlib.crc32(body) & 0xFFFFFFFF
    if corrupt_crc:
        crc ^= 0x000000FF
    return body + struct.pack("<I", crc)


def write_pcap(path: Path, packets):
    out = bytearray()
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    ts = 1_700_000_000
    for i, pkt in enumerate(packets):
        out += struct.pack("<IIII", ts + i, i * 1000, len(pkt), len(pkt))
        out += pkt
    path.write_bytes(bytes(out))


# ----------------------------------------------------------------------------
# TLV (H05)
# ----------------------------------------------------------------------------
def tlv(typ: int, val: bytes) -> bytes:
    return struct.pack(">HI", typ, len(val)) + val


def read_tlvs(buf: bytes):
    out = []
    i = 0
    while i + 6 <= len(buf):
        typ, ln = struct.unpack(">HI", buf[i:i + 6])
        i += 6
        val = buf[i:i + ln]
        i += ln
        out.append((typ, val))
    return out


# ----------------------------------------------------------------------------
# RSA helpers (H04)
# ----------------------------------------------------------------------------
def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)


def modinv(a, m):
    g, x, _ = egcd(a % m, m)
    assert g == 1
    return x % m


def generate_rsa(bits=1024, seed=1234):
    rnd = random.Random(seed)

    def is_prime(n, k=24):
        if n < 2:
            return False
        for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            if n % p == 0:
                return n == p
        d = n - 1
        r = 0
        while d % 2 == 0:
            d //= 2
            r += 1
        for _ in range(k):
            a = rnd.randrange(2, n - 1)
            x = pow(a, d, n)
            if x in (1, n - 1):
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def gen_prime(nbits):
        while True:
            p = rnd.getrandbits(nbits) | (1 << (nbits - 1)) | 1
            if is_prime(p):
                return p

    while True:
        p = gen_prime(bits // 2)
        q = gen_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        e = 65537
        phi = (p - 1) * (q - 1)
        if egcd(e, phi)[0] == 1:
            d = modinv(e, phi)
            return dict(n=n, e=e, d=d, p=p, q=q)


# ----------------------------------------------------------------------------
# LFSR (M04)
# ----------------------------------------------------------------------------
def lfsr_keystream(seed_state, taps, length):
    """Fibonacci LFSR. seed_state: int (nonzero). taps: list of tap exponents
    (1-based positions counted from the newest bit). Emits `length` bytes,
    MSB-first within each byte, output bit = XOR of tapped state bits."""
    state = seed_state
    deg = max(taps)
    bits = []
    for _ in range(length * 8):
        out = 0
        for t in taps:
            out ^= (state >> (deg - t)) & 1
        bits.append(state & 1)
        state = (state >> 1) | (out << (deg - 1))
    return bytes(int("".join(str(b) for b in bits[i:i + 8]), 2) for i in range(0, len(bits), 8))


if __name__ == "__main__":
    assert base41_decode(base41_encode(b"Hello, Los Santos!")) == b"Hello, Los Santos!"
    assert affine_dec(affine_enc("the flag is here", 7, 11), 7, 11) == "the flag is here"
    ks = lfsr_keystream(0x5AA55A, [23, 5], 16)
    assert len(ks) == 16
    print("lib_fta self-test OK")
