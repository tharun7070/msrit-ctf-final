#!/usr/bin/env python3
"""M03 - LSPD Midnight Audit. Generator (private organizer tooling).

Produces, in challenges_rebuilt/MEDIUM/M03:
  * lspd_auth.log     -- 1000-entry KEYED hash-chained audit log, 3 entries
                         forged (spread over two checkpoint blocks) plus a
                         decoy event sequence.
  * audit_delta.bin   -- TRIPLY nested sidecar holding the ORIGINAL content of
                         the forged entries.
  * CHAIN_SPEC.txt    -- participant-facing format documentation (also carries
                         the per-block checkpoint roots).

Keyed chain:
    content_i    = "<seq>|<timestamp>|<event_code>|<data>"
    chain_hash_i = HMAC_SHA256(key = SALT, msg = chain_hash_{i-1} + content_i)
    genesis      = 64*"0"
  The 2-byte SALT is NOT stored anywhere: the participant must brute-force the
  small salt space and match the first block's checkpoint root.

Block checkpoints (every 100 entries):
    root_b = HMAC_SHA256(key = SALT, msg = "block=<b>|" + concat(contents_b))
  The roots are published in CHAIN_SPEC.txt; the salt is not.

Forgery = content_i rewritten but chain_hash_i left as originally computed, so a
keyed recomputation flags exactly those lines. The forged entries live in two
different checkpoint blocks -> MORE THAN ONE block has a broken root; repairing
a single block is not enough.

Decoy event sequence = a contiguous run of "<c>_REACCEPT" codes at the head of
the log whose first characters pairwise-XOR to a fake flag. A naive
"code.endswith('ACCEPT')" (substring) rule latches onto it; the genuine carriers
end with the exact class token "_ACCEPT".

Flag recovery (kept OUT of every participant-facing artifact):
    Take every event_code ending exactly "_ACCEPT"; classify it by the low bit
    of sha256(code); the flag is the XOR of the class-0 first-character column
    with the class-1 first-character column, in file order.

Private organizer tooling. Never shipped verbatim.
"""
import hashlib
import hmac
import random
import string
import struct
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

FLAG = L.FLAGS["M03"]
OUT = L.out_dir("M03")

N_ENTRIES = 1000
BLOCK = 100
N_BLOCKS = N_ENTRIES // BLOCK
SALT_BYTES = 2                      # small brute-forceable salt space
DELTA_MAGIC = b"AUD2"
TRANSPOSE_W = 7                     # columnar transpose width (stored in delta)
XOR_MUL = 0x5D                      # index-derived XOR keystream
XOR_ADD = 0x1F
FORGE_TARGETS = [604, 655, 812]     # blocks 7, 7 and 9 -> second broken block

DECOY_FLAG = "FTA{f4k3_ch41n_unkey3d_l00ks_f1n3}"

# Characters usable as the FIRST character of an event_code. Never '|' (field
# separator) and never a control char, so the log stays line-parseable.
SHARE_POOL = [c for c in (string.ascii_letters + string.digits + "!#$%&*+-=?@^_~")
              if c != "|"]
NON_ACCEPT_CLASSES = ["DENY", "TRACE", "ESCORT", "PATROL", "ALERT", "STOP"]
DECOY_CLASS = "REACCEPT"            # substring "ACCEPT" but not the exact class


def hmac_hex(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def content_of(e) -> str:
    return f"{e[0]}|{e[1]}|{e[2]}|{e[3]}"


def code_class(ec: str) -> int:
    """Cross-field class: low bit of the first hex nibble of sha256(code)."""
    return int(hashlib.sha256(ec.encode()).hexdigest()[0], 16) & 1


def build_shares(rnd, text) -> list:
    """Two first-characters per byte; x ^ y == byte, both printable.
    Pairs sit adjacent, so a naive adjacent-XOR of them yields `text`."""
    shares = []
    for ch in text:
        f = ord(ch)
        while True:
            x = rnd.choice(SHARE_POOL)
            y = chr(ord(x) ^ f)
            if 33 <= ord(y) <= 126 and y != "|":
                shares.append(x)
                shares.append(y)
                break
    return shares


def build_carrier_pairs(rnd, text) -> list:
    """One (class-0 char, class-1 char) pair per byte. The pair XORs to the
    byte and the two characters land in OPPOSITE hash classes, so the genuine
    predicate (class-0 column ^ class-1 column) recovers `text`."""
    pairs = []
    for ch in text:
        f = ord(ch)
        while True:
            x = rnd.choice(SHARE_POOL)
            y = chr(ord(x) ^ f)
            if not (33 <= ord(y) <= 126) or y == "|":
                continue
            cx = code_class(f"{x}_ACCEPT")
            cy = code_class(f"{y}_ACCEPT")
            if cx != cy:
                even, odd = (x, y) if cx == 0 else (y, x)
                pairs.append((even, odd))
                break
    return pairs


def make_data(rnd, seq):
    unit = rnd.randint(100, 999)
    tmpl = rnd.choice([
        "unit=UNIT-{u}; call=10-{c}; note=radio check ok",
        "unit=UNIT-{u}; plate=5AND{n}; note=traffic stop logged",
        "unit=UNIT-{u}; call=10-{c}; note=dispatch ack received",
        "unit=UNIT-{u}; zone=D{zone}; note=patrol sweep complete",
        "unit=UNIT-{u}; call=11-{c}; note=CCTV relay synced",
    ])
    return tmpl.format(u=unit, c=rnd.randint(10, 99), n=rnd.randint(100, 999),
                       zone=rnd.randint(1, 9))


def rle_encode(data: bytes) -> bytes:
    """Custom RLE (see CHAIN_SPEC.txt):
         token 0x00 <n> <n raw bytes>   -> literal block (n in 1..255)
         token <n> <value>              -> run of `value` repeated n times (n in 3..255)
    """
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        j = i
        while j < n and data[j] == data[i] and (j - i) < 255:
            j += 1
        run = j - i
        if run >= 3:
            out.append(run)
            out.append(data[i])
            i = j
            continue
        # literal block: gather until the next run of >= 3
        lit = bytearray()
        while i < n and len(lit) < 255:
            k = i
            while k < n and data[k] == data[i] and (k - i) < 255:
                k += 1
            if k - i >= 3:
                break
            lit.append(data[i])
            i += 1
        out.append(0x00)
        out.append(len(lit))
        out.extend(lit)
    return bytes(out)


def xor_index(data: bytes) -> bytes:
    """Layer 2 of the nested delta: XOR every byte with an index-derived
    keystream byte = (index * 0x5D + 0x1F) mod 256."""
    return bytes(b ^ ((i * XOR_MUL + XOR_ADD) & 0xFF) for i, b in enumerate(data))


def transpose_fwd(data: bytes, w: int) -> bytes:
    """Layer 3 of the nested delta: pad to a multiple of `w`, fill a w-column
    matrix row-major, then emit it column-major."""
    n = len(data)
    rows = (n + w - 1) // w
    padded = data + b"\x00" * (rows * w - n)
    out = bytearray()
    for c in range(w):
        for r in range(rows):
            out.append(padded[r * w + c])
    return bytes(out)


def block_msg(b: int, contents) -> bytes:
    return (f"block={b}|" + "".join(contents)).encode()


def find_breaks(lines, key) -> list:
    prev = "0" * 64
    breaks = []
    for idx, line in enumerate(lines):
        content = "|".join(line.split("|")[:4])
        if hmac_hex(key, (prev + content).encode()) != line.split("|")[4]:
            breaks.append(idx)
        prev = line.split("|")[4]
    return breaks


def decode_flag(lines) -> str:
    evens, odds = [], []
    for line in lines:
        ec = line.split("|")[2]
        if ec.endswith("_ACCEPT"):
            (evens if code_class(ec) == 0 else odds).append(ec[0])
    assert len(evens) == len(odds), (len(evens), len(odds))
    return "".join(chr(ord(a) ^ ord(b)) for a, b in zip(evens, odds))


def naive_flag(lines) -> str:
    """The decoy path: substring match on 'ACCEPT' + adjacent-XOR."""
    chars = [ln.split("|")[2][0] for ln in lines if ln.split("|")[2].endswith("ACCEPT")]
    return "".join(chr(ord(chars[i]) ^ ord(chars[i + 1]))
                   for i in range(0, len(chars) - 1, 2))


def main():
    rnd = random.Random(0xA0D17C0DE)
    salt = bytes(rnd.randrange(256) for _ in range(SALT_BYTES))

    # ---- event codes ------------------------------------------------------
    decoy_n = 2 * len(DECOY_FLAG)
    carrier_n = 2 * len(FLAG)
    reserved = set(FORGE_TARGETS)
    pool = [s for s in range(decoy_n + BLOCK, N_ENTRIES + 1) if s not in reserved]
    carrier_seqs = sorted(reserved | set(rnd.sample(pool, carrier_n - len(reserved))))
    assert len(carrier_seqs) == carrier_n

    carrier_code = {}
    for j, (even, odd) in enumerate(build_carrier_pairs(rnd, FLAG)):
        carrier_code[carrier_seqs[2 * j]] = f"{even}_ACCEPT"
        carrier_code[carrier_seqs[2 * j + 1]] = f"{odd}_ACCEPT"

    decoy_shares = build_shares(rnd, DECOY_FLAG)

    # ---- build entries ----------------------------------------------------
    t0 = datetime(2026, 11, 23, 0, 0, 0)
    entries = []
    for seq in range(1, N_ENTRIES + 1):
        ts = (t0 + timedelta(seconds=seq * 7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        if seq <= decoy_n:
            ec = f"{decoy_shares[seq - 1]}_{DECOY_CLASS}"
        elif seq in carrier_code:
            ec = carrier_code[seq]
        else:
            ec = f"{rnd.choice(SHARE_POOL)}_{rnd.choice(NON_ACCEPT_CLASSES)}"
        entries.append([seq, ts, ec, make_data(rnd, seq), None])

    # ---- seal the keyed chain --------------------------------------------
    prev = "0" * 64
    for e in entries:
        h = hmac_hex(salt, (prev + content_of(e)).encode())
        e[4] = h
        prev = h

    # ---- checkpoint roots over original contents -------------------------
    roots = []
    for b in range(1, N_BLOCKS + 1):
        chunk = [content_of(e) for e in entries[(b - 1) * BLOCK:b * BLOCK]]
        roots.append(hmac_hex(salt, block_msg(b, chunk)))

    # sanity: the genuine predicate recovers the flag on untampered entries
    pristine = [f"{e[0]}|{e[1]}|{e[2]}|{e[3]}|{e[4]}" for e in entries]
    assert decode_flag(pristine) == FLAG
    assert naive_flag(pristine)[:len(DECOY_FLAG)] == DECOY_FLAG, naive_flag(pristine)

    # ---- forge: two share corruptions + one class downgrade, two blocks ---
    originals = {}
    for k, seq in enumerate(sorted(FORGE_TARGETS)):
        idx = seq - 1
        originals[seq] = content_of(entries[idx])
        old_ec = entries[idx][2]
        if k < 2:
            alt = rnd.choice(SHARE_POOL)
            while alt == old_ec[0]:
                alt = rnd.choice(SHARE_POOL)
            entries[idx][2] = f"{alt}_ACCEPT"
        else:
            entries[idx][2] = f"{old_ec[0]}_DENY"

    log_lines = [f"{e[0]}|{e[1]}|{e[2]}|{e[3]}|{e[4]}" for e in entries]
    (OUT / "lspd_auth.log").write_text("\n".join(log_lines) + "\n", encoding="utf-8")

    # ---- triply-nested delta ---------------------------------------------
    delta = bytearray(DELTA_MAGIC)
    delta.append(TRANSPOSE_W)
    delta += struct.pack("<H", len(originals))
    for seq in sorted(originals):
        r = rle_encode(originals[seq].encode())
        blob = transpose_fwd(xor_index(r), TRANSPOSE_W)
        delta += struct.pack("<H", seq) + struct.pack("<I", len(r))
        delta += struct.pack("<I", len(blob)) + blob
    (OUT / "audit_delta.bin").write_bytes(bytes(delta))

    (OUT / "CHAIN_SPEC.txt").write_text(render_spec(roots), encoding="utf-8")

    # ---- self-checks ------------------------------------------------------
    breaks = find_breaks(log_lines, salt)
    assert len(breaks) == len(FORGE_TARGETS), breaks
    forged_seqs = [int(log_lines[i].split("|")[0]) for i in breaks]
    assert sorted(forged_seqs) == sorted(FORGE_TARGETS), forged_seqs

    broken_blocks = set()
    for i in breaks:
        broken_blocks.add((i // BLOCK) + 1)
    assert len(broken_blocks) >= 2, broken_blocks

    print(f"[M03] wrote {len(log_lines)} log lines -> {OUT / 'lspd_auth.log'}")
    print(f"[M03] forged seqs (verified): {forged_seqs}  blocks {sorted(broken_blocks)}")
    print(f"[M03] checkpoint roots: {len(roots)} (salt = {SALT_BYTES} bytes, hidden)")
    print(f"[M03] delta bytes: {len(delta)} -> {OUT / 'audit_delta.bin'}")
    print(f"[M03] decoy seq block 1..{decoy_n} -> {DECOY_FLAG}")


def render_spec(roots):
    root_lines = "\n".join(
        f"  root[{b:>2}]  end_seq={b * BLOCK:<4}  digest={r}"
        for b, r in enumerate(roots, 1))
    spec = CHAIN_SPEC
    for token, value in (("__ROOTS__", root_lines), ("__W__", str(TRANSPOSE_W)),
                         ("__XMUL__", hex(XOR_MUL)), ("__XADD__", hex(XOR_ADD)),
                         ("__BLOCK__", str(BLOCK)), ("__NBLOCKS__", str(N_BLOCKS))):
        spec = spec.replace(token, value)
    return spec


CHAIN_SPEC = """\
LSPD AUTOMATED AUDIT BUS -- CHAIN FILE SPECIFICATION
====================================================

FILE: lspd_auth.log
  One record per line:
      <seq>|<timestamp>|<event_code>|<data>|<chain_hash>
  Fields:
    seq         integer dispatch sequence number, 1..1000, strictly increasing
    timestamp   ISO-8601 UTC, e.g. 2026-11-23T00:00:07Z
    event_code  audit token of the form "<first>_<CLASS>" where <first> is a
                single non-'|' printable character and <CLASS> is the event
                class (e.g. ACCEPT, DENY, TRACE, ESCORT, PATROL, ALERT, STOP)
    data        free-form dispatch note (never contains '|')
    chain_hash  64 lowercase hex chars

CHAIN DEFINITION (KEYED)
  Let content_i = "<seq>|<timestamp>|<event_code>|<data>" (the first four
  fields). The chain is drawn with HMAC-SHA256 under a secret key:
      chain_hash_i = HMAC_SHA256( key = SALT,
                                  msg = chain_hash_{i-1} + content_i )
      chain_hash_0 = "0" * 64          (64 ASCII zeroes, the genesis link)
  To verify a file, walk it top-to-bottom recomputing each chain_hash from the
  PRECEDING STORED hash and the current content. A record whose recomputed hash
  differs from its stored hash has been tampered with.

  The SALT is a 2-byte (16-bit) value. It is NOT stored anywhere in this file
  set. Recover it as follows ("roots first"): take the block-1 checkpoint root
  printed below and brute-force the 65536 candidate salts, recomputing block-1's
  root for each candidate, and keep the one that matches. No other candidate
  will match.

BLOCK CHECKPOINTS
  Records are grouped into fixed blocks of __BLOCK__. For block b the checkpoint
  root is
      root_b = HMAC_SHA256( key = SALT,
                            msg = "block=<b>|" + concatenated block-b contents )
  Block b spans records <seq> in [ __BLOCK__*(b-1)+1 .. __BLOCK__*b ]. The
  __NBLOCKS__ roots are:

__ROOTS__

  Both the per-record keyed chain AND every block root must agree. A block whose
  recomputed root differs from the value above is compromised. (Breaking an
  early block does NOT corrupt a later block's root; each block is rooted
  independently, so several blocks can be broken at once.)

FILE: audit_delta.bin
  A TRIPLY nested binary patch carrying the ORIGINAL content (the first four
  fields, i.e. the "<seq>|<timestamp>|<event_code>|<data>" string) of every
  record that was altered after the chain was sealed. Layout:

      magic            4 bytes, ASCII "AUD2"
      width            1 byte  (columnar-transpose width W = __W__)
      record_count     uint16 little-endian
      then record_count records, each:
          seq          uint16 little-endian  (which log record this restores)
          raw_len      uint32 little-endian  (length of the inner RLE blob)
          blob_len     uint32 little-endian  (length of the stored blob)
          blob         blob_len bytes

  The content bytes pass through THREE stages on the way in; undo them in
  reverse:
      stage 1  RLE   : content -> run-length encoded blob (see below)
      stage 2  XOR   : rle[i] ^= ((i * __XMUL__ + __XADD__) mod 256)  (index-derived)
      stage 3  TRNS  : the XORed bytes are zero-padded to a multiple of W, laid
                       into a W-column matrix row-major, and emitted column-major
  To decode one record:
      1. inverse-transpose `blob` with width W -> padded stream, keep first
         raw_len bytes -> the XORed RLE stream.
      2. undo the stage-2 XOR over the first raw_len positions.
      3. RLE-decode the result -> the original content.

  The custom RLE (stage 1):
      token 0x00 <n> <n bytes>   literal block, <n> is 1..255 raw bytes
      token <n> <value>          a run of <value> repeated <n> times (n is 3..255)
  Note 0x00 is reserved for the literal opcode, so run counts are always >= 3.
  Undoing only one or two stages yields garbage.

FLAG DERIVATION (cross-field predicate)
  Consider every record whose event_code ends with the exact class token
  "_ACCEPT". Classify each such code by the low bit of the first hex nibble of
  its SHA-256 digest, i.e. class(code) = int(sha256_hex(code)[0], 16) & 1.
  Walking the file top-to-bottom, build two columns by taking the FIRST
  character of each code in each class. The flag is the byte-wise XOR of the
  class-0 column with the class-1 column, in order.
"""


if __name__ == "__main__":
    main()
