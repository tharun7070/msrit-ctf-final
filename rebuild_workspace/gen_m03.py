#!/usr/bin/env python3
"""M03 - LSPD Midnight Audit. Generator (private organizer tooling).

Produces, in challenges_rebuilt/MEDIUM/M03:
  * lspd_auth.log    -- 1000-entry tamper-evident audit log. Each record is
                        chained by a KEYED HMAC whose key is BLOCK-DEPENDENT
                        (a salt schedule), and every 100-record block is pinned
                        by a checkpoint root. Three records are forged across
                        two different blocks.
  * audit_delta.bin  -- TWO sealed regions: region A (quintuply nested originals
                        of the forged records, keyed by the recovered salt) and
                        region B (the flag mask, keyed by material that only
                        exists AFTER a repair).
  * CHAIN_SPEC.txt   -- participant-facing format documentation + block roots.
  * OPS_NOTE.txt     -- a CANARY: an official-looking note that advertises a
                        WRONG method (unkeyed chain, salt 0x0000, plain RLE).
  * flash_backup.bin -- a BAIT blob that decodes (under the canary's wrong
                        method) into a plausible-looking but unrecoverable
                        pseudo-log: a dead end that looks like progress.

Keyed chain (BLOCK-DEPENDENT key / salt schedule):
    salt_1   = 2-byte secret, hidden, brute-forced against published root[1]
    salt_b   = sha256(b"LSPD/chain-salt|" + root_{b-1})[:2]      (b >= 2)
    content_i    = "<seq>|<timestamp>|<event_code>|<data>"
    chain_hash_i = HMAC_SHA256(key = salt_{block(i)}, msg = prev + content_i)
    genesis      = 64*"0"
Recovering ONE salt does NOT repair the file: each block is keyed by a
different salt derived from the *previous published root*.

Block checkpoints (every 100 entries):
    root_b = HMAC_SHA256(key = salt_b, msg = "block=<b>|" + concat(contents_b))

Trap block: block 6 is left fully intact (its chain and its published root both
agree), yet it carries a contiguous run of near-miss "<c>_ACCEPTED" tokens that
a naive substring matcher decodes into a honeypot flag. A solver who only
confirms chain/root integrity stops there.

Region A of the delta is FIVE layers deep, the last two keyed/derived:
    content -> RLE -> XOR(index) -> transpose(W) -> XOR(keystream(salt_1))
            -> rotate-left(R bits, R = derived from the last checkpoint root)
Region B holds the 33-byte flag mask XORed with a keystream keyed by
    sha256(b"AUD4-B|" + root_last + b"|" + <original content of last forged rec>)
so region A must be decoded and the chain repaired before region B is readable.

Flag recovery (kept OUT of every participant-facing artifact):
    predicate: take every event_code ending exactly "_ACCEPT"; classify by the
    low bit of sha256(code)[0]; XOR the class-0 first-char column with the
    class-1 column -> a 33-byte sealed token M.
    flag = M XOR (region-B mask).

Private organizer tooling. Never shipped verbatim.
"""
import base64
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
SALT_BYTES = 2                      # small brute-forceable bootstrap salt
TRANSPOSE_W = 7
XOR_MUL = 0x5D
XOR_ADD = 0x1F
MAGIC_A = b"AUD4"
MAGIC_B = b"AUDB"
DOM_SALT = b"LSPD/chain-salt|"
DOM_KA = b"AUD4-A|"
DOM_KB = b"AUD4-B|"

TRAP_BLOCK = 6                      # intact block carrying the honeypot run
DECOY_CLASS = "REACCEPT"            # substring "ACCEPT", not the exact class
HONEY_CLASS = "ACCEPTED"            # substring "ACCEPT", not the exact class
FORGE_AT_BLOCK = [4, 8, 10]         # three forgeries, three different blocks

DECOY_FLAG = "FTA{r34cc3pt_run_1s_n0t_th3_4ud1t}"
HONEYPOT_FLAG = "FTA{cl34n_bl0ck_h0nyp0t_4cc3pt3d}"

# The sealed token the cross-field predicate yields (printable, NOT the flag).
SEALED_TOKEN = ("l5pd_s3al3d_aud1t_t0k3n_v2" + "_" * 8)[:len(FLAG)]
assert len(SEALED_TOKEN) == len(FLAG) and all(33 <= ord(c) <= 126 for c in SEALED_TOKEN)
# region-B mask: SEALED_TOKEN XOR mask == FLAG  ->  final unwrap
FLAG_MASK = bytes(ord(a) ^ ord(b) for a, b in zip(SEALED_TOKEN, FLAG))

SHARE_POOL = [c for c in (string.ascii_letters + string.digits + "!#$%&*+-=?@^_~")
              if c != "|"]
NON_ACCEPT_CLASSES = ["DENY", "TRACE", "ESCORT", "PATROL", "ALERT", "STOP"]


# ---------------------------------------------------------------------------
# primitives
# ---------------------------------------------------------------------------
def hmac_hex(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def keystream(key: bytes, n: int) -> bytes:
    out = bytearray()
    ctr = 0
    while len(out) < n:
        out += hashlib.sha256(key + struct.pack("<I", ctr)).digest()
        ctr += 1
    return bytes(out[:n])


def rotl(b: int, r: int) -> int:
    return ((b << r) | (b >> (8 - r))) & 0xFF


def rotr(b: int, r: int) -> int:
    return ((b >> r) | (b << (8 - r))) & 0xFF


def content_of(e) -> str:
    return f"{e[0]}|{e[1]}|{e[2]}|{e[3]}"


def code_class(ec: str) -> int:
    return int(hashlib.sha256(ec.encode()).hexdigest()[0], 16) & 1


def block_msg(b: int, contents) -> bytes:
    return (f"block={b}|" + "".join(contents)).encode()


def derive_salt(prev_root: str) -> bytes:
    return hashlib.sha256(DOM_SALT + prev_root.encode()).digest()[:SALT_BYTES]


# ---------------------------------------------------------------------------
# code construction
# ---------------------------------------------------------------------------
def build_shares(rnd, text) -> list:
    """Two first-characters per byte; adjacent pair XORs to the byte."""
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
    """One (class-0 char, class-1 char) pair per byte, XORing to the byte."""
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


# ---------------------------------------------------------------------------
# region A codec (five layers)
# ---------------------------------------------------------------------------
def rle_encode(data: bytes) -> bytes:
    out = bytearray()
    i, n = 0, len(data)
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
    return bytes(b ^ ((i * XOR_MUL + XOR_ADD) & 0xFF) for i, b in enumerate(data))


def transpose_fwd(data: bytes, w: int) -> bytes:
    n = len(data)
    rows = (n + w - 1) // w
    padded = data + b"\x00" * (rows * w - n)
    out = bytearray()
    for c in range(w):
        for r in range(rows):
            out.append(padded[r * w + c])
    return bytes(out)


def rot_of(root_last: str) -> int:
    """Rotation amount derived from the LAST published checkpoint root."""
    return (int(root_last, 16) % 7) + 1


def encode_region_a(content: bytes, ka: bytes, r: int) -> tuple:
    blob = rle_encode(content)
    raw_len = len(blob)
    blob = xor_index(blob)
    blob = transpose_fwd(blob, TRANSPOSE_W)
    ks = keystream(ka, len(blob))
    blob = bytes(b ^ k for b, k in zip(blob, ks))
    blob = bytes(rotl(b, r) for b in blob)
    return raw_len, blob


# ---------------------------------------------------------------------------
# flag / decoy helpers
# ---------------------------------------------------------------------------
def predicate_token(lines) -> str:
    evens, odds = [], []
    for ln in lines:
        ec = ln.split("|")[2]
        if ec.endswith("_ACCEPT"):
            (evens if code_class(ec) == 0 else odds).append(ec[0])
    assert len(evens) == len(odds), (len(evens), len(odds))
    return "".join(chr(ord(a) ^ ord(b)) for a, b in zip(evens, odds))


def run_flags(lines, token: str) -> str:
    """Adjacent-XOR over each contiguous run of "<c>_<token>" codes."""
    out = []
    run = []
    prev_seq = None
    for ln in lines:
        f = ln.split("|")
        seq, ec = int(f[0]), f[2]
        if ec.endswith("_" + token):
            if prev_seq is not None and seq != prev_seq + 1:
                out.append(run)
                run = []
            run.append(ec[0])
            prev_seq = seq
        elif run:
            out.append(run)
            run = []
            prev_seq = None
    if run:
        out.append(run)
    res = []
    for rn in out:
        res.append("".join(chr(ord(rn[i]) ^ ord(rn[i + 1]))
                           for i in range(0, len(rn) - 1, 2)))
    return "".join(res)


def find_breaks(lines, salts) -> list:
    prev = "0" * 64
    breaks = []
    for idx, line in enumerate(lines):
        b = idx // BLOCK
        content = "|".join(line.split("|")[:4])
        if hmac_hex(salts[b], (prev + content).encode()) != line.split("|")[4]:
            breaks.append(idx)
        prev = line.split("|")[4]
    return breaks


def recompute_roots(lines, salts) -> list:
    roots = []
    for b in range(1, N_BLOCKS + 1):
        chunk = ["|".join(ln.split("|")[:4])
                 for ln in lines[(b - 1) * BLOCK:b * BLOCK]]
        roots.append(hmac_hex(salts[b - 1], block_msg(b, chunk)))
    return roots


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------
def main():
    rnd = random.Random(0xA0D17C0DE)
    bootstrap_salt = bytes(rnd.randrange(256) for _ in range(SALT_BYTES))

    # ---- choose sequence layout ------------------------------------------
    decoy_n = 2 * len(DECOY_FLAG)
    honey_start = (TRAP_BLOCK - 1) * BLOCK + 1
    honey_n = 2 * len(HONEYPOT_FLAG)
    honey_seqs = set(range(honey_start, honey_start + honey_n))
    carrier_n = 2 * len(SEALED_TOKEN)

    allowed = [s for s in range(decoy_n + 1, N_ENTRIES + 1) if s not in honey_seqs]
    while True:
        carrier_seqs = sorted(rnd.sample(allowed, carrier_n))
        blocks = {(s - 1) // BLOCK + 1 for s in carrier_seqs}
        if all(b in blocks for b in FORGE_AT_BLOCK):
            break

    forge_seqs = []
    used_blocks = set()
    for tb in FORGE_AT_BLOCK:
        cand = [s for s in carrier_seqs
                if (s - 1) // BLOCK + 1 == tb and s not in forge_seqs]
        assert cand, f"no carrier in block {tb}"
        forge_seqs.append(cand[0])
    forge_seqs = sorted(forge_seqs)

    # ---- event codes ------------------------------------------------------
    decoy_shares = build_shares(rnd, DECOY_FLAG)
    honey_shares = build_shares(rnd, HONEYPOT_FLAG)
    carrier_code = {}
    for j, (even, odd) in enumerate(build_carrier_pairs(rnd, SEALED_TOKEN)):
        carrier_code[carrier_seqs[2 * j]] = f"{even}_ACCEPT"
        carrier_code[carrier_seqs[2 * j + 1]] = f"{odd}_ACCEPT"

    # ---- entries (original, sealed) --------------------------------------
    t0 = datetime(2026, 11, 23, 0, 0, 0)
    entries = []
    honey_list = sorted(honey_seqs)
    for seq in range(1, N_ENTRIES + 1):
        ts = (t0 + timedelta(seconds=seq * 7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        if seq <= decoy_n:
            ec = f"{decoy_shares[seq - 1]}_{DECOY_CLASS}"
        elif seq in honey_seqs:
            ec = f"{honey_shares[honey_list.index(seq)]}_{HONEY_CLASS}"
        elif seq in carrier_code:
            ec = carrier_code[seq]
        else:
            ec = f"{rnd.choice(SHARE_POOL)}_{rnd.choice(NON_ACCEPT_CLASSES)}"
        entries.append([seq, ts, ec, make_data(rnd, seq), None])

    # ---- salt schedule + roots (over original contents) ------------------
    contents = [content_of(e) for e in entries]
    roots = []
    salts = []
    for b in range(1, N_BLOCKS + 1):
        salt_b = bootstrap_salt if b == 1 else derive_salt(roots[b - 2])
        salts.append(salt_b)
        roots.append(hmac_hex(salt_b, block_msg(b, contents[(b - 1) * BLOCK:b * BLOCK])))

    # ---- seal the keyed chain --------------------------------------------
    prev = "0" * 64
    for idx, e in enumerate(entries):
        h = hmac_hex(salts[idx // BLOCK], (prev + content_of(e)).encode())
        e[4] = h
        prev = h

    pristine = [f"{e[0]}|{e[1]}|{e[2]}|{e[3]}|{e[4]}" for e in entries]
    assert predicate_token(pristine) == SEALED_TOKEN

    # ---- forge: rewrite content, keep the stored (original) hash ---------
    originals = {}
    for k, seq in enumerate(forge_seqs):
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

    # ---- region A (five layers, keyed by the recovered bootstrap salt) ---
    r = rot_of(roots[-1])
    ka = DOM_KA + bootstrap_salt
    delta = bytearray(MAGIC_A)
    delta.append(TRANSPOSE_W)
    delta += struct.pack("<H", len(originals))
    for seq in sorted(originals):
        raw_len, blob = encode_region_a(originals[seq].encode(), ka, r)
        delta += struct.pack("<H", seq) + struct.pack("<I", raw_len)
        delta += struct.pack("<I", len(blob)) + blob

    # ---- region B (flag mask keyed by post-repair material) --------------
    last_original = originals[forge_seqs[-1]]
    kb = DOM_KB + roots[-1].encode() + b"|" + last_original.encode()
    masked = bytes(m ^ k for m, k in zip(FLAG_MASK, keystream(kb, len(FLAG_MASK))))
    delta += MAGIC_B + struct.pack("<H", len(masked)) + masked
    (OUT / "audit_delta.bin").write_bytes(bytes(delta))

    (OUT / "CHAIN_SPEC.txt").write_text(render_spec(roots), encoding="utf-8")
    write_canary()
    write_bait(forge_seqs)

    # ---- self-checks ------------------------------------------------------
    breaks = find_breaks(log_lines, salts)
    assert len(breaks) == len(forge_seqs), breaks
    forged_seqs = [int(log_lines[i].split("|")[0]) for i in breaks]
    assert sorted(forged_seqs) == forge_seqs, forged_seqs
    broken_blocks = sorted({(i // BLOCK) + 1 for i in breaks})
    assert len(broken_blocks) >= 2, broken_blocks
    assert TRAP_BLOCK not in broken_blocks, "trap block must stay intact"
    assert not all(recompute_roots(log_lines, salts)[bb - 1] == roots[bb - 1]
                   for bb in broken_blocks)
    # full recovery self-check
    repaired = list(log_lines)
    for i in breaks:
        seq, _t, _e, _d, h = repaired[i].split("|")
        repaired[i] = f"{originals[int(seq)]}|{h}"
    assert find_breaks(repaired, salts) == [], "chain still broken"
    assert recompute_roots(repaired, salts) == roots, "roots still broken"
    token = predicate_token(repaired)
    assert token == SEALED_TOKEN
    recovered = bytes(ord(a) ^ b for a, b in zip(token, FLAG_MASK)).decode()
    assert recovered == FLAG, recovered
    # traps behave
    assert run_flags(pristine, DECOY_CLASS)[:len(DECOY_FLAG)] == DECOY_FLAG
    assert run_flags(pristine, HONEY_CLASS)[:len(HONEYPOT_FLAG)] == HONEYPOT_FLAG
    assert DECOY_FLAG != FLAG and HONEYPOT_FLAG != FLAG

    anti_leak()

    print(f"[M03] wrote {len(log_lines)} log lines -> {OUT / 'lspd_auth.log'}")
    print(f"[M03] forged seqs (verified): {forged_seqs}  blocks {broken_blocks}")
    print(f"[M03] salt schedule: bootstrap {SALT_BYTES}B hidden + {N_BLOCKS - 1} derived")
    print(f"[M03] trap block {TRAP_BLOCK} intact, honeypot run seq "
          f"{honey_start}..{honey_start + honey_n - 1} -> {HONEYPOT_FLAG}")
    print(f"[M03] decoy run 1..{decoy_n} -> {DECOY_FLAG}")
    print(f"[M03] delta bytes: {len(delta)} (region A 5 layers + region B mask)")


def write_canary():
    note = OPS_NOTE
    (OUT / "OPS_NOTE.txt").write_text(note, encoding="utf-8")


def write_bait(forge_seqs):
    """flash_backup.bin: under the canary's WRONG method (plain RLE) it decodes
    to a plausible-looking but fake 'recovered log' -> a dead end."""
    lines = []
    for seq in forge_seqs:
        ts = "2026-11-23T00:00:00Z"
        lines.append(f"{seq}|{ts}|x_ACCEPT|unit=UNIT-000; note=restored-from-flash (UNVERIFIED)")
    pseudo = ("\n".join(lines) + "\n").encode()
    (OUT / "flash_backup.bin").write_bytes(rle_encode(pseudo))


def anti_leak():
    """Hard guarantee: the real flag (and its inner token) appear in NO file."""
    inner = FLAG[4:-1]
    for p in sorted(OUT.iterdir()):
        if not p.is_file():
            continue
        blob = p.read_bytes()
        assert FLAG.encode() not in blob, f"REAL FLAG LEAKED in {p.name}"
        assert inner.encode() not in blob, f"FLAG TOKEN LEAKED in {p.name}"


def render_spec(roots):
    root_lines = "\n".join(
        f"  root[{b:>2}]  end_seq={b * BLOCK:<4}  digest={r}"
        for b, r in enumerate(roots, 1))
    spec = CHAIN_SPEC
    for token, value in (("__ROOTS__", root_lines), ("__W__", str(TRANSPOSE_W)),
                         ("__XMUL__", hex(XOR_MUL)), ("__XADD__", hex(XOR_ADD)),
                         ("__BLOCK__", str(BLOCK)), ("__NBLOCKS__", str(N_BLOCKS)),
                         ("__TRAP__", str(TRAP_BLOCK))):
        spec = spec.replace(token, value)
    return spec


CHAIN_SPEC = """\
LSPD AUTOMATED AUDIT BUS -- CHAIN FILE SPECIFICATION
====================================================
(Authoritative. Unofficial desk notes are not part of this specification and
 have been known to be stale.)

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

CHAIN DEFINITION (KEYED, BLOCK-DEPENDENT KEY)
  Let content_i = "<seq>|<timestamp>|<event_code>|<data>" (the first four
  fields). The chain is drawn with HMAC-SHA256 under a per-block key drawn from
  a salt schedule:
      salt_1 = the 2-byte (16-bit) bootstrap key; NOT stored anywhere
      salt_b = SHA256( "LSPD/chain-salt|" + root_{b-1} )[0:2]      for b >= 2
      chain_hash_i = HMAC_SHA256( key = salt_{block(i)},
                                  msg = chain_hash_{i-1} + content_i )
      chain_hash_0 = "0" * 64          (64 ASCII zeroes, the genesis link)
  block(i) = floor((i-1) / __BLOCK__) + 1.
  Walk the file top-to-bottom recomputing each chain_hash from the PRECEDING
  STORED hash and the current content. A record whose recomputed hash differs
  from its stored hash has been tampered with. NOTE that a single recovered key
  does NOT verify the whole file: each block uses its own salt, chained off the
  previous block's PUBLISHED root.

  To bootstrap: take the block-1 root printed below and brute-force the 65536
  candidate 2-byte salts, recomputing block-1's root for each; keep the match.

BLOCK CHECKPOINTS
  Records are grouped into fixed blocks of __BLOCK__. For block b:
      root_b = HMAC_SHA256( key = salt_b,
                            msg = "block=<b>|" + concatenated block-b contents )
  Block b spans records <seq> in [ __BLOCK__*(b-1)+1 .. __BLOCK__*b ]. The
  __NBLOCKS__ roots are:

__ROOTS__

  Both the per-record keyed chain AND every block root must agree. (Breaking an
  early block does NOT corrupt a later block's PUBLISHED root; each block is
  rooted independently, so several blocks can be broken at once.)

FILE: audit_delta.bin
  A sidecar with TWO sealed regions.

  REGION A -- originals of every altered record, nested FIVE deep.
      magic            4 bytes, ASCII "AUD4"
      width            1 byte  (columnar-transpose width W = __W__)
      record_count     uint16 little-endian
      then record_count records, each:
          seq          uint16 little-endian  (which log record this restores)
          raw_len      uint32 little-endian  (length of the inner RLE blob)
          blob_len     uint32 little-endian  (length of the stored blob)
          blob         blob_len bytes
  The content passes through FIVE stages on the way in; undo them in REVERSE.
  Let R = (int(root___NBLOCKS__, 16) mod 7) + 1  (the rotation amount, taken
  from the LAST checkpoint root above) and let
  KA = b"AUD4-A|" + <bootstrap salt>.  Keystream bytes are
  KS = SHA256(key || uint32-le counter 0,1,2,...) concatenated.
      stage 1  RLE   : content -> run-length blob (below)
      stage 2  XOR   : rle[i] ^= ((i * __XMUL__ + __XADD__) mod 256)
      stage 3  TRNS  : zero-pad to a multiple of W, fill W-column matrix
                       row-major, emit column-major
      stage 4  KEY   : b ^= KS(KA)            (same offset)
      stage 5  ROT   : b = rotate-left(b, R)
  To decode one record, undo stages 5..1 in that order:
      a. rotate-right each byte by R.
      b. XOR the stage-4 keystream (KA) over the blob.
      c. inverse-transpose with width W -> padded stream; keep raw_len bytes.
      d. undo the stage-2 index XOR over the first raw_len positions.
      e. RLE-decode -> original content.
  Stage 4 is keyed by the bootstrap salt: region A is unreadable until you have
  recovered salt_1. Undoing fewer/more/out-of-order stages yields garbage.

  REGION B -- the flag mask, appended after the last region-A record:
      magic            4 bytes, ASCII "AUDB"
      mask_len         uint16 little-endian
      masked           mask_len bytes = MASK ^ KS(KB)
  KB = b"AUD4-B|" + root___NBLOCKS__ + b"|" + <original content of the LAST
  restored record>  (i.e. the highest-seq record carried in region A). Region B
  therefore cannot be read until region A has been decoded AND the chain has
  been repaired.

  The custom RLE (stage 1):
      token 0x00 <n> <n bytes>   literal block, <n> is 1..255 raw bytes
      token <n> <value>          a run of <value> repeated <n> times (n 3..255)

FLAG DERIVATION (cross-field predicate, then a sealed unwrap)
  1. Predicate -- consider every record whose event_code ends with the EXACT
     class token "_ACCEPT". Classify each by the low bit of the first hex
     nibble of its SHA-256 digest: class(code) = int(sha256_hex(code)[0],16) & 1.
     Walking the file top-to-bottom, build two columns from the FIRST character
     of each such code, per class. XOR the class-0 column with the class-1
     column, byte for byte, to obtain a 33-byte sealed token M.
  2. Unwrap -- the flag is M XOR (the region-B mask), byte for byte.
  Codes whose class token merely CONTAINS "ACCEPT" (e.g. a "..._ACCEPTED" or a
  "..._REACCEPT") are NOT part of the predicate.
"""

OPS_NOTE = """\
LSPD OPS QUICKNOTE  (desk copy -- not part of the signed specification)
====================================================================
Hey nightshift,

Here's the fast way to audit the log, from the old SOP binder:

  1. The audit chain is a PLAIN SHA-256 chain. Recompute
     sha256(prev || content) and compare. The "keyed" talk is folklore.
  2. The audit salt never changes: it is the factory default 0x0000. Any
     block that fails under 0x0000 is just a transcription slip.
  3. audit_delta.bin is a single RLE stream -- decode it straight away, no
     XOR, no transpose. Takes ten seconds.
  4. The flag is the run of ACCEPT records near the head of the file: take the
     first character of each, XOR neighbours in pairs. Done.
  5. If the chain looks off, flash_backup.bin holds yesterday's pre-audit log
     as a plain RLE blob. Decode it and just re-paste the originals.

Don't overthink it. -- Sgt. B.
"""


if __name__ == "__main__":
    main()
