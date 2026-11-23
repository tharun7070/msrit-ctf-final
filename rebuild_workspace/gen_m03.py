#!/usr/bin/env python3
"""M03 - LSPD Midnight Audit. Generator (private organizer tooling).

Produces, in challenges_rebuilt/MEDIUM/M03:
  * lspd_auth.log     -- 1000-entry hash-chained audit log, 3 entries forged
  * audit_delta.bin   -- custom RLE patch holding the ORIGINAL content of the 3
                         forged entries
  * CHAIN_SPEC.txt    -- participant-facing format documentation

Hash chain:
    content_i    = "<seq>|<timestamp>|<event_code>|<data>"
    chain_hash_i = sha256hex(chain_hash_{i-1} + content_i), genesis = 64*"0"

Forgery = content_i was rewritten but chain_hash_i left as originally computed,
so recomputing the chain flags exactly those 3 lines.

Flag recovery (kept OUT of every participant-facing artifact):
    For every entry whose event_code ends with "_ACCEPT", take the FIRST
    character of the event_code. XOR adjacent pairs -> the flag bytes.

Private organizer tooling. Never shipped verbatim.
"""
import hashlib
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
N_FORGED = 3
DELTA_MAGIC = b"AUD1"

# Characters usable as the FIRST character of an event_code. Never '|' (field
# separator) and never a control char, so the log stays line-parseable.
SHARE_POOL = [c for c in (string.ascii_letters + string.digits + "!#$%&*+-=?@^_~")
              if c != "|"]
NON_ACCEPT_CLASSES = ["DENY", "TRACE", "ESCORT", "PATROL", "ALERT", "STOP"]


def sha256hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def build_shares(rnd) -> list:
    """Two first-characters per flag byte; x ^ y == flag byte, both printable."""
    shares = []
    for ch in FLAG:
        f = ord(ch)
        while True:
            x = rnd.choice(SHARE_POOL)
            y = chr(ord(x) ^ f)
            if 33 <= ord(y) <= 126 and y != "|":
                shares.append(x)
                shares.append(y)
                break
    return shares


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


def find_breaks(lines) -> list:
    prev = "0" * 64
    breaks = []
    for idx, line in enumerate(lines):
        seq, ts, ec, data, h = line.split("|")
        calc = sha256hex(prev + f"{seq}|{ts}|{ec}|{data}")
        if calc != h:
            breaks.append(idx)
        prev = h
    return breaks


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

CHAIN DEFINITION
  Let content_i = "<seq>|<timestamp>|<event_code>|<data>" (the first four
  fields). The chain is:
      chain_hash_i = sha256_hex( chain_hash_{i-1} + content_i )
      chain_hash_0 = "0" * 64          (64 ASCII zeroes, the genesis link)
  i.e. each record commits to the PREVIOUS record's stored hash. To verify a
  file, walk it top-to-bottom recomputing each chain_hash from the PRECEDING
  STORED hash and the current content. A record whose recomputed hash differs
  from its stored hash has been tampered with.

FILE: audit_delta.bin
  A binary patch carrying the ORIGINAL content (the first four fields, i.e.
  the "<seq>|<timestamp>|<event_code>|<data>" string) of every record that was
  altered after the chain was sealed. Layout:

      magic            4 bytes, ASCII "AUD1"
      record_count     uint16 little-endian
      then record_count records, each:
          seq          uint16 little-endian  (which log record this restores)
          blob_len     uint32 little-endian  (length of the RLE blob below)
          blob         blob_len bytes of RUN-LENGTH-ENCODED content

  The content bytes are compressed with this custom RLE:
      token 0x00 <n> <n bytes>   literal block, <n> is 1..255 raw bytes
      token <n> <value>          a run of <value> repeated <n> times (n is 3..255)
  Note 0x00 is reserved for the literal opcode, so run counts are always >= 3.

  Restoring a record means replacing its first four fields with the decoded
  original content. The record's stored chain_hash is untouched (the delta
  only rewrites content), which is exactly what re-seals the chain.
"""


def main():
    rnd = random.Random(0xA0D17C0DE)
    shares = build_shares(rnd)
    assert len(shares) == 2 * len(FLAG)

    accept_seqs = sorted(rnd.sample(range(1, N_ENTRIES + 1), len(shares)))
    share_by_seq = {seq: shares[i] for i, seq in enumerate(accept_seqs)}

    t0 = datetime(2026, 11, 23, 0, 0, 0)
    entries = []
    for seq in range(1, N_ENTRIES + 1):
        ts = (t0 + timedelta(seconds=seq * 7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        if seq in share_by_seq:
            ec = f"{share_by_seq[seq]}_ACCEPT"
        else:
            ec = f"{rnd.choice(SHARE_POOL)}_{rnd.choice(NON_ACCEPT_CLASSES)}"
        entries.append([seq, ts, ec, make_data(rnd, seq), None])

    # seal the chain
    prev = "0" * 64
    for e in entries:
        h = sha256hex(prev + f"{e[0]}|{e[1]}|{e[2]}|{e[3]}")
        e[4] = h
        prev = h

    # forge 3 ACCEPT records: two with a corrupted share char, one whose class
    # is downgraded so the ACCEPT set silently changes.
    targets = sorted(rnd.sample(accept_seqs, N_FORGED))
    originals = {}
    for k, seq in enumerate(targets):
        idx = seq - 1
        originals[seq] = (f"{entries[idx][0]}|{entries[idx][1]}|"
                          f"{entries[idx][2]}|{entries[idx][3]}")
        old_ec = entries[idx][2]
        if k < 2:
            share = old_ec[0]
            alt = rnd.choice(SHARE_POOL)
            while alt == share:
                alt = rnd.choice(SHARE_POOL)
            entries[idx][2] = f"{alt}_ACCEPT"
        else:
            entries[idx][2] = f"{old_ec[0]}_DENY"

    log_lines = [f"{e[0]}|{e[1]}|{e[2]}|{e[3]}|{e[4]}" for e in entries]
    (OUT / "lspd_auth.log").write_text("\n".join(log_lines) + "\n", encoding="utf-8")

    delta = bytearray(DELTA_MAGIC)
    delta += struct.pack("<H", N_FORGED)
    for seq in sorted(originals):
        blob = rle_encode(originals[seq].encode())
        delta += struct.pack("<H", seq) + struct.pack("<I", len(blob)) + blob
    (OUT / "audit_delta.bin").write_bytes(bytes(delta))

    (OUT / "CHAIN_SPEC.txt").write_text(CHAIN_SPEC, encoding="utf-8")

    breaks = find_breaks(log_lines)
    assert len(breaks) == N_FORGED, breaks
    forged_seqs = [int(log_lines[i].split("|")[0]) for i in breaks]
    assert sorted(forged_seqs) == targets

    print(f"[M03] wrote {len(log_lines)} log lines -> {OUT / 'lspd_auth.log'}")
    print(f"[M03] forged seqs (verified): {forged_seqs}")
    print(f"[M03] delta bytes: {len(delta)} -> {OUT / 'audit_delta.bin'}")


if __name__ == "__main__":
    main()
