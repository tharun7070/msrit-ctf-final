#!/usr/bin/env python3
"""E10 "Towing Yard Ignition" -- reference solver (organizer / participant path).

Recovers the yard ignition phrase from `ignition.vmb`.

The workspace note (`YARD_NOTES.txt`) and the supplied `disassemble.py` are a
TRAP: their opcode table is wrong (ADD and XOR are swapped) and their encoding
rule is wrong (they treat every byte except the opcode byte as verbatim).  A
naive VM built from that note reads the header CONST/CHECK verbatim, so the
FNV-1a-32 integrity gate fails and the module HALTs with the DECOY phrase.

The CORRECT decode (confirmed here) is:

    * every byte at offset >= 5 is XORed with OPKEY (opcodes, operands, and the
      header words CONST / CHECK / bytecode_len alike);
    * the true opcode table has 0x60 = XOR and 0x61 = ADD.

With those corrections the gate passes (FNV-1a-32(CONST) == CHECK) and the VM
executes the program, which prints the real ignition phrase.

solve reads ONLY the artifacts in L.out_dir("E10").
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

MAGIC = b"VMB1"
OPKEY = 0x7E
DECOY = "FTA{1gn1t10n_1mm0b1l1z3r_b41t}"

# ---- internal op ids -------------------------------------------------------
(OP_PUSH, OP_XOR, OP_ADD, OP_ROT, OP_DUP, OP_DROP, OP_PRINT, OP_HALT) = range(8)

# ---- raw opcode bytes (CORRECT) -------------------------------------------
RAW = {
    OP_PUSH: 0x10,
    OP_XOR: 0x60,
    OP_ADD: 0x61,
    OP_ROT: 0x70,
    OP_DUP: 0x80,
    OP_DROP: 0x81,
    OP_PRINT: 0xA0,
    OP_HALT: 0xF0,
}
TRUE_TABLE = {v: k for k, v in RAW.items()}

# the WRONG table from YARD_NOTES.txt / disassemble.py (ADD<->XOR swapped)
WRONG_TABLE = dict(TRUE_TABLE)
WRONG_TABLE[0x60] = OP_ADD
WRONG_TABLE[0x61] = OP_XOR

CORRECT_ENC = {"header": True, "opcode": True, "operand": True}
NAIVE_ENC = {"header": False, "opcode": True, "operand": False}


def fnv1a(b: bytes) -> int:
    h = 2166136261
    for x in b:
        h = ((h ^ x) * 16777619) & 0xFFFFFFFF
    return h


def rol8(v: int, n: int = 1) -> int:
    n &= 7
    if n == 0:
        return v & 0xFF
    return ((v << n) | (v >> (8 - n))) & 0xFF


def vm_run(raw: bytes, table: dict, enc: dict):
    """Execute `raw`; returns (output_str, checksum_ok).

    `enc` selects which byte classes are XORed with OPKEY on decode:
    header words, opcode bytes, operand bytes.
    """
    assert raw[:4] == MAGIC, "bad magic"
    opkey = raw[4]

    def mb(b, on):
        return (b ^ opkey) if on else b

    const = bytes(mb(x, enc["header"]) for x in raw[5:9])
    check = int.from_bytes(bytes(mb(x, enc["header"]) for x in raw[9:13]), "big")
    blen = int.from_bytes(bytes(mb(x, enc["header"]) for x in raw[13:15]), "big")
    blen = min(blen, len(raw) - 15)
    code = raw[15:15 + blen]

    if fnv1a(const) != check:
        return DECOY, False

    st = []
    out = bytearray()
    ip = 0
    n = len(code)
    while ip < n:
        op = table.get(mb(code[ip], enc["opcode"]))
        ip += 1
        if op is None:
            break
        if op == OP_PUSH:
            st.append(mb(code[ip], enc["operand"]))
            ip += 1
        elif op == OP_XOR:
            b = st.pop() if st else 0
            a = st.pop() if st else 0
            st.append((a ^ b) & 0xFF)
        elif op == OP_ADD:
            b = st.pop() if st else 0
            a = st.pop() if st else 0
            st.append((a + b) & 0xFF)
        elif op == OP_ROT:
            a = st.pop() if st else 0
            st.append(rol8(a, 1))
        elif op == OP_DUP:
            st.append(st[-1] if st else 0)
        elif op == OP_DROP:
            if st:
                st.pop()
        elif op == OP_PRINT:
            out.append(st.pop() if st else 0)
        elif op == OP_HALT:
            break
    return bytes(out).decode("latin-1"), True


def solve():
    raw = (L.out_dir("E10") / "ignition.vmb").read_bytes()
    assert raw[:4] == MAGIC, "not a VMB1 module"

    phrase, ok = vm_run(raw, TRUE_TABLE, CORRECT_ENC)
    assert ok, "ignition integrity gate failed on the corrected decode"
    phrase = phrase.strip()

    m = re.fullmatch(r"FTA\{[a-z0-9_]+\}", phrase)
    assert m, "unexpected ignition phrase: %r" % phrase
    assert phrase == L.FLAGS["E10"], (phrase, L.FLAGS["E10"])

    print("[E10] PASS ->", phrase)
    return phrase


if __name__ == "__main__":
    solve()
