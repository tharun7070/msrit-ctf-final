#!/usr/bin/env python3
"""E10 "Towing Yard Ignition" -- generator (private organizer tooling).

Builds a custom stack-VM bytecode module `ignition.vmb` plus a participant
workspace note (`YARD_NOTES.txt`) and a slightly-broken disassembler
(`disassemble.py`). Running the module through the CORRECT VM prints the
canonical ignition phrase; a naive VM built from the (deliberately wrong)
workspace note trips an FNV-1a-32 integrity gate and emits the DECOY phrase.

ignition.vmb binary layout (little agent, big-endian words)
    off  size  field
    0    4     MAGIC  = ASCII b"VMB1"
    4    1     OPKEY  (opcode XOR key)
    5    4     CONST  (big-endian uint32)   -- the ignition seed
    9    4     CHECK  (big-endian uint32)   -- FNV-1a-32(CONST)
    13   2     bytecode_len (big-endian uint16)
    15   N     bytecode

Encoding (CORRECT -- only discoverable by a careful solver):
    * EVERY byte with offset >= 5 (i.e. everything after the OPKEY byte) is
      XORed with OPKEY: opcode bytes, PUSH operand bytes, and the header words
      CONST / CHECK / bytecode_len.  MAGIC and OPKEY itself are plain.
    * decode:  plain = stored ^ OPKEY

VM ops (internal ids):
    PUSH imm (1 operand) | XOR | ADD | ROT (rol8 top,1) | DUP | DROP |
    PRINT (pop byte, append to output) | HALT

Anti-tamper: before executing, the VM computes FNV-1a-32 over the decoded
CONST and compares it to the decoded CHECK; on mismatch it HALTs immediately
and emits the DECOY phrase instead of the real one.

The flag never appears verbatim in any artifact (operands are double-masked);
only DECOY FTA{...} strings are present.  Generation is deterministic.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

MAGIC = b"VMB1"
OPKEY = 0x7E
CONST_PLAIN = b"VIGN"                       # the ignition seed (header CONST)
DECOY = "FTA{1gn1t10n_1mm0b1l1z3r_b41t}"    # emitted when the gate fails

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

# ---- the WRONG table presented to participants in YARD_NOTES.txt ----------
# exactly one opcode is wrong: ADD and XOR are swapped.
WRONG_TABLE = dict(TRUE_TABLE)
WRONG_TABLE[0x60] = OP_ADD
WRONG_TABLE[0x61] = OP_XOR

IMM = {OP_PUSH}

CORRECT_ENC = {"header": True, "opcode": True, "operand": True}
NAIVE_ENC = {"header": False, "opcode": True, "operand": False}


# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
def build_program(flag: str):
    """Straight-line program that prints `flag` on the correct VM.

    Uses every op at least once: PUSH/ROT/DROP preamble, XOR and ADD forms in
    the body, PRINT per character, DUP/DROP tail, HALT.
    """
    prog = [(OP_PUSH, 0xA5), (OP_ROT,), (OP_DROP,)]
    for i, c in enumerate(flag.encode()):
        if i % 2 == 0:                       # c = a ^ k
            k = (0x11 + i * 37) & 0xFF
            prog += [(OP_PUSH, c ^ k), (OP_PUSH, k), (OP_XOR,)]
        else:                                # c = (a + k) & 0xff
            k = (0x2B + i * 53) & 0xFF
            prog += [(OP_PUSH, (c - k) & 0xFF), (OP_PUSH, k), (OP_ADD,)]
        prog += [(OP_PRINT,)]
    prog += [(OP_PUSH, 0x00), (OP_DUP,), (OP_DROP,), (OP_DROP,), (OP_HALT,)]
    return prog


def assemble(prog) -> bytes:
    """Serialize to bytecode: opcodes AND operands XORed with OPKEY."""
    out = bytearray()
    for item in prog:
        out.append(RAW[item[0]] ^ OPKEY)
        for a in item[1:]:
            out.append((a & 0xFF) ^ OPKEY)
    return bytes(out)


# ---------------------------------------------------------------------------
def vm_run(raw: bytes, table: dict, enc: dict):
    """Execute `raw`. Returns (output_str, checksum_ok).

    `table` maps decoded opcode byte -> internal op.
    `enc` selects which byte classes get XORed with OPKEY on decode.
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

    # --- anti-tamper gate ---------------------------------------------------
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


# ---------------------------------------------------------------------------
YARD_NOTES = """\
============================================================
  TOWING YARD IGNITION -- WORKSPACE NOTE        (module: ignition.vmb)
============================================================
Recovered from the ECU of a towed Declasse Voodoo. The module is a tiny
stack-VM program. Run it in a correct VM to print the yard ignition
phrase that releases the tow gate.

FILE LAYOUT (ignition.vmb)
--------------------------
  off  size  field
  0    4     MAGIC  = ASCII "VMB1"
  4    1     OPKEY  (opcode XOR key)
  5    4     CONST  (big-endian uint32)   -- the ignition seed
  9    4     CHECK  (big-endian uint32)   -- stored integrity word
  13   2     bytecode_len (big-endian uint16)
  15   N     bytecode

ENCODING
--------
* The bytecode OPCODE bytes are XORed with OPKEY. Decode with: byte ^ OPKEY.
* The immediate/operand bytes (the byte after a PUSH) are stored VERBATIM.
* The header words (CONST, CHECK, bytecode_len) are stored VERBATIM as well.

OPCODE TABLE   (decode: op = table[byte ^ OPKEY])
-------------------------------------------------
  0x10  PUSH imm     (1 operand byte follows)
  0x60  ADD
  0x61  XOR
  0x70  ROT          (rotate the top stack byte left by 1 bit)
  0x80  DUP
  0x81  DROP
  0xA0  PRINT        (pop one byte, append it to the output)
  0xF0  HALT

VM SEMANTICS
------------
  * PUSH pushes its immediate onto the stack.
  * XOR / ADD pop b, then pop a, and push (a <op> b) & 0xff.
  * ROT pops a byte and pushes rol8(byte, 1).
  * DUP duplicates the top of stack (0 if empty).
  * DROP pops and discards the top of stack.
  * PRINT pops one byte and appends it to the output stream.
  * HALT stops execution.

INTEGRITY / DETECT RULE
-----------------------
A correct decode MUST satisfy

        FNV-1a-32(header CONST) == header CHECK

(the ignition phrase's checksum seed). If your computed FNV-1a-32 over the
CONST word does NOT equal CHECK, then your decode is wrong -- re-check the
opcode table and the encoding rules above and try again.

SAFETY
------
If the integrity gate fails, the immobiliser trips and the unit HALTS after
emitting a DECOY phrase. The decoy is NOT the real ignition phrase. For
reference the immobiliser emits:

    FTA{1gn1t10n_1mm0b1l1z3r_b41t}
"""

DISASSEMBLE = '''\
#!/usr/bin/env python3
"""ignition.vmb disassembler (yard toolchain).

Standalone listing tool for the recovered `ignition.vmb` bytecode module.
Reads the module beside this script and prints a listing plus the module's
integrity verdict.

Usage:  python disassemble.py [path-to-ignition.vmb]
"""
import sys
from pathlib import Path

MAGIC = b"VMB1"

# opcode byte -> (mnemonic, operand-byte-count)   -- per the workspace note
TABLE = {
    0x10: ("PUSH", 1),
    0x60: ("ADD", 0),
    0x61: ("XOR", 0),
    0x70: ("ROT", 0),
    0x80: ("DUP", 0),
    0x81: ("DROP", 0),
    0xA0: ("PRINT", 0),
    0xF0: ("HALT", 0),
}

IMMOBILISER_PHRASE = "FTA{1gn1t10n_1mm0b1l1z3r_b41t}"


def fnv1a(b):
    h = 2166136261
    for x in b:
        h = ((h ^ x) * 16777619) & 0xFFFFFFFF
    return h


def main():
    here = Path(__file__).resolve().parent
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else here / "ignition.vmb"
    raw = path.read_bytes()
    if raw[:4] != MAGIC:
        print("not a VMB1 module:", path)
        return 2

    opkey = raw[4]
    const = raw[5:9]                       # read verbatim
    check = raw[9:13]                      # read verbatim
    blen = int.from_bytes(raw[13:15], "big")
    n = min(blen, len(raw) - 15)
    code = raw[15:15 + n]

    print("== ignition.vmb ==")
    print("OPKEY      : 0x%02x" % opkey)
    print("CONST      : %s" % const.hex())
    print("CHECK      : %s" % check.hex())
    print("bytecode   : %d bytes" % n)
    print("-- listing --")

    ip = 0
    while ip < len(code):
        b = code[ip] ^ opkey
        mnem = TABLE.get(b)
        if mnem is None:
            print("%04d: %02x   ???" % (ip, code[ip]))
            ip += 1
            continue
        name, nargs = mnem
        if nargs:
            args = code[ip + 1:ip + 1 + nargs]
            print("%04d: %02x   %s %s" % (ip, code[ip], name,
                  " ".join("0x%02x" % a for a in args)))
        else:
            print("%04d: %02x   %s" % (ip, code[ip], name))
        ip += 1 + nargs

    print("-- integrity --")
    got = fnv1a(const)
    want = int.from_bytes(check, "big")
    if got == want:
        print("[+] FNV-1a-32(CONST) == CHECK -- gate OK")
    else:
        print("[!] FNV-1a-32(CONST) = 0x%08x != CHECK = 0x%08x -- GATE FAILED"
              % (got, want))
        print("    immobiliser engaged; unit emits: " + IMMOBILISER_PHRASE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


# ---------------------------------------------------------------------------
def main():
    out = L.out_dir("E10")
    flag = L.FLAGS["E10"]

    const = CONST_PLAIN
    check = fnv1a(const)
    code = assemble(build_program(flag))

    hdr = bytearray()
    hdr += MAGIC
    hdr.append(OPKEY)
    hdr += bytes(x ^ OPKEY for x in const)
    hdr += bytes(x ^ OPKEY for x in check.to_bytes(4, "big"))
    hdr += bytes(x ^ OPKEY for x in len(code).to_bytes(2, "big"))
    vmb = bytes(hdr) + code

    # ---- verify the CORRECT VM path ---------------------------------------
    got_flag, ok = vm_run(vmb, TRUE_TABLE, CORRECT_ENC)
    assert ok, "correct decode failed its own integrity gate"
    assert got_flag == flag, (got_flag, flag)

    # ---- verify the NAIVE VM path (note table + note encoding) ------------
    got_naive, ok_naive = vm_run(vmb, WRONG_TABLE, NAIVE_ENC)
    assert ok_naive is False, "naive decode unexpectedly passed the gate"
    assert got_naive == DECOY, got_naive

    # ---- anti-leak ---------------------------------------------------------
    assert flag.encode() not in vmb, "flag leaked verbatim into ignition.vmb"
    assert DECOY.encode() not in vmb, "decoy unexpectedly present in bytecode"

    # ---- write artifacts ---------------------------------------------------
    p1 = out / "ignition.vmb"
    p1.write_bytes(vmb)
    print("wrote %s (%d bytes)" % (p1, len(vmb)))

    p2 = out / "YARD_NOTES.txt"
    p2.write_text(YARD_NOTES, encoding="utf-8", newline="\n")
    assert flag.encode() not in p2.read_bytes(), "flag leaked into YARD_NOTES"
    print("wrote %s" % p2)

    p3 = out / "disassemble.py"
    p3.write_text(DISASSEMBLE, encoding="utf-8", newline="\n")
    assert flag.encode() not in p3.read_bytes(), "flag leaked into disassemble.py"
    print("wrote %s" % p3)

    print("[E10] bytecode %d bytes, CONST=%s, CHECK=0x%08x, OPKEY=0x%02x"
          % (len(code), const.decode(), check, OPKEY))
    print("[E10] correct VM -> %s | naive VM -> %s" % (got_flag, got_naive))


if __name__ == "__main__":
    main()
