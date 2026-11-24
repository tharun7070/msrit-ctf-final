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
