#!/usr/bin/env python3
"""H01 "Zancudo Deadbolt" -- reference solver (organizer / participant path).

``zancudo_gate`` is a stripped Linux x86-64 ELF that never stores the accepted
passphrase verbatim (nor either decoy). Static ``strings`` yields nothing
useful; the interesting material lives in .rodata as seven magic-tagged blobs
and one *encrypted* vault:

    ZCFG  runtime key-derivation constants  [C][VM_CTX2][ENV_DEFAULT][VM_CTX3]
    ZXT1/ZXT2/ZXT3  VM opcode translation tables (byte -> internal op)
    ZVM1  VM1 program
    ZVM2  VM2 program, *masked* with VM1's result
    ZVM3  VM3 program, *masked* with VM2's result
    ZDVL  ciphertext of the data vault

Recovery path (mirrors the C pipeline bit for bit):

  1. Recover v1 by emulating VM1; unmask and run VM2 (must equal VM_CTX2);
     unmask and run VM3 with v2 (must equal VM_CTX3). No single-blob
     decompilation is enough -- each VM's at-rest bytes are masked by the
     previous VM's result.
  2. The vault key seed depends on the passphrase *length*. Brute-force it:
     for every length 1..MAXLEN derive the seed, run the two-pass decryption,
     and accept the length whose header equals itself and whose 256-byte SBOX is
     a permutation of 0..255. That combination is unique.
  3. Invert the layered check: the non-linear byte map
         (SBOX[in[i]] * K[i]) mod 251 == TARGET[i]
     inverts with the modular inverse (251 is prime, every K[i] != 0) plus a
     unique SBOX pre-image for every residue >= 5. Cross-check the four
     independent gates (FNV-1a, HMAC-like mix, CRC-style salt, rotate/xor).

Traps this solver deliberately ignores:
  * tripping any anti-debug gate makes the binary print a decoy flag;
  * ZANCUDO_SERVICE makes it print a dead-end schedule dump + a decoy flag;
  * ENGINEER_NOTE.txt advertises that dead end as the reliable shortcut.
"""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, r"d:\ctf\FLAG_THEFT_AUTO_FINAL\rebuild_workspace")
import lib_fta as L

OUT = L.out_dir("H01")
GATE = OUT / "zancudo_gate"

MOD = 251
MAXLEN = 200
PERM = set(range(256))
M64 = (1 << 64) - 1

CRC_XOR = 0x13579BDF
SEED2_MUL = 0x2545F4914F6CDD1D

# .rodata blob magics (never contain "FTA")
MG_CFG = b"ZCFG"
MG_XT1 = b"ZXT1"
MG_XT2 = b"ZXT2"
MG_XT3 = b"ZXT3"
MG_VM1 = b"ZVM1"
MG_VM2 = b"ZVM2"
MG_VM3 = b"ZVM3"
MG_VLT = b"ZDVL"

# vault plaintext layout (offsets inside the decrypted buffer)
OFF_SBOX = 4
OFF_K = OFF_SBOX + 256               # 260
CIPHER_LEN = OFF_K + 2 * MAXLEN + 16  # 676

# bytecode VM opcodes (mirror the C interpreter)
(O_NOP, O_PUSH, O_DROP, O_ADD, O_SUB, O_XOR, O_AND, O_OR, O_MUL, O_SHL, O_SHR,
 O_DUP, O_SWAP, O_JMP, O_JZ, O_JNZ, O_HALT) = range(17)
O_BAD = 17
IMM_OPS = {O_PUSH, O_SHL, O_SHR, O_JMP, O_JZ, O_JNZ}


def wsl_path(p) -> str:
    s = str(p).replace("\\", "/")
    return "/mnt/" + s[0].lower() + s[2:]


def rd32(p: bytes) -> int:
    return int.from_bytes(p, "little")


# ---------------------------------------------------------------------------
# key derivation -- bit-for-bit mirror of gen_h01.py / the C code
# ---------------------------------------------------------------------------
def splitmix64(z):
    z = (z + 0x9E3779B97F4A7C15) & M64
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M64
    return (z ^ (z >> 31)) & M64


def derive_seed(c, length, env, v1, v2, v3):
    s = (c
         ^ ((length * 0x9E3779B97F4A7C15) & M64)
         ^ ((env << 33) & M64)
         ^ ((v1 << 7) & M64)
         ^ v2
         ^ ((v3 << 17) & M64)) & M64
    return splitmix64(s)


def keystream(seed, n):
    st = (seed | 1) & M64
    out = bytearray()
    for _ in range(n):
        x = st
        x ^= (x << 13) & M64
        x ^= x >> 7
        x ^= (x << 17) & M64
        x &= M64
        st = x
        out.append(x & 0xFF)
    return bytes(out)


def seed2_of(seed, v3):
    return splitmix64((seed ^ ((v3 * SEED2_MUL) & M64) ^ 0x9E3779B97F4A7C15) & M64)


def decrypt_vault(cipher, seed, v3):
    a = keystream(seed, len(cipher))
    b = keystream(seed2_of(seed, v3), len(cipher))
    return bytes(c ^ x ^ y for c, x, y in zip(cipher, a, b))


def fnv1a(b):
    h = 2166136261
    for x in b:
        h = ((h ^ x) * 16777619) & 0xFFFFFFFF
    return h


def hmix(b, seed):
    h = (seed ^ (seed >> 32)) & 0xFFFFFFFF
    for x in b:
        h = (h ^ x) & 0xFFFFFFFF
        h = (h * 16777619) & 0xFFFFFFFF
        h = (h ^ (h >> 15)) & 0xFFFFFFFF
        h = (h * 2246822519) & 0xFFFFFFFF
    return h


def gate_crc(b, salt):
    h = salt & 0xFFFFFFFF
    for x in b:
        h ^= x
        h &= 0xFFFFFFFF
        for _ in range(8):
            if h & 1:
                h = (h >> 1) ^ 0xEDB88320
            else:
                h >>= 1
            h &= 0xFFFFFFFF
    return h


def gate_pos(b, seed):
    h = (seed ^ (seed >> 29)) & 0xFFFFFFFF
    for i, x in enumerate(b):
        h = (h + x + i) & 0xFFFFFFFF
        h = ((h << 5) | (h >> 27)) & 0xFFFFFFFF
        h ^= (x * 0x9E3779B1) & 0xFFFFFFFF
        h &= 0xFFFFFFFF
    return h


# ---------------------------------------------------------------------------
# bytecode VM emulator (mirror of the C dispatcher)
# ---------------------------------------------------------------------------
def vm_run(code: bytes, xlat: bytes) -> int:
    st = []
    ip = 0
    n = len(code)
    while True:
        if ip < 0 or ip >= n:
            return st[-1] & 0xFFFFFFFF if st else 0
        op = xlat[code[ip]]
        ip += 1
        if op == O_NOP:
            continue
        if op == O_PUSH:
            st.append(code[ip] & 0xFF)
            ip += 1
        elif op == O_DROP:
            if st:
                st.pop()
        elif op in (O_ADD, O_SUB, O_XOR, O_AND, O_OR, O_MUL):
            b = st.pop() if st else 0
            a = st.pop() if st else 0
            if op == O_ADD:
                r = a + b
            elif op == O_SUB:
                r = a - b
            elif op == O_XOR:
                r = a ^ b
            elif op == O_AND:
                r = a & b
            elif op == O_OR:
                r = a | b
            else:
                r = a * b
            st.append(r & 0xFFFFFFFF)
        elif op == O_SHL:
            imm = code[ip] & 0xFF
            ip += 1
            a = st.pop() if st else 0
            st.append((a << (imm & 31)) & 0xFFFFFFFF)
        elif op == O_SHR:
            imm = code[ip] & 0xFF
            ip += 1
            a = st.pop() if st else 0
            st.append((a >> (imm & 31)) & 0xFFFFFFFF)
        elif op == O_DUP:
            st.append(st[-1] if st else 0)
        elif op == O_SWAP:
            if len(st) >= 2:
                st[-1], st[-2] = st[-2], st[-1]
        elif op == O_JMP:
            rel = code[ip]
            ip += 1
            ip += rel - 256 if rel > 127 else rel
        elif op == O_JZ:
            rel = code[ip]
            ip += 1
            v = st.pop() if st else 0
            if v == 0:
                ip += rel - 256 if rel > 127 else rel
        elif op == O_JNZ:
            rel = code[ip]
            ip += 1
            v = st.pop() if st else 0
            if v != 0:
                ip += rel - 256 if rel > 127 else rel
        elif op == O_HALT:
            return st[-1] & 0xFFFFFFFF if st else 0
        else:
            return 0xDEADBEEF


def prog_len(code: bytes, xlat: bytes, cap: int = 4096) -> int:
    """Self-terminating program length: walk until HALT (no end marker stored)."""
    ip = 0
    while ip < cap and ip < len(code) + 1:
        op = xlat[code[ip]]
        ip += 1
        if op == O_HALT:
            return ip
        if op in IMM_OPS:
            ip += 1
    raise AssertionError("VM program did not terminate with HALT")


# ---------------------------------------------------------------------------
# blob localisation: stripped binary, so find by magic content
# ---------------------------------------------------------------------------
def find_magic(data: bytes, magic: bytes) -> int:
    hits = []
    start = 0
    while True:
        j = data.find(magic, start)
        if j < 0:
            break
        hits.append(j)
        start = j + 1
    assert len(hits) == 1, f"magic {magic!r} occurs {len(hits)} times"
    return hits[0]


def parse_blobs(data: bytes):
    pc = find_magic(data, MG_CFG)
    cfg_c = rd32(data[pc + 4:pc + 8])
    vm_ctx = rd32(data[pc + 8:pc + 12])
    env_def = rd32(data[pc + 12:pc + 16])
    vm_ctx3 = rd32(data[pc + 16:pc + 20])

    px1 = find_magic(data, MG_XT1)
    px2 = find_magic(data, MG_XT2)
    px3 = find_magic(data, MG_XT3)
    xlat1 = data[px1 + 4:px1 + 4 + 256]
    xlat2 = data[px2 + 4:px2 + 4 + 256]
    xlat3 = data[px3 + 4:px3 + 4 + 256]
    assert len(xlat1) == 256 and len(xlat2) == 256 and len(xlat3) == 256

    pv1 = find_magic(data, MG_VM1)
    pv2 = find_magic(data, MG_VM2)
    pv3 = find_magic(data, MG_VM3)
    pvl = find_magic(data, MG_VLT)

    def vm_payload(p):
        ln = int.from_bytes(data[p + 4:p + 6], "little")
        return data[p + 6:p + 6 + ln]

    vm1 = vm_payload(pv1)
    vm2_stored = vm_payload(pv2)
    vm3_stored = vm_payload(pv3)
    cipher = data[pvl + 4:pvl + 4 + CIPHER_LEN]
    assert len(cipher) == CIPHER_LEN
    return (cfg_c, vm_ctx, env_def, vm_ctx3, xlat1, xlat2, xlat3,
            vm1, vm2_stored, vm3_stored, cipher)


def _unmask(stored: bytes, base: int) -> bytes:
    return bytes(stored[i] ^ ((base >> (8 * (i & 3))) & 0xFF)
                 for i in range(len(stored)))


def run_vms(cfg_c, vm_ctx, vm_ctx3, xlat1, xlat2, xlat3, vm1, vm2_stored, vm3_stored):
    v1 = vm_run(vm1, xlat1)
    vm2 = _unmask(vm2_stored, v1 ^ 0x9E3779B9)
    v2 = vm_run(vm2, xlat2)
    assert v2 == vm_ctx, f"chained-VM2 integrity mismatch ({v2:#010x} != {vm_ctx:#010x})"
    vm3 = _unmask(vm3_stored, v2 ^ 0x85EBCA6B)
    v3 = vm_run(vm3, xlat3)
    assert v3 == vm_ctx3, f"chained-VM3 integrity mismatch ({v3:#010x} != {vm_ctx3:#010x})"
    return v1, v2, v3


def decrypt_real_vault(cfg_c, env_def, v1, v2, v3, cipher):
    """Brute-force the passphrase length, then decrypt the vault."""
    cands = []
    for ltry in range(1, MAXLEN + 1):
        seed = derive_seed(cfg_c, ltry, env_def, v1, v2, v3)
        dec = decrypt_vault(cipher, seed, v3)
        if rd32(dec[:4]) == ltry and set(dec[OFF_SBOX:OFF_SBOX + 256]) == PERM:
            cands.append((ltry, seed, dec))
    assert len(cands) == 1, f"length brute-force not unique ({len(cands)} hits)"
    ltry, seed, dec = cands[0]
    return ltry, seed, dec


def recover_flag(need, seed, dec, v3) -> str:
    sbox = list(dec[OFF_SBOX:OFF_SBOX + 256])
    k = list(dec[OFF_K:OFF_K + need])
    target = list(dec[OFF_K + need:OFF_K + 2 * need])
    cs_stored = rd32(dec[OFF_K + 2 * need:OFF_K + 2 * need + 4])
    hx_stored = rd32(dec[OFF_K + 2 * need + 4:OFF_K + 2 * need + 8])
    cr_stored = rd32(dec[OFF_K + 2 * need + 8:OFF_K + 2 * need + 12])
    ps_stored = rd32(dec[OFF_K + 2 * need + 12:OFF_K + 2 * need + 16])

    preimage = {}
    for b, s in enumerate(sbox):
        r = s % MOD
        preimage[r] = None if r in preimage else b

    out = bytearray()
    for idx in range(need):
        inv = pow(k[idx], -1, MOD)
        r = (target[idx] * inv) % MOD
        b = preimage.get(r)
        assert b is not None, f"byte {idx}: residue {r} has no unique pre-image"
        out.append(b)

    # cross-check the four independent gates
    assert fnv1a(out) == cs_stored, "FNV-1a checksum gate disagrees"
    assert hmix(out, seed) == hx_stored, "mixing gate disagrees"
    assert gate_crc(out, (v3 ^ CRC_XOR) & 0xFFFFFFFF) == cr_stored, "CRC-style gate disagrees"
    assert gate_pos(out, seed) == ps_stored, "rotate/xor gate disagrees"
    return out.decode()


def solve():
    data = GATE.read_bytes()
    (cfg_c, vm_ctx, env_def, vm_ctx3, xlat1, xlat2, xlat3,
     vm1, vm2_stored, vm3_stored, cipher) = parse_blobs(data)
    v1, v2, v3 = run_vms(cfg_c, vm_ctx, vm_ctx3, xlat1, xlat2, xlat3,
                         vm1, vm2_stored, vm3_stored)
    need, seed, dec = decrypt_real_vault(cfg_c, env_def, v1, v2, v3, cipher)
    flag = recover_flag(need, seed, dec, v3)
    assert flag == L.FLAGS["H01"], flag

    # confirm against the live binary (its own env byte must match env_def; the
    # bait ZANCUDO_SERVICE override must be unset)
    r = subprocess.run(["wsl.exe", "-e", "bash", "-lc",
                        f"env -u ZANCUDO_ENTROPY -u ZANCUDO_SERVICE "
                        f"'{wsl_path(GATE)}' '{flag}'"],
                       capture_output=True, text=True)
    ok = "ZANCUDO DEADBOLT RELEASED" in r.stdout
    print(f"[H01] gate banner: {r.stdout.strip().splitlines()[0] if r.stdout else r.stderr.strip()}")
    assert ok and r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    print("[H01] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
