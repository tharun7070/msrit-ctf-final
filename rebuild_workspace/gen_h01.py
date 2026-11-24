#!/usr/bin/env python3
"""H01 "Zancudo Deadbolt" -- generator (private organizer tooling).

Emits ``zancudo_gate.c`` (a self-contained, heavily obfuscated Linux x86-64 ELF
source), then builds + strips the binary inside WSL and drops it in
L.out_dir("H01").

The accepted passphrase == L.FLAGS["H01"]. It is *never* stored verbatim.

Stacked anti-automation layers
------------------------------
A. Anti-analysis: four independent gates (PTRACE_TRACEME, /proc/self/status
   TracerPid, a wall-clock timing probe, and a parent-process-name check). Any
   one tripping diverts to a FAKE success path printing a plausible but WRONG
   flag so automated solvers get poisoned output.
B. Multi-stage virtualization: two chained bytecode VMs, each with a
   control-flow-flattened dispatcher and opaque predicates. VM1's result masks
   VM2's at-rest bytecode, so VM2 cannot even be decoded without running VM1.
C. Runtime-derived vault key: the SBOX/K/TARGET/checksum vault is stored as
   ciphertext in .rodata and decrypted only with a keystream derived from
   (passphrase length, a build constant, an environment byte, and the chained
   VM result). Dumping .rodata statically yields ciphertext.
D. Layered check: three sequential transforms -- an FNV-1a checksum gate, the
   classic (SBOX[b]*K) mod 251 map, and an HMAC-like mixing gate -- all seeded
   from the same runtime key, so a partial reversal does not yield the flag.

The passphrase is recoverable because MOD = 251 is prime and every K[i] is a
nonzero residue, so each accepted byte has a unique pre-image under the SBOX.

SOLUTION.md correction note: genuine control-flow flattening + manual opaque
predicates are used; no third-party OLLVM is available in this environment.
"""
import random
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, r"d:\ctf\FLAG_THEFT_AUTO_FINAL\rebuild_workspace")
import lib_fta as L

WS = Path(r"d:\ctf\FLAG_THEFT_AUTO_FINAL\rebuild_workspace")
OUT = L.out_dir("H01")

MAXLEN = 200            # sanity bound on passphrase length
MOD = 251               # prime modulus for the multiply
SEED = 0x484F3131       # deterministic ("H01") -- sbox / k / fake material
SEED2 = 0x5A4E4355      # deterministic -- opcode translation tables
FLAG = L.FLAGS["H01"]

# ---- runtime key-derivation constants (baked into the ELF, not secret) ----
CFG_C = 0x7F4A7C15              # "anti-debug-safe" build constant
ENV_DEFAULT = 0x5B              # fallback env byte ('[') when env unset
VM_CTX = 0x0FF1CE42            # chained-VM integrity target

# ---- .rodata blob magics (ASCII, never contain "FTA") ----
MG_CFG = b"ZCFG"
MG_XT1 = b"ZXT1"
MG_XT2 = b"ZXT2"
MG_VM1 = b"ZVM1"
MG_VM2 = b"ZVM2"
MG_VLT = b"ZDVL"

# vault plaintext layout (offsets inside the decrypted buffer):
#   [u32 need][SBOX 256][K need][T need][u32 checksum][u32 mix][padding]
OFF_SBOX = 4
OFF_K = OFF_SBOX + 256                # 260
CIPHER_LEN = OFF_K + 2 * MAXLEN + 8   # 668

M64 = (1 << 64) - 1

OPERATIONS_TXT = """ZANCUDO ACCESS CONTROL STATION
==============================
installation : Fort Zancudo, Hangar 13 perimeter
station      : access control station "ZANCUDO DEADBOLT"
platform     : native Linux x86-64 service binary  (zancudo_gate)

Interface
---------
The station admits a single operator passphrase as its one positional
argument and is driven exactly as:

    ./zancudo_gate <passphrase>

Exit status
-----------
  0  passphrase accepted (the station announces release)
  1  passphrase rejected (the deadbolt holds)
  2  malformed invocation (no passphrase supplied)
  any other non-zero value still means "no release"

Field notes
-----------
* The station performs a self-check before it serves anybody. Interrogate it
  the way it expects to be interrogated or it will not talk to you.
* Everything it needs is on board; it fetches nothing over the network.
* There is no recovery console and no maintenance back door.
* If the station ever answers with a passphrase of its own, treat that answer
  with suspicion: the station is under no obligation to tell you the truth
  about why it said yes.
"""

# ---------------------------------------------------------------------------
# runtime key derivation -- mirrored bit-for-bit in C and in solve_h01.py
# ---------------------------------------------------------------------------
def splitmix64(z):
    z = (z + 0x9E3779B97F4A7C15) & M64
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M64
    return (z ^ (z >> 31)) & M64


def derive_seed(c, length, env, v1, v2):
    s = (c
         ^ ((length * 0x9E3779B97F4A7C15) & M64)
         ^ ((env << 33) & M64)
         ^ ((v1 << 7) & M64)
         ^ v2) & M64
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


# ---------------------------------------------------------------------------
# bytecode VM (reference simulator -- mirrors the C interpreter exactly)
# ---------------------------------------------------------------------------
(O_NOP, O_PUSH, O_DROP, O_ADD, O_SUB, O_XOR, O_AND, O_OR, O_MUL, O_SHL, O_SHR,
 O_DUP, O_SWAP, O_JMP, O_JZ, O_JNZ, O_HALT) = range(17)
O_BAD = 17


def vm_run(code, xlat):
    """Return the uint32 result of running `code` through translation `xlat`."""
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
        elif op == O_PUSH:
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


def make_xlat(rnd):
    """Random opcode translation: xlat[byte] = internal op, unused -> O_BAD."""
    xlat = [O_BAD] * 256
    slots = rnd.sample(range(256), 17)
    for i, b in enumerate(slots):
        xlat[b] = i
    byte_for_op = {i: slots[i] for i in range(17)}
    return xlat, byte_for_op


def asm(prog, byte_for_op):
    out = []
    for ins in prog:
        out.append(byte_for_op[ins[0]])
        for a in ins[1:]:
            out.append(a & 0xFF)
    return bytes(out)


VM1_PROG = [(O_PUSH, 0xCA), (O_PUSH, 0xF3), (O_SHL, 8), (O_OR,),
            (O_PUSH, 0xB0), (O_SHL, 16), (O_OR,),
            (O_PUSH, 0x1D), (O_SHL, 24), (O_OR,), (O_HALT,)]

VM2_PROG = [(O_PUSH, 0x42), (O_PUSH, 0xCE), (O_SHL, 8), (O_OR,),
            (O_PUSH, 0xF1), (O_SHL, 16), (O_OR,),
            (O_PUSH, 0x0F), (O_SHL, 24), (O_OR,), (O_HALT,)]

VM1_EXPECT = 0x1DB0F3CA
VM2_EXPECT = 0x0FF1CE42


# ---------------------------------------------------------------------------
# embedded data vault
# ---------------------------------------------------------------------------
def build_vault(seed):
    fb = FLAG.encode()
    assert 1 <= len(fb) <= MAXLEN, "implausible passphrase length"
    rnd = random.Random(SEED)
    # Build a permutation where no accepted byte resolves ambiguously: for a
    # target r = (SBOX[b]*K) mod 251 a second pre-image only exists when r <= 4.
    while True:
        sbox = list(range(256))
        rnd.shuffle(sbox)
        if all((sbox[b] % MOD) >= 5 for b in fb):
            break
    k = [rnd.randrange(1, MOD) for _ in range(len(fb))]
    target = [(sbox[b] % MOD * k[i]) % MOD for i, b in enumerate(fb)]

    n = len(fb)
    cs = fnv1a(fb)
    hx = hmix(fb, seed)

    plain = bytearray()
    plain += n.to_bytes(4, "little")
    plain += bytes(sbox)
    plain += bytes(k)
    plain += bytes(target)
    plain += cs.to_bytes(4, "little")
    plain += hx.to_bytes(4, "little")
    pad = CIPHER_LEN - len(plain)
    assert pad >= 0, (len(plain), CIPHER_LEN)
    plain += bytes(rnd.randrange(256) for _ in range(pad))

    ks = keystream(seed, CIPHER_LEN)
    cipher = bytes(p ^ q for p, q in zip(plain, ks))
    return bytes(plain), cipher, k, target, sbox, n, cs, hx


def _c_array(decl, data, per=16):
    rows = []
    for r in range(0, len(data), per):
        rows.append("    " + ", ".join(f"0x{b:02x}" for b in data[r:r + per]))
    return f"{decl} = {{\n" + ",\n".join(rows) + "\n};"


C_HEAD = r'''/* zancudo_gate.c -- GENERATED by gen_h01.py (FLAG THEFT AUTO / H01).
 *
 * Fort Zancudo access-control station firmware. The accepted passphrase is
 * never stored verbatim. Layered guards:
 *   - four independent anti-debug / anti-tracing gates that divert to a fake
 *     success path printing a plausible but wrong passphrase,
 *   - two chained bytecode VMs with control-flow-flattened dispatchers,
 *   - an encrypted .rodata vault decrypted with a runtime-derived keystream,
 *   - a three-transform layered passphrase check.
 *
 * Build (inside WSL/Linux x86-64):
 *     gcc -O2 -o zancudo_gate zancudo_gate.c && strip -s zancudo_gate
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <time.h>

#define MOD         251
#define MAXLEN      200

/* decrypted vault plaintext layout */
#define OFF_HDR   0
#define OFF_SBOX  4
#define OFF_K     (OFF_SBOX + 256)          /* 260 */
#define OFF_T(n)  (OFF_K + (n))
#define OFF_CS(n) (OFF_K + 2 * (n))
#define OFF_HX(n) (OFF_CS(n) + 4)

/* opaque-predicate guard: reads 0 at runtime; volatile so it cannot be folded */
static volatile uint32_t g_guard = 0;

'''

C_MID = r'''#define VM1_LEN ((int)(sizeof(g_vm1) - 4))
#define VM2_LEN ((int)(sizeof(g_vm2) - 4))
#define CIPHER_LEN ((int)(sizeof(g_cipher) - 4))

'''

C_TAIL = r'''
/* ------------------------------------------------------------------ */
/* little-endian read + checksum + key derivation (mirrors gen_h01.py)*/
/* ------------------------------------------------------------------ */
static uint32_t rd32(const volatile unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t splitmix64(uint64_t z)
{
    z += 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static void ks_init(uint64_t *st, uint64_t seed) { *st = seed | 1ULL; }

static unsigned char ks_next(uint64_t *st)
{
    uint64_t x = *st;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *st = x;
    return (unsigned char)(x & 0xffu);
}

static uint32_t fnv1a(const unsigned char *b, int n)
{
    uint32_t h = 2166136261u;
    int i;
    for (i = 0; i < n; i++) {
        h ^= b[i];
        h *= 16777619u;
    }
    return h;
}

static uint32_t hmix(const unsigned char *b, int n, uint64_t seed)
{
    uint32_t h = (uint32_t)(seed ^ (seed >> 32));
    int i;
    for (i = 0; i < n; i++) {
        h ^= b[i];
        h *= 16777619u;
        h ^= h >> 15;
        h *= 2246822519u;
    }
    return h;
}

/* ------------------------------------------------------------------ */
/* anti-analysis: four independent traps. Any hit -> fake success.    */
/* ------------------------------------------------------------------ */
static int is_debugger_name(const char *s)
{
    static const char *bl[] = {
        "gdb", "lldb", "strace", "ltrace", "valgrind", "radare2", "r2 ",
        "rr ", "frida", "ghidra", "pwndbg", "gef", "dlv", "ida", "winedbg",
        "rr-debugger", "sprocket", "x64dbg", "windbg", 0
    };
    int i;
    if (!s) return 0;
    for (i = 0; bl[i]; i++)
        if (strstr(s, bl[i])) return 1;
    return 0;
}

static int read_file(const char *path, char *out, int cap)
{
    FILE *f = fopen(path, "rb");
    size_t r;
    if (!f) return 0;
    r = fread(out, 1, (size_t)(cap - 1), f);
    out[r] = 0;
    fclose(f);
    return 1;
}

static int trap_check(void)
{
    int traced = 0;

    /* trap B: TracerPid must be 0. Checked before TRACEME so the process
       state is still pristine. */
    {
        FILE *f = fopen("/proc/self/status", "rb");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "TracerPid:", 10) == 0) {
                    if (strtol(line + 10, 0, 10) != 0) traced = 1;
                    break;
                }
            }
            fclose(f);
        }
    }

    /* trap A: already traced -> PTRACE_TRACEME fails with EPERM. */
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0)
        traced = 1;

    /* trap C: wall-clock timing probe. A debugger pausing at a breakpoint or
       single-stepping blows well past the generous threshold. */
    {
        struct timespec t0, t1;
        volatile uint32_t acc = 0;
        long us;
        int i;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < 200000; i++)
            acc = acc * 7u + (uint32_t)i * 2654435761u;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        us = (long)(t1.tv_sec - t0.tv_sec) * 1000000L +
             (long)(t1.tv_nsec - t0.tv_nsec) / 1000L;
        if (us > 500000) traced = 1;
        if (acc == 0xFFFFFFFFu) traced ^= 0; /* keep acc live */
    }

    /* trap D: the parent process must not look like a debugger. */
    {
        pid_t pp = getppid();
        char buf[512];
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/comm", (int)pp);
        if (read_file(path, buf, sizeof(buf)) && is_debugger_name(buf))
            traced = 1;
        snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pp);
        if (read_file(path, buf, sizeof(buf)) && is_debugger_name(buf))
            traced = 1;
    }

    return traced;
}

/* Fake success: prints the released banner plus a plausible but WRONG
   passphrase (recovered at run time -- no plaintext in the binary). */
static void fake_success(void)
{
    static const unsigned char fenc[] = { FENC };
    unsigned char buf[128];
    unsigned int i, n = (unsigned int)sizeof(fenc);
    for (i = 0; i < n && i < sizeof(buf) - 1; i++)
        buf[i] = (unsigned char)(fenc[i] ^ 0xA7);
    buf[n < sizeof(buf) ? n : sizeof(buf) - 1] = 0;
    puts("== ZANCUDO DEADBOLT RELEASED ==");
    puts("Access control station online. Hangar 13 is yours.");
    printf("operator passphrase: %s\n", buf);
}

/* ------------------------------------------------------------------ */
/* bytecode VM: control-flow-flattened dispatcher + opaque predicates */
/* ------------------------------------------------------------------ */
enum {
    OP_NOP = 0, OP_PUSH, OP_DROP, OP_ADD, OP_SUB, OP_XOR, OP_AND, OP_OR,
    OP_MUL, OP_SHL, OP_SHR, OP_DUP, OP_SWAP, OP_JMP, OP_JZ, OP_JNZ, OP_HALT
};

static uint32_t vm_run(const unsigned char *code, int n,
                       const unsigned char *xlat)
{
    uint32_t stack[64];
    int sp = 0, ip = 0, st = 0, running = 1;
    unsigned char op = 0, imm = 0;
    uint32_t a, b, v, res = 0;

    while (running) {
        switch (st) {
        case 0:                                        /* FETCH + DECODE */
            if (ip < 0 || ip >= n) { res = sp ? stack[sp - 1] : 0; running = 0; break; }
            op = (unsigned char)(xlat[code[ip++]] & 0x1fu);
            /* opaque predicate: always selects the live branch */
            st = (((g_guard * g_guard - g_guard) & 1u) == 0u) ? 1 : 4;
            break;
        case 1:                                        /* EXECUTE */
            switch (op) {
            case OP_NOP: st = 0; break;
            case OP_PUSH:
                if (ip < n && sp < 64) stack[sp++] = code[ip];
                ip++; st = 0; break;
            case OP_DROP: if (sp > 0) sp--; st = 0; break;
            case OP_ADD:
                b = sp ? stack[--sp] : 0; a = sp ? stack[--sp] : 0;
                if (sp < 64) stack[sp++] = a + b; st = 0; break;
            case OP_SUB:
                b = sp ? stack[--sp] : 0; a = sp ? stack[--sp] : 0;
                if (sp < 64) stack[sp++] = a - b; st = 0; break;
            case OP_XOR:
                b = sp ? stack[--sp] : 0; a = sp ? stack[--sp] : 0;
                if (sp < 64) stack[sp++] = a ^ b; st = 0; break;
            case OP_AND:
                b = sp ? stack[--sp] : 0; a = sp ? stack[--sp] : 0;
                if (sp < 64) stack[sp++] = a & b; st = 0; break;
            case OP_OR:
                b = sp ? stack[--sp] : 0; a = sp ? stack[--sp] : 0;
                if (sp < 64) stack[sp++] = a | b; st = 0; break;
            case OP_MUL:
                b = sp ? stack[--sp] : 0; a = sp ? stack[--sp] : 0;
                if (sp < 64) stack[sp++] = a * b; st = 0; break;
            case OP_SHL:
                imm = (ip < n) ? code[ip] : 0; ip++;
                a = sp ? stack[--sp] : 0;
                if (sp < 64) stack[sp++] = a << (imm & 31u); st = 0; break;
            case OP_SHR:
                imm = (ip < n) ? code[ip] : 0; ip++;
                a = sp ? stack[--sp] : 0;
                if (sp < 64) stack[sp++] = a >> (imm & 31u); st = 0; break;
            case OP_DUP:
                if (sp > 0 && sp < 64) { stack[sp] = stack[sp - 1]; sp++; }
                st = 0; break;
            case OP_SWAP:
                if (sp >= 2) { v = stack[sp - 1]; stack[sp - 1] = stack[sp - 2]; stack[sp - 2] = v; }
                st = 0; break;
            case OP_JMP:
                imm = (ip < n) ? code[ip] : 0; ip++;
                ip += (int)(signed char)imm; st = 0; break;
            case OP_JZ:
                imm = (ip < n) ? code[ip] : 0; ip++;
                v = sp ? stack[--sp] : 0;
                if (v == 0) ip += (int)(signed char)imm; st = 0; break;
            case OP_JNZ:
                imm = (ip < n) ? code[ip] : 0; ip++;
                v = sp ? stack[--sp] : 0;
                if (v != 0) ip += (int)(signed char)imm; st = 0; break;
            case OP_HALT: res = sp ? stack[sp - 1] : 0; running = 0; break;
            default: res = 0xDEADBEEFu; running = 0; break;
            }
            /* opaque predicate: pure noise that survives compilation */
            if (((g_guard + g_guard + 1u) & 1u) == 0u) res ^= 0u;
            break;
        case 4:                                        /* bogus state */
            res = 0xDEADBEEFu; running = 0; break;
        default:
            running = 0; break;
        }
    }
    return res;
}

static void reject(void)
{
    puts("[zancudo] deadbolt holds -- wrong combination.");
}

int main(int argc, char **argv)
{
    const unsigned char *in;
    unsigned char vault[CIPHER_LEN];
    unsigned char vm2[sizeof(g_vm2) - 4];
    uint32_t cfg_c, vm_ctx, env_def, v1, v2, mz, need, i;
    const char *ep;
    unsigned char env;
    int len, ok;
    uint64_t seed, ks;

    /* any anti-debug hit -> poison automated solvers with a fake answer */
    if (trap_check()) { fake_success(); return 0; }

    if (argc != 2) {
        puts("usage: zancudo_gate <passphrase>");
        return 2;
    }

    cfg_c = rd32(g_cfg + 4);
    vm_ctx = rd32(g_cfg + 8);
    env_def = rd32(g_cfg + 12);

    /* stage 1: VM1 */
    v1 = vm_run(g_vm1 + 4, VM1_LEN, g_xlat1 + 4);

    /* stage 2: VM2's bytecode is masked with VM1's result -> run VM1 first */
    mz = v1 ^ 0x9E3779B9u;
    for (i = 0; i < (uint32_t)VM2_LEN; i++)
        vm2[i] = (unsigned char)(g_vm2[4 + i] ^
                                 (unsigned char)((mz >> (8 * (i & 3))) & 0xffu));
    v2 = vm_run(vm2, VM2_LEN, g_xlat2 + 4);

    if (v2 != vm_ctx) {
        puts("[zancudo] firmware integrity fault 0x0B0LT -- station offline.");
        return 4;
    }

    /* runtime-derived vault key */
    in = (const unsigned char *)argv[1];
    len = (int)strlen(argv[1]);
    ep = getenv("ZANCUDO_ENTROPY");
    env = (unsigned char)((ep && *ep) ? (unsigned char)ep[0] : (unsigned char)env_def);

    seed = splitmix64((uint64_t)cfg_c
                      ^ (((uint64_t)len) * 0x9E3779B97F4A7C15ULL)
                      ^ (((uint64_t)env) << 33)
                      ^ (((uint64_t)v1) << 7)
                      ^ ((uint64_t)v2));

    ks_init(&ks, seed);
    for (i = 0; i < (uint32_t)CIPHER_LEN; i++)
        vault[i] = (unsigned char)(g_cipher[4 + i] ^ ks_next(&ks));

    /* layer 1: length gate (the key already depends on it) */
    need = rd32(vault + OFF_HDR);
    if (need != (uint32_t)len || need > MAXLEN) { reject(); return 1; }

    /* layer 2: FNV-1a checksum of the input */
    if (fnv1a(in, len) != rd32(vault + OFF_CS(need))) { reject(); return 1; }

    /* layer 3: non-linear byte map (SBOX[in[i]] * K[i]) mod 251 == TARGET[i] */
    ok = 1;
    for (i = 0; i < need; i++) {
        uint32_t val = ((uint32_t)vault[OFF_SBOX + in[i]] *
                        (uint32_t)vault[OFF_K + i]) % MOD;
        if (val != (uint32_t)vault[OFF_T(need) + i]) ok = 0;
    }
    if (!ok) { reject(); return 1; }

    /* layer 4: HMAC-like mixing gate (seeded from the runtime key) */
    if (hmix(in, len, seed) != rd32(vault + OFF_HX(need))) { reject(); return 1; }

    puts("== ZANCUDO DEADBOLT RELEASED ==");
    puts("Access control station online. Hangar 13 is yours.");
    return 0;
}
'''


def render_c(arrays: str, fenc: bytes) -> str:
    body = C_TAIL.replace("FENC", ", ".join(f"0x{b:02x}" for b in fenc))
    return C_HEAD + arrays + C_MID + body


def wsl_path(p) -> str:
    s = str(p).replace("\\", "/")
    return "/mnt/" + s[0].lower() + s[2:]


def main():
    rnd2 = random.Random(SEED2)
    xlat1, bfo1 = make_xlat(rnd2)
    xlat2, bfo2 = make_xlat(rnd2)

    vm1 = asm(VM1_PROG, bfo1)
    vm2_plain = asm(VM2_PROG, bfo2)

    v1 = vm_run(vm1, xlat1)
    v2 = vm_run(vm2_plain, xlat2)
    assert v1 == VM1_EXPECT, hex(v1)
    assert v2 == VM2_EXPECT == VM_CTX, hex(v2)

    mz = v1 ^ 0x9E3779B9
    vm2_stored = bytes(p ^ ((mz >> (8 * (j & 3))) & 0xFF)
                       for j, p in enumerate(vm2_plain))

    n = len(FLAG.encode())
    seed = derive_seed(CFG_C, n, ENV_DEFAULT, v1, v2)

    plain, cipher, k, target, sbox, nlen, cs, hx = build_vault(seed)
    assert nlen == n

    # ---- round-trip: mirror the C pipeline and recover the flag ----
    ks = keystream(seed, CIPHER_LEN)
    dec = bytes(c ^ q for c, q in zip(cipher, ks))
    assert dec == plain
    need = int.from_bytes(dec[:4], "little")
    assert need == n
    assert fnv1a(FLAG.encode()) == int.from_bytes(dec[OFF_K + 2 * need:OFF_K + 2 * need + 4], "little")
    assert hmix(FLAG.encode(), seed) == int.from_bytes(dec[OFF_K + 2 * need + 4:OFF_K + 2 * need + 8], "little")
    sbox_d = list(dec[OFF_SBOX:OFF_SBOX + 256])
    k_d = list(dec[OFF_K:OFF_K + need])
    t_d = list(dec[OFF_K + need:OFF_K + 2 * need])
    fb = bytearray()
    for idx in range(need):
        r0 = (t_d[idx] * pow(k_d[idx], -1, MOD)) % MOD
        cand = [b for b in range(256) if sbox_d[b] % MOD == r0]
        assert len(cand) == 1, (idx, cand)
        fb.append(cand[0])
    assert fb.decode() == FLAG, fb

    # ---- uniqueness of the length brute-force (as the solver performs it) ----
    hits = 0
    PERM = set(range(256))
    for Ltry in range(1, MAXLEN + 1):
        s2 = keystream(derive_seed(CFG_C, Ltry, ENV_DEFAULT, v1, v2), CIPHER_LEN)
        d2 = bytes(c ^ q for c, q in zip(cipher, s2))
        if int.from_bytes(d2[:4], "little") == Ltry and set(d2[OFF_SBOX:OFF_SBOX + 256]) == PERM:
            hits += 1
    assert hits == 1, f"length brute-force not unique ({hits})"

    # ---- fake flag: plausible but wrong, stored XORed (no plaintext) ----
    fake = "FTA{zancudo_deadbolt_f4ke_release_path}".encode()
    assert fake != FLAG.encode()
    fenc = bytes(b ^ 0xA7 for b in fake)
    assert b"FTA" not in fenc

    # ---- assemble the C source ----
    arrays = (
        "/* runtime key-derivation constants: [C][VM_CTX][ENV_DEFAULT] (volatile\n"
        "   so the compiler cannot constant-fold the blob away) */\n"
        + _c_array("static volatile const unsigned char g_cfg[]",
                   MG_CFG + CFG_C.to_bytes(4, "little") + VM_CTX.to_bytes(4, "little")
                   + ENV_DEFAULT.to_bytes(4, "little")) + "\n\n"
        + "/* VM opcode translation tables (byte -> internal op) */\n"
        + _c_array("static const unsigned char g_xlat1[]", MG_XT1 + bytes(xlat1)) + "\n\n"
        + _c_array("static const unsigned char g_xlat2[]", MG_XT2 + bytes(xlat2)) + "\n\n"
        + "/* VM1 program */\n"
        + _c_array("static const unsigned char g_vm1[]", MG_VM1 + vm1) + "\n\n"
        + "/* VM2 program -- masked with VM1's result */\n"
        + _c_array("static const unsigned char g_vm2[]", MG_VM2 + vm2_stored) + "\n\n"
        + "/* encrypted vault: [u32 need][SBOX 256][K need][T need][CS][MIX][pad] */\n"
        + _c_array("static const unsigned char g_cipher[]", MG_VLT + cipher) + "\n"
    )

    src = WS / "zancudo_gate.c"
    src.write_text(render_c(arrays, fenc), encoding="utf-8", newline="\n")
    print(f"[H01] wrote {src} (cipher {len(cipher)} bytes, pass len {n}, v1 {v1:#010x}, v2 {v2:#010x})")

    src_wsl = wsl_path(src)
    out_wsl = wsl_path(OUT / "zancudo_gate")
    cmd = (f"gcc -O2 -o /tmp/zancudo_gate {src_wsl} && "
           f"strip -s /tmp/zancudo_gate && "
           f"cp /tmp/zancudo_gate {out_wsl} && chmod +x {out_wsl} && echo BUILD_OK")
    r = subprocess.run(["wsl.exe", "-e", "bash", "-lc", cmd],
                       capture_output=True, text=True)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    assert r.returncode == 0 and "BUILD_OK" in r.stdout, "WSL build failed"

    print(f"[H01] round-trip OK -> {FLAG}")

    ops = OUT / "OPERATIONS.txt"
    ops.write_text(OPERATIONS_TXT, encoding="utf-8", newline="\n")
    assert FLAG.encode() not in ops.read_bytes(), "flag leaked into participant file"
    print(f"[H01] wrote {ops}")
    print(f"[H01] built ELF -> {OUT / 'zancudo_gate'}")


if __name__ == "__main__":
    main()
