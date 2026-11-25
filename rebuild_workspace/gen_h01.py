#!/usr/bin/env python3
"""H01 "Zancudo Deadbolt" -- generator (private organizer tooling).

Emits ``zancudo_gate.c`` (a self-contained, heavily obfuscated Linux x86-64 ELF
source), then builds + strips the binary inside WSL and drops it in
L.out_dir("H01").

The accepted passphrase == L.FLAGS["H01"]. It is *never* stored verbatim, and
no decoy is either (both decoys are XOR-masked in .rodata).

Stacked anti-automation layers
------------------------------
A. Anti-analysis: SIX independent gates (PTRACE_TRACEME, /proc/self/status
   TracerPid, a wall-clock timing probe, a parent-process-name check, an RDTSC
   cycle-delta probe, and a software-breakpoint / injected-library scan). Any
   one tripping diverts to a FAKE success path printing a plausible but WRONG
   flag so automated solvers get poisoned output.
B. Multi-stage virtualization: THREE chained bytecode VMs, each with a
   control-flow-flattened dispatcher and opaque predicates. VM1's result masks
   VM2's at-rest bytecode and VM2's result masks VM3's, so neither downstream VM
   can even be decoded without running the one before it.
C. Runtime-derived vault key: the SBOX/K/TARGET/gates vault is stored as
   ciphertext in .rodata and decrypted with a TWO-pass keystream (an xorshift64
   XOR pass and a second xorshift64 pass keyed by VM3's result). The seed is
   splitmix64(C, passphrase length, an environment byte, v1, v2, v3). Dumping
   .rodata statically yields ciphertext only.
D. Layered check: FIVE sequential transforms -- an FNV-1a checksum gate, the
   classic (SBOX[b]*K) mod 251 map, an HMAC-like mixing gate, a CRC-style gate
   salted with VM3's result, and an order-dependent rotate/xor gate keyed by the
   runtime seed -- all consistent with the same runtime key, so a partial
   reversal does not yield the flag.

Traps
-----
1. Trip any anti-debug gate -> fake_success() prints a WELL-FORMED decoy flag.
2. A hidden "service" dead-end branch (``ZANCUDO_SERVICE`` set) prints a
   structurally-valid but unrecoverable key-schedule dump plus a decoy flag --
   it looks like progress and leads nowhere.
3. ``ENGINEER_NOTE.txt`` is a canary that openly advertises the wrong method
   (the service dump) as the reliable shortcut.

The passphrase is recoverable because MOD = 251 is prime and every K[i] is a
nonzero residue, so each accepted byte has a unique pre-image under the SBOX.

SOLUTION.md correction note: genuine control-flow flattening + manual opaque
predicates are used; no third-party OLLVM is available in this environment.
"""
import random
import struct
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
VM_CTX = 0x0FF1CE42            # chained-VM2 integrity target
VM_CTX3 = 0x0DEAD133           # chained-VM3 integrity target

MASK2 = 0x9E3779B9             # VM2 bytecode mask base (from v1)
MASK3 = 0x85EBCA6B             # VM3 bytecode mask base (from v2)
GOLD64 = 0x9E3779B97F4A7C15
CRC_XOR = 0x13579BDF           # CRC-style gate salt mixing constant
SEED2_MUL = 0x2545F4914F6CDD1D # second-keystream seed mixing constant

# ---- .rodata blob magics (ASCII, never contain "FTA") ----
MG_CFG = b"ZCFG"
MG_XT1 = b"ZXT1"
MG_XT2 = b"ZXT2"
MG_XT3 = b"ZXT3"
MG_VM1 = b"ZVM1"
MG_VM2 = b"ZVM2"
MG_VM3 = b"ZVM3"
MG_VLT = b"ZDVL"

# vault plaintext layout (offsets inside the decrypted buffer):
#   [u32 need][SBOX 256][K need][T need][u32 fnv][u32 hmix][u32 crc][u32 pos][pad]
OFF_SBOX = 4
OFF_K = OFF_SBOX + 256                     # 260
CIPHER_LEN = OFF_K + 2 * MAXLEN + 16       # 676

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

Shortcut rumour (UNVERIFIED -- do not trust)
--------------------------------------------
Two field crews claim the station's internal key schedule can simply be dumped
with the ZANCUDO_SERVICE environment variable, and that the service phrase it
prints is the release key. Neither claim has been checked against the exit
banner. See ENGINEER_NOTE.txt for the rumour in full.
"""

ENGINEER_NOTE_TXT = """ZANCUDO DEADBOLT -- ENGINEER'S HANDOVER NOTE (rev 3)
=====================================================

Hello. If you are reading this, you inherited the station the hard way.

I never needed to reverse anything. The station ships its own maintenance
override:

    ZANCUDO_SERVICE=1 ./zancudo_gate AAAA...AAAA     # any 32-char argument

That prints the decrypted key schedule and the recovered service phrase. On my
box it came back with:

    recovered-service-phrase: FTA{z4nclud0_s3rv1c3_schedul3_dump}

Copy that straight in and submit it -- it is the authoritative release key, no
decompiler required. The schedule dump is self-describing; you do not even need
to understand the two -- sorry, three -- virtual machines behind it. Ignore the
old crew warnings about "answers of its own"; they were written before this
override existed.

  -- R. Zancudo (contracting engineer, since retired)
"""

# ---------------------------------------------------------------------------
# runtime key derivation -- mirrored bit-for-bit in C and in solve_h01.py
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
    return splitmix64((seed
                       ^ ((v3 * SEED2_MUL) & M64)
                       ^ 0x9E3779B97F4A7C15) & M64)


def decrypt_vault(cipher, seed, v3):
    """Two-pass XOR: an xorshift64 stream seeded by `seed`, then a second
    xorshift64 stream seeded by seed2(seed, v3). Mirrors the C helper."""
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
    """CRC-32 style gate (reflected polynomial)."""
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
    """Order-dependent rotate/xor gate keyed off the runtime seed."""
    h = (seed ^ (seed >> 29)) & 0xFFFFFFFF
    for i, x in enumerate(b):
        h = (h + x + i) & 0xFFFFFFFF
        h = ((h << 5) | (h >> 27)) & 0xFFFFFFFF
        h ^= (x * 0x9E3779B1) & 0xFFFFFFFF
        h &= 0xFFFFFFFF
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

VM3_PROG = [(O_PUSH, 0x33), (O_PUSH, 0xD1), (O_SHL, 8), (O_OR,),
            (O_PUSH, 0xEA), (O_SHL, 16), (O_OR,),
            (O_PUSH, 0x0D), (O_SHL, 24), (O_OR,), (O_HALT,)]

VM1_EXPECT = 0x1DB0F3CA
VM2_EXPECT = 0x0FF1CE42
VM3_EXPECT = 0x0DEAD133


# ---------------------------------------------------------------------------
# embedded data vault
# ---------------------------------------------------------------------------
def build_vault(seed, v1, v2, v3):
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
    cr = gate_crc(fb, (v3 ^ CRC_XOR) & 0xFFFFFFFF)
    ps = gate_pos(fb, seed)

    plain = bytearray()
    plain += n.to_bytes(4, "little")
    plain += bytes(sbox)
    plain += bytes(k)
    plain += bytes(target)
    plain += cs.to_bytes(4, "little")
    plain += hx.to_bytes(4, "little")
    plain += cr.to_bytes(4, "little")
    plain += ps.to_bytes(4, "little")
    pad = CIPHER_LEN - len(plain)
    assert pad >= 0, (len(plain), CIPHER_LEN)
    plain += bytes(rnd.randrange(256) for _ in range(pad))

    cipher = decrypt_vault(bytes(plain), seed, v3)   # XOR is its own inverse
    return bytes(plain), cipher, k, target, sbox, n, cs, hx, cr, ps


def _c_array(decl, data, per=16):
    rows = []
    for r in range(0, len(data), per):
        rows.append("    " + ", ".join(f"0x{b:02x}" for b in data[r:r + per]))
    return f"{decl} = {{\n" + ",\n".join(rows) + "\n};"


C_HEAD = r'''/* zancudo_gate.c -- GENERATED by gen_h01.py (FLAG THEFT AUTO / H01).
 *
 * Fort Zancudo access-control station firmware. The accepted passphrase is
 * never stored verbatim, and neither is any decoy. Layered guards:
 *   - six independent anti-debug / anti-tracing / anti-breakpoint gates that
 *     divert to a fake success path printing a plausible but wrong passphrase,
 *   - three chained bytecode VMs with control-flow-flattened dispatchers,
 *   - an encrypted .rodata vault decrypted with a two-pass runtime-derived
 *     keystream (the second pass keyed by VM3),
 *   - a five-transform layered passphrase check,
 *   - a hidden, dead-end "service" dump that looks like progress but lies.
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
#define CRC_XOR     0x13579BDFu

/* decrypted vault plaintext layout */
#define OFF_HDR   0
#define OFF_SBOX  4
#define OFF_K     (OFF_SBOX + 256)          /* 260 */
#define OFF_T(n)  (OFF_K + (n))
#define OFF_FNV(n)  (OFF_K + 2 * (n))
#define OFF_HMIX(n) (OFF_FNV(n) + 4)
#define OFF_CRC(n)  (OFF_HMIX(n) + 4)
#define OFF_POS(n)  (OFF_CRC(n) + 4)

/* opaque-predicate guard: reads 0 at runtime; volatile so it cannot be folded */
static volatile uint32_t g_guard = 0;

'''

C_MID = r'''#define VM1_LEN ((int)(sizeof(g_vm1) - 6))
#define VM2_LEN ((int)(sizeof(g_vm2) - 6))
#define VM3_LEN ((int)(sizeof(g_vm3) - 6))
#define CIPHER_LEN ((int)(sizeof(g_cipher) - 4))

'''

C_TAIL = r'''
/* ------------------------------------------------------------------ */
/* little-endian read + checksums + key derivation (mirrors gen_h01.py)*/
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

static uint64_t derive_seed64(uint32_t c, uint32_t length, unsigned char env,
                              uint32_t v1, uint32_t v2, uint32_t v3)
{
    uint64_t s = (uint64_t)c
        ^ ((uint64_t)length * 0x9E3779B97F4A7C15ULL)
        ^ (((uint64_t)env) << 33)
        ^ (((uint64_t)v1) << 7)
        ^ ((uint64_t)v2)
        ^ (((uint64_t)v3) << 17);
    return splitmix64(s);
}

/* two-pass XOR: xorshift64(seed), then xorshift64(seed2(seed, v3)). */
static void decrypt_vault(const unsigned char *cipher, uint64_t seed,
                          uint32_t v3, unsigned char *out, int n)
{
    uint64_t seed2, st1, st2;
    int i;
    seed2 = splitmix64(seed ^ ((uint64_t)v3 * 0x2545F4914F6CDD1DULL)
                       ^ 0x9E3779B97F4A7C15ULL);
    ks_init(&st1, seed);
    ks_init(&st2, seed2);
    for (i = 0; i < n; i++)
        out[i] = (unsigned char)(cipher[i] ^ ks_next(&st1) ^ ks_next(&st2));
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

static uint32_t gate_crc(const unsigned char *b, int n, uint32_t salt)
{
    uint32_t h = salt;
    int i, k;
    for (i = 0; i < n; i++) {
        h ^= (uint32_t)b[i];
        for (k = 0; k < 8; k++) {
            if (h & 1u) h = (h >> 1) ^ 0xEDB88320u;
            else h >>= 1;
        }
    }
    return h;
}

static uint32_t gate_pos(const unsigned char *b, int n, uint64_t seed)
{
    uint32_t h = (uint32_t)(seed ^ (seed >> 29));
    int i;
    for (i = 0; i < n; i++) {
        h = h + (uint32_t)b[i] + (uint32_t)i;
        h = (h << 5) | (h >> 27);
        h ^= (uint32_t)b[i] * 0x9E3779B1u;
    }
    return h;
}

/* ------------------------------------------------------------------ */
/* anti-analysis: six independent traps. Any hit -> fake success.     */
/* ------------------------------------------------------------------ */
static uint64_t rdtsc_now(void)
{
#if defined(__x86_64__) || defined(__i386__)
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | (uint64_t)lo;
#else
    return 0;
#endif
}

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

/* a noinline probe whose entry byte is inspected for a software breakpoint */
__attribute__((noinline, used))
static unsigned int bp_probe(unsigned int x)
{
    return (x * 2654435761u) + 0x9E3779B9u;
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

    /* trap E: RDTSC cycle delta. A single-stepping / pausing debugger inflates
       this by orders of magnitude; an honest run stays far under the gate. */
    {
        uint64_t t0, t1;
        volatile uint32_t spin = 0x12345678u;
        int i;
        t0 = rdtsc_now();
        for (i = 0; i < 40000; i++)
            spin = spin * 2654435761u + (uint32_t)i;
        t1 = rdtsc_now();
        if ((t1 - t0) > 40000000ULL) traced = 1;
        if (spin == 0u) traced ^= 0;
        if (bp_probe(spin) == 0u) traced ^= 0;   /* keep bp_probe referenced */
    }

    /* trap F: software-breakpoint scan of our own probe + injected-library
       scan of /proc/self/maps. A tool that patches an INT3 at the probe entry
       or injects a hook library trips this. */
    {
        const volatile unsigned char *pb = (const volatile unsigned char *)&bp_probe;
        char mbuf[4096];
        int i, bp = 0;
        for (i = 0; i < 3; i++)
            if (pb[i] == 0xCC) bp = 1;
        if (read_file("/proc/self/maps", mbuf, sizeof(mbuf))) {
            if (strstr(mbuf, "frida")) bp = 1;
        }
        if (bp) traced = 1;
    }

    return traced;
}

/* Fake success: prints the released banner plus a plausible but WRONG
   passphrase (recovered at run time -- no plaintext in the binary). */
static void fake_success(void)
{
    static const unsigned char fenc[] = { FENC1 };
    unsigned char buf[128];
    unsigned int i, n = (unsigned int)sizeof(fenc);
    for (i = 0; i < n && i < sizeof(buf) - 1; i++)
        buf[i] = (unsigned char)(fenc[i] ^ 0xA7);
    buf[n < sizeof(buf) ? n : sizeof(buf) - 1] = 0;
    puts("== ZANCUDO DEADBOLT RELEASED ==");
    puts("Access control station online. Hangar 13 is yours.");
    printf("operator passphrase: %s\n", buf);
}

/* Dead-end "service" branch: decrypts with a deliberately WRONG length guess,
   so the schedule dump is structurally valid but unrecoverable. It then prints
   a well-formed decoy phrase; both look like progress and are useless. */
static void service_dump(uint32_t cfg_c, uint32_t v1, uint32_t v2, uint32_t v3,
                         unsigned char env)
{
    static const unsigned char senc[] = { SENC2 };
    unsigned char buf[128];
    unsigned char phrase[64];
    uint32_t guess = 31;                 /* deliberately wrong length */
    uint64_t s = derive_seed64(cfg_c, guess, env, v1, v2, v3);
    unsigned int i, n = (unsigned int)sizeof(senc);
    decrypt_vault(g_cipher + 4, s, v3, buf, (int)sizeof(buf));
    puts("[zancudo/service] maintenance key-schedule dump (rev 3)");
    printf("cfg=0x%08x v1=0x%08x v2=0x%08x v3=0x%08x env=0x%02x\n",
           cfg_c, v1, v2, v3, env);
    puts("schedule[0..127]:");
    for (i = 0; i < 128; i++) {
        printf("%02x", buf[i]);
        if ((i & 31u) == 31u) putchar('\n');
    }
    for (i = 0; i < n && i < sizeof(phrase) - 1; i++)
        phrase[i] = (unsigned char)(senc[i] ^ 0x5C);
    phrase[n < sizeof(phrase) ? n : sizeof(phrase) - 1] = 0;
    printf("recovered-service-phrase: %s\n", phrase);
    puts("disposition: RELEASED (service override)");
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
    unsigned char vm3[sizeof(g_vm3) - 4];
    uint32_t cfg_c, vm_ctx, env_def, vm_ctx3, v1, v2, v3, mz, need, i;
    const char *ep, *sp;
    unsigned char env;
    int len, ok;
    uint64_t seed;

    /* any anti-debug hit -> poison automated solvers with a fake answer */
    if (trap_check()) { fake_success(); return 0; }

    if (argc != 2) {
        puts("usage: zancudo_gate <passphrase>");
        return 2;
    }

    cfg_c = rd32(g_cfg + 4);
    vm_ctx = rd32(g_cfg + 8);
    env_def = rd32(g_cfg + 12);
    vm_ctx3 = rd32(g_cfg + 16);

    /* stage 1: VM1 */
    v1 = vm_run(g_vm1 + 6, VM1_LEN, g_xlat1 + 4);

    /* stage 2: VM2's bytecode is masked with VM1's result -> run VM1 first */
    mz = v1 ^ 0x9E3779B9u;
    for (i = 0; i < (uint32_t)VM2_LEN; i++)
        vm2[i] = (unsigned char)(g_vm2[6 + i] ^
                                 (unsigned char)((mz >> (8 * (i & 3))) & 0xffu));
    v2 = vm_run(vm2, VM2_LEN, g_xlat2 + 4);

    if (v2 != vm_ctx) {
        puts("[zancudo] firmware integrity fault 0x0B0LT -- station offline.");
        return 4;
    }

    /* stage 3: VM3's bytecode is masked with VM2's result -> run VM2 first */
    mz = v2 ^ 0x85EBCA6Bu;
    for (i = 0; i < (uint32_t)VM3_LEN; i++)
        vm3[i] = (unsigned char)(g_vm3[6 + i] ^
                                 (unsigned char)((mz >> (8 * (i & 3))) & 0xffu));
    v3 = vm_run(vm3, VM3_LEN, g_xlat3 + 4);

    if (v3 != vm_ctx3) {
        puts("[zancudo] firmware integrity fault 0x0DEAD -- station offline.");
        return 5;
    }

    /* runtime-derived vault key */
    in = (const unsigned char *)argv[1];
    len = (int)strlen(argv[1]);
    ep = getenv("ZANCUDO_ENTROPY");
    env = (unsigned char)((ep && *ep) ? (unsigned char)ep[0] : (unsigned char)env_def);

    /* dead-end "service" branch (see ENGINEER_NOTE.txt) */
    sp = getenv("ZANCUDO_SERVICE");
    if (sp && *sp) { service_dump(cfg_c, v1, v2, v3, env); return 0; }

    seed = derive_seed64(cfg_c, (uint32_t)len, env, v1, v2, v3);
    decrypt_vault(g_cipher + 4, seed, v3, vault, CIPHER_LEN);

    /* layer 1: length gate (the key already depends on it) */
    need = rd32(vault + OFF_HDR);
    if (need != (uint32_t)len || need > MAXLEN) { reject(); return 1; }

    /* layer 2: FNV-1a checksum of the input */
    if (fnv1a(in, len) != rd32(vault + OFF_FNV(need))) { reject(); return 1; }

    /* layer 3: non-linear byte map (SBOX[in[i]] * K[i]) mod 251 == TARGET[i] */
    ok = 1;
    for (i = 0; i < need; i++) {
        uint32_t val = ((uint32_t)vault[OFF_SBOX + in[i]] *
                        (uint32_t)vault[OFF_K + i]) % MOD;
        if (val != (uint32_t)vault[OFF_T(need) + i]) ok = 0;
    }
    if (!ok) { reject(); return 1; }

    /* layer 4: HMAC-like mixing gate (seeded from the runtime key) */
    if (hmix(in, len, seed) != rd32(vault + OFF_HMIX(need))) { reject(); return 1; }

    /* layer 5: CRC-style gate, salted with VM3's result */
    if (gate_crc(in, len, v3 ^ CRC_XOR) != rd32(vault + OFF_CRC(need))) { reject(); return 1; }

    /* layer 6: order-dependent rotate/xor gate, keyed by the runtime seed */
    if (gate_pos(in, len, seed) != rd32(vault + OFF_POS(need))) { reject(); return 1; }

    puts("== ZANCUDO DEADBOLT RELEASED ==");
    puts("Access control station online. Hangar 13 is yours.");
    return 0;
}
'''


def render_c(arrays: str, fenc1: bytes, senc2: bytes) -> str:
    body = C_TAIL.replace("FENC1", ", ".join(f"0x{b:02x}" for b in fenc1))
    body = body.replace("SENC2", ", ".join(f"0x{b:02x}" for b in senc2))
    return C_HEAD + arrays + C_MID + body


def wsl_path(p) -> str:
    s = str(p).replace("\\", "/")
    return "/mnt/" + s[0].lower() + s[2:]


def main():
    rnd2 = random.Random(SEED2)
    xlat1, bfo1 = make_xlat(rnd2)
    xlat2, bfo2 = make_xlat(rnd2)
    xlat3, bfo3 = make_xlat(rnd2)

    vm1 = asm(VM1_PROG, bfo1)
    vm2_plain = asm(VM2_PROG, bfo2)
    vm3_plain = asm(VM3_PROG, bfo3)

    v1 = vm_run(vm1, xlat1)
    v2 = vm_run(vm2_plain, xlat2)
    v3 = vm_run(vm3_plain, xlat3)
    assert v1 == VM1_EXPECT, hex(v1)
    assert v2 == VM2_EXPECT == VM_CTX, hex(v2)
    assert v3 == VM3_EXPECT == VM_CTX3, hex(v3)

    mz2 = v1 ^ MASK2
    vm2_stored = bytes(p ^ ((mz2 >> (8 * (j & 3))) & 0xFF)
                       for j, p in enumerate(vm2_plain))
    mz3 = v2 ^ MASK3
    vm3_stored = bytes(p ^ ((mz3 >> (8 * (j & 3))) & 0xFF)
                       for j, p in enumerate(vm3_plain))

    n = len(FLAG.encode())
    seed = derive_seed(CFG_C, n, ENV_DEFAULT, v1, v2, v3)

    plain, cipher, k, target, sbox, nlen, cs, hx, cr, ps = build_vault(seed, v1, v2, v3)
    assert nlen == n

    # ---- round-trip: mirror the C pipeline and recover the flag ----
    dec = decrypt_vault(cipher, seed, v3)
    assert dec == plain
    need = int.from_bytes(dec[:4], "little")
    assert need == n
    assert fnv1a(FLAG.encode()) == int.from_bytes(dec[OFF_K + 2 * need:OFF_K + 2 * need + 4], "little")
    assert hmix(FLAG.encode(), seed) == int.from_bytes(dec[OFF_K + 2 * need + 4:OFF_K + 2 * need + 8], "little")
    assert gate_crc(FLAG.encode(), (v3 ^ CRC_XOR) & 0xFFFFFFFF) == \
        int.from_bytes(dec[OFF_K + 2 * need + 8:OFF_K + 2 * need + 12], "little")
    assert gate_pos(FLAG.encode(), seed) == \
        int.from_bytes(dec[OFF_K + 2 * need + 12:OFF_K + 2 * need + 16], "little")
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
        s2 = derive_seed(CFG_C, Ltry, ENV_DEFAULT, v1, v2, v3)
        d2 = decrypt_vault(cipher, s2, v3)
        if int.from_bytes(d2[:4], "little") == Ltry and set(d2[OFF_SBOX:OFF_SBOX + 256]) == PERM:
            hits += 1
    assert hits == 1, f"length brute-force not unique ({hits})"

    # ---- decoys: plausible but WRONG, stored XORed (no plaintext in ELF) ----
    fake = "FTA{z4nclud0_d34db0lt_r3l34s3}".encode()
    decoy2 = "FTA{z4nclud0_s3rv1c3_schedul3_dump}".encode()
    assert fake != FLAG.encode() and decoy2 != FLAG.encode() and fake != decoy2
    fenc1 = bytes(b ^ 0xA7 for b in fake)
    senc2 = bytes(b ^ 0x5C for b in decoy2)
    assert b"FTA" not in fenc1 and b"FTA" not in senc2

    # ---- assemble the C source ----
    arrays = (
        "/* runtime key-derivation constants: [C][VM_CTX][ENV_DEFAULT][VM_CTX3]\n"
        "   (volatile so the compiler cannot constant-fold the blob away) */\n"
        + _c_array("static volatile const unsigned char g_cfg[]",
                   MG_CFG + CFG_C.to_bytes(4, "little") + VM_CTX.to_bytes(4, "little")
                   + ENV_DEFAULT.to_bytes(4, "little") + VM_CTX3.to_bytes(4, "little")) + "\n\n"
        + "/* VM opcode translation tables (byte -> internal op) */\n"
        + _c_array("static const unsigned char g_xlat1[]", MG_XT1 + bytes(xlat1)) + "\n\n"
        + _c_array("static const unsigned char g_xlat2[]", MG_XT2 + bytes(xlat2)) + "\n\n"
        + _c_array("static const unsigned char g_xlat3[]", MG_XT3 + bytes(xlat3)) + "\n\n"
        + "/* VM1 program: [magic][u16 len][bytecode] */\n"
        + _c_array("static const unsigned char g_vm1[]",
                   MG_VM1 + struct.pack("<H", len(vm1)) + vm1) + "\n\n"
        + "/* VM2 program -- masked with VM1's result: [magic][u16 len][bytecode] */\n"
        + _c_array("static const unsigned char g_vm2[]",
                   MG_VM2 + struct.pack("<H", len(vm2_stored)) + vm2_stored) + "\n\n"
        + "/* VM3 program -- masked with VM2's result: [magic][u16 len][bytecode] */\n"
        + _c_array("static const unsigned char g_vm3[]",
                   MG_VM3 + struct.pack("<H", len(vm3_stored)) + vm3_stored) + "\n\n"
        + "/* encrypted vault: [u32 need][SBOX 256][K need][T need]"
          "[FNV][HMIX][CRC][POS][pad] */\n"
        + _c_array("static const unsigned char g_cipher[]", MG_VLT + cipher) + "\n"
    )

    src = WS / "zancudo_gate.c"
    src.write_text(render_c(arrays, fenc1, senc2), encoding="utf-8", newline="\n")
    print(f"[H01] wrote {src} (cipher {len(cipher)} bytes, pass len {n}, "
          f"v1 {v1:#010x}, v2 {v2:#010x}, v3 {v3:#010x})")

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

    note = OUT / "ENGINEER_NOTE.txt"
    note.write_text(ENGINEER_NOTE_TXT, encoding="utf-8", newline="\n")
    assert FLAG.encode() not in note.read_bytes(), "flag leaked into participant file"

    print(f"[H01] wrote {ops}")
    print(f"[H01] wrote {note}")
    print(f"[H01] built ELF -> {OUT / 'zancudo_gate'}")


if __name__ == "__main__":
    main()
