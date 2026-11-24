#!/usr/bin/env bash
# E03 — Sandy Shores Hidden Stash. Builds an ext2 image (deleted-file recovery).
# Run inside WSL from the rebuild_workspace directory. Writes safehouse.img into
# the challenge output directory. Private organizer tooling.
#
# Hardened design (stacked layers):
#   * THREE deleted inodes: /ledger.dat, /ledger.bak, /notes.tmp. All three carve
#     + decompress to plausible content; only ONE is genuine.
#   * The genuine stash is selected by a non-obvious rule: its on-disk byte
#     length equals the `span=` field on line 42 of the surviving activity.log.
#   * Payload is masked with a REPEATING MULTI-BYTE key derived arithmetically
#     from TWO raw fields on that same log line (hostname + relay id).
#   * After unmasking the payload still needs an extra reversible layer:
#     zlib -> byte-reverse -> base64 -> plaintext.
set -euo pipefail

STAGE=/tmp/e03_stage
IMG=/tmp/e03_safehouse.img
OUT="/mnt/d/ctf/FLAG_THEFT_AUTO_FINAL/challenges_rebuilt/EASY/E03"
mkdir -p "$OUT"

rm -rf "$STAGE" "$IMG"
mkdir -p "$STAGE/receipts" "$STAGE/notes"

python3 - <<'PY'
import base64, random, zlib

stage = "/tmp/e03_stage"
FLAG = "FTA{ext2_st4sh_r3c0v3r3d_s4ndy_51}"

# ---------------------------------------------------------------------------
# activity.log : the surviving log. Line 42 carries the raw fields that define
# both the repeating-XOR key AND which deleted stash is genuine. The rule
# itself is NOT written anywhere -- only the raw field values.
# ---------------------------------------------------------------------------
rnd = random.Random(0x1337E03)
verbs = ["HEARTBEAT", "SYNC", "PUSH", "POLL", "ACK", "RETRY", "DUMP", "SEAL", "PURGE", "PING"]
host42 = "shores-dock-04"
relay = 7781

lines = []
for i in range(1, 61):
    if i == 42:
        # the only line carrying relay= and span= ; span filled in below
        line = (f"2026-11-20T03:14:07Z host={host42} user=ron action=SEAL "
                f"status=ok relay={relay} span=SPAN relist=ok")
    else:
        if rnd.random() < 0.25:
            host = f"shores-dock-{rnd.randint(1, 9):02d}"
        else:
            host = f"sandy-relay-{rnd.randint(1, 9)}"
        line = (f"2026-11-20T{rnd.randint(0, 23):02d}:{rnd.randint(0, 59):02d}:"
                f"{rnd.randint(0, 59):02d}Z host={host} "
                f"user={rnd.choice(['ron', 'trevor', 'wendy', 'pavel'])} "
                f"action={rnd.choice(verbs)} status={rnd.choice(['ok', 'degraded', 'queued'])}")
    lines.append(line)


# ---------------------------------------------------------------------------
# Layer 2: repeating multi-byte XOR key, derived arithmetically from TWO fields
# of the log line (the hostname string and the relay integer).
# ---------------------------------------------------------------------------
def derive_key(host: str, relay: int) -> bytes:
    klen = 4 + (len(host) % 5)                       # 4..8 bytes, from field 1
    return bytes((ord(host[i])                      # field 1: one char per byte
                  + ((relay >> (8 * (i % 4))) & 0xFF)  # field 2: rotating relay byte
                  + 7 * i) & 0xFF                    # position mixing
                 for i in range(klen))


key = derive_key(host42, relay)


# Layer 3: payload pipeline  plaintext -> base64 -> byte-reverse -> zlib
def seal(msg: str) -> bytes:
    rev = base64.b64encode(msg.encode())[::-1]
    comp = zlib.compress(rev, 9)
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(comp))


# genuine + two decoys (decoys each carry a plausible/fake FTA{...})
GENUINE = ("SAFEHOUSE LEDGER (SANDY SHORES)\n"
           "session=sandy-shores-audit\n"
           f"drop_flag={FLAG}\n")
DECOY_BAK = ("SAFEHOUSE LEDGER (SANDY SHORES)\n"
             "session=sandy-shores-audit\n"
             "rotation=previous\n"
             "drop_flag=FTA{l3dg3r_b4k_r0t4t3d_00}\n")
DECOY_TMP = ("SAFEHOUSE OPERATOR NOTES\n"
             "the night ledger was rotated; this scratch copy is stale\n"
             "if you carved this inode you took the bait\n"
             "drop_flag=FTA{tmp_n0t3_shr3dd3d_00}\n")

genuine = seal(GENUINE)
bak = seal(DECOY_BAK)
tmp = seal(DECOY_TMP)

# guarantee the three sealed blobs have distinct byte lengths so that `span`
# unambiguously selects exactly one of them
while len(bak) in (len(genuine), len(tmp)):
    DECOY_BAK += "."
    bak = seal(DECOY_BAK)
while len(tmp) == len(genuine):
    DECOY_TMP += "."
    tmp = seal(DECOY_TMP)

span = len(genuine)                                  # identification rule value

lines[41] = lines[41].replace("span=SPAN", f"span={span}")
open(f"{stage}/notes/activity.log", "w").write("\n".join(lines) + "\n")

open(f"{stage}/ledger.dat", "wb").write(genuine)
open(f"{stage}/ledger.bak", "wb").write(bak)
open(f"{stage}/notes.tmp", "wb").write(tmp)

# --- surviving decoy receipts & notes ---
open(f"{stage}/receipts/bar_tab.txt", "w").write(
    "Tequila Sunrise x2 .... 18.00\nNacho Supreme ....... 9.50\n"
    "Total due ........... 27.50\nPaid in Vespucci tokens.\n")
open(f"{stage}/notes/README.txt", "w").write(
    "SAFEHOUSE OPERATOR NOTES\n------------------------\n"
    "Stash ledger rotated nightly. Old ledgers are shredded after audit.\n"
    "If the listing looks empty, remember deletions are not overwrites.\n"
    "The rotation log is the only thing that outlives the ledgers.\n")

print(f"[E03] key length={len(key)} span={span} decoys=({len(bak)},{len(tmp)})")
PY

# --- build the ext2 filesystem from the staging directory ---
dd if=/dev/zero of="$IMG" bs=1024 count=8192 status=none
mke2fs -q -t ext2 -b 1024 -F -d "$STAGE" "$IMG"

# --- delete the three stashes (freed inodes keep their data blocks) ---
for f in ledger.dat ledger.bak notes.tmp; do
  debugfs -w -R "rm $f" "$IMG" >/dev/null 2>&1 \
    || debugfs -w -R "rm /$f" "$IMG" >/dev/null 2>&1 || true
done
echo "[E03] deleted /ledger.dat /ledger.bak /notes.tmp (3 freed inodes, one genuine)"

cp "$IMG" "$OUT/safehouse.img"
ls -l "$OUT/safehouse.img"
echo "[E03] OK image built"
