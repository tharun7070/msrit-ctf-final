#!/usr/bin/env bash
# E03 — Sandy Shores Hidden Stash. Builds an ext2 image (deleted-file recovery).
# Run inside WSL from the rebuild_workspace directory. Writes safehouse.img into
# the challenge output directory. Private organizer tooling.
set -euo pipefail

STAGE=/tmp/e03_stage
IMG=/tmp/e03_safehouse.img
OUT="/mnt/d/ctf/FLAG_THEFT_AUTO_FINAL/challenges_rebuilt/EASY/E03"
mkdir -p "$OUT"

rm -rf "$STAGE" "$IMG"
mkdir -p "$STAGE/receipts" "$STAGE/notes"

python3 - <<'PY'
import os, zlib, random, hashlib
stage = "/tmp/e03_stage"
FLAG = "FTA{ext2_st4sh_r3c0v3r3d_s4ndy_51}"

# --- activity.log : line 42 carries the recovery byte in its hostname field ---
rnd = random.Random(0x1337E03)
verbs = ["HEARTBEAT","SYNC","PUSH","POLL","ACK","RETRY","DUMP","SEAL","PURGE","PING"]
lines = []
for i in range(1, 61):
    host = f"sandy-relay-{rnd.randint(1,9)}"
    if i == 42:
        host = "shores-dock-04"          # 3rd char 'o', 7th char 'k'
    lines.append(f"2026-11-20T{rnd.randint(0,23):02d}:{rnd.randint(0,59):02d}:{rnd.randint(0,59):02d}Z "
                 f"host={host} user={rnd.choice(['ron','trevor','wendy','pavel'])} "
                 f"action={rnd.choice(verbs)} status={rnd.choice(['ok','degraded','queued'])}")
open(f"{stage}/notes/activity.log","w").write("\n".join(lines)+"\n")

host42 = "shores-dock-04"
key = ord(host42[2]) ^ ord(host42[6])     # byte used to mask the stash
print("[E03] recovery byte derived from activity.log:42 hostname =", key)

# --- decoy receipts & notes ---
open(f"{stage}/receipts/bar_tab.txt","w").write(
    "Tequila Sunrise x2 .... 18.00\nNacho Supreme ....... 9.50\n"
    "Total due ........... 27.50\nPaid in Vespucci tokens.\n")
open(f"{stage}/notes/README.txt","w").write(
    "SAFEHOUSE OPERATOR NOTES\n------------------------\n"
    "Stash ledger rotated nightly. Old ledgers are shredded after audit.\n"
    "If the listing looks empty, remember deletions are not overwrites.\n")

# --- the stash: zlib-compressed, then masked with the single recovery byte ---
payload = ("SAFEHOUSE LEDGER (SANDY SHORES)\n"
           "session=sandy-shores-audit\n"
           f"drop_flag={FLAG}\n").encode()
masked = bytes(b ^ key for b in zlib.compress(payload))
open(f"{stage}/ledger.dat","wb").write(masked)
print("[E03] stash bytes:", len(masked))
PY

# --- build the ext2 filesystem from the staging directory ---
dd if=/dev/zero of="$IMG" bs=1024 count=8192 status=none
mke2fs -q -t ext2 -b 1024 -F -d "$STAGE" "$IMG"

# --- delete the stash file (data blocks remain on disk) ---
debugfs -w -R "rm ledger.dat" "$IMG" >/dev/null 2>&1 || debugfs -w -R "rm /ledger.dat" "$IMG" >/dev/null 2>&1
echo "[E03] deleted /ledger.dat (recoverable from freed blocks)"

cp "$IMG" "$OUT/safehouse.img"
ls -l "$OUT/safehouse.img"
echo "[E03] image built"
