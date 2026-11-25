#!/usr/bin/env python3
"""Integration builder for the FLAG THEFT AUTO challenge replacement.

Single source of truth for the 25 main-event rebuilt challenges plus the
10-challenge BONUS wave (revealed at T+60min). From the data below it
regenerates (data only -- no component structure, no styling):

  * organizer_private/CTFD_IMPORT/manifest.json        (25 main, private flags)
  * organizer_private/CTFD_IMPORT/manifest_bonus.json  (10 bonus, hidden until T+60)
  * organizer_private/CTFD_IMPORT/attachments_sha256.csv
  * organizer_private/ANSWER_KEY.md
  * organizer_private/CHALLENGE_MATRIX.csv
  * frontend/src/data/challengeMeta.js
  * <root>/<LEVEL>/<CID>/MISSION.md  (+ evidence artefacts copied in)
    for root in {challenges, frontend/public/challenges, frontend/dist/challenges}
  * MISSIONS.md + SHA256SUMS.txt in each of the three challenge roots

Private flags are imported from lib_fta.FLAGS. Participant artefacts are read
from challenges_rebuilt/<LEVEL>/<CID>/.
"""
import hashlib
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L  # noqa: E402

ROOT = L.ROOT
SRC = L.OUT                       # challenges_rebuilt
FLAGS = L.FLAGS
ROOTS = [ROOT / "challenges",
         ROOT / "frontend" / "public" / "challenges",
         ROOT / "frontend" / "dist" / "challenges"]
LEVELS = {"E": "EASY", "M": "MEDIUM", "H": "HARD", "B": "BONUS"}
BONUS_ACT = "Bonus Wave"

# ---------------------------------------------------------------------------
# 1. Challenge content (participant-safe).  Briefing/objective/hints/files.
# ---------------------------------------------------------------------------
CH = [
    dict(cid="E01", title="Lester’s Pager Panic", level="Easy", act="The Street Job",
         location="Lester's Hideout", category="Cryptography",
         topic="Dual modular filter + per-row stream permutation", points=50, mission=1,
         thumb="/images/jason-1.webp",
         briefing="Lester's pager dumped a whole night of dispatch chatter and only a sliver of it is his. The genuine courier packets never announce themselves: a real row must satisfy more than one arithmetic secret at once, and the ones that satisfy only one are poisoned. Even the wording is hostile — the payloads use a private alphabet that is then scrambled again, row by row, by a rule the salvaged decoder will not hand you. The drop is also re-ordered under a third, hidden key and padded with a marker you have to notice before you can trust a single byte.",
         objective="Recover the single dispatch message. Nothing in the log names the columns, the permutation, or the order.",
         files=["dispatch.csv", "decoder"],
         hints=["One condition is not enough. More than one arithmetic rule must hold together for a row to be genuine, and the near-misses that satisfy just one will corrupt your output.",
                "The decoder reveals the alphabet and radix only. Every payload is then re-scrambled per row; recover the row-dependent permutation before you trust a decoded character.",
                "Order is decided by three keys with a fixed tie-break, and the assembled plaintext carries a short marker you must recognise and strip."],
         solution="Keep rows satisfying BOTH (col_A*col_B) mod col_C == 7 AND (col_A+col_B) mod col_C == (col_D mod col_C). For each genuine row, base-41 decode then invert the per-row alphabet permutation idx -> (k*idx+m) mod 41 with k = 1+(col_A mod 40), m = col_D mod 41 (use pow(k,-1,41)). Sort genuine rows by (col_C mod 5 asc, col_D mod 2 asc, -col_E desc, packet_id asc). Concatenate decodes, strip the fixed 2-byte marker \\x1b\\x13. Decoys satisfy only one condition (one decodes to a fake flag); using a single filter yields garbage."),
    dict(cid="E02", title="Vinewood Shift Change", level="Easy", act="The Street Job",
         location="Vinewood Boulevard", category="Cryptography",
         topic="Dual fingerprint gate + transposition-over-substitution", points=50, mission=2,
         thumb="/images/jason-2.webp",
         briefing="Vinewood's night-shift taxi ledger is almost all legitimate fares. One car was never meant to be logged and its manifest line is wrapped in a shift nobody wrote down. A decoy line decrypts perfectly under the lazy assumption and leads nowhere. Worse, the line is not merely substituted: a transposition sits on top, so a single-stage break returns scrambled text. The sample block is rigged the same way, so the textbook frequency attack will confidently hand you a parameter pair that is simply wrong.",
         objective="Find the genuine intercepted line, unwind both stages of its cipher, and recover the manifest.",
         files=["taxi_ledger.txt", "frequency_sample.bin"],
         hints=["One fingerprint is not enough: the genuine line must satisfy two independent conditions, one on its timestamp and one on its route.",
                "A substitution sits under a transposition. Undo only the substitution and you get scrambled output; you must identify the transposition width as well.",
                "The sample is transposed too. Run frequency analysis without untransposing it first and you will recover a plausible but false (a,b)."],
         solution="Keep the row where SHA1(timestamp) ends in a3 AND SHA256(route) starts with nibble 4. Undo a columnar transposition of width 9, then affine-decrypt with a=7,b=11. The sample is affine(transpose(english),7,11), 441 = 9x49; naive frequency analysis returns a wrong pair (1,20). Ignore the Caesar-5 decoy (FTA{wrong_route}) and the single-stage affine decoy (a near-miss flag)."),
    dict(cid="E03", title="Sandy Shores Hidden Stash", level="Easy", act="The Street Job",
         location="Sandy Shores", category="Linux forensics",
         topic="ext2 recovery + multi-byte keyed mask", points=50, mission=3,
         thumb="/images/jason-3.webp",
         briefing="The Sandy Shores safehouse yielded a dead laptop, imaged before the drive could be wiped. Several files were deleted, and only one stash is genuine — the others are the kind of bait that rewards a shallow carve. The real payload is masked with a repeating key whose every byte is computed from two separate fields on a surviving dock-worker log, and then wrapped in two more reversible layers before it is readable. The deletion order tells you nothing; a wasted carve tells you a lot.",
         objective="Recover the genuine deleted payload from the image, identify it among the decoys, and reverse its full masking chain.",
         files=["safehouse.img"],
         hints=["More than one deleted file survives. The genuine stash matches a numeric field recorded elsewhere on the image; the bait does not.",
                "The mask is not a single byte. It repeats, and each key byte is computed from two distinct fields on the same surviving line.",
                "After unmasking you are still not done: the bytes sit inside two more reversible transforms before they are text."],
         solution="Carve the three deleted inodes; the genuine one is /ledger.dat whose sealed byte length equals the span= field on activity.log line 42. Build an 8-byte repeating XOR key arithmetically from that same line's host + relay fields; unmask, then invert the pipeline base64 -> byte-reverse -> zlib (i.e. zlib-decompress, reverse, base64-decode). Decoys /ledger.bak and /notes.tmp decode to bait flags."),
    dict(cid="E04", title="Del Perro Camera Roll", level="Easy", act="The Street Job",
         location="Del Perro Pier", category="Steganography",
         topic="Gated bit-plane stego + geometry-keyed mask", points=50, mission=4,
         thumb="/images/lucia-1.webp",
         briefing="Del Perro's pier camera caught nothing suspicious, but the file is heavier than its picture deserves. The payload does not ride in every pixel and not in the lowest plane — only certain 'blessed' pixels carry it, and a blanket low-bit sweep returns bait. What you finally extract is masked with a key built from the image's own geometry plus a logged salt, and then wrapped twice, in a decompressor and a text encoding from a forgotten decade.",
         objective="Extract the hidden message and reverse every layer, ignoring the traps placed for the obvious tool.",
         files=["camera_roll.png", "README.txt"],
         hints=["A plain LSB dump finds bait. Only some pixels are used; a watermark hints at the selection rule but does not spell it out.",
                "The bits are not in the lowest two bit-planes, and what you extract is XOR-masked with a key derived from the image's dimensions plus a salt left in metadata.",
                "Once unmasked, two wraps remain: a decompressor and an older text encoding."],
         solution="Parse the watermark metadata to recover the gate coefficients + salt; select pixels satisfying (3x+5y) mod 7 == 4; read bits 2..3 of R,G,B column-major; XOR with the repeating 32-byte SHA256 key; then parse a 2-byte big-endian length + gzip(utf-7(flag)). Decoys: a metadata 'flag' and a naive 2-LSB bait stream."),
    dict(cid="E05", title="Wrong Extension, Right Exit", level="Easy", act="The Street Job",
         location="Los Santos Customs", category="File forensics",
         topic="Triple-format polyglot + PBKDF2 AES + 3-table database", points=50, mission=5,
         thumb="/images/lucia-2.webp",
         briefing="A customs courier filed a manifest that is three files at once: a clean customs form, to another reader something else entirely, and to a third yet another thing. `file` will not save you here. Folded inside is an encrypted archive whose passphrase is not printed anywhere — it is assembled from two separate values the form holds apart, pushed through a slow KDF, with the IV carried somewhere other than the ciphertext. What comes back is a database, and the flag sits behind a join no single table can answer.",
         objective="Unwrap the polyglot, derive the key from the two separated fields, decrypt the archive, and resolve the three-way join.",
         files=["impound_dossier.pdf"],
         hints=["Extensions lie, and so does `file`: this document is valid as three different formats at once.",
                "The passphrase is not one value. Combine two separate fields from the PDF through a slow KDF, and find the IV somewhere other than the ciphertext.",
                "What comes back is a database full of decoys. Only a three-table join on an unusual token reaches the real record."],
         solution="Treat impound_dossier.pdf as a PDF+GIF89a+ZIP polyglot. AES-128 key = PBKDF2-HMAC-SHA256(password = SERIAL + '|' + ROUTE_CODE, salt, 50000, dklen=16), where SERIAL is the AcroForm field 'serial' (not the body text) and ROUTE_CODE is printed in the visible body; the IV rides in the ZIP extra field. Decrypt to vault.db (tables operators/routes/seals joined on a TEXT token); the flag is the XOR of the three joined *_hex columns. Decoys: a fake flag row and a grep-able fake 'ARCHIVE KEY' comment."),
    dict(cid="M01", title="Fleeca Vault Glitch", level="Medium", act="The Big Heist",
         location="Fleeca Bank", category="Web security",
         topic="Two-stage stored injection + un-reversed alias + veiled columns + session gate", points=100, mission=6,
         thumb="/images/lucia-3.webp",
         briefing="Fleeca's offline kiosk has two faces: a careful registration desk and a careless profile loader that trusts what it reads back. The bug lives on a LATER visit — after a second sync stores a derived copy of your data, written through one more transform the loader never reverses. The escrow columns come back veiled, keyed by a session you must earn first, and the obvious ledger is a trap wired to a canary that poisons your teller session and serves decoy rows. A honeypot admin is still waiting to waste your afternoon.",
         objective="Trip the multi-stage stored-data flaw through the un-reversed transform, derive the session key, unveil the columns, and avoid the canary.",
         files=["fleeca_kiosk.py", "fleeca.db", "common_pw.txt"],
         hints=["Registering is not exploiting, and the stored alias is not what you typed — a later sync writes it through one more transform (a reversal plus a rotation) that the loader never undoes. Compose your payload so it survives that round-trip.",
                "The obvious ledger is bait and it is wired to a canary: touching it poisons your session and serves decoy rows. The real table is advertised elsewhere in the database, and the escrow columns are individually veiled (base64 plus a session-keyed mask), so you must earn the session first.",
                "The password hash is keyed by a per-user salt and a server pepper you must read out of the database, and a valid HMAC session token is a separate, mandatory gate that also seeds the column veil."],
         solution="register (safe) -> sync (stores rot13(rev(payload)); pre-compose rot13(desired[::-1])) -> load (interpolates the stored alias raw). Bypass the custom scrubber with a /*...*/ comment to run a second-order UNION injection against the real table advertised in config.core_ledger — do NOT touch the decoy escrow ledger (it trips a canary). Authenticate with trunc(sha256('fleeca-h2'|per_user_salt|pw|user[::-1]|server_pepper))[:20] using salt+pepper read from fleeca.db, and present token = HMAC(secret_key, user|nonce). Un-veil each escrow column: base64-decode then XOR the SHA256 counter-mode keystream of HMAC(session_key,'M01-escrow-veil') tagged per column. Decoys: honeypot admin/sunshine; the escrow/vault/receipts tables full of fake flags."),
    dict(cid="M02", title="Airport Ghost Flight", level="Medium", act="The Big Heist",
         location="Los Santos International Airport", category="Network forensics",
         topic="IPv4 fragmentation + nested frames + scoped seal + nonce-keyed mask", points=100, mission=7,
         thumb="/images/jason-1.webp",
         briefing="LSIA's tower talks to a plane radar insists isn't there. The capture does not even hand you whole packets: each message is shattered across IPv4 fragments you must reassemble before a single protocol byte makes sense. Inside, two layers of framing hide a scoped seal that covers only part of each frame, and the mask is keyed by a session nonce carried once, on the first genuine message. A decoy group boasts a valid whole-frame checksum and reassembles to a flag that is a lie, and the outer ordering field is bait.",
         objective="Reassemble the fragmented datagrams, walk both framing layers, harvest the session nonce, and reconstruct the ghost flight's callsign.",
         files=["airport_traffic.pcap", "MANIFEST.txt"],
         hints=["Nothing here is packet-shaped yet. Reassemble the IPv4 fragments first — group by a shared IP id and sort by fragment offset — before you parse any protocol.",
                "The seal covers only part of the frame: a whole-frame checksum rejects the genuine packets and, tellingly, accepts the decoy group. The session nonce rides once, on the first genuine message — harvest it before you can unmask anything.",
                "The mask is keyed by the session nonce and the inner sequence, not by the outer order field (which is bait)."],
         solution="Parse the pcap; reassemble IPv4 fragments per (src,dst,id,proto) ordered by offset, then assemble the TCP flows. Outer frame: magic 0xDEAD1A70, type 0x0A, seal = CRC32 over frame[0:12] || payload SKIPPING the 2-byte route field. Harvest the session nonce from the first genuine frame's SESSION_MAGIC prefix. Inner frame: magic 0x1A70C0DE, itype 0x5C; XOR the inner data with keystream(nonce, inner_seq), then order by the inner seq. Decoys: a naive whole-frame-CRC group that reassembles to a fake flag, plus bad-seal / wrong-type frames."),
    dict(cid="M03", title="LSPD Midnight Audit", level="Medium", act="The Big Heist",
         location="Los Santos Police Department", category="Log forensics",
         topic="Keyed chain + hidden salt + checkpoint roots + triply-nested delta", points=100, mission=8,
         thumb="/images/jason-2.webp",
         briefing="Nightshift closes in two hours and Dispatch wants the audit signed off. The LSPD automated audit bus dumped a thousand dispatch records into lspd_auth.log, but three of them were rewritten after the fact. You are handed the tamper-evident chain, a sealed sidecar (audit_delta.bin), the on-disk specification -- and, because someone meant well, an unofficial desk note. Recover the altered records, bring the chain back into agreement, and hand Dispatch the real audit flag.",
         objective="Repair the keyed, block-dependent audit chain, open both sealed regions of audit_delta.bin in the correct order, and submit the flag that satisfies the spec's acceptance predicate and final sealed unwrap.",
         files=["lspd_auth.log", "audit_delta.bin", "CHAIN_SPEC.txt", "OPS_NOTE.txt", "flash_backup.bin"],
         hints=["The audit key is not a single constant. It rolls forward, block by block, and block one's key was deliberately never written down. The spec tells you exactly what IS published so you can pin it down yourself.", "Do not trust OPS_NOTE.txt -- it describes an older, weaker procedure kept in the front of an old binder. CHAIN_SPEC.txt is the authoritative, signed document; when they disagree, the spec wins.", "audit_delta.bin hides more than a first glance suggests: the originals sit several transformations deep, and the last piece of the puzzle only opens once the whole log has been repaired -- and the order in which you do things matters."],
         solution="ORGANIZER WALKTHROUGH (M03 -- LSPD Midnight Audit).\n\nSurface: lspd_auth.log is 1000 records '<seq>|<ts>|<event_code>|<data>|<chain_hash>'. Three records were forged (seqs 319, 707, 901, in blocks 4, 8 and 10 respectively). audit_delta.bin is the sealed sidecar with the originals. CHAIN_SPEC.txt is authoritative; OPS_NOTE.txt is bait.\n\nSTEP 1 -- Recover the per-block salt schedule (the chain is NOT one fixed key).\nThe chain is HMAC-SHA256: chain_hash_i = HMAC(key = salt_{block(i)}, msg = chain_hash_{i-1} + content_i), genesis = 64 ASCII zeroes, block(i) = floor((i-1)/100)+1. salt_1 is a hidden 2-byte bootstrap. For b>=2, salt_b = SHA256(b'LSPD/chain-salt|' + root_{b-1})[0:2], where root_b = HMAC(key = salt_b, msg = b'block=<b>|' + concat(block-b contents)). The spec publishes root[1..10]. Brute-force the 65536 candidate 2-byte salts against the published root[1]; keep the match -> salt_1. Then walk root[1]..root[9] to derive salt_2..salt_10. A solver that assumes a single global salt (the canary's lie) can never verify the file: breaking/recovering block 1 does not touch the other blocks' keys. Each block is rooted independently, so several blocks can be broken at once -- that is why three forgeries survive in three different blocks.\n\nSTEP 2 -- Locate the tampered records. Walk the file top-to-bottom; for each record recompute chain_hash_i from the PREVIOUS STORED hash and the current content using that block's salt, and compare to the stored hash. Mismatches => forged seqs 319 / 707 / 901. You also confirm each block root still matches its published digest (block roots are recomputed from stored contents; a forged block root would immediately expose it). This is the 'strict ordering' pressure: you must derive the salt schedule in order before any block can be audited.\n\nSTEP 3 -- Decode REGION A of audit_delta.bin (originals, nested FIVE deep).\nHeader: magic b'AUD4', width byte (7), uint16 record_count, then the record payloads. Decode in REVERSE of the encode pipeline:\n  encode: rle_encode -> xor_index -> transpose_fwd(blob, W=7) -> XOR keystream(KA) -> rotate-left(b, r)\n  decode: rotate-right(b, r) -> XOR keystream(KA) -> transpose_inv -> un-xor_index -> rle_decode\nKeys are DERIVED, not shortcuts: KA = b'AUD4-A|' + bootstrap_salt(2 bytes); the rotation r = (int(root_last,16) % 7) + 1 where root_last = root[10]. keystream(key,n) = concat of sha256(key + struct.pack('<I', ctr)) counter mode. The xor_index layer uses per-position (i*0x5D + 0x1F) & 0xFF. Output = the true originals for the three forged records. Apply them to lspd_auth.log and the chain + all roots re-agree.\n\nSTEP 4 -- Decode REGION B (the final gate; key comes from a repaired block).\nRegion B is a masked blob: masked = FLAG_MASK XOR keystream(KB, len), where KB = b'AUD4-B|' + root[10] + b'|' + last_original. NOTE the KB input: root[10] (only known after the salt schedule is recovered) AND last_original, the recovered original content of the LAST repaired record. This forces you to finish the repair BEFORE Region B will decode -- the ordering trap. Also note the flag itself is never the stored bytes; Region B holds FLAG_MASK = SEALED_TOKEN XOR FLAG, so you still cannot read the flag from Region B alone.\n\nSTEP 5 -- Apply the cross-field acceptance predicate to obtain SEALED_TOKEN.\nOver all event_codes that end EXACTLY '_ACCEPT' (watch the decoys below), classify each by the low bit of sha256(code)[0]: class-0 first characters XOR'd column-wise, then XOR against the class-1 first-character column. The predicate is deliberately narrow (exact suffix '_ACCEPT', not substring) so code strings like 'x_REACCEPT' / 'x_ACCEPTED' are excluded. Result = SEALED_TOKEN (a 32-byte-ish ASCII token).\n\nSTEP 6 -- Final unwrap.\nFLAG = SEALED_TOKEN XOR FLAG_MASK (byte-wise). => FTA{h4sh_ch41n_t4mp3r_l5pd_aud1t}. This is the only path that combines the repaired chain (for KB), the strict-order decode, and the exact-suffix predicate.\n\nTRAPS AND HOW TO DETECT/AVOID EACH:\nT1 (well-formed decoy found FIRST): The head of the log contains a contiguous run of ACCEPT records (seq 1..68). A naive solver takes the 'first run of ACCEPT-adjacent records', XORs neighbouring first-characters, and gets a perfectly valid-looking flag: FTA{r34cc3pt_run_1s_n0t_th3_4ud1t}. DETECT: the spec's predicate requires an EXACT '_ACCEPT' suffix and a sha256-parity split, not a contiguous run; the decoy run's codes carry the REACCEPT class. AVOID: implement the spec predicate verbatim and reject runs.\nT2 (dead-end / honeypot clean block): Block 6 is left fully INTACT (no forgery) and contains a honeypot run (seq 501..566) that decodes to FTA{cl34n_bl0ck_h0nyp0t_4cc3pt3d}. A solver that only hunts 'clean blocks' or trusts a run of ACCEPTED-class codes is rewarded with a structurally valid but wrong flag. DETECT: block 6 has no break, so 'repair' does nothing there; its flag fails the predicate and never XORs to the sealed token. AVOID: only trust the flag that survives the full predicate + sealed unwrap.\nT3 (bait artifact advertising a wrong method): OPS_NOTE.txt is a desk canary claiming (a) the chain is a PLAIN sha256(prev||content) chain, (b) the salt is the factory default 0x0000, (c) audit_delta.bin is a single RLE stream needing no XOR/transpose, (d) the flag is the head ACCEPT run, and (e) flash_backup.bin holds yesterday's log as a plain RLE blob. Following it: the plain-chain recompute fails on every block, salt 0x0000 fails immediately, and flash_backup.bin decodes (it really IS a plain RLE stream) to a plausible 'restored-from-flash (UNVERIFIED)' pseudo-log that leads to a dead end with NO flag. DETECT: the note self-identifies as 'not part of the signed specification'; the spec explicitly labels unofficial desk notes as stale. AVOID: never import the canary's method; use CHAIN_SPEC.txt only.\nT4 (structurally-valid garbage under the wrong key): Decoding Region A with the canary's salt 0x0000 (instead of the recovered bootstrap salt) yields NON-empty, printable-ish but meaningless data -- it looks like progress. DETECT: the output is not valid 'seq|ts|code|data' records and does not repair the chain (recomputed hashes still mismatch). AVOID: always key Region A from the brute-forced salt_1, and confirm the repair actually makes all block roots agree.\n\nANTI-LEAK: gen/solve/validate assert the literal flag and the SEALED_TOKEN never appear in ANY shipped artifact (log, spec, note, both binary regions). The flag exists only as FLAG_MASK XOR token and is reconstructed in-memory. Total artifact footprint is well under 2 MB and generation is deterministic (fixed RNG seeds; two runs give identical SHA256 for every file)."),
    dict(cid="M04", title="Underground XOR Radio", level="Medium", act="The Big Heist",
         location="Underground Market", category="Cryptography",
         topic="Three interleaved LFSRs + header lane offset + partial KPA + lane transpose", points=100, mission=9,
         thumb="/images/jason-3.webp",
         briefing="A black-market radio burst is only a few hundred bytes, but its keystream came from three machines taking turns in fixed-length bursts, and the schedule's starting lane and burst length are written in the one part of the packet that is not encrypted. Only the first sliver of a known header survived capture (the recorder zero-filled the rest), so one register must be reconstructed by linear algebra rather than assumed. Masking is not the whole wire: before transmission the frame is wrapped twice more, both wraps keyed off the cleartext header, over a fixed-width lane transpose. The recovered signal notes are bait as much as they are intel — they mix genuine captured fields with an unverified block that describes a superseded firmware revision and confidently wrong parameters, and the on-duty analyst's note pushes you toward that older net and an answer it hands you far too easily.",
         objective="Read the cleartext sync header, de-multiplex the three generators from the surviving known-plaintext sample, recover every register, undo the full post-mask chain (wash, spin and the lane transpose) and recover the live payload of radio_packet.bin, submitted as one flag in the form FTA{...}.",
         files=["radio_packet.bin", "keystream_sample.bin", "SIGNAL_SPEC.txt", "OPERATOR_NOTE.txt", "legacy_burst.bin", "branchB_candidate.bin"],
         hints=["Three generators take turns in fixed-length bursts, and both the starting lane and the burst length are readable in the cleartext sync header of radio_packet.bin — read the header before you de-multiplex. Do not trust SIGNAL_SPEC.txt as a whole: it mixes genuinely captured fields with an (FIELD-INTEL, UNVERIFIED) block that describes an older burst from a superseded firmware revision, and the analyst's note steers you straight at that older net.", "keystream_sample.bin is a known-plaintext prefix: the leading bytes are header XOR mask, and the recorder then zero-filled the tail, so bytes [15:64] are LOST and must not be fed back as if they were header. The two small lanes yield to Berlekamp-Massey; the largest register is too big for that from this little data and must be reconstructed as a small linear output system over GF(2) using the taps the header publishes.", "The XOR is not the last step: after masking the transmitter wraps the frame twice more, both wraps keyed off the cleartext header (so a wrong header value or the wrong taps produces a frame that still looks well-formed but will not decode), and a fixed-width lane interleaver sits underneath. Undo those transforms before you XOR the mask, and treat any path that hands you a confident, well-formed answer early — and any note telling you to stop re-deriving the small registers — as a trap."],
         solution="ORGANIZER WALKTHROUGH (M04 · Underground XOR Radio)\n\nReal flag (byte-identical): FTA{lfsr23_b3rl3k4mp_m4ss3y_r4d10}. Shipped artifacts: radio_packet.bin (16-byte cleartext sync header + wrapped ciphertext, 424 B ciphertext), keystream_sample.bin (64 B, leading 15 B surviving, tail zero-filled), SIGNAL_SPEC.txt (mixed-bag spec), OPERATOR_NOTE.txt (bait canary), legacy_burst.bin (decoy burst), branchB_candidate.bin (dead-end dump). The flag is never stored verbatim in any artifact (gen + validate assert this).\n\nReal layer stack (all deterministic, every layer keyed off the cleartext header):\n  mask = round-robin burst multiplex of R0(deg11, taps [11,2], seed 0x5AB), R1(deg13, taps [13,4], seed 0x1A2B) and the beacon R2(deg23, taps [23,5], seed 0x5A3C19); schedule r = (g + off) mod 3, BURST = 5 mask-bytes per register visit, lane offset off = 1.\n  x1  = message XOR mask                                  [layer 1/2: XOR + interleaved LFSR mask]\n  x2  = 8-byte lane transpose of x1 (row-major write, column-major read)   [layer 3]\n  x3  = SPIN: each fixed 16-byte span of x2 left-rotated by XK = 13        [layer 4 NEW]\n  ct  = x3 XOR WASH, WASH = the 16-byte cleartext header repeated          [layer 5 NEW]\n  packet = header(16) + ct\n\nHeader (16 bytes, cleartext): [0:4] magic \"RDRX\"; [4] version 2; [5] lane offset off; [6] burst length b; [7] beacon degree Lb; [8:12] beacon tap bitmask LE (bits 5 and 23); [12] MODE byte 0xAA; [13] SPIN key 13; [14] WASH/flavour byte 0x5C; [15] checksum = (sum(header[0:15]) XOR 0xA5) & 0xFF. The MODE byte is a red herring on this capture: the live net always uses the fixed schedule above, so the spec's claim that MODE 'selects the live interleave schedule' is one of its false statements — a solver must notice MODE does not change the decode.\n\n--- Step 1: parse the header ---\nRead radio_packet.bin[:16]. Verify magic and the checksum ((sum of first 15 bytes XOR 0xA5) & 0xFF == byte 15). Extract off=1, b=5, Lb=23, taps from the LE bitmask = {5,23}, XK=13.\n\n--- Step 2: recover the mask from the known-plaintext sample ---\nkeystream_sample.bin[:15] is header[:15] XOR mask[:15]; bytes [15:64] are zero-filled (lost) and must be ignored, NOT unmasked. Unmask the first 15 bytes, then de-multiplex them with r = (i // b + off) mod 3 where i is the index in the un-masked stream and b=5. This splits them across three lanes (the last, partial burst covers lane index (2+1)%3).\n  * Lanes R0 and R1 (deg 11 and 13): feed the recovered lane bits (MSB-first per mask byte) to Berlekamp-Massey to get the LFSR feedback polynomial, then extend the sequence to the number of mask bytes each lane must emit over the whole packet.\n  * Lane R2 / beacon (deg 23): too few known bits for BM, so solve it as a linear system over GF(2): build the degree-23 state-output matrix from the published taps {5,23} and solve for the 23-bit seed that reproduces the known beacon-lane bits. This is the one register the header fully describes.\nRe-multiplex the three regenerated streams with the same schedule to rebuild the full mask for len(ct) bytes.\n\n--- Step 3: peel the two new header-keyed wraps ---\nRemove WASH first: ct XOR (header_[0:16] repeated to len(ct)) => x3. Then remove SPIN: for each 16-byte span of x3, right-rotate by XK = 13 (inverse of the transmitter's left-rotate) => x2.\n\n--- Step 4: undo the lane transpose and XOR ---\nInvert the 8-byte lane transpose (the write was row-major into 8-byte rows, the read was column-major): for n bytes, block count = ceil(n/8); dst position p maps from wire index perm[p] = (p // block_count)*? — concretely, wire index for output p is (p % 8) * blockcount + (p // 8) adjusted for the ragged tail; implementing the inverse permutation and applying it to x2 yields x1. Finally x1 XOR mask = plaintext message.\n\n--- Step 5: read the payload ---\nThe plaintext is LSPD dispatch chatter containing 'DECODED PAYLOAD >> ' + the flag + ' << TX END'. Extract FTA{...} => FTA{lfsr23_b3rl3k4mp_m4ss3y_r4d10}.\n\n--- TRAP 1 — decoy flag found first (legacy_burst.bin + OPERATOR_NOTE.txt) ---\nlegacy_burst.bin is a raw burst with NO sync header, generated by a superseded four-register net (R0 [11,5]/0x05EE, R1 [13,7]/0x1F1E, R2 [17,9]/0x1234, R3 [23,9]/0xDEAD), burst 4, offset 0, then an 8-byte lane transpose and no spin/wash. Driving it exactly with the SIGNAL_SPEC.txt FIELD-INTEL block (the OPERATOR_NOTE tells you to do precisely this, and to submit the result) reproduces an entire plausible transmission whose payload is the well-formed DECOY flag FTA{l1n34r_f33db4ck_b34c0n_f4k3}. A naive solver stops here. It is wrong. SIGNAL_SPEC.txt also carries a second stale fragment FTA{lfsr_is_not_a_public_key_23} ('do not submit'). Only the three-register net actually matches the sync header on radio_packet.bin.\n\n--- TRAP 2 — dead-end branch (branchB_candidate.bin) ---\nOPERATOR_NOTE.txt claims the analyst 'carried the recovered mask onto radio_packet.bin but trusted the FIELD-INTEL beacon taps, and dumped the result to branchB_candidate.bin'. Decoding the live packet with the WRONG beacon taps {17,9} (and the wrong degree 17 that follows from them) reproduces branchB_candidate.bin exactly. Its output is structurally valid — ~79% printable dispatch text — but the beacon lane is regenerated under the wrong register, so roughly every fifth byte group is unrecoverable garbage. It looks like progress and never resolves; the flag is not in it (asserted). The correct path ignores the FIELD-INTEL taps and uses the header's {5,23}.\n\n--- TRAP 3 — canary advertising the wrong method (OPERATOR_NOTE.txt + FIELD-INTEL block) ---\nOPERATOR_NOTE.txt and the '(FIELD-INTEL, UNVERIFIED)' block in SIGNAL_SPEC.txt openly advertise the wrong next step: trust the four-register legacy parameters, submit the legacy payload, treat the sync header as 'new-firmware noise', ignore branchB_candidate.bin as a mere dead end, and (explicitly) 'do not waste time re-deriving R0/R1'. That instruction is the bait — the legacy net does not decrypt the live packet. Detect: the note's claimed decoy flag differs from the payload the header-consistent decode yields, and the note contradicts SIGNAL_SPEC's own caveat that the FIELD-INTEL block 'reproduced the legacy burst but NOT a current-net header'. Avoid: trust only the cleartext header + the known-plaintext sample, and re-derive every register.\n\n--- Why an AI solver struggles ---\n(1) The most prominent narrative (the analyst note + FIELD-INTEL spec block) leads to a complete, well-formed DECOY flag, so a greedy solver submits trap 1 immediately. (2) The secondary artifact (branchB_candidate.bin) is byte-identical to a real decode attempt with the wrong taps and looks like readable traffic, so it reads as near-success, not failure. (3) The two extra header-keyed wraps (SPIN, WASH) and the unused MODE byte mean there is no independent shortcut: a correct mask with the wrong wrap undoes to stable-looking garbage, and the spec's own statements about MODE are false. (4) Nothing reduces to a single formula — the solver must combine a KPA header, BM on two lanes, a GF(2) solve on the third, a header-keyed span rotation, a header-keyed wash, and a lane transpose, in the right order, driven only by the cleartext header.\n\nVerification (run from d:\\ctf\\FLAG_THEFT_AUTO_FINAL\\rebuild_workspace):\n- python gen_m04.py -> writes keystream_sample.bin, radio_packet.bin, SIGNAL_SPEC.txt, OPERATOR_NOTE.txt, legacy_burst.bin, branchB_candidate.bin; asserts the real flag is in no artifact and the decoy != real.\n- python solve_m04.py -> '[M04] PASS -> FTA{lfsr23_b3rl3k4mp_m4ss3y_r4d10}'.\n- python validate_m04.py -> VALIDATE OK (solver PASS; header CRC ok; wrong-flag rejected='FTA{lfrr23_b3rl3k4mp_m4ss3y_r4d10}'; wrong lane offset / wrong beacon taps / skip-WASH / skip-SPIN / wrong SPIN key all rejected; dead-end artifact == the genuine wrong-taps branch, 79% printable, no flag; legacy burst decodes to the decoy flag via the FIELD-INTEL method; real flag in no artifact)."),
    dict(cid="M05", title="Debugging the Dispatch", level="Medium", act="The Big Heist",
         location="Lester's Hideout", category="Programming",
         topic="Serialised race + three-bug stage 2 + stage-3 unwrap", points=100, mission=10,
         thumb="/images/lucia-1.webp",
         briefing="The depot dispatch node at the Los Santos freight relay, broken_dispatch.py, fans 1200 tagged packets across eight worker threads and seals a manifest to out.bin -- except the seal it writes never balances, because the workers race across THREE shared process-wide structures (a per-lane tally, a running ledger and a running mix). The sealed manifest carries two masked programs -- a reconciler and an assembler -- that only unmask once the node's final dispatched/ledger/mix triple is correct. The reconciler is miscompiled in more than one independent place and its second lane is built on its first, so a single clean pass looks plausible and is still wrong. The assembler refuses to return the dispatch value from one lane alone. A retired operator's note ships in the package and is happy to hand you a short cut; it is not telling the truth. Recover the genuine dispatched flag.",
         objective="Repair the depot node so its sealed manifest is correct, unmask and fix the embedded reconciler, then combine BOTH lane runs through the assembler to recover the true dispatched flag -- ignoring every planted shortcut and fake.",
         files=["broken_dispatch.py", "dispatch_packets.json", "README.txt", "recovery_note.txt"],
         hints=["Start with the node itself, not the note. Run it, watch the numbers it reports, and run it again: a dispatch whose totals drift between runs, or fall short of the freight log, has not finished its work. One clean pass must clear every packet exactly once and balance both the reported count and the running ledger against the log.", "The out.bin manifest is a sealed container; the two programs inside cannot even be read until the node's final, correct triple is known. Repairing the node is therefore a prerequisite, not the puzzle. And once unmasked, the reconciler is still wrong in several independent ways, with its second lane derived from the first -- a single pass will look convincing and still disagree.", "Treat any flag you meet early as bait until it survives the ENTIRE chain. The reconciler's fallback path, the manifest notes and the operator's note all offer a confident, well-formed answer; none of them is the dispatch value. The real value only appears when both lane runs are combined with the sealed triple, and it is wrapped one layer deeper than the reconciler implies. If your last step produced a flag without both lanes and without the sealed triple, you are holding a decoy."],
         solution="Organizer walkthrough of M05 'Debugging the Dispatch' (medium; deepened). Shipped package in challenges_rebuilt/MEDIUM/M05: broken_dispatch.py (raced node), dispatch_packets.json (1200 tagged packets), README.txt (honest data-flow manual), recovery_note.txt (a deliberately lying canary). The real flag FTA{c0ncurr3ncy_r4c3_d15p4tch_f1x} appears in no shipped artifact.\n\nPEEL ORDER (flag <- artifact):\n  flag <- stage3_decode <- wrap_decode <- extra_unwrap(key) <- gate(key) <- (R0 XOR R1) <- stage2(lane0, lane1) <- unmask outer <- b85/zlib/json.\n\nSTEP 1 -- RUN THE NODE, SEE THE RACE. broken_dispatch.py reads dispatch_packets.json into ONE FIFO queue, starts 8 threads behind a threading.Barrier, and each worker drains the queue. DispatchNode keeps THREE shared process-wide structures: self.lanes (per-lane tally dict), self.ledger (running 64-bit sum of cleared tags), self.mix (running 64-bit hashed tally, seeded 0x123456789ABCDEF0). clear_packet() snapshots all three (lane tally, acc=ledger, mx=mix), publishes to a trace, THEN commits all three with non-atomic read-modify-writes. With sys.setswitchinterval(1e-6) the interleaving drops updates, so seal() writes a manifest whose dispatched count and/or ledger/mix are short. out.bin = base85(zlib(json(manifest))) and is reliably wrong (validator confirms 8/8).\n\nSTEP 2 -- REPAIR THE NODE (ground truth). The intent is 'clear every packet exactly once'. Either wrap the whole snapshot+commit in a single threading.Lock (the reference solver does this), or compute directly from the log:\n  dispatched = 1200\n  ledger = (sum(p['tag'] for p in packets)) & (2**64-1) = 18405489353859530566\n  mix = (0x123456789ABCDEF0 + sum(splitmix64(p['tag']) for p in packets)) & (2**64-1) = 13199405904029897168\nNote the mix is a COMMUTATIVE hashed tally (it ADDS splitmix64(tag) rather than rotating-folding), so a lock-only repair reproduces it deterministically regardless of commit order -- this is deliberate, see trap 2 notes below.\n\nSTEP 3 -- UNMASK THE EMBEDDED PROGRAMS. The correct triple yields:\n  digest = seal_digest(ledger, mix, dispatched)   # h=ledger; h^=splitmix64(mix ^ 0xA5A5...); h^=splitmix64(dispatched ^ 0x5A5A...); return splitmix64(h)\n  key    = derive_key(ledger, mix, dispatched) = splitmix64(digest ^ 0x0D15A7C4C0DE0000) = 0x518e25f4fd0cf06d\nEach of manifest['stage2_b64'] and manifest['assemble_b64'] is a base64 blob XOR-'scrambled' with ks64(digest, len) (a 64-bit LCG keystream, out=(h>>33)&0xFF). XOR them back with ks64(digest, len) to recover stage2.py and assemble.py.\n\nSTEP 4 -- FIX THE RECONCILER (stage2.py; FOUR independent bugs). It unmasks two lane records SEALED0/SEALED1 with ks32(signature ^ salt), where signature folds the fixed TAGS list through rotl32(.,7), xor>>16, *0x9E3779B9 -- all 32-bit unsigned. Shipped defects:\n  (a) rotl32 lacks the 32-bit overflow mask -> 'h = rotl32(h,7)' returns an oversized int and the 32-bit identity breaks. Fix: mask the rotate result with 0xFFFFFFFF.\n  (b) extract_record parses the length little-endian at offset 3: 'n = int.from_bytes(plain[0:2],\"little\"); body = plain[3:3+n]'. The record is big-endian at offset 2: 'n = int.from_bytes(plain[0:2],\"big\"); body = plain[2:2+n]' and the trailer lives at plain[2+n:6+n].\n  (c) alignment 'correction': 'span = n + 1 if (n & 3) == 0 else n' reads the trailer ONE byte late whenever the record length is a multiple of 4. Every base64 payload (and therefore every record here) has n%4==0, so the trailer bytes are misread and the check fails. Fix: span = n always.\n  (d) CARRIED-STATE DEFECT across the two invocations: 'signature(tags)' reseeds from 0x1BADB002 on every call, but lane 1 is meant to CONTINUE the signature lane 0 produced. Fix: h0 = fold(TAGS, 0x1BADB002); h1 = fold(TAGS, h0) and use (h0 ^ SALT0) / (h1 ^ SALT1) as the two keystream seeds. This is the bug that ONLY shows on the second lane: a single-pass test of lane 0 succeeds and misleads.\nWith all four fixed, run() returns R0 (88 bytes) and R1 (88 bytes) -- the two lane payloads.\n\nPARTIAL-FIX TRAP (trap 2). Repair (a) and (b) but leave (c): every trailer check trips, the shipped main() catches the ValueError and prints ARCHIVED_VALUE = FTA{d15p4tch_l3g4cy_p4th_d3c0y} followed by ARCHIVED_REWARD_B64, a base64 blob that decodes to the well-formed decoy FTA{4rch1v3d_r3c0rd_4cc3pt3d_as_truth}. That path looks like a rewarding finish and is entirely fake. Leaving only (d) wrong is worse: both lanes decrypt (the trailer still matches) but lane 1 is seeded from the constant, so the combination is structurally valid garbage that defies decoding -- a dead end that looks like progress.\n\nSTEP 5 -- ASSEMBLE (assemble.py) AND REVEAL. With key and the two lane payloads:\n  dispatch = R0 XOR R1                    # the gated dispatch value W (88 bytes)\n  inner    = gate(dispatch, key)          # XOR dstream(key ^ 0x61E7A11, len)\n  wrapped  = extra_unwrap(inner, key)     # XOR dstream(key ^ 0xE47A5EED) then byte-rotate-right by (key & 7)\n  s3       = wrap_decode(wrapped)         # base64-decode then XOR fixed rotating THIRD_KEY=(5A C3 77 21)\n  flag     = stage3_decode(s3)            # rotating XOR (ROT_SEED=0x9E3779B9) then run-length expansion (pairs value,count)\nResult: FTA{c0ncurr3ncy_r4c3_d15p4tch_f1x}.\n\nEXTRA LAYERS vs the old design (+2 minimum): (i) a keyed GATE above the payload, and (ii) an extra keyed WRAP (byte-rotate + keystream) beneath it -- both keyed on the sealed triple so there is no independent shortcut; plus the two-run XOR requirement (neither lane alone yields the flag) and the cross-invocation state-carry bug.\n\nTRAPS (>=3, validator asserts each fires):\n1. Decoy flags a naive/automated solve finds FIRST -- recovery_note.txt carries FTA{4rch1v3d_s33d_1s_n0t_4_k3y}; the manifest 'notes' field carries FTA{v01d_s3gm3nt_n0t_d15p4tch3d}; the partial fix prints FTA{d15p4tch_l3g4cy_p4th_d3c0y} and a reward blob decoding to FTA{4rch1v3d_r3c0rd_4cc3pt3d_as_truth}. A grep for FTA{...} returns a well-formed flag immediately.\n2. Dead-end branch (wrong key/order) with structurally valid, unrecoverable garbage -- un-chained lane 1, or feeding one lane twice, produces output that survives the trailer check but never decodes to the flag.\n3. Canary / bait artifact -- recovery_note.txt openly advertises a WRONG method (use the archived seed 0xDEADBEEFC0FFEE01; a single pass is enough; combine lanes with OR, not XOR). Every one of those claims is false.\n\nVERIFIED from rebuild_workspace: `python gen_m05.py` -> wrote MEDIUM/M05; `python solve_m05.py` -> [M05] PASS -> FTA{c0ncurr3ncy_r4c3_d15p4tch_f1x}; `python validate_m05.py` -> M05 VALIDATE OK (8/8 race visible, wrong flag rejected, both lane runs required, partial fix lands on ARCHIVED_VALUE + decoy, traps present, real flag absent from every artifact, 100003 bytes total)."),
    dict(cid="H01", title="Zancudo Deadbolt", level="Hard", act="The Final Getaway",
         location="Fort Zancudo Military Base", category="Reverse engineering",
         topic="Anti-analysis traps + chained VMs + runtime-keyed vault", points=160, mission=11,
         thumb="/images/lucia-2.webp",
         briefing="Fort Zancudo's Hangar 13 deadbolt runs firmware nobody has logged into since the desert went sideways. Your only copy is a stripped native binary that refuses to be watched and asks for a single operator passphrase. It is under no obligation to tell you the truth about why it says no — and when it is being watched, it lies with a straight face and a confident release banner. Behind the flattened dispatchers sit chained virtual machines, and the station's tables are not sitting in plaintext in the file. Interrogate the station exactly the way it expects, or it will hand you a flag of its own invention and walk you into a dead end.",
         objective="Defeat the anti-analysis traps, reverse the chained virtual machines, and recover the single operator passphrase, submitted as one flag in the form FTA{...}.",
         files=["zancudo_gate", "OPERATIONS.txt", "ENGINEER_NOTE.txt"],
         hints=["The station fights being watched. Attach a debugger, set a breakpoint, single-step it, or run it under a tracer and it will print a confident release with a passphrase of its own — treat that answer with suspicion. Think about what an honest, untraced run looks like versus an observed one before you trust anything it says.", "There is more than one virtual machine behind those flattened dispatchers, and they are chained: a later stage cannot even be decoded until the stage before it has actually run. Do not expect any single blob to be self-contained, and do not expect the description on the tin to match the truth.", "The passphrase length is itself part of the key, so the right length is not given to you — you have to find it. The vault carries several independent consistency checks that only agree for the one true byte string; use them to prove you found the right length and the right bytes rather than guessing."],
         solution="ORGANIZER WALKTHROUGH (H01 · Zancudo Deadbolt)\n\nShipped artifacts: `zancudo_gate` (stripped Linux x86-64 ELF), `OPERATIONS.txt` (neutral interface notes), `ENGINEER_NOTE.txt` (the bait canary). The accepted passphrase is exactly `FTA{z4nclud0_vm_d34db0lt_unl0ck}` and is never stored verbatim; neither decoy is stored verbatim (both are XOR-masked in .rodata).\n\n--- 0. Recon ---\n`file`/`readelf` show a stripped, dynamically linked ELF, no symbols, no plaintext. `strings ... | grep FTA` returns nothing (confirm this — if it ever returns a hit, the anti-leak assertion in gen_h01.py has regressed). The interesting data are eight magic-tagged blobs in .rodata: ZCFG, ZXT1/ZXT2/ZXT3, ZVM1/ZVM2/ZVM3, ZDVL. The magics are ASCII and never contain \"FTA\".\n\n--- 1. Layer: anti-analysis (SIX gates) — detect and avoid ---\ntrap_check() runs before anything else; ANY hit diverts to fake_success() and returns exit 0.\n  A. PTRACE_TRACEME fails (EPERM) when the process is already traced.\n  B. /proc/self/status TracerPid must be 0.\n  C. Wall-clock timing probe: 200k-iteration loop; >500 ms ⇒ traced (a debugger pausing/single-stepping blows past it).\n  D. Parent-process-name check: /proc/<ppid>/comm and /proc/<ppid>/cmdline are scanned against a blocklist {gdb, lldb, strace, ltrace, valgrind, radare2, r2, rr, frida, ghidra, pwndbg, gef, dlv, ida, winedbg, sprocket, x64dbg, windbg}.\n  E. RDTSC cycle-delta probe: a 40k-iteration dependent multiply chain timed with RDTSC; a delta > 40,000,000 cycles ⇒ traced (honest runs stay far below; note this also catches single-stepping in emulators).\n  F. Software-breakpoint scan: the first 3 bytes of the noinline `bp_probe` are checked for 0xCC (INT3); plus /proc/self/maps is scanned for the substring \"frida\". A patched INT3 at the probe entry or an injected hook trips this.\nDetection (for the solver): run the binary plain. If it prints \"== ZANCUDO DEADBOLT RELEASED ==\" together with a passphrase while you were NOT solving anything (i.e. while under a tracer or after patching), that is Trap 1 — a decoy. To avoid: never attach a tracer, never patch an INT3 into the probe, never inject a library, and keep the run fast/idle. The reference solver deliberately does static recovery in Python and only invokes the live binary once, untraced, with the confirmed passphrase.\n\n--- TRAP 1 — fake success path (well-formed decoy flag) ---\nfake_success() prints the release banner plus decoy1, XOR-0xA7 masked in .rodata: FTA{z4nclud0_d34db0lt_r3l34s3}. It is structurally valid and its exit code is 0, so a cheating/automated solver that runs under instrumentation submits a plausible-but-wrong flag. Detect: it appears whenever any of gates A–F fires; also its value differs from the real flag. Avoid: re-run untraced, and treat any passphrase the station \"volunteers\" as hostile.\n\n--- TRAP 2 — ZANCUDO_SERVICE dead-end branch ---\nIf the env var ZANCUDO_SERVICE is set, main() calls service_dump() instead of the real checks. It deliberately derives the vault key with a WRONG length guess (31), decrypts the .rodata vault, and prints a \"maintenance key-schedule dump (rev 3)\" of 128 pseudo-random-looking bytes followed by decoy2 (XOR-0x5C): FTA{z4nclud0_s3rv1c3_schedul3_dump}, then \"disposition: RELEASED (service override)\". It is structurally valid (proper banner, hex grid, a well-formed flag) but unrecoverable garbage — it is decrypted under the wrong key, so it can never match the real vault, and its flag is a decoy. Detect: the env-gated branch is a dead end; the schedule bytes never satisfy the real checks. Avoid: never set ZANCUDO_SERVICE; do not trust the \"recovered-service-phrase\".\n\n--- TRAP 3 — ENGINEER_NOTE.txt canary ---\nENGINEER_NOTE.txt openly advertises the wrong method: it tells the reader to run `ZANCUDO_SERVICE=1 ./zancudo_gate AAAA...AAAA` and claims the printed phrase (decoy2) is \"the authoritative release key, no decompiler required\", and that the crew warnings about \"answers of its own\" are obsolete. It exists to bait an AI/naive solver into Trap 2. Detect: it contradicts OPERATIONS.txt's own warning (\"treat that answer with suspicion\"). Avoid: ignore the note's claimed shortcut entirely.\n\n--- 2. Layer: chained virtual machines (THREE stages) ---\nEach VM is a bytecode interpreter with a control-flow-flattened dispatcher (state machine FETCH/DECODE/EXECUTE with states 0/1/4) and opaque predicates built on a volatile g_guard (reads 0). Opcodes are translated per-VM via g_xlat1/2/3 (256-byte byte→internal-op tables). VM blobs are stored as [magic][u16 len][bytecode] at offset +6.\n  Stage 1: run VM1 with xlat1 ⇒ v1 = 0x1DB0F3CA.\n  Stage 2: VM2's at-rest bytecode is masked with v1^0x9E3779B9 (4-byte-period XOR). Unmask, run with xlat2 ⇒ v2 must equal VM_CTX = 0x0FF1CE42 (read from ZCFG+8); otherwise the binary prints \"firmware integrity fault 0x0B0LT\" and exits 4.\n  Stage 3: VM3's at-rest bytecode is masked with v2^0x85EBCA6B. Unmask, run with xlat3 ⇒ v3 must equal VM_CTX3 = 0x0DEAD133 (from ZCFG+16); else \"firmware integrity fault 0x0DEAD\" and exit 5.\nKey design point: VM2 cannot be decoded without v1 and VM3 cannot be decoded without v2, so no single blob can be decompiled independently — the chain must be executed in order.\n\n--- 3. Layer: runtime-derived vault key + two-pass decryption ---\nZCFG also carries C = 0x7F4A7C15 and the default env byte 0x5B. The vault key is:\n  seed = splitmix64( C ^ (len * 0x9E3779B97F4A7C15) ^ (env<<33) ^ (v1<<7) ^ v2 ^ (v3<<17) )\nwhere len = strlen(passphrase) and env = first byte of $ZANCUDO_ENTROPY or the default. The ZDVL vault is decrypted with a TWO-pass XOR keystream: an xorshift64 stream seeded by `seed`, XORed with a second xorshift64 stream seeded by seed2 = splitmix64(seed ^ (v3 * 0x2545F4914F6CDD1D) ^ 0x9E3779B97F4A7C15). Static dumping of .rodata therefore yields ciphertext only; the second pass is keyed by VM3's result, tying decryption to the VM chain.\n\n--- 4. Layer: length brute-force (the length is part of the key) ---\nVault plaintext layout: [u32 need][SBOX 256][K need][T need][u32 fnv][u32 hmix][u32 crc][u32 pos][pad], CIPHER_LEN = 676. For each Ltry in 1..MAXLEN, derive seed(Ltry), two-pass decrypt, and accept the Ltry whose first u32 == Ltry AND whose 256-byte SBOX slice is a permutation of 0..255. This combination is unique (gen_h01.py asserts hits == 1); the true length is 32.\n\n--- 5. Layer: FIVE-transforms passphrase check + inversion ---\nThe binary checks six layers; the last five are the actual byte gates (layer 0 is the implicit length-in-key):\n  1. Length gate: need == len, need <= MAXLEN.\n  2. FNV-1a checksum of the input == stored.\n  3. Non-linear byte map: for each i, (SBOX[in[i]] * K[i]) mod 251 == TARGET[i]. 251 is prime and every K[i] != 0, so it inverts: r = TARGET[i] * K[i]^-1 mod 251, then the unique b with SBOX[b] % 251 == r (gen_h01.py guarantees no accepted byte resolves ambiguously; a second pre-image needs r <= 4).\n  4. HMAC-like mixing gate hmix(input, seed) == stored.\n  5. CRC-style gate (reflected poly 0xEDB88320) salted with v3 ^ CRC_XOR (CRC_XOR = 0x13579BDF) == stored.\n  6. Order-dependent rotate/xor gate gate_pos(input, seed) == stored.\nGates 2/4/5/6 are independent cross-checks: only the one true byte string satisfies all of them, so a partial reversal is caught immediately.\n\n--- 6. Final ---\nInvert layer 3 to recover the bytes, cross-check layers 2/4/5/6, and you get the operator passphrase: FTA{z4nclud0_vm_d34db0lt_unl0ck}. Confirm against the live binary with `env -u ZANCUDO_ENTROPY -u ZANCUDO_SERVICE ./zancudo_gate '<flag>'` — it must print the release banner and exit 0. The reference solver (solve_h01.py) performs exactly this static path and prints the flag; validate_h01.py re-derives it, checks that both decoys are rejected as wrong passphrases, exercises both traps (debugger-parent ⇒ decoy1; ZANCUDO_SERVICE ⇒ schedule dump + decoy2), and asserts no plaintext flag appears in any artifact."),
    dict(cid="H02", title="The Recursive Freeway", level="Hard", act="The Final Getaway",
         location="Final Getaway", category="Algorithms",
         topic="Weighted graph isomorphism + spectral fingerprint", points=160, mission=12,
         thumb="/images/lucia-3.webp",
         briefing="The getaway routing grid is a weighted graph in which every junction looks alike, so degree filtering is useless. Somewhere inside sits a single district that matches a stolen weighted blueprint, and several near-miss districts survive a first look. The district's registry scraps are stored on its junctions in no trustworthy order. Only the right weighted invariants single out the true district, and only the right order reassembles the token.",
         objective="Find the unique weight-consistent 12-junction district and assemble its registry fragments into the clearance flag exactly as PROTOCOL.md specifies.",
         files=["junctions.json", "template.json", "PROTOCOL.md"],
         hints=["Degrees will not help you - every junction has the same degree, so degree filtering is a decoy. Edge weights and local structure are your only pruning tools.", "A single spectral signature is not a unique key here: more than one district clears the weighted normalised-Laplacian fingerprint in PROTOCOL.md, and one of the near-correct districts is a clean scaled copy of another - normalisation is blind to a global rescaling of every edge weight, so reach for a second weighted invariant that a uniform scaling would actually change and check it against the blueprint before trusting a match. Any note insisting no second check is needed is a decoy.", "The field note in PROTOCOL.md is not trustworthy: the true reading order is not junction-id order. The order is fixed by the district's own spectrum, and two fragments sit in a four-decimal dead heat, so a single spectral key will mis-order them."],
         solution="Full stack, in the order a solver meets it.\n\n(0) SURFACE. template.json is a weighted 12-node ring: the cycle (0,1),(1,2),...,(11,0) plus three chords (0,3),(0,6),(1,8); weights are drawn from {1,2,3}. junctions.json is a 2500-node, 5000-edge weighted network in which EVERY node has degree exactly 4 (near-regular), so any degree-based filter prunes nothing. Each junction carries a 1-3 character label fragment.\n\n(1) TOPOLOGY. An induced-subgraph isomorphism search (networkx GraphMatcher(J, T).subgraph_monomorphisms_iter()) returns SIX districts: the real district, a scaled dead-end, and four single-weight near-misses (each changes one edge weight). The three edge-decoys (one edge removed) drop out at this stage. Topology alone leaves six candidates.\n\n(2) INVARIANT A - weighted normalised Laplacian spectrum. For a candidate build A (12x12, A[i,j]=w), d = row sums, L = I - D^(-1/2) A D^(-1/2); take eigenvalues ascending and round to 4 dp. The blueprint fingerprint is (0.0, 0.1855, 0.256, 0.5402, 0.6982, 0.9835, 1.0492, 1.2366, 1.4622, 1.7925, 1.8397, 1.9565). Exactly TWO districts match it. PROTOCOL.md asserts this is the only uniqueness test - that is the TRAP 3 lie; it is necessary but NOT sufficient.\n\n(3) WHY TWO SURVIVE (the dead end, TRAP 2). The second survivor is a district whose every edge weight is doubled (x2). Normalisation divides out the degrees, so scaling all weights by a constant leaves L unchanged - identical spectrum. It is topologically and spectrally indistinguishable from the real district under invariant A. A solver who stops here assembles a token from the wrong district and fails.\n\n(4) INVARIANT B - weighted spanning-tree count tau. Build the weighted Laplacian Lap = diag(d) - A and take the cofactor det(Lap[:-1,:-1]) (Kirchhoff); this is the weighted number of spanning trees. tau is NOT scale-invariant: tau(2W) = 2^(n-1) tau(W), so doubling every weight multiplies tau by 2^11 = 2048. The blueprint tau is 120712; the scaled dead-end tau is 120712*2048 = 247218176. Only the true district matches 120712 -> a unique district.\n\n(5) DERIVATION - the real reading order. Read the matched district's twelve labels in a TWO-KEY spectral order: principal eigenvector of the weighted adjacency A (weighted eigenvector centrality, sign-fixed positive) DESCENDING, rounded to 4 dp, ties broken by the Fiedler vector (2nd eigenvector of the normalised Laplacian) ASCENDING. The blueprint was chosen so two junctions share the same 4-dp centrality, so a single-key order mis-orders them. Two-key order -> junction sequence [768, 1031, 1339, 115, 195, 240, 402, 436, 511, 1567, 1625, 2227] -> body 'sp3ctr4l_fr33w4y_gr4ph_150m0rph' -> flag FTA{sp3ctr4l_fr33w4y_gr4ph_150m0rph}.\n\nTRAPS - how to detect and avoid each:\n  * TRAP 1 (naive decoy flag). The twelve fragments are the SAME pieces the generator re-orders, and junction ids are relabelled so that reading the TRUE district's labels in ascending junction-id order spells FTA{fr33w4y_gr4ph_sp3ctr4l_150m0rph} - a well-formed WRONG flag. Naive/automated pipelines, and anyone following the field note, print this FIRST. Detection: the claimed 'ascending id' order is fiction; the correct order is spectral.\n  * TRAP 2 (dead-end district). The scaled district (all weights x2) passes invariant A but fails invariant B (tau x2048). Read in its own correct spectral order it spells FTA{sp3ctr4l_gr4ph_fr33w4y_150m0rph} - a second well-formed WRONG flag. Detection: apply invariant B.\n  * TRAP 3 (bait spec). PROTOCOL.md carries a 'RECOVERED FIELD NOTE (crew 5)' that (a) claims the normalised-Laplacian spectrum is the ONLY uniqueness test and other invariants are folklore, and (b) instructs the reader to output the matched district's labels in ascending junction-id order. Both claims are false; following either yields TRAP 1 or the dead end. Detection: verify uniqueness independently (invariant B) and never trust an embedded note that removes the discriminator.\n  * Secondary trap. Ordering by centrality alone (single key) leaves the 4-dp tie unbroken and yields the malformed token FTA{sp3ctr4l_fr33w4y_gr4ph_m0r150ph}. Detection: the two-key tie-break.\n\nHUMAN SOLVABILITY. Everything needed ships in the three files. A skilled analyst (i) runs the documented topology + fingerprint test, (ii) notices a second district survives and reaches for an independent invariant, (iii) recognises the dead end as a uniform rescale and picks a scale-sensitive weighted invariant (spanning-tree count is the natural one), and (iv) resolves the ordering tie with a second spectral key. No network access or guessing is required."),
    dict(cid="H03", title="Impound Evidence Matryoshka", level="Hard", act="The Final Getaway",
         location="Los Santos Police Department", category="Multi-stage forensics",
         topic="7-layer chained stego + cryptographic nesting", points=160, mission=13,
         thumb="/images/jason-1.webp",
         briefing="The impound lot's evidence camera, impound_camera.png, came back from the techs with an unexpected second job: it is a matryoshka. Nine shells sit stacked inside the image and its trailing sectors, each one locked by something you only recover from the shell before it, and several artefacts are placed specifically to send you home early with a convincing fake. One field note describes the whole stack as arithmetic and structure; a separate 'official quick-cut card' claims to shortcut it. Recover the true recovered_flag.",
         objective="Recover the genuine recovered_flag from impound_camera.png by peeling all nine chained shells and ignoring the planted bait.",
         files=["impound_camera.png", "EVIDENCE_NOTE.txt", "RECOVERY_INSTRUCTIONS.txt"],
         hints=["Read the recovered field note end to end before touching a single byte; it is the only honest description of the stack. The separate quick-cut card contradicts it, so decide which of the two is authoritative before you believe a 'flag'.", "Not every artefact is real. A metadata field, a manifest inside one of the trailing archives, and an inner member all hand you flags that are not the answer. Two archives sit after the image's IEND marker and only one of them is opened by the value you derive from the picture. Treat any flag you find early as bait until it survives the entire chain.", "The chain is strictly ordered and does not shortcut. The low-bit payload cannot be read without a mask and a stride/offset that are recovered from other shells, and the final program refuses to print the real flag unless it is handed the exact token recovered two shells above it. If your last step prints a flag without being given a token, you are looking at a decoy."],
         solution="Organizer walkthrough of H03 (9 shells, strictly ordered; every key flows down from the shell above). Shipped: impound_camera.png (carrier), EVIDENCE_NOTE.txt (honest method), RECOVERY_INSTRUCTIONS.txt (a deliberately lying 'official' card).\n\nS1 GEO GATE (EXIF GPS -> MASK). The PNG EXIF holds GPS lat 34 deg 03 min 07.92 sec N and lon 118 deg 14 min 37.32 sec W. Decimal: lat 34.0522, lon 118.2437. CODE = pad5(round(abs(lat)*10000) mod 100000) + pad5(round(abs(lon)*10000) mod 100000) = '40522' + '82437' = '4052282437'. The tEXt chunk 'gate.card' is HEX of GATE_NONCE(16) || AES-256-CTR ciphertext. Key = PBKDF2-HMAC-SHA256('GEO-4052282437', salt 'impound-geogate-7', 100000 iters, dkLen 32); the blob's first 16 bytes are the initial counter. Decrypt -> 16-byte MASK = 5c3fb17e02d49a6f8e1c70b3d5a2f490. MASK is used twice later: to unmask the Shell-2 payload AND as the Shell-5 GCM AAD.\n\nS2 GATED + MASKED LSB. 2 least-significant bits are stored in every RGB channel; pixels are scanned COLUMN-MAJOR (down a column, then the next column right), channels R,G,B. A slot is numbered by its 0-based position in that scan; ONLY slots where (i mod STRIDE == OFFSET) carry the real payload, every other slot repeats a BAIT string (so a blanket LSB dump yields junk). STRIDE/OFFSET are not in the image; derive them from Shell 7's frequency table: D = row count = 67, T = sum of counts = 696, STRIDE = (D mod 7) + 2 = 6, OFFSET = T mod STRIDE = 0. Read the selected slots MSB-first: first 4 bytes = big-endian LEN, remaining LEN bytes are MASK-masked; unmask with plain[j] = masked[j] XOR MASK[j mod 16]. Output = TAG(16) || CTR_BLOB, where TAG = a17f0c3d9b452e6812c4a90f73e1d5b8.\n\nS3 AES-256-CTR (CODE -> BADGE). Key = PBKDF2-HMAC-SHA256('IMPOUND-4052282437', salt 'lspd-impound-2026', 100000, 32). CTR_BLOB = counter(16) || ciphertext; decrypt -> BADGE = 'VAULT-K9-4471'.\n\nS4 TRAILING ZONE: TWO ARCHIVES. After IEND is a scratch sector dump, then two legacy ZipCrypto archives. The decoy block delimited by --#EVIDENCE-BAG--# ... --#BAG-END--# is opened by the PUBLIC password 4471 (printed on its own manifest) and only yields bait. The real block delimited by --#VAULT-BEGIN--# ... --#VAULT-END--# is opened by the BADGE recovered in Shell 3. Inside the vault: layer4.bin (real cargo, an AES-GCM blob) and bait.txt (ignore).\n\nS5 AES-256-GCM (nonce from Shell 2, AAD from Shell 1). layer4.bin = ciphertext || tag(16). Key = PBKDF2-HMAC-SHA256(BADGE + ':' + CODE, salt 'evac-vault-7731', 100000, 32). GCM nonce = SHA256(b'gcm' || TAG)[:12]. AAD = MASK (supplying the wrong mask fails the tag check). Plaintext is a second PNG: a black/white MTX-1 matrix.\n\nS6 MTX-1 MATRIX (-> ROUTE_KEY | STREAM). 81x81 modules with a 4-module white quiet zone. Row 0 and column 0 are SYNC ladders (module i is BLACK iff i is EVEN); rotate the grid until both ladders match to fix orientation. Every module with x>=1 AND y>=1 carries one data bit, read ROW-MAJOR (y ascending, then x ascending), byte-aligned MSB-first: first 16 bits = big-endian length L, then L ASCII chars. The text is ROUTE_KEY || '|' || base64url(STREAM); split on the FIRST '|'. Here ROUTE_KEY = 'ROUTE-9F3A1C' (keys Shell 8).\n\nS7 HUFFMAN (-> SEAL_TOKEN | SEALED_SOURCE). base64url-decode STREAM: first 16 bits = big-endian symbol count C, then C Huffman symbols read MSB-first (left edge = bit 0, right edge = bit 1), decoded with the note's frequency table. Rebuild the tree from frequencies ONLY: repeatedly merge the two lowest-frequency nodes; on a tie prefer the earlier-inserted node (leaves inserted first in ascending ASCII order, internal nodes in creation order). The text is SEAL_TOKEN || '|' || base64(SEALED_SOURCE); split on the FIRST '|'. Here SEAL_TOKEN = 'SEAL-7B2D04'.\n\nS8 SEALED SOURCE (AES-256-CTR). SEALED_SOURCE = nonce(16) || ciphertext. Key = PBKDF2-HMAC-SHA256(ROUTE_KEY, salt 'matryoshka-seal', 100000, 32); the first 16 bytes are the initial counter. Plaintext is Python source.\n\nS9 RUN WITH THE SEAL. Execute the source passing SEAL_TOKEN as sys.argv[1]. It SHA256-hashes the token and, only for the exact SEAL_TOKEN, XOR-reconstructs and prints the true flag; any other token (or none) prints the decoy FTA{wr0ng_cl34r4nc3_t0k3n}. A correct run: python stage.py SEAL-7B2D04 -> FTA{m4try0shk4_f1v3_l4y3rs_c4rv3d}.\n\nTRAPS (5):\n1. decoy-metadata: the PngInfo 'flag' tEXt and an EXIF ImageDescription both carry well-formed decoy flags (FTA{l5b_pl41n_dump_b41t_7f}, FTA{3x1f_gps_tr4p_d3c0y}). A metadata scrape finds a 'flag' first. Detect/avoid: no metadata flag is the real one; it is not the same string the chain produces.\n2. decoy-ZIP (valid container, looks like progress): the EVIDENCE-BAG archive is a VALID extractable ZipCrypto ZIP; its manifest.txt advertises recovered_flag=FTA{3v1d3nc3_b4g_4471_0p3n3d}, and a README inside pushes a wrong method. Detect/avoid: the public password 4471 does NOT open the real vault (the vault needs the derived BADGE), so the bag is bait.\n3. canary-note: RECOVERY_INSTRUCTIONS.txt openly and confidently claims the PngInfo field is 'authoritative', that payload bytes should be XORed with 0x5A, and that STRIDE/OFFSET are 8/0. All three claims are wrong. Detect/avoid: trust the field note; the 'quick-cut card' is a lie.\n4. blanket-LSB: dumping ALL LSBs with no gating and no mask returns the repeating bait string, never the payload.\n5. token-gate: Shell 9 prints the decoy unless fed the exact SEAL_TOKEN, catching a solver who drops the token while peeling two shells down.\n\nFollowing S1->S9 with the derived keys yields FTA{m4try0shk4_f1v3_l4y3rs_c4rv3d}."),
    dict(cid="H04", title="LEGAL RAGGING", level="Hard", act="The Final Getaway",
         location="Fleeca Bank", category="Cryptography",
         topic="Blinded RSA-CRT fault + timing oracle + freshness gate", points=160, mission=14,
         thumb="/images/jason-2.webp",
         briefing="Fleeca's mock gateway signs bank orders with RSA-CRT and keeps a 'debug' signing route it was never supposed to ship. That route blinds what it signs and, occasionally, lies about one of its two internal halves — rarely, and in either half. A second route leaks, byte by byte, a live nonce the vault order must carry, and the verifier now also demands the right role and a fresh timestamp. Two signatures are no longer enough on their own.\n\nSPECIAL OFFLINE HINT — CREW FITNESS CHECK\n\nVisit the organizer desk to unlock an optional hint. One willing team representative can complete 10 push-ups, or choose an equivalent non-physical logic task. The organizer will provide the hint privately. This activity is optional, supervised and compliant with college rules — there is no pressure, humiliation or compulsory physical activity.",
         objective="Recover the signing key from the blinded, faulty debug route, satisfy the nonce and freshness gates, forge an admin order, and unlock the vault.",
         files=["bank_gateway.py", "guest.token", "AUDIT_BRIEF.txt"],
         hints=["The debug route blinds what it signs; undo the blinding before any faulty half becomes visible. It also faults rarely, and in either half.",
                "The order must carry a nonce that only the second, timing-based route will reveal, and it changes every process.",
                "A correctly-signed order under the wrong role — or with a stale/wrong nonce — is still refused. The brief's parameters are bait."],
         bonus_hint="OFFLINE BONUS HINT (reward for the crew fitness check / equivalent logic task): The debug route faults in EITHER half, so never assume your gcd landed on p — check p*q == n and keep whichever prime falls out. If a gcd returns n itself (both halves faulted at once), throw that signature away and collect another. The timing route leaks the nonce one byte at a time against a candidate guess, so treat it as a yes/no per candidate byte instead of brute-forcing the whole value. The freshness window stated in AUDIT_BRIEF.txt is real — build and submit the order immediately after you sign it.",
         solution="Call sign_debug on a fixed message to collect a correct and a faulty signature; un-blind each (sig_blind * r^-1 mod n) first. Faults land in p or q, so gcd(bad^e - m mod n, n) may return either prime — accept both and check p*q == n. Recover d, derive the live audit nonce one byte at a time via the verify_debug timing oracle, assemble ADMIN_MESSAGE with that nonce + a fresh timestamp, sign it as role 'admin', and submit to read the flag from the FTA_H04_FLAG environment variable. Decoys: a legacy signed token that verifies but is refused, and wrong leads in AUDIT_BRIEF.txt."),
    dict(cid="H05", title="Last Ride Out", level="Hard", act="The Final Getaway",
         location="Final Getaway", category="Multilayer cryptography",
         topic="4-party agreement break + HKDF + nested AES", points=160, mission=15,
         thumb="/images/jason-3.webp",
         briefing="The getaway's final message crossed a four-party key agreement. A captured transcript and the encrypted payload survive, and two of the four seats were never checked — read the framing and you will see which contributions are bound and which are taken on faith and re-advertised. The shared secret is not a neat sum but a weighted product, so sitting in an unchecked seat means solving for a value, not merely choosing one. The payload is nested twice, and some of the confirmations are decoys.\n\nCLASSIFIED OFFLINE INTEL\n\nCollect a confidential paper riddle from the organizer desk. Solve it to receive an additional hint for this mission.",
         objective="Parse the transcript, identify the unauthenticated seats, steer the weighted session key, and decrypt the nested payload.",
         files=["intercept.bin", "final_payload.enc", "ESCAPE_PROTOCOL.md", "FORMAT_SPEC.txt"],
         hints=["More than three voices are on the line. Read the framing: some contributions carry a binding tag and some do not — the unbound ones are trusted.",
                "The session secret is a weighted product of the contributions, not a sum; steering it means solving for a share value rather than picking one.",
                "There are decoy key-confirmations. The real one sits between them, and the payload is nested twice."],
         bonus_hint="OFFLINE BONUS HINT (reward for collecting and solving the paper riddle from the organizer desk): Exactly two of the four contributions ship REDUCED — a bare 32-byte element with no binding tag, re-advertised on the wire. Those are the two seats you can steer; the other two are bound (32-byte element + 16-byte tag) and already fixed, so F is a weighted product of one per-seat exponent applied in seat order and you only need to solve for a single reduced share's value. Pick a target session secret you can compute yourself, then invert that seat's exponent modulo (p-1): XC = (Y* · R⁻¹)^(13⁻¹ mod (p-1)). The genuine agreement confirmation sits between two decoys, and the payload is AES-GCM on the outside and AES-CBC on the inside.",
         solution="Parse the TLV transcript: shares A/B are bound (32B element + 16B tag = 48B) while C/D are reduced (bare 32B) and re-advertised. The agreement value is Y = XA^5 * XB^11 * XC^13 * XD^17 mod p; the key is K = HKDF(salt, Y, info||sid). Choose an attacker-known target and solve for the injected C share XC = (Y* * R^-1)^(13^-1 mod (p-1)). Confirm against record 0x0020 (0x0021/0x0022 are decoys), then AES-256-GCM decrypt final_payload.enc and finally AES-256-CBC the inner blob."),
    # --- Wave 2 "namesake-easy" — labelled Easy, engineered to be brutal ---------
    dict(cid="E06", title="Payphone Static", level="Easy", act="The Street Job",
         location="Little Seoul", category="Steganography",
         topic="Split DTMF burst + custom keypad + keyed XOR", points=50, mission=16,
         thumb="/images/jason-1.webp",
         briefing="A payphone outside a Little Seoul laundromat kept spitting out a call nobody placed. The recording is mostly handshake noise; the genuine traffic only begins after a long dead interval. The file hides more than it says — a lazy low-bit sweep hands you a smug little flag that is a lie — and what follows the gap is a two-block keypad code plus a payload sealed with a key you must first assemble from the keypad block itself.",
         objective="Recover the single courier phrase. The recording names nothing: split the burst, discard the handshake, rebuild the key, and peel the payload.",
         files=["payphone.wav", "EXCHANGE.txt"],
         hints=["A blanket DTMF decode concatenates three blocks and fails. A long dead interval separates a handshake from the operational traffic — discard everything before the double gap.",
                "The handshake is bait, and so is the flag written into the sample's lowest bits. The real key is not a number: the operational block is a sequence of (key, offset) digit pairs read off the exchange's private pad.",
                "The payload digits are one large decimal number. The key you assembled seeds a hash keystream (an XOR), and decompression is the very last step."],
         solution="Split the WAV by silence into three DTMF blocks; discard block A (handshake). Block B is 6 digits = three (key,offset) pairs -> the 3-letter pad word via EXCHANGE.txt's 10x3 keypad; that word seeds SHA256(word+'payphone') as the keystream. Block C is the decimal form of zlib(flag) XOR keystream. Convert block C to bytes, XOR the keystream, zlib-decompress. Decoys: the LSB payload 'FTA{d34d_b34t_0n_th3_w1r3}' and EXCHANGE.txt's printed 'confirmed courier phrase'."),
    dict(cid="E07", title="Wanted Poster", level="Easy", act="The Street Job",
         location="Vinewood Hills", category="Steganography",
         topic="Hue-keyed Vigenere over a rail fence", points=50, mission=17,
         thumb="/images/jason-2.webp",
         briefing="A wanted poster from Vinewood Hills carries a prisoner's parting note and a row of printer's seal swatches that most people take for decoration. The ciphertext is printed in plain sight, but the watchword the note advertises is a plant; the real keyword is carried only by the colours of the seal. Two classical ciphers are stacked, and the poster also hides a lazy low-bit payload that decodes to a flag that will get you laughed out of the precinct.",
         objective="Recover the real keyword from the seal, unwind both classical layers, and submit the recovered flag.",
         files=["wanted_poster.png", "DEPUTIZE.txt"],
         hints=["The watchword printed in the note is wrong on purpose. Only the seal's colours carry the real one — sample the swatch row and map each hue bin to a letter.",
                "Two classical ciphers are stacked: undo the substitution first, then the transposition.",
                "The poster's lowest bit-plane holds a decoy flag. Ignore it."],
         solution="Read the 'ciphertext' text chunk (or OCR the CIPHERTEXT line). Sample the bottom seal swatch row; hue bin int(hue/360*26) -> the keyword. Vigenere-decrypt the letters of the ciphertext with that keyword, then rail-fence (rails=3) decode -> flag. Decoys: DEPUTIZE.txt's 'FREEWAY' watchword and its printed flag line, plus the LSB decoy 'FTA{p0st3r_lsb_b41t}'."),
    dict(cid="E08", title="Dead Drop Uplink", level="Easy", act="The Street Job",
         location="La Mesa", category="Network forensics",
         topic="Custom UDP sessions + CRC gate + keyed XOR", points=50, mission=18,
         thumb="/images/jason-3.webp",
         briefing="A tow-truck dead drop pinged a cell tower in La Mesa and vanished. The capture holds two interleaved sessions with identical framing; exactly one is real, and the spec sheet you were handed points at the wrong one — a replayed decoy whose fragments reassemble into a flag that isn't the drop. The genuine session's key rides in a single control uplink, folded twice.",
         objective="Pick the genuine session, validate its fragments, recover the session key, and reconstruct the drop.",
         files=["dead_drop.pcap", "UPLINK_SPEC.txt"],
         hints=["Two sessions share the framing, and the spec's port and magic lead to the decoy. The genuine session is the one whose control packet actually carries a key.",
                "The key is folded twice — undo both. Then CRC-validate the data fragments before you trust a single one.",
                "Fragments must be ordered by their sequence field, and the keystream is keyed by the session key at each fragment's global offset."],
         solution="Parse the pcap's Ethernet/IPv4/UDP; collect custom payloads (MAGIC | SESSION | SEQ | CRC16 | FRAGMENT). Find the CONTROL packet (udp/4444) and base64+rot13-decode the session key; match its SESSION id to select the genuine DATA packets (udp/4445). Verify CRC-16, order by SEQ, XOR the SHA256(key) keystream, zlib-decompress. Decoy: the 0xD1E0 / udp-4446 session reassembles to 'FTA{r3pl4y3d_s3ss10n_b41t}'."),
    dict(cid="E09", title="Chop Shop Terminal", level="Easy", act="The Street Job",
         location="Strawberry", category="Web security",
         topic="Obfuscated client-side checker + PRNG keystream", points=50, mission=19,
         thumb="/images/lucia-1.webp",
         briefing="A Strawberry chop shop screens clients with a browser 'terminal' that validates an access token locally. The checker is buried under a rotating string table and a home-grown generator, and it lies in two places: a dead branch and a comment both offer 'the' key, and neither opens the door. The only truth is the arithmetic the page actually runs.",
         objective="Recover the token the checker would accept — without a browser doing the work for you.",
         files=["terminal.html", "chopshop.js"],
         hints=["The comment and the dead branch are plants. The page's real decision is an arithmetic comparison against an embedded digest.",
                "The keystream is a small integer generator seeded by a value that is itself masked. Recover the seed before generating anything.",
                "Invert the same order the checker applies: base64 first, then the masked keystream, then compare."],
         solution="Deobfuscate chopshop.js: un-rotate the string array (rotation 3) and un-mask the seed (stored = seed XOR 0xa5a5f00d). Regenerate the xorshift32 keystream, XOR the embedded TARGET hex, base64-decode -> flag. Decoys: the dead-branch 'FTA{sh0p_b41t_d34d_c0d3}' and the comment 'FTA{c0mm3nt_s4ys_th15}'."),
    dict(cid="E10", title="Towing Yard Ignition", level="Easy", act="The Street Job",
         location="El Burro Heights", category="Reverse engineering",
         topic="Custom bytecode VM + anti-tamper gate", points=50, mission=20,
         thumb="/images/lucia-2.webp",
         briefing="A towed car's immobiliser module dumps a single opaque blob and a mechanic's note; the keyfob tool that shipped with it is subtly wrong and will happily show you a program that prints a decoy 'ignition' phrase. The blob is bytecode for a small machine, and it refuses to cooperate when read through a bad lens — the correct phrase is the only string that satisfies the module's own checksum.",
         objective="Repair your reading of the bytecode, execute it correctly, and recover the ignition phrase.",
         files=["ignition.vmb", "YARD_NOTES.txt", "disassemble.py"],
         hints=["The provided disassembler's table is wrong in exactly one place; its listing is a dead end.",
                "The blob's header is obfuscated the same way as its instructions — read the key from the header and unmask before you decode anything.",
                "The module self-checks: the true phrase must satisfy FNV-1a-32 == the header CHECK. Use that to tell a correct decode from the decoy."],
         solution="The .vmb layout is MAGIC | OPKEY | CONST(4) | CHECK(4) | len(2) | bytecode, with every byte at offset >= 5 XORed by OPKEY. Implement the VM with the CORRECTED opcode table (the note swaps ADD/XOR and wrongly claims operands are stored verbatim), run the program, and confirm FNV-1a-32(CONST) == CHECK. The correct VM prints 'FTA{t0w1ng_y4rd_byt3c0d3_1gn1t10n}'; the naive table trips the gate and yields 'FTA{1gn1t1on_1mm0b1l1z3r_b41t}'."),
    # --- Wave 3 relay pair — Easy, two offline captures from the same relay -----
    dict(cid="E11", title="Ghost Relay", level="Easy", act="The Street Job",
         location="Paleto Bay", category="Network forensics",
         topic="Offline wire capture + custom relay reassembly", points=50, mission=21,
         thumb="/images/lucia-1.webp",
         briefing="A black-market courier relay in Paleto Bay was caught mid-drop, and the only thing recovered is a short wire capture of the burst it threw back at a passer-by who poked it. The relay never talks first, and when it did answer it did not answer politely — the parcel came back as a scatter of small datagrams leaving from several ports at once, salted with a replay nobody asked for. Listen on a single socket and you read noise; you have to work the whole conversation at the frame level to decide which fragments are the drop. Everything you need is already in the capture.",
         objective="Reassemble the parcel hiding in the capture and submit the flag.",
         files=["ghost_relay.pcap"],
         hints=["The capture holds one relay burst. Read it at the frame level; the parcel is split across two carriers.",
                "Merge the fragments arriving on udp/7001 and udp/7002 by their sequence field, and pick the key out of the single control fragment on udp/7000.",
                "A legacy replay burst on udp/7003 frames itself with a different magic and inflates to a bait flag. Trust the CRC, not the port number."],
         solution="Open ghost_relay.pcap in Wireshark (or tcpdump). Collect the COURIER RELAY PROTOCOL frames (MAGIC | SESSION | SEQ | CRC16 | FRAGMENT; magic 0xCB01, session 0xC11A). The CONTROL frame (SEQ=0xFFFF, udp/7000) carries base64(rot13(hex(SK))); decode the 16-byte key. Merge the CRC-valid DATA fragments from udp/7001 (even SEQ) and udp/7002 (odd SEQ), order by SEQ, XOR the SHA256(SK) keystream and zlib-inflate. Decoy: the udp/7003 burst (magic 0xCB02) reassembles to 'FTA{r3pl4y3d_r3l4y_b41t_d0_n0t_subm1t}'."),
    dict(cid="E12", title="Relay Archive", level="Easy", act="The Street Job",
         location="Grapeseed", category="Network forensics",
         topic="Offline relay archive + dual-carrier merge + decoy replays", points=50, mission=22,
         thumb="/images/jason-1.webp",
         briefing="The same Ghost Relay keeps a buffer for crews working dark, and what you have here is the relay's off-air copy of what it was holding when it went quiet. It mixes a genuine parcel with old fragments it left on the legacy replay carrier, and the notes shipped with the dump are a plant — they point you at the wrong port and hand you two bait flags by name. The genuine parcel remembers the relay it came from: it is stamped with the very session tag from the Ghost Relay capture, and it is the only parcel in the dump spread across two carriers rather than one.",
         objective="Identify the genuine parcel in the archive, reassemble it, and submit the flag. It is directly related to the capture from Ghost Relay.",
         files=["relay_archive.pcap", "COURIER_RELAY.txt"],
         hints=["Every parcel in the dump uses the same framing and the same magic; the port the notes insist on is the legacy replay path, where the bait lives.",
                "The genuine parcel is the only one delivered across TWO carriers (udp/7001 and udp/7002), and it reuses the session tag captured in Ghost Relay.",
                "The key is folded twice (base64 then a rotation); CRC-check the fragments before you trust a byte, then order by SEQ, XOR and inflate."],
         solution="Parse relay_archive.pcap (Ethernet/IPv4/UDP). Collect COURIER RELAY PROTOCOL frames (magic 0xCB01); group by SESSION. The genuine parcel is the only one whose CRC-valid DATA fragments arrive across BOTH udp/7001 and udp/7002; its tag equals the Ghost Relay (E11) capture tag (0xC11A). Decode the key from its CONTROL fragment base64(rot13(hex(SK))), order fragments by SEQ, XOR the SHA256(SK) keystream, zlib-inflate. Decoys: the single-carrier udp/7003 replays inflate to 'FTA{l3g4cy_r3pl4y_p4th_b41t}' and 'FTA{0ld_r3l4y_buff3r_b41t}' agent-bait printed in COURIER_RELAY.txt."),
    # --- Wave 4 "Nightshift" — malware-analysis trilogy (Medium, chained 23/24/25) -
    # Part 1 -> 2 -> 3: each part recovers a token the next part demands. No live
    # service: the whole chain is offline artefacts.
    dict(cid="M06", title="Nightshift Loader — Part 1", level="Medium", act="The Big Heist",
         location="Mirror Park", category="Malware analysis",
         topic="Private packer + rotated key table + custom base + checksum gate", points=100, mission=23,
         thumb="/images/lucia-1.webp",
         briefing="A crew's fixer implant was recovered mid-drop in Mirror Park: one opaque blob, the wrapper's scratch notes, and a half-written unpacker somebody abandoned. It is not a real executable and the usual tools learn nothing from it — the container invents its own layout and admits no standard signature. Three reversible layers sit between you and the implant's dispatch order, and the notes confidently nominate the wrong one to undo first. The abandoned stub still runs and cheerfully prints a little phrase the crew left behind for exactly this situation; it is not the drop.",
         objective="Reverse the wrapper and recover the implant's dispatch order plus the token it is meant to hand onward. Nothing in the notes names an algorithm that actually works.",
         files=["nightshift_loader.bin", "LOADER_NOTES.txt", "unpack_stub.py"],
         hints=["The table you are told to use as stored is not usable as stored: one byte in the header decides how it must be turned before any key material is correct, and the abandoned stub ignores that byte completely.",
                "A checksum gate sits between the two transforms. If you are brute-forcing a byte order until it merely looks like text, stop — the gate already knows whether you are right.",
                "What comes out is not ASCII. The container carries its own private alphabet, and once you decode with it, the dispatch order and a short token sit on the lines that follow."],
         solution="Parse the NSLF container: magic (4B), version (u16 LE), rort byte at offset 6, then a section table of (4-byte tag | u32 LE length | body): KEYT, CHST, PACK, DBUG. Un-rotate the KEYT table left by rort (the note's use-as-stored route fails the CRC gate). XOR PACK[4:] with the SHA-256 counter keystream of that key and verify zlib.crc32(body) == the stored u32 in PACK[:4]. The decoded body is base-40 text over the 40-char alphabet stored in CHST; decode it to a payload of 'FLAG:<flag>' and 'TOKEN:<32 hex>'. The 16-byte TOKEN is required by Part 2. DBUG is a decoy (base64 XOR 0x5a) that yields the bait flag. Bait: the stub prints FTA{n1ghtsh1ft_l04d3r_d3bug_b41t_d0_n0t_subm1t}."),
    dict(cid="M07", title="Nightshift Config — Part 2", level="Medium", act="The Big Heist",
         location="Elysian Island", category="Malware analysis",
         topic="Smeared RAM XOR key + trap nibble + keyed KDF/HMAC + decoy section", points=100, mission=24,
         thumb="/images/lucia-2.webp",
         briefing="The fixer stashed its configuration beside a scrap of process memory pulled from a dockyard terminal at Elysian Island. The key was never stored whole: four allocations in the heap slice hold it split apart, and a fifth looks exactly like the ones you want but belongs to a build the crew retired — combining it yields a key that opens nothing. The config is double-locked, and one lock will not even answer unless you already carry the dispatch order from the loader. One of the two sealed sections is genuine and one is a planted twin for the retired key; the notes swear the wrong one is live.",
         objective="Rebuild the smeared key from the live buffers only, unlock the config with the dispatch order from Part 1, and read the C2 endpoint and session id it keeps for the next stage.",
         files=["nightshift_config.bin", "ram_slice.bin", "CONFIG_NOTES.txt"],
         hints=["The passphrase is not one value. Every live allocation must be combined, and a corrupt one announces itself before you trust it — the fifth record sitting near the live four is not live.",
                "One field in that stray record is a single nibble off from its twin, and it is there on purpose. Feeding the stray key material gives a key that decrypts to noise, not to the config.",
                "The container gates you twice: one sealed section authenticates against the dispatch order alone as a checkpoint, and only then does the genuine payload open — under a key derived from the order and the rebuilt memory key together."],
         solution="Read the NSCF container (magic + version + section table): TAGV, LEGC, LIVE. From ram_slice.bin (magic NSRAM1, u16 count, then 16-byte heap records of name|status|8 data|check byte = (sum(data) XOR 0x5a) & 0xff) take the four records with status 1 and names KEY0..KEY3 and XOR their 8-byte bodies together to rebuild the smeared key. The freed shadow K2SH record is a trap: it is KEY2 with one nibble flipped and only opens the LEGC decoy. Authenticate the gate first — TAGV must equal HMAC-SHA256(mac_key → sha256('NS-CFG-MAC'||key), 'ns-config-tag')[:16] — then derive key = sha256('NS-CFG-KEY'||Token||ram_key) and AES-like decrypt LIVE: key stream = sha256 counter mode keyed by (key, 8-byte IV), tag = the last 16 bytes. Payload carries 'FLAG:', 'C2:<host>:<port>', 'SESSION:<32 hex>'. The endpoint + 16-byte session id feed Part 3. Bait: LEGC (trap-keyed) and the note's 'live' claim both yield FTA{n1ghtsh1ft_c2_c0nf1g_b41t_d0_n0t_subm1t}."),
    dict(cid="M08", title="Nightshift C2 — Part 3", level="Medium", act="The Big Heist",
         location="Port of Los Santos", category="Malware analysis",
         topic="Stateful C2 protocol + HMAC-gated chained frames + plaintext decoy broadcast", points=100, mission=25,
         thumb="/images/lucia-3.webp",
         briefing="The last piece is the crew's command channel as it crossed the wire, lifted off a Port of Los Santos relay. It is not HTTP and it is not polite: every real message is an authenticated frame, the channel is salted with replays and at least one tampered frame, and a frame only decrypts in its true position — a later frame is locked by the one the crew already accepted. The capture also carries a plaintext diagnostic the implant let slip; it names an archived flag that will be refused on sight. Two endpoints appear on the wire, and the one the notes favour is a retired session that carries no key you hold.",
         objective="Authenticate the genuine session using the endpoint and session id from Part 2, walk the frames in order, and recover the exfiltrated flag.",
         files=["nightshift_c2.pcap", "C2_NOTES.txt"],
         hints=["Do not trust a frame you cannot authenticate. An HMAC tag covers every real frame, and it is keyed by the session id from Part 2 — replays and the tampered frame simply drop out.",
                "The key stream is chained: each frame mixes the previous authenticated frame's tag, so the frames must be decrypted strictly in order, not gathered and sorted after the fact.",
                "One flow on the wire belongs to a different session that never authenticates under your key. The plaintext diagnostic broadcast is a plant; its archived flag is bait and will be rejected."],
         solution="Parse the pcap, reassemble each TCP 4-tuple, and read NC2 frames: magic 'NC2\\x01', ftype, u32 LE seq, 16-byte nonce, u16 LE ciphertext length, ciphertext, 16-byte tag. mac_key = sha256('NS-C2-MAC'||sid); frame tag = HMAC-SHA256(mac_key, header||ciphertext)[:16]. Use Part 2's endpoint (198.51.100.7:4444) to select the genuine flow and Part 2's session id as the key. Drop ftype-0 diagnostics, drop frames failing the tag, dedupe by seq, then decrypt in seq order: key stream = sha256 counter mode over ('NS-C2-KS'||prev_tag||nonce||seq||i), where prev_tag starts as the session id and becomes the previous authenticated frame's tag. The ftype-3 exfil plaintext carries the flag. Bait: the plaintext notice's FTA{n1ghtsh1ft_c2_s3ss10n_b41t_d0_n0t_subm1t} and the retired 203.0.113.9:4445 flow."),
]

# ---------------------------------------------------------------------------
# 1b. BONUS WAVE — released by the scheduler at T+60min. $25 each, mixed and
# mostly comic. Four are browser mini-games on the event site; the rest are
# standalone downloads. `game` (when present) is the on-site route slug.
# ---------------------------------------------------------------------------
BONUS = [
    dict(cid="B01", title="Simon Says: Dispatch Edition", level="Bonus", act=BONUS_ACT,
         location="Dispatch Desk", category="Interactive game",
         topic="Memory game + keyed XOR", points=25, mission=26,
         thumb="/images/jason-1.webp", game="simon",
         briefing="The night dispatcher will only speak in sequences. Repeat the call-backs cleanly and the desk coughs up an access key; without it the tape you pulled is just noise.",
         objective="Beat the dispatch memory game to earn the key, then unmask the tape.",
         files=["dispatch_tape.txt"],
         hints=["The tape is XOR-masked with a fixed ASCII key. The game hands you that key — but only if you keep the sequence perfect.",
                "Watch the four tones, not the colours; one wrong note resets the whole desk.",
                "Once you hold the key, XOR it byte-for-byte across the hex in dispatch_tape.txt."],
         solution="Win the on-site Simon game (repeat the 8-tone sequence with no error) to reveal the 16-byte ASCII key 5IM0N-D15P4TCH-K. dispatch_tape.txt holds hex == flag XOR (key repeated); XOR the repeating key over the decoded bytes to recover the flag."),
    dict(cid="B02", title="The Reflex Job", level="Bonus", act=BONUS_ACT,
         location="Alarm Grid", category="Interactive game",
         topic="Reaction game + keyed XOR", points=25, mission=27,
         thumb="/images/jason-2.webp", game="reflex",
         briefing="An alarm you have to outrun with reflexes alone. Hit the window tight enough and the rig prints a key; miss and it just runs again.",
         objective="Pass the reaction test to earn the key, then decode the rig log.",
         files=["reflex_log.txt"],
         hints=["The log is XOR-masked; the game prints the exact key only on a clean, fast hit.",
                "Speed matters to the millisecond — the window is unforgiving.",
                "XOR the repeating ASCII key across the hex in reflex_log.txt."],
         solution="Hit the reaction target in under 200 ms to print the 16-byte key R3FL3X-W1ND0W-26. reflex_log.txt hex == flag XOR (key repeated); XOR to recover the flag."),
    dict(cid="B03", title="Captain's Log, Star Date Whatever", level="Bonus", act=BONUS_ACT,
         location="Bridge Terminal", category="Interactive game",
         topic="Command-parsing game + keyed XOR", points=25, mission=28,
         thumb="/images/jason-3.webp", game="terminal",
         briefing="The bridge terminal only listens to a captain who knows the ship. Talk it into unlocking the log and it prints the key to the manifest.",
         objective="Issue the right commands to the in-browser terminal and decode the manifest.",
         files=["starship_manifest.txt"],
         hints=["Type `help` first; the terminal is honest about what it understands.",
                "One command needs the ship's override code — it is written where a captain would keep it.",
                "The manifest is XOR-masked with the 16-byte key the terminal prints on unlock."],
         solution="In the on-site terminal issue: help -> scan -> unlock --code 4702 -> override warp. `override warp` prints key WARP-C0RE-K3Y-26. starship_manifest.txt hex == flag XOR (key repeated); XOR to recover."),
    dict(cid="B04", title="Achievement Unlocked: Touched Grass", level="Bonus", act=BONUS_ACT,
         location="The Outside", category="Interactive game",
         topic="Patience/idle game + keyed XOR", points=25, mission=29,
         thumb="/images/lucia-1.webp", game="idle",
         briefing="Every gamer knows the rarest achievement there is: log off and go outside. The launcher refuses to reveal anything until you do precisely nothing for a while.",
         objective="Earn the achievement, then decode the launcher manifest.",
         files=["achievements.json"],
         hints=["The rarest achievements are not earned by doing something. They are earned by not doing anything.",
                "Any input — any click or key at all — resets the timer. Leave it alone.",
                "The JSON is XOR-masked with the achievement string the launcher finally prints."],
         solution="In the on-site patched-achievement gag, leave the page untouched for 30 continuous seconds (any input resets). The achievement T0UCH3D-GR4SS-26 is then revealed as the key. achievements.json hex == flag XOR (key repeated); XOR to recover."),
    dict(cid="B05", title="Niko's Pizza Receipt", level="Bonus", act=BONUS_ACT,
         location="Pizza This", category="Misc",
         topic="Receipt arithmetic + keyed XOR", points=25, mission=30,
         thumb="/images/lucia-2.webp",
         briefing="Niko swears the pizza place skimmed him. The receipt adds up to nothing sensible and there is a blob stapled to the bottom; work out by how much he was fleeced and you can unwrap it.",
         objective="Find the overcharge on the itemised receipt and unwrap the blob.",
         files=["receipt.txt"],
         hints=["Add up qty x unit price yourself; do not trust the printed TOTAL.",
                "The overcharge is a whole number of cents, and it is the key.",
                "XOR OVERCHARGE_BLOB with the overcharge as a 4-byte little-endian value, repeated."],
         solution="receipt.txt lists qty x unit_price per line plus a printed TOTAL and an OVERCHARGE_BLOB (hex). The true itemised sum is 4317 cents; the printed TOTAL is 5654; the overcharge is 1337 cents. XOR the blob with the 4-byte little-endian value 1337, repeated, to recover the flag."),
    dict(cid="B06", title="Wi-Fi Named 'FBI Surveillance Van'", level="Bonus", act=BONUS_ACT,
         location="Los Santos Suburbs", category="Cryptography",
         topic="Weak-passphrase WPA-style KDF + blob", points=25, mission=31,
         thumb="/images/lucia-3.webp",
         briefing="Someone's home Wi-Fi is literally called 'FBI Surveillance Van', which is either a joke or the worst OPSEC in Los Santos. A handshake was captured and the passphrase is presumably worse than the SSID.",
         objective="Recover the passphrase, derive the keystream, and unwrap the captured blob.",
         files=["handshake.hc22000", "wordlist.txt"],
         hints=["The capture is a toy, not a real 4-way handshake: one salt plus one ciphertext blob.",
                "The passphrase is in the supplied wordlist, and it is exactly the kind of thing this network owner would pick.",
                "Keystream = PBKDF2-HMAC-SHA256(passphrase, salt, 60000, dklen=32); XOR it across the blob; the right passphrase yields text beginning FTA{."],
         solution="handshake.hc22000 stores SALT=<hex> and BLOB=<hex>. For each candidate passphrase in wordlist.txt compute ks = PBKDF2-HMAC-SHA256(passphrase.encode(), salt, 60000, dklen=32) and XOR it across BLOB. The passphrase 'surveillance-van-2026' yields a plaintext starting FTA{ (the flag); every other candidate yields garbage."),
    dict(cid="B07", title="Rick Roll Protocol", level="Bonus", act=BONUS_ACT,
         location="The Internet", category="Cryptography",
         topic="Lyric-keyed Vigenere + rail fence", points=25, mission=32,
         thumb="/images/jason-1.webp",
         briefing="A courier left a love letter that is 100 percent definitely not a rickroll. Decode it properly and it will tell you the rules, and then hand you the flag.",
         objective="Unwind the two cipher layers and recover the flag.",
         files=["lyrics_cipher.txt"],
         hints=["Two layers sit here: a transposition over a substitution.",
                "The substitution key is the exact lyric phrase everyone in Los Santos knows but refuses to type.",
                "Undo a rail-fence of width 5 first, then Vigenere-decrypt with key 'nevergonnagiveyouup'."],
         solution="lyrics_cipher.txt = Vigenere(rail_fence(flag, width=5), key='nevergonnagiveyouup'). Reverse the rail fence (width 5) first, then Vigenere-decrypt with key 'nevergonnagiveyouup' to recover the flag. A decoy line decodes to a fake flag if you skip the transposition."),
    dict(cid="B08", title="404 Flag Not Found", level="Bonus", act=BONUS_ACT,
         location="Some Server", category="Web security",
         topic="HTTP header parsing + double base64", points=25, mission=33,
         thumb="/images/jason-2.webp",
         briefing="You requested a page; the server returned a joke and a wall of headers. The interesting part was never in the body.",
         objective="Read the response like a machine, not a browser, and recover the flag.",
         files=["raw_http_response.txt"],
         hints=["It is a raw HTTP response, not HTML. Read the headers, not the pretty page.",
                "A non-standard header carries the payload, and it is encoded twice.",
                "Decode the X-Courier-Route header value as base64, then base64 again. The body's 'flag' is bait."],
         solution="raw_http_response.txt is a raw HTTP/1.1 response. Header X-Courier-Route = base64(base64(flag)); decode it twice. The rendered body contains a decoy FTA{404_fake_page}."),
    dict(cid="B09", title="Facebook Marketplace Rugpull", level="Bonus", act=BONUS_ACT,
         location="Marketplace", category="OSINT",
         topic="Listing JSON + chat-price XOR", points=25, mission=34,
         thumb="/images/jason-3.webp",
         briefing="A 'cheap car, no lowballers, I know what I have' listing goes sideways. The listing and the seller's own chat log disagree; the price you were actually quoted is the key.",
         objective="Reconcile the listing with the chat and unwrap the blob.",
         files=["listing.json", "chat_log.txt"],
         hints=["The asking price is not the agreed price. The seller said the real number in chat.",
                "The agreed price is a whole number of dollars and it is the key.",
                "XOR the listing's base64 blob with the agreed price as a 4-byte little-endian value, repeated."],
         solution="listing.json shows ask 4200 and holds COURIER_BLOB (base64 of flag XOR keystream). chat_log.txt reveals 'final price: $3699'. XOR COURIER_BLOB (after base64-decoding) with the 4-byte little-endian value 3699, repeated, to recover the flag."),
    dict(cid="B10", title="Grand Theft Alpaca: Install Linux", level="Bonus", act=BONUS_ACT,
         location="A Basement", category="Reverse engineering",
         topic="Obfuscated shell script + base64", points=25, mission=35,
         thumb="/images/lucia-1.webp",
         briefing="To claim the alpaca you must prove you can daily-drive a Linux desktop. The so-called installer is 90 percent jokes and 10 percent payload; run the logic in your head and it hands over the flag.",
         objective="Read the script like a machine and recover the embedded payload.",
         files=["installer_script.sh"],
         hints=["Most lines are jokes. Only the ones that actually pipe data matter.",
                "The payload is handed around with echo | base64 -d, twice.",
                "There are decoy flags in the comments. The real one decodes from the final base64 line."],
         solution="installer_script.sh contains interleaved decoy jokes (rm -rf jokes, a fake FTA{...} comment) and a real payload: echo '<b64>' | base64 -d | base64 -d. Double-decode the final base64 line to recover the flag."),
]

# Main event (25) followed by the bonus wave (10).
ALL = CH + BONUS


# The H04/H05 offline notices live inside each challenge's `briefing` string, so
# they flow once into the website card (challengeMeta.js), the participant
# MISSION.md and the CTFd description -- no duplicate blocks.
def description(ch):
    files_lines = "\n".join(f"- `{f}`" for f in ch["files"])
    game_note = ""
    if ch.get("game"):
        game_note = (
            "## Interactive component\n"
            "This mission ships a browser mini-game hosted on the event site. Open the mission "
            "card on the site to play it; the download alone is not enough to reach the key.\n\n"
        )
    return (
        f"# {ch['cid']} · {ch['title']}\n\n"
        f"**Level:** {ch['level']} · **Points:** {ch['points']} · **Category:** {ch['category']}  \n"
        f"**Location:** {ch['location']} · **Focus:** {ch['topic']}\n\n"
        f"## Mission briefing\n{ch['briefing']}\n\n"
        f"## Objective\n{ch['objective']} Submit exactly one recovered flag to CTFd, in the form "
        f"`FTA{{...}}`. The braces and capitalization matter. Do not submit explanations.\n\n"
        f"## Evidence files\n{files_lines}\n\n"
        f"{game_note}"
        f"## Scope and safety\n"
        f"Work only on the downloaded challenge artifacts. All targets, identities and addresses are "
        f"fictional. No scanning, account access, or attacks against a real network are required or "
        f"allowed.\n\n"
        f"Hints are unlockable on the event platform; they are not required to solve the mission.\n"
    )


# ---------------------------------------------------------------------------
# 2. manifest.json + attachments_sha256.csv
# ---------------------------------------------------------------------------
def _manifest_entries(chs):
    entries = []
    for ch in chs:
        lvl = LEVELS[ch["cid"][0]]
        entries.append({
            "id": ch["cid"],
            "name": f"{ch['cid']} | {ch['title']}",
            "level": ch["level"],
            "category": ch["category"],
            "location": ch["location"],
            "topic": ch["topic"],
            "points": ch["points"],
            "description": description(ch),
            "flag": FLAGS[ch["cid"]],
            "hints": list(ch["hints"]),
            "files": list(ch["files"]),
            "directory": f"challenges/{lvl}/{ch['cid']}",
            "solution_outline": ch["solution"],
        })
    return entries


def build_manifest():
    out_dir = ROOT / "organizer_private" / "CTFD_IMPORT"
    man = {"event": "FLAG THEFT AUTO", "challenges": _manifest_entries(CH)}
    out = out_dir / "manifest.json"
    out.write_text(json.dumps(man, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("wrote", out.relative_to(ROOT))

    # Bonus wave: imported separately as HIDDEN challenges and flipped visible
    # by reveal_bonus.py at T+60min. `state` is documented here for tooling.
    bonus = {"event": "FLAG THEFT AUTO", "wave": "bonus",
             "reveal_offset_minutes": 60, "state": "hidden",
             "challenges": _manifest_entries(BONUS)}
    bout = out_dir / "manifest_bonus.json"
    bout.write_text(json.dumps(bonus, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("wrote", bout.relative_to(ROOT))

    rows = ["id,filename,size_bytes,sha256"]
    for ch in ALL:
        lvl = LEVELS[ch["cid"][0]]
        for f in ch["files"]:
            p = SRC / lvl / ch["cid"] / f
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            rows.append(f"{ch['cid']},{f},{p.stat().st_size},{h}")
    (out_dir / "attachments_sha256.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    print("wrote attachments_sha256.csv")
    return man


# ---------------------------------------------------------------------------
# 3. challengeMeta.js  (data only -- resolver/constants preserved)
# ---------------------------------------------------------------------------
def js(s):
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n") + "'"


def build_meta_js():
    blocks = []
    for ch in ALL:
        key = js(f"{ch['cid']} | {ch['title']}")
        game_line = f"    game: {js(ch['game'])},\n" if ch.get("game") else ""
        block = (
            f"  {key}: {{\n"
            f"    fta_id: {js(ch['cid'])}, level: {js(ch['level'])}, act: {js(ch['act'])},\n"
            f"    location: {js(ch['location'])}, topic: {js(ch['topic'])},\n"
            f"    missionNum: {ch['mission']}, reward: {ch['points']},\n"
            f"    thumbnail: {js(ch['thumb'])},\n"
            f"{game_line}"
            f"    briefing: {js(ch['briefing'])},\n"
            f"    objective: {js(ch['objective'])},\n"
            f"    hints: [{', '.join(js(h) for h in ch['hints'])}],\n"
            f"    files: [{', '.join(js(f) for f in ch['files'])}],\n"
            f"  }},"
        )
        blocks.append(block)
        if ch["cid"] == "E01":
            # ASCII-apostrophe alias so both punctuation variants resolve.
            alias = block.replace("Lester\u2019s", "Lester\\'s")
            blocks.append(alias)
    meta = "\n".join(blocks)

    def arr_entries(chs, start):
        arr = []
        for i, ch in enumerate(chs, start=start):
            game_field = f", game: {js(ch['game'])}" if ch.get("game") else ""
            arr.append(
                "  {\n"
                f"    id: {i}, ctfd_id: {i}, fta_id: {js(ch['cid'])}, name: {js(ch['cid'] + ' | ' + ch['title'])},\n"
                f"    level: {js(ch['level'])}, act: {js(ch['act'])}, location: {js(ch['location'])},\n"
                f"    category: {js(ch['category'])}, topic: {js(ch['topic'])}, value: {ch['points']}, reward: {ch['points']},\n"
                f"    files: [{', '.join(js(f) for f in ch['files'])}], thumbnail: {js(ch['thumb'])}{game_field},\n"
                f"    briefing: {js(ch['briefing'])},\n"
                f"    objective: {js(ch['objective'])},\n"
                f"    hints: [{', '.join(js(h) for h in ch['hints'])}],\n"
                "  },"
            )
        return "\n".join(arr)

    arr_s = arr_entries(CH, 1)
    barr_s = arr_entries(BONUS, 26)


    body = f"""/**
 * Local metadata for all 25 main-event challenges plus the 10-challenge bonus wave.
 * This file contains ONLY participant-safe information:
 * challenge names, locations, descriptions visible in MISSION.md.
 * NO flags, NO solutions, NO private data.
 *
 * Keys match CTFd challenge names (supporting both ASCII and Unicode punctuation).
 */
export const CHALLENGE_META = {{
{meta}
}};

/**
 * Normalizes strings by replacing curly quotes/apostrophes with ASCII quotes
 */
export function normalizeName(str) {{
  if (!str) return '';
  return String(str)
    .replace(/[\\u2018\\u2019]/g, "'")
    .replace(/[\\u201C\\u201D]/g, '"')
    .trim()
    .toLowerCase();
}}

/**
 * Bulletproof resolver that matches challenge metadata by:
 * 1. Direct name match
 * 2. Normalized name match (handling unicode vs ascii apostrophes)
 * 3. fta_id prefix (E01, M03, H05, B07)
 * 4. Mission index (1-35)
 */
export function getChallengeMeta(identifier) {{
  if (!identifier) return {{}};
  const s = String(identifier).trim();

  // 1. Direct key match
  if (CHALLENGE_META[s]) return CHALLENGE_META[s];

  // 2. Normalized match
  const norm = normalizeName(s);
  for (const [key, meta] of Object.entries(CHALLENGE_META)) {{
    if (normalizeName(key) === norm) return meta;
  }}

  // 3. Match by fta_id prefix (e.g. "E01 | ...", "E01", "m02", or "B07")
  const idMatch = s.match(/([EMHB]\\d{{2}})/i);
  if (idMatch) {{
    const ftaId = idMatch[1].toUpperCase();
    for (const meta of Object.values(CHALLENGE_META)) {{
      if (meta.fta_id === ftaId) return meta;
    }}
  }}

  // 4. Match by missionNum
  const num = parseInt(s, 10);
  if (!isNaN(num)) {{
    for (const meta of Object.values(CHALLENGE_META)) {{
      if (meta.missionNum === num) return meta;
    }}
  }}

  return {{}};
}}

// Canonical ordered list of the 25 main-event challenges
export const ALL_15_CHALLENGES = [
{arr_s}
];

// Bonus wave (10 x $25) — CTFd keeps these hidden until T+60min after the
// event begins; they surface on the board automatically once revealed.
export const BONUS_CHALLENGES = [
{barr_s}
];

// Minutes after event start at which the bonus wave becomes visible.
export const BONUS_REVEAL_OFFSET_MINUTES = 60;

export const LEVEL_ORDER = {{ Easy: 1, Medium: 2, Hard: 3, Bonus: 4 }};
export const LEVEL_COLORS = {{
  Easy:   {{ border: 'rgba(57,255,20,0.4)',  text: '#39ff14', bg: 'rgba(57,255,20,0.08)' }},
  Medium: {{ border: 'rgba(255,165,0,0.4)',  text: '#ffa500', bg: 'rgba(255,165,0,0.08)' }},
  Hard:   {{ border: 'rgba(255,68,68,0.5)',  text: '#ff4444', bg: 'rgba(255,68,68,0.08)' }},
  Bonus:  {{ border: 'rgba(0,229,255,0.5)',  text: '#00e5ff', bg: 'rgba(0,229,255,0.08)' }},
}};
export const ACT_INFO = {{
  'The Street Job':    {{ num: 'I',   total: '$500', count: 10 }},
  'The Big Heist':     {{ num: 'II',  total: '$800', count: 8 }},
  'The Final Getaway': {{ num: 'III', total: '$800', count: 5 }},
  'Bonus Wave':        {{ num: 'IV',  total: '$250', count: 10 }},
}};
"""
    out = ROOT / "frontend" / "src" / "data" / "challengeMeta.js"
    out.write_text(body, encoding="utf-8")
    print("wrote", out.relative_to(ROOT))


# ---------------------------------------------------------------------------
# 4. participant trees: MISSION.md + artefacts + indexes
# ---------------------------------------------------------------------------
def sync_tree(root: Path):
    root.mkdir(parents=True, exist_ok=True)
    for ch in ALL:
        lvl = LEVELS[ch["cid"][0]]
        src = SRC / lvl / ch["cid"]
        dst = root / lvl / ch["cid"]
        dst.mkdir(parents=True, exist_ok=True)
        desired = set(ch["files"]) | {"MISSION.md"}
        for old in dst.iterdir():
            if old.is_file() and old.name not in desired:
                old.unlink()
        (dst / "MISSION.md").write_text(description(ch), encoding="utf-8")
        for f in ch["files"]:
            s = src / f
            assert s.is_file() and s.stat().st_size > 0, f"missing artefact {s}"
            shutil.copy2(s, dst / f)
    # indexes
    write_missions_md(root)
    write_sha256sums(root)
    print("synced", root.relative_to(ROOT))


def write_missions_md(root: Path):
    lines = ["# Mission Board (all missions are independent)", "",
             "| ID | Act | Title | Focus | Points |",
             "|---|---|---|---|---:|"]
    for ch in ALL:
        lines.append(f"| {ch['cid']} | {ch['level']} | {ch['title']} | {ch['topic']} | {ch['points']} |")
    lines += ["",
              "Open each mission folder to read `MISSION.md` and access only its evidence attachments. "
              "CTFd provides three progressive hints per mission.",
              "",
              "> The `BONUS/` missions (B01-B10, $25 each) are a bonus wave revealed on the event "
              "platform 60 minutes after the event begins; a few of them also require playing a small "
              "browser game on the event site."]
    (root / "MISSIONS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_sha256sums(root: Path):
    entries = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.name != "SHA256SUMS.txt":
            rel = p.relative_to(root).as_posix()
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            entries.append(f"{h}  {rel}")
    (root / "SHA256SUMS.txt").write_text("# SHA-256 checksums relative to this folder\n"
                                         + "\n".join(entries) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# 5. organizer private answer key + matrix
# ---------------------------------------------------------------------------
def build_answer_key():
    out = ["# PRIVATE ANSWER KEY · DO NOT DISTRIBUTE", "",
           "**Security classification: organizer only.** Contains all 25 main-event flags plus the "
           "10 bonus-wave flags (revealed at T+60min) and reference walkthroughs for fictional offline "
           "labs. Do not upload to CTFd attachments, GitHub, or student shares. Main-event bounty "
           "$2,200; bonus wave $250 ($25 x 10).", ""]
    for ch in ALL:
        if ch["cid"] == "B01":
            out += ["# BONUS WAVE — revealed at T+60min · $25 each", "",
                    "Four of these (B01-B04) ship an on-site browser mini-game; the game reveals a key "
                    "the player then applies by hand to the downloaded artefact. The remainder are "
                    "standalone downloads.", ""]
        out += [f"## {ch['cid']} · {ch['title']} — {ch['points']} points", "",
                f"**Category:** {ch['category']} | **Location:** {ch['location']}  ",
                f"**Correct flag:** `{FLAGS[ch['cid']]}`  ",
                f"**Required evidence:** " + ", ".join(f"`{f}`" for f in ch["files"]), "",
                "### Solving procedure", "", ch["solution"], "",
                "### Progressive hints (shown in CTFd)", ""]
        out += [f"{i}. {h}" for i, h in enumerate(ch["hints"], 1)]
        if ch.get("bonus_hint"):
            out += ["", "### Offline bonus hint (reward for the on-site physical task)", "",
                    ch["bonus_hint"], "",
                    "_Read this to the crew (or hand it over) once they complete the task. "
                    "It is not imported into CTFd and does not deduct points._"]
        out += ["", "---", ""]
    (ROOT / "organizer_private" / "ANSWER_KEY.md").write_text("\n".join(out), encoding="utf-8")
    print("wrote ANSWER_KEY.md")


def build_matrix():
    import csv
    out = ROOT / "organizer_private" / "CHALLENGE_MATRIX.csv"
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "name", "level", "act", "location", "category", "topic", "points",
                    "attachment_count", "attachments", "hint_count", "flag",
                    "participant_directory", "summary"])
        for ch in ALL:
            lvl = LEVELS[ch["cid"][0]]
            w.writerow([ch["cid"], f"{ch['cid']} | {ch['title']}", ch["level"], ch["act"],
                        ch["location"], ch["category"], ch["topic"], ch["points"],
                        len(ch["files"]), ";".join(ch["files"]), len(ch["hints"]),
                        FLAGS[ch["cid"]], f"challenges/{lvl}/{ch['cid']}", ch["solution"]])
    print("wrote CHALLENGE_MATRIX.csv")


def main():
    assert len(CH) == 25
    assert sum(c["points"] for c in CH) == 2200
    assert len(BONUS) == 10
    assert sum(c["points"] for c in BONUS) == 250
    assert all(c.get("game") is None or c["game"] in
               {"simon", "reflex", "terminal", "idle"} for c in BONUS)
    build_manifest()
    build_meta_js()
    for r in ROOTS:
        sync_tree(r)
    build_answer_key()
    build_matrix()
    print("INTEGRATION DATA BUILD OK (25 main + 10 bonus)")


if __name__ == "__main__":
    main()
