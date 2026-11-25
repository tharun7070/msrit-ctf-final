# PRIVATE ANSWER KEY · DO NOT DISTRIBUTE

**Security classification: organizer only.** Contains all 25 main-event flags plus the 10 bonus-wave flags (revealed at T+60min) and reference walkthroughs for fictional offline labs. Do not upload to CTFd attachments, GitHub, or student shares. Main-event bounty $2,200; bonus wave $250 ($25 x 10).

## E01 · Lester’s Pager Panic — 50 points

**Category:** Cryptography | **Location:** Lester's Hideout  
**Correct flag:** `FTA{41_c1ph3r_b4s3_cust0m_m0d_p4g3r_l3st3r_2026}`  
**Required evidence:** `dispatch.csv`, `decoder`

### Solving procedure

Keep rows satisfying BOTH (col_A*col_B) mod col_C == 7 AND (col_A+col_B) mod col_C == (col_D mod col_C). For each genuine row, base-41 decode then invert the per-row alphabet permutation idx -> (k*idx+m) mod 41 with k = 1+(col_A mod 40), m = col_D mod 41 (use pow(k,-1,41)). Sort genuine rows by (col_C mod 5 asc, col_D mod 2 asc, -col_E desc, packet_id asc). Concatenate decodes, strip the fixed 2-byte marker \x1b\x13. Decoys satisfy only one condition (one decodes to a fake flag); using a single filter yields garbage.

### Progressive hints (shown in CTFd)

1. One condition is not enough. More than one arithmetic rule must hold together for a row to be genuine, and the near-misses that satisfy just one will corrupt your output.
2. The decoder reveals the alphabet and radix only. Every payload is then re-scrambled per row; recover the row-dependent permutation before you trust a decoded character.
3. Order is decided by three keys with a fixed tie-break, and the assembled plaintext carries a short marker you must recognise and strip.

---

## E02 · Vinewood Shift Change — 50 points

**Category:** Cryptography | **Location:** Vinewood Boulevard  
**Correct flag:** `FTA{4ff1n3_v1n3w00d_sh1ft_c0nv0y_99}`  
**Required evidence:** `taxi_ledger.txt`, `frequency_sample.bin`

### Solving procedure

Keep the row where SHA1(timestamp) ends in a3 AND SHA256(route) starts with nibble 4. Undo a columnar transposition of width 9, then affine-decrypt with a=7,b=11. The sample is affine(transpose(english),7,11), 441 = 9x49; naive frequency analysis returns a wrong pair (1,20). Ignore the Caesar-5 decoy (FTA{wrong_route}) and the single-stage affine decoy (a near-miss flag).

### Progressive hints (shown in CTFd)

1. One fingerprint is not enough: the genuine line must satisfy two independent conditions, one on its timestamp and one on its route.
2. A substitution sits under a transposition. Undo only the substitution and you get scrambled output; you must identify the transposition width as well.
3. The sample is transposed too. Run frequency analysis without untransposing it first and you will recover a plausible but false (a,b).

---

## E03 · Sandy Shores Hidden Stash — 50 points

**Category:** Linux forensics | **Location:** Sandy Shores  
**Correct flag:** `FTA{ext2_st4sh_r3c0v3r3d_s4ndy_51}`  
**Required evidence:** `safehouse.img`

### Solving procedure

Carve the three deleted inodes; the genuine one is /ledger.dat whose sealed byte length equals the span= field on activity.log line 42. Build an 8-byte repeating XOR key arithmetically from that same line's host + relay fields; unmask, then invert the pipeline base64 -> byte-reverse -> zlib (i.e. zlib-decompress, reverse, base64-decode). Decoys /ledger.bak and /notes.tmp decode to bait flags.

### Progressive hints (shown in CTFd)

1. More than one deleted file survives. The genuine stash matches a numeric field recorded elsewhere on the image; the bait does not.
2. The mask is not a single byte. It repeats, and each key byte is computed from two distinct fields on the same surviving line.
3. After unmasking you are still not done: the bytes sit inside two more reversible transforms before they are text.

---

## E04 · Del Perro Camera Roll — 50 points

**Category:** Steganography | **Location:** Del Perro Pier  
**Correct flag:** `FTA{lsb_c0lumn_m4j0r_ut7_p13r}`  
**Required evidence:** `camera_roll.png`, `README.txt`

### Solving procedure

Parse the watermark metadata to recover the gate coefficients + salt; select pixels satisfying (3x+5y) mod 7 == 4; read bits 2..3 of R,G,B column-major; XOR with the repeating 32-byte SHA256 key; then parse a 2-byte big-endian length + gzip(utf-7(flag)). Decoys: a metadata 'flag' and a naive 2-LSB bait stream.

### Progressive hints (shown in CTFd)

1. A plain LSB dump finds bait. Only some pixels are used; a watermark hints at the selection rule but does not spell it out.
2. The bits are not in the lowest two bit-planes, and what you extract is XOR-masked with a key derived from the image's dimensions plus a salt left in metadata.
3. Once unmasked, two wraps remain: a decompressor and an older text encoding.

---

## E05 · Wrong Extension, Right Exit — 50 points

**Category:** File forensics | **Location:** Los Santos Customs  
**Correct flag:** `FTA{p0lygl0t_pdf_zip_aes_v4ult}`  
**Required evidence:** `impound_dossier.pdf`

### Solving procedure

Treat impound_dossier.pdf as a PDF+GIF89a+ZIP polyglot. AES-128 key = PBKDF2-HMAC-SHA256(password = SERIAL + '|' + ROUTE_CODE, salt, 50000, dklen=16), where SERIAL is the AcroForm field 'serial' (not the body text) and ROUTE_CODE is printed in the visible body; the IV rides in the ZIP extra field. Decrypt to vault.db (tables operators/routes/seals joined on a TEXT token); the flag is the XOR of the three joined *_hex columns. Decoys: a fake flag row and a grep-able fake 'ARCHIVE KEY' comment.

### Progressive hints (shown in CTFd)

1. Extensions lie, and so does `file`: this document is valid as three different formats at once.
2. The passphrase is not one value. Combine two separate fields from the PDF through a slow KDF, and find the IV somewhere other than the ciphertext.
3. What comes back is a database full of decoys. Only a three-table join on an unusual token reaches the real record.

---

## M01 · Fleeca Vault Glitch — 100 points

**Category:** Web security | **Location:** Fleeca Bank  
**Correct flag:** `FTA{s3c0nd_0rd3r_fl33c4_byp4ss}`  
**Required evidence:** `fleeca_kiosk.py`, `fleeca.db`, `common_pw.txt`

### Solving procedure

register (safe) -> sync (stores rot13(rev(payload)); pre-compose rot13(desired[::-1])) -> load (interpolates the stored alias raw). Bypass the custom scrubber with a /*...*/ comment to run a second-order UNION injection against the real table advertised in config.core_ledger — do NOT touch the decoy escrow ledger (it trips a canary). Authenticate with trunc(sha256('fleeca-h2'|per_user_salt|pw|user[::-1]|server_pepper))[:20] using salt+pepper read from fleeca.db, and present token = HMAC(secret_key, user|nonce). Un-veil each escrow column: base64-decode then XOR the SHA256 counter-mode keystream of HMAC(session_key,'M01-escrow-veil') tagged per column. Decoys: honeypot admin/sunshine; the escrow/vault/receipts tables full of fake flags.

### Progressive hints (shown in CTFd)

1. Registering is not exploiting, and the stored alias is not what you typed — a later sync writes it through one more transform (a reversal plus a rotation) that the loader never undoes. Compose your payload so it survives that round-trip.
2. The obvious ledger is bait and it is wired to a canary: touching it poisons your session and serves decoy rows. The real table is advertised elsewhere in the database, and the escrow columns are individually veiled (base64 plus a session-keyed mask), so you must earn the session first.
3. The password hash is keyed by a per-user salt and a server pepper you must read out of the database, and a valid HMAC session token is a separate, mandatory gate that also seeds the column veil.

---

## M02 · Airport Ghost Flight — 100 points

**Category:** Network forensics | **Location:** Los Santos International Airport  
**Correct flag:** `FTA{b1n_pr0t0_crc32_gh0st_fl1ght}`  
**Required evidence:** `airport_traffic.pcap`, `MANIFEST.txt`

### Solving procedure

Parse the pcap; reassemble IPv4 fragments per (src,dst,id,proto) ordered by offset, then assemble the TCP flows. Outer frame: magic 0xDEAD1A70, type 0x0A, seal = CRC32 over frame[0:12] || payload SKIPPING the 2-byte route field. Harvest the session nonce from the first genuine frame's SESSION_MAGIC prefix. Inner frame: magic 0x1A70C0DE, itype 0x5C; XOR the inner data with keystream(nonce, inner_seq), then order by the inner seq. Decoys: a naive whole-frame-CRC group that reassembles to a fake flag, plus bad-seal / wrong-type frames.

### Progressive hints (shown in CTFd)

1. Nothing here is packet-shaped yet. Reassemble the IPv4 fragments first — group by a shared IP id and sort by fragment offset — before you parse any protocol.
2. The seal covers only part of the frame: a whole-frame checksum rejects the genuine packets and, tellingly, accepts the decoy group. The session nonce rides once, on the first genuine message — harvest it before you can unmask anything.
3. The mask is keyed by the session nonce and the inner sequence, not by the outer order field (which is bait).

---

## M03 · LSPD Midnight Audit — 100 points

**Category:** Log forensics | **Location:** Los Santos Police Department  
**Correct flag:** `FTA{h4sh_ch41n_t4mp3r_l5pd_aud1t}`  
**Required evidence:** `lspd_auth.log`, `audit_delta.bin`, `CHAIN_SPEC.txt`, `OPS_NOTE.txt`, `flash_backup.bin`

### Solving procedure

ORGANIZER WALKTHROUGH (M03 -- LSPD Midnight Audit).

Surface: lspd_auth.log is 1000 records '<seq>|<ts>|<event_code>|<data>|<chain_hash>'. Three records were forged (seqs 319, 707, 901, in blocks 4, 8 and 10 respectively). audit_delta.bin is the sealed sidecar with the originals. CHAIN_SPEC.txt is authoritative; OPS_NOTE.txt is bait.

STEP 1 -- Recover the per-block salt schedule (the chain is NOT one fixed key).
The chain is HMAC-SHA256: chain_hash_i = HMAC(key = salt_{block(i)}, msg = chain_hash_{i-1} + content_i), genesis = 64 ASCII zeroes, block(i) = floor((i-1)/100)+1. salt_1 is a hidden 2-byte bootstrap. For b>=2, salt_b = SHA256(b'LSPD/chain-salt|' + root_{b-1})[0:2], where root_b = HMAC(key = salt_b, msg = b'block=<b>|' + concat(block-b contents)). The spec publishes root[1..10]. Brute-force the 65536 candidate 2-byte salts against the published root[1]; keep the match -> salt_1. Then walk root[1]..root[9] to derive salt_2..salt_10. A solver that assumes a single global salt (the canary's lie) can never verify the file: breaking/recovering block 1 does not touch the other blocks' keys. Each block is rooted independently, so several blocks can be broken at once -- that is why three forgeries survive in three different blocks.

STEP 2 -- Locate the tampered records. Walk the file top-to-bottom; for each record recompute chain_hash_i from the PREVIOUS STORED hash and the current content using that block's salt, and compare to the stored hash. Mismatches => forged seqs 319 / 707 / 901. You also confirm each block root still matches its published digest (block roots are recomputed from stored contents; a forged block root would immediately expose it). This is the 'strict ordering' pressure: you must derive the salt schedule in order before any block can be audited.

STEP 3 -- Decode REGION A of audit_delta.bin (originals, nested FIVE deep).
Header: magic b'AUD4', width byte (7), uint16 record_count, then the record payloads. Decode in REVERSE of the encode pipeline:
  encode: rle_encode -> xor_index -> transpose_fwd(blob, W=7) -> XOR keystream(KA) -> rotate-left(b, r)
  decode: rotate-right(b, r) -> XOR keystream(KA) -> transpose_inv -> un-xor_index -> rle_decode
Keys are DERIVED, not shortcuts: KA = b'AUD4-A|' + bootstrap_salt(2 bytes); the rotation r = (int(root_last,16) % 7) + 1 where root_last = root[10]. keystream(key,n) = concat of sha256(key + struct.pack('<I', ctr)) counter mode. The xor_index layer uses per-position (i*0x5D + 0x1F) & 0xFF. Output = the true originals for the three forged records. Apply them to lspd_auth.log and the chain + all roots re-agree.

STEP 4 -- Decode REGION B (the final gate; key comes from a repaired block).
Region B is a masked blob: masked = FLAG_MASK XOR keystream(KB, len), where KB = b'AUD4-B|' + root[10] + b'|' + last_original. NOTE the KB input: root[10] (only known after the salt schedule is recovered) AND last_original, the recovered original content of the LAST repaired record. This forces you to finish the repair BEFORE Region B will decode -- the ordering trap. Also note the flag itself is never the stored bytes; Region B holds FLAG_MASK = SEALED_TOKEN XOR FLAG, so you still cannot read the flag from Region B alone.

STEP 5 -- Apply the cross-field acceptance predicate to obtain SEALED_TOKEN.
Over all event_codes that end EXACTLY '_ACCEPT' (watch the decoys below), classify each by the low bit of sha256(code)[0]: class-0 first characters XOR'd column-wise, then XOR against the class-1 first-character column. The predicate is deliberately narrow (exact suffix '_ACCEPT', not substring) so code strings like 'x_REACCEPT' / 'x_ACCEPTED' are excluded. Result = SEALED_TOKEN (a 32-byte-ish ASCII token).

STEP 6 -- Final unwrap.
FLAG = SEALED_TOKEN XOR FLAG_MASK (byte-wise). => FTA{h4sh_ch41n_t4mp3r_l5pd_aud1t}. This is the only path that combines the repaired chain (for KB), the strict-order decode, and the exact-suffix predicate.

TRAPS AND HOW TO DETECT/AVOID EACH:
T1 (well-formed decoy found FIRST): The head of the log contains a contiguous run of ACCEPT records (seq 1..68). A naive solver takes the 'first run of ACCEPT-adjacent records', XORs neighbouring first-characters, and gets a perfectly valid-looking flag: FTA{r34cc3pt_run_1s_n0t_th3_4ud1t}. DETECT: the spec's predicate requires an EXACT '_ACCEPT' suffix and a sha256-parity split, not a contiguous run; the decoy run's codes carry the REACCEPT class. AVOID: implement the spec predicate verbatim and reject runs.
T2 (dead-end / honeypot clean block): Block 6 is left fully INTACT (no forgery) and contains a honeypot run (seq 501..566) that decodes to FTA{cl34n_bl0ck_h0nyp0t_4cc3pt3d}. A solver that only hunts 'clean blocks' or trusts a run of ACCEPTED-class codes is rewarded with a structurally valid but wrong flag. DETECT: block 6 has no break, so 'repair' does nothing there; its flag fails the predicate and never XORs to the sealed token. AVOID: only trust the flag that survives the full predicate + sealed unwrap.
T3 (bait artifact advertising a wrong method): OPS_NOTE.txt is a desk canary claiming (a) the chain is a PLAIN sha256(prev||content) chain, (b) the salt is the factory default 0x0000, (c) audit_delta.bin is a single RLE stream needing no XOR/transpose, (d) the flag is the head ACCEPT run, and (e) flash_backup.bin holds yesterday's log as a plain RLE blob. Following it: the plain-chain recompute fails on every block, salt 0x0000 fails immediately, and flash_backup.bin decodes (it really IS a plain RLE stream) to a plausible 'restored-from-flash (UNVERIFIED)' pseudo-log that leads to a dead end with NO flag. DETECT: the note self-identifies as 'not part of the signed specification'; the spec explicitly labels unofficial desk notes as stale. AVOID: never import the canary's method; use CHAIN_SPEC.txt only.
T4 (structurally-valid garbage under the wrong key): Decoding Region A with the canary's salt 0x0000 (instead of the recovered bootstrap salt) yields NON-empty, printable-ish but meaningless data -- it looks like progress. DETECT: the output is not valid 'seq|ts|code|data' records and does not repair the chain (recomputed hashes still mismatch). AVOID: always key Region A from the brute-forced salt_1, and confirm the repair actually makes all block roots agree.

ANTI-LEAK: gen/solve/validate assert the literal flag and the SEALED_TOKEN never appear in ANY shipped artifact (log, spec, note, both binary regions). The flag exists only as FLAG_MASK XOR token and is reconstructed in-memory. Total artifact footprint is well under 2 MB and generation is deterministic (fixed RNG seeds; two runs give identical SHA256 for every file).

### Progressive hints (shown in CTFd)

1. The audit key is not a single constant. It rolls forward, block by block, and block one's key was deliberately never written down. The spec tells you exactly what IS published so you can pin it down yourself.
2. Do not trust OPS_NOTE.txt -- it describes an older, weaker procedure kept in the front of an old binder. CHAIN_SPEC.txt is the authoritative, signed document; when they disagree, the spec wins.
3. audit_delta.bin hides more than a first glance suggests: the originals sit several transformations deep, and the last piece of the puzzle only opens once the whole log has been repaired -- and the order in which you do things matters.

---

## M04 · Underground XOR Radio — 100 points

**Category:** Cryptography | **Location:** Underground Market  
**Correct flag:** `FTA{lfsr23_b3rl3k4mp_m4ss3y_r4d10}`  
**Required evidence:** `radio_packet.bin`, `keystream_sample.bin`, `SIGNAL_SPEC.txt`, `OPERATOR_NOTE.txt`, `legacy_burst.bin`, `branchB_candidate.bin`

### Solving procedure

ORGANIZER WALKTHROUGH (M04 · Underground XOR Radio)

Real flag (byte-identical): FTA{lfsr23_b3rl3k4mp_m4ss3y_r4d10}. Shipped artifacts: radio_packet.bin (16-byte cleartext sync header + wrapped ciphertext, 424 B ciphertext), keystream_sample.bin (64 B, leading 15 B surviving, tail zero-filled), SIGNAL_SPEC.txt (mixed-bag spec), OPERATOR_NOTE.txt (bait canary), legacy_burst.bin (decoy burst), branchB_candidate.bin (dead-end dump). The flag is never stored verbatim in any artifact (gen + validate assert this).

Real layer stack (all deterministic, every layer keyed off the cleartext header):
  mask = round-robin burst multiplex of R0(deg11, taps [11,2], seed 0x5AB), R1(deg13, taps [13,4], seed 0x1A2B) and the beacon R2(deg23, taps [23,5], seed 0x5A3C19); schedule r = (g + off) mod 3, BURST = 5 mask-bytes per register visit, lane offset off = 1.
  x1  = message XOR mask                                  [layer 1/2: XOR + interleaved LFSR mask]
  x2  = 8-byte lane transpose of x1 (row-major write, column-major read)   [layer 3]
  x3  = SPIN: each fixed 16-byte span of x2 left-rotated by XK = 13        [layer 4 NEW]
  ct  = x3 XOR WASH, WASH = the 16-byte cleartext header repeated          [layer 5 NEW]
  packet = header(16) + ct

Header (16 bytes, cleartext): [0:4] magic "RDRX"; [4] version 2; [5] lane offset off; [6] burst length b; [7] beacon degree Lb; [8:12] beacon tap bitmask LE (bits 5 and 23); [12] MODE byte 0xAA; [13] SPIN key 13; [14] WASH/flavour byte 0x5C; [15] checksum = (sum(header[0:15]) XOR 0xA5) & 0xFF. The MODE byte is a red herring on this capture: the live net always uses the fixed schedule above, so the spec's claim that MODE 'selects the live interleave schedule' is one of its false statements — a solver must notice MODE does not change the decode.

--- Step 1: parse the header ---
Read radio_packet.bin[:16]. Verify magic and the checksum ((sum of first 15 bytes XOR 0xA5) & 0xFF == byte 15). Extract off=1, b=5, Lb=23, taps from the LE bitmask = {5,23}, XK=13.

--- Step 2: recover the mask from the known-plaintext sample ---
keystream_sample.bin[:15] is header[:15] XOR mask[:15]; bytes [15:64] are zero-filled (lost) and must be ignored, NOT unmasked. Unmask the first 15 bytes, then de-multiplex them with r = (i // b + off) mod 3 where i is the index in the un-masked stream and b=5. This splits them across three lanes (the last, partial burst covers lane index (2+1)%3).
  * Lanes R0 and R1 (deg 11 and 13): feed the recovered lane bits (MSB-first per mask byte) to Berlekamp-Massey to get the LFSR feedback polynomial, then extend the sequence to the number of mask bytes each lane must emit over the whole packet.
  * Lane R2 / beacon (deg 23): too few known bits for BM, so solve it as a linear system over GF(2): build the degree-23 state-output matrix from the published taps {5,23} and solve for the 23-bit seed that reproduces the known beacon-lane bits. This is the one register the header fully describes.
Re-multiplex the three regenerated streams with the same schedule to rebuild the full mask for len(ct) bytes.

--- Step 3: peel the two new header-keyed wraps ---
Remove WASH first: ct XOR (header_[0:16] repeated to len(ct)) => x3. Then remove SPIN: for each 16-byte span of x3, right-rotate by XK = 13 (inverse of the transmitter's left-rotate) => x2.

--- Step 4: undo the lane transpose and XOR ---
Invert the 8-byte lane transpose (the write was row-major into 8-byte rows, the read was column-major): for n bytes, block count = ceil(n/8); dst position p maps from wire index perm[p] = (p // block_count)*? — concretely, wire index for output p is (p % 8) * blockcount + (p // 8) adjusted for the ragged tail; implementing the inverse permutation and applying it to x2 yields x1. Finally x1 XOR mask = plaintext message.

--- Step 5: read the payload ---
The plaintext is LSPD dispatch chatter containing 'DECODED PAYLOAD >> ' + the flag + ' << TX END'. Extract FTA{...} => FTA{lfsr23_b3rl3k4mp_m4ss3y_r4d10}.

--- TRAP 1 — decoy flag found first (legacy_burst.bin + OPERATOR_NOTE.txt) ---
legacy_burst.bin is a raw burst with NO sync header, generated by a superseded four-register net (R0 [11,5]/0x05EE, R1 [13,7]/0x1F1E, R2 [17,9]/0x1234, R3 [23,9]/0xDEAD), burst 4, offset 0, then an 8-byte lane transpose and no spin/wash. Driving it exactly with the SIGNAL_SPEC.txt FIELD-INTEL block (the OPERATOR_NOTE tells you to do precisely this, and to submit the result) reproduces an entire plausible transmission whose payload is the well-formed DECOY flag FTA{l1n34r_f33db4ck_b34c0n_f4k3}. A naive solver stops here. It is wrong. SIGNAL_SPEC.txt also carries a second stale fragment FTA{lfsr_is_not_a_public_key_23} ('do not submit'). Only the three-register net actually matches the sync header on radio_packet.bin.

--- TRAP 2 — dead-end branch (branchB_candidate.bin) ---
OPERATOR_NOTE.txt claims the analyst 'carried the recovered mask onto radio_packet.bin but trusted the FIELD-INTEL beacon taps, and dumped the result to branchB_candidate.bin'. Decoding the live packet with the WRONG beacon taps {17,9} (and the wrong degree 17 that follows from them) reproduces branchB_candidate.bin exactly. Its output is structurally valid — ~79% printable dispatch text — but the beacon lane is regenerated under the wrong register, so roughly every fifth byte group is unrecoverable garbage. It looks like progress and never resolves; the flag is not in it (asserted). The correct path ignores the FIELD-INTEL taps and uses the header's {5,23}.

--- TRAP 3 — canary advertising the wrong method (OPERATOR_NOTE.txt + FIELD-INTEL block) ---
OPERATOR_NOTE.txt and the '(FIELD-INTEL, UNVERIFIED)' block in SIGNAL_SPEC.txt openly advertise the wrong next step: trust the four-register legacy parameters, submit the legacy payload, treat the sync header as 'new-firmware noise', ignore branchB_candidate.bin as a mere dead end, and (explicitly) 'do not waste time re-deriving R0/R1'. That instruction is the bait — the legacy net does not decrypt the live packet. Detect: the note's claimed decoy flag differs from the payload the header-consistent decode yields, and the note contradicts SIGNAL_SPEC's own caveat that the FIELD-INTEL block 'reproduced the legacy burst but NOT a current-net header'. Avoid: trust only the cleartext header + the known-plaintext sample, and re-derive every register.

--- Why an AI solver struggles ---
(1) The most prominent narrative (the analyst note + FIELD-INTEL spec block) leads to a complete, well-formed DECOY flag, so a greedy solver submits trap 1 immediately. (2) The secondary artifact (branchB_candidate.bin) is byte-identical to a real decode attempt with the wrong taps and looks like readable traffic, so it reads as near-success, not failure. (3) The two extra header-keyed wraps (SPIN, WASH) and the unused MODE byte mean there is no independent shortcut: a correct mask with the wrong wrap undoes to stable-looking garbage, and the spec's own statements about MODE are false. (4) Nothing reduces to a single formula — the solver must combine a KPA header, BM on two lanes, a GF(2) solve on the third, a header-keyed span rotation, a header-keyed wash, and a lane transpose, in the right order, driven only by the cleartext header.

Verification (run from d:\ctf\FLAG_THEFT_AUTO_FINAL\rebuild_workspace):
- python gen_m04.py -> writes keystream_sample.bin, radio_packet.bin, SIGNAL_SPEC.txt, OPERATOR_NOTE.txt, legacy_burst.bin, branchB_candidate.bin; asserts the real flag is in no artifact and the decoy != real.
- python solve_m04.py -> '[M04] PASS -> FTA{lfsr23_b3rl3k4mp_m4ss3y_r4d10}'.
- python validate_m04.py -> VALIDATE OK (solver PASS; header CRC ok; wrong-flag rejected='FTA{lfrr23_b3rl3k4mp_m4ss3y_r4d10}'; wrong lane offset / wrong beacon taps / skip-WASH / skip-SPIN / wrong SPIN key all rejected; dead-end artifact == the genuine wrong-taps branch, 79% printable, no flag; legacy burst decodes to the decoy flag via the FIELD-INTEL method; real flag in no artifact).

### Progressive hints (shown in CTFd)

1. Three generators take turns in fixed-length bursts, and both the starting lane and the burst length are readable in the cleartext sync header of radio_packet.bin — read the header before you de-multiplex. Do not trust SIGNAL_SPEC.txt as a whole: it mixes genuinely captured fields with an (FIELD-INTEL, UNVERIFIED) block that describes an older burst from a superseded firmware revision, and the analyst's note steers you straight at that older net.
2. keystream_sample.bin is a known-plaintext prefix: the leading bytes are header XOR mask, and the recorder then zero-filled the tail, so bytes [15:64] are LOST and must not be fed back as if they were header. The two small lanes yield to Berlekamp-Massey; the largest register is too big for that from this little data and must be reconstructed as a small linear output system over GF(2) using the taps the header publishes.
3. The XOR is not the last step: after masking the transmitter wraps the frame twice more, both wraps keyed off the cleartext header (so a wrong header value or the wrong taps produces a frame that still looks well-formed but will not decode), and a fixed-width lane interleaver sits underneath. Undo those transforms before you XOR the mask, and treat any path that hands you a confident, well-formed answer early — and any note telling you to stop re-deriving the small registers — as a trap.

---

## M05 · Debugging the Dispatch — 100 points

**Category:** Programming | **Location:** Lester's Hideout  
**Correct flag:** `FTA{c0ncurr3ncy_r4c3_d15p4tch_f1x}`  
**Required evidence:** `broken_dispatch.py`, `dispatch_packets.json`, `README.txt`, `recovery_note.txt`

### Solving procedure

Organizer walkthrough of M05 'Debugging the Dispatch' (medium; deepened). Shipped package in challenges_rebuilt/MEDIUM/M05: broken_dispatch.py (raced node), dispatch_packets.json (1200 tagged packets), README.txt (honest data-flow manual), recovery_note.txt (a deliberately lying canary). The real flag FTA{c0ncurr3ncy_r4c3_d15p4tch_f1x} appears in no shipped artifact.

PEEL ORDER (flag <- artifact):
  flag <- stage3_decode <- wrap_decode <- extra_unwrap(key) <- gate(key) <- (R0 XOR R1) <- stage2(lane0, lane1) <- unmask outer <- b85/zlib/json.

STEP 1 -- RUN THE NODE, SEE THE RACE. broken_dispatch.py reads dispatch_packets.json into ONE FIFO queue, starts 8 threads behind a threading.Barrier, and each worker drains the queue. DispatchNode keeps THREE shared process-wide structures: self.lanes (per-lane tally dict), self.ledger (running 64-bit sum of cleared tags), self.mix (running 64-bit hashed tally, seeded 0x123456789ABCDEF0). clear_packet() snapshots all three (lane tally, acc=ledger, mx=mix), publishes to a trace, THEN commits all three with non-atomic read-modify-writes. With sys.setswitchinterval(1e-6) the interleaving drops updates, so seal() writes a manifest whose dispatched count and/or ledger/mix are short. out.bin = base85(zlib(json(manifest))) and is reliably wrong (validator confirms 8/8).

STEP 2 -- REPAIR THE NODE (ground truth). The intent is 'clear every packet exactly once'. Either wrap the whole snapshot+commit in a single threading.Lock (the reference solver does this), or compute directly from the log:
  dispatched = 1200
  ledger = (sum(p['tag'] for p in packets)) & (2**64-1) = 18405489353859530566
  mix = (0x123456789ABCDEF0 + sum(splitmix64(p['tag']) for p in packets)) & (2**64-1) = 13199405904029897168
Note the mix is a COMMUTATIVE hashed tally (it ADDS splitmix64(tag) rather than rotating-folding), so a lock-only repair reproduces it deterministically regardless of commit order -- this is deliberate, see trap 2 notes below.

STEP 3 -- UNMASK THE EMBEDDED PROGRAMS. The correct triple yields:
  digest = seal_digest(ledger, mix, dispatched)   # h=ledger; h^=splitmix64(mix ^ 0xA5A5...); h^=splitmix64(dispatched ^ 0x5A5A...); return splitmix64(h)
  key    = derive_key(ledger, mix, dispatched) = splitmix64(digest ^ 0x0D15A7C4C0DE0000) = 0x518e25f4fd0cf06d
Each of manifest['stage2_b64'] and manifest['assemble_b64'] is a base64 blob XOR-'scrambled' with ks64(digest, len) (a 64-bit LCG keystream, out=(h>>33)&0xFF). XOR them back with ks64(digest, len) to recover stage2.py and assemble.py.

STEP 4 -- FIX THE RECONCILER (stage2.py; FOUR independent bugs). It unmasks two lane records SEALED0/SEALED1 with ks32(signature ^ salt), where signature folds the fixed TAGS list through rotl32(.,7), xor>>16, *0x9E3779B9 -- all 32-bit unsigned. Shipped defects:
  (a) rotl32 lacks the 32-bit overflow mask -> 'h = rotl32(h,7)' returns an oversized int and the 32-bit identity breaks. Fix: mask the rotate result with 0xFFFFFFFF.
  (b) extract_record parses the length little-endian at offset 3: 'n = int.from_bytes(plain[0:2],"little"); body = plain[3:3+n]'. The record is big-endian at offset 2: 'n = int.from_bytes(plain[0:2],"big"); body = plain[2:2+n]' and the trailer lives at plain[2+n:6+n].
  (c) alignment 'correction': 'span = n + 1 if (n & 3) == 0 else n' reads the trailer ONE byte late whenever the record length is a multiple of 4. Every base64 payload (and therefore every record here) has n%4==0, so the trailer bytes are misread and the check fails. Fix: span = n always.
  (d) CARRIED-STATE DEFECT across the two invocations: 'signature(tags)' reseeds from 0x1BADB002 on every call, but lane 1 is meant to CONTINUE the signature lane 0 produced. Fix: h0 = fold(TAGS, 0x1BADB002); h1 = fold(TAGS, h0) and use (h0 ^ SALT0) / (h1 ^ SALT1) as the two keystream seeds. This is the bug that ONLY shows on the second lane: a single-pass test of lane 0 succeeds and misleads.
With all four fixed, run() returns R0 (88 bytes) and R1 (88 bytes) -- the two lane payloads.

PARTIAL-FIX TRAP (trap 2). Repair (a) and (b) but leave (c): every trailer check trips, the shipped main() catches the ValueError and prints ARCHIVED_VALUE = FTA{d15p4tch_l3g4cy_p4th_d3c0y} followed by ARCHIVED_REWARD_B64, a base64 blob that decodes to the well-formed decoy FTA{4rch1v3d_r3c0rd_4cc3pt3d_as_truth}. That path looks like a rewarding finish and is entirely fake. Leaving only (d) wrong is worse: both lanes decrypt (the trailer still matches) but lane 1 is seeded from the constant, so the combination is structurally valid garbage that defies decoding -- a dead end that looks like progress.

STEP 5 -- ASSEMBLE (assemble.py) AND REVEAL. With key and the two lane payloads:
  dispatch = R0 XOR R1                    # the gated dispatch value W (88 bytes)
  inner    = gate(dispatch, key)          # XOR dstream(key ^ 0x61E7A11, len)
  wrapped  = extra_unwrap(inner, key)     # XOR dstream(key ^ 0xE47A5EED) then byte-rotate-right by (key & 7)
  s3       = wrap_decode(wrapped)         # base64-decode then XOR fixed rotating THIRD_KEY=(5A C3 77 21)
  flag     = stage3_decode(s3)            # rotating XOR (ROT_SEED=0x9E3779B9) then run-length expansion (pairs value,count)
Result: FTA{c0ncurr3ncy_r4c3_d15p4tch_f1x}.

EXTRA LAYERS vs the old design (+2 minimum): (i) a keyed GATE above the payload, and (ii) an extra keyed WRAP (byte-rotate + keystream) beneath it -- both keyed on the sealed triple so there is no independent shortcut; plus the two-run XOR requirement (neither lane alone yields the flag) and the cross-invocation state-carry bug.

TRAPS (>=3, validator asserts each fires):
1. Decoy flags a naive/automated solve finds FIRST -- recovery_note.txt carries FTA{4rch1v3d_s33d_1s_n0t_4_k3y}; the manifest 'notes' field carries FTA{v01d_s3gm3nt_n0t_d15p4tch3d}; the partial fix prints FTA{d15p4tch_l3g4cy_p4th_d3c0y} and a reward blob decoding to FTA{4rch1v3d_r3c0rd_4cc3pt3d_as_truth}. A grep for FTA{...} returns a well-formed flag immediately.
2. Dead-end branch (wrong key/order) with structurally valid, unrecoverable garbage -- un-chained lane 1, or feeding one lane twice, produces output that survives the trailer check but never decodes to the flag.
3. Canary / bait artifact -- recovery_note.txt openly advertises a WRONG method (use the archived seed 0xDEADBEEFC0FFEE01; a single pass is enough; combine lanes with OR, not XOR). Every one of those claims is false.

VERIFIED from rebuild_workspace: `python gen_m05.py` -> wrote MEDIUM/M05; `python solve_m05.py` -> [M05] PASS -> FTA{c0ncurr3ncy_r4c3_d15p4tch_f1x}; `python validate_m05.py` -> M05 VALIDATE OK (8/8 race visible, wrong flag rejected, both lane runs required, partial fix lands on ARCHIVED_VALUE + decoy, traps present, real flag absent from every artifact, 100003 bytes total).

### Progressive hints (shown in CTFd)

1. Start with the node itself, not the note. Run it, watch the numbers it reports, and run it again: a dispatch whose totals drift between runs, or fall short of the freight log, has not finished its work. One clean pass must clear every packet exactly once and balance both the reported count and the running ledger against the log.
2. The out.bin manifest is a sealed container; the two programs inside cannot even be read until the node's final, correct triple is known. Repairing the node is therefore a prerequisite, not the puzzle. And once unmasked, the reconciler is still wrong in several independent ways, with its second lane derived from the first -- a single pass will look convincing and still disagree.
3. Treat any flag you meet early as bait until it survives the ENTIRE chain. The reconciler's fallback path, the manifest notes and the operator's note all offer a confident, well-formed answer; none of them is the dispatch value. The real value only appears when both lane runs are combined with the sealed triple, and it is wrapped one layer deeper than the reconciler implies. If your last step produced a flag without both lanes and without the sealed triple, you are holding a decoy.

---

## H01 · Zancudo Deadbolt — 160 points

**Category:** Reverse engineering | **Location:** Fort Zancudo Military Base  
**Correct flag:** `FTA{z4nclud0_vm_d34db0lt_unl0ck}`  
**Required evidence:** `zancudo_gate`, `OPERATIONS.txt`, `ENGINEER_NOTE.txt`

### Solving procedure

ORGANIZER WALKTHROUGH (H01 · Zancudo Deadbolt)

Shipped artifacts: `zancudo_gate` (stripped Linux x86-64 ELF), `OPERATIONS.txt` (neutral interface notes), `ENGINEER_NOTE.txt` (the bait canary). The accepted passphrase is exactly `FTA{z4nclud0_vm_d34db0lt_unl0ck}` and is never stored verbatim; neither decoy is stored verbatim (both are XOR-masked in .rodata).

--- 0. Recon ---
`file`/`readelf` show a stripped, dynamically linked ELF, no symbols, no plaintext. `strings ... | grep FTA` returns nothing (confirm this — if it ever returns a hit, the anti-leak assertion in gen_h01.py has regressed). The interesting data are eight magic-tagged blobs in .rodata: ZCFG, ZXT1/ZXT2/ZXT3, ZVM1/ZVM2/ZVM3, ZDVL. The magics are ASCII and never contain "FTA".

--- 1. Layer: anti-analysis (SIX gates) — detect and avoid ---
trap_check() runs before anything else; ANY hit diverts to fake_success() and returns exit 0.
  A. PTRACE_TRACEME fails (EPERM) when the process is already traced.
  B. /proc/self/status TracerPid must be 0.
  C. Wall-clock timing probe: 200k-iteration loop; >500 ms ⇒ traced (a debugger pausing/single-stepping blows past it).
  D. Parent-process-name check: /proc/<ppid>/comm and /proc/<ppid>/cmdline are scanned against a blocklist {gdb, lldb, strace, ltrace, valgrind, radare2, r2, rr, frida, ghidra, pwndbg, gef, dlv, ida, winedbg, sprocket, x64dbg, windbg}.
  E. RDTSC cycle-delta probe: a 40k-iteration dependent multiply chain timed with RDTSC; a delta > 40,000,000 cycles ⇒ traced (honest runs stay far below; note this also catches single-stepping in emulators).
  F. Software-breakpoint scan: the first 3 bytes of the noinline `bp_probe` are checked for 0xCC (INT3); plus /proc/self/maps is scanned for the substring "frida". A patched INT3 at the probe entry or an injected hook trips this.
Detection (for the solver): run the binary plain. If it prints "== ZANCUDO DEADBOLT RELEASED ==" together with a passphrase while you were NOT solving anything (i.e. while under a tracer or after patching), that is Trap 1 — a decoy. To avoid: never attach a tracer, never patch an INT3 into the probe, never inject a library, and keep the run fast/idle. The reference solver deliberately does static recovery in Python and only invokes the live binary once, untraced, with the confirmed passphrase.

--- TRAP 1 — fake success path (well-formed decoy flag) ---
fake_success() prints the release banner plus decoy1, XOR-0xA7 masked in .rodata: FTA{z4nclud0_d34db0lt_r3l34s3}. It is structurally valid and its exit code is 0, so a cheating/automated solver that runs under instrumentation submits a plausible-but-wrong flag. Detect: it appears whenever any of gates A–F fires; also its value differs from the real flag. Avoid: re-run untraced, and treat any passphrase the station "volunteers" as hostile.

--- TRAP 2 — ZANCUDO_SERVICE dead-end branch ---
If the env var ZANCUDO_SERVICE is set, main() calls service_dump() instead of the real checks. It deliberately derives the vault key with a WRONG length guess (31), decrypts the .rodata vault, and prints a "maintenance key-schedule dump (rev 3)" of 128 pseudo-random-looking bytes followed by decoy2 (XOR-0x5C): FTA{z4nclud0_s3rv1c3_schedul3_dump}, then "disposition: RELEASED (service override)". It is structurally valid (proper banner, hex grid, a well-formed flag) but unrecoverable garbage — it is decrypted under the wrong key, so it can never match the real vault, and its flag is a decoy. Detect: the env-gated branch is a dead end; the schedule bytes never satisfy the real checks. Avoid: never set ZANCUDO_SERVICE; do not trust the "recovered-service-phrase".

--- TRAP 3 — ENGINEER_NOTE.txt canary ---
ENGINEER_NOTE.txt openly advertises the wrong method: it tells the reader to run `ZANCUDO_SERVICE=1 ./zancudo_gate AAAA...AAAA` and claims the printed phrase (decoy2) is "the authoritative release key, no decompiler required", and that the crew warnings about "answers of its own" are obsolete. It exists to bait an AI/naive solver into Trap 2. Detect: it contradicts OPERATIONS.txt's own warning ("treat that answer with suspicion"). Avoid: ignore the note's claimed shortcut entirely.

--- 2. Layer: chained virtual machines (THREE stages) ---
Each VM is a bytecode interpreter with a control-flow-flattened dispatcher (state machine FETCH/DECODE/EXECUTE with states 0/1/4) and opaque predicates built on a volatile g_guard (reads 0). Opcodes are translated per-VM via g_xlat1/2/3 (256-byte byte→internal-op tables). VM blobs are stored as [magic][u16 len][bytecode] at offset +6.
  Stage 1: run VM1 with xlat1 ⇒ v1 = 0x1DB0F3CA.
  Stage 2: VM2's at-rest bytecode is masked with v1^0x9E3779B9 (4-byte-period XOR). Unmask, run with xlat2 ⇒ v2 must equal VM_CTX = 0x0FF1CE42 (read from ZCFG+8); otherwise the binary prints "firmware integrity fault 0x0B0LT" and exits 4.
  Stage 3: VM3's at-rest bytecode is masked with v2^0x85EBCA6B. Unmask, run with xlat3 ⇒ v3 must equal VM_CTX3 = 0x0DEAD133 (from ZCFG+16); else "firmware integrity fault 0x0DEAD" and exit 5.
Key design point: VM2 cannot be decoded without v1 and VM3 cannot be decoded without v2, so no single blob can be decompiled independently — the chain must be executed in order.

--- 3. Layer: runtime-derived vault key + two-pass decryption ---
ZCFG also carries C = 0x7F4A7C15 and the default env byte 0x5B. The vault key is:
  seed = splitmix64( C ^ (len * 0x9E3779B97F4A7C15) ^ (env<<33) ^ (v1<<7) ^ v2 ^ (v3<<17) )
where len = strlen(passphrase) and env = first byte of $ZANCUDO_ENTROPY or the default. The ZDVL vault is decrypted with a TWO-pass XOR keystream: an xorshift64 stream seeded by `seed`, XORed with a second xorshift64 stream seeded by seed2 = splitmix64(seed ^ (v3 * 0x2545F4914F6CDD1D) ^ 0x9E3779B97F4A7C15). Static dumping of .rodata therefore yields ciphertext only; the second pass is keyed by VM3's result, tying decryption to the VM chain.

--- 4. Layer: length brute-force (the length is part of the key) ---
Vault plaintext layout: [u32 need][SBOX 256][K need][T need][u32 fnv][u32 hmix][u32 crc][u32 pos][pad], CIPHER_LEN = 676. For each Ltry in 1..MAXLEN, derive seed(Ltry), two-pass decrypt, and accept the Ltry whose first u32 == Ltry AND whose 256-byte SBOX slice is a permutation of 0..255. This combination is unique (gen_h01.py asserts hits == 1); the true length is 32.

--- 5. Layer: FIVE-transforms passphrase check + inversion ---
The binary checks six layers; the last five are the actual byte gates (layer 0 is the implicit length-in-key):
  1. Length gate: need == len, need <= MAXLEN.
  2. FNV-1a checksum of the input == stored.
  3. Non-linear byte map: for each i, (SBOX[in[i]] * K[i]) mod 251 == TARGET[i]. 251 is prime and every K[i] != 0, so it inverts: r = TARGET[i] * K[i]^-1 mod 251, then the unique b with SBOX[b] % 251 == r (gen_h01.py guarantees no accepted byte resolves ambiguously; a second pre-image needs r <= 4).
  4. HMAC-like mixing gate hmix(input, seed) == stored.
  5. CRC-style gate (reflected poly 0xEDB88320) salted with v3 ^ CRC_XOR (CRC_XOR = 0x13579BDF) == stored.
  6. Order-dependent rotate/xor gate gate_pos(input, seed) == stored.
Gates 2/4/5/6 are independent cross-checks: only the one true byte string satisfies all of them, so a partial reversal is caught immediately.

--- 6. Final ---
Invert layer 3 to recover the bytes, cross-check layers 2/4/5/6, and you get the operator passphrase: FTA{z4nclud0_vm_d34db0lt_unl0ck}. Confirm against the live binary with `env -u ZANCUDO_ENTROPY -u ZANCUDO_SERVICE ./zancudo_gate '<flag>'` — it must print the release banner and exit 0. The reference solver (solve_h01.py) performs exactly this static path and prints the flag; validate_h01.py re-derives it, checks that both decoys are rejected as wrong passphrases, exercises both traps (debugger-parent ⇒ decoy1; ZANCUDO_SERVICE ⇒ schedule dump + decoy2), and asserts no plaintext flag appears in any artifact.

### Progressive hints (shown in CTFd)

1. The station fights being watched. Attach a debugger, set a breakpoint, single-step it, or run it under a tracer and it will print a confident release with a passphrase of its own — treat that answer with suspicion. Think about what an honest, untraced run looks like versus an observed one before you trust anything it says.
2. There is more than one virtual machine behind those flattened dispatchers, and they are chained: a later stage cannot even be decoded until the stage before it has actually run. Do not expect any single blob to be self-contained, and do not expect the description on the tin to match the truth.
3. The passphrase length is itself part of the key, so the right length is not given to you — you have to find it. The vault carries several independent consistency checks that only agree for the one true byte string; use them to prove you found the right length and the right bytes rather than guessing.

---

## H02 · The Recursive Freeway — 160 points

**Category:** Algorithms | **Location:** Final Getaway  
**Correct flag:** `FTA{sp3ctr4l_fr33w4y_gr4ph_150m0rph}`  
**Required evidence:** `junctions.json`, `template.json`, `PROTOCOL.md`

### Solving procedure

Full stack, in the order a solver meets it.

(0) SURFACE. template.json is a weighted 12-node ring: the cycle (0,1),(1,2),...,(11,0) plus three chords (0,3),(0,6),(1,8); weights are drawn from {1,2,3}. junctions.json is a 2500-node, 5000-edge weighted network in which EVERY node has degree exactly 4 (near-regular), so any degree-based filter prunes nothing. Each junction carries a 1-3 character label fragment.

(1) TOPOLOGY. An induced-subgraph isomorphism search (networkx GraphMatcher(J, T).subgraph_monomorphisms_iter()) returns SIX districts: the real district, a scaled dead-end, and four single-weight near-misses (each changes one edge weight). The three edge-decoys (one edge removed) drop out at this stage. Topology alone leaves six candidates.

(2) INVARIANT A - weighted normalised Laplacian spectrum. For a candidate build A (12x12, A[i,j]=w), d = row sums, L = I - D^(-1/2) A D^(-1/2); take eigenvalues ascending and round to 4 dp. The blueprint fingerprint is (0.0, 0.1855, 0.256, 0.5402, 0.6982, 0.9835, 1.0492, 1.2366, 1.4622, 1.7925, 1.8397, 1.9565). Exactly TWO districts match it. PROTOCOL.md asserts this is the only uniqueness test - that is the TRAP 3 lie; it is necessary but NOT sufficient.

(3) WHY TWO SURVIVE (the dead end, TRAP 2). The second survivor is a district whose every edge weight is doubled (x2). Normalisation divides out the degrees, so scaling all weights by a constant leaves L unchanged - identical spectrum. It is topologically and spectrally indistinguishable from the real district under invariant A. A solver who stops here assembles a token from the wrong district and fails.

(4) INVARIANT B - weighted spanning-tree count tau. Build the weighted Laplacian Lap = diag(d) - A and take the cofactor det(Lap[:-1,:-1]) (Kirchhoff); this is the weighted number of spanning trees. tau is NOT scale-invariant: tau(2W) = 2^(n-1) tau(W), so doubling every weight multiplies tau by 2^11 = 2048. The blueprint tau is 120712; the scaled dead-end tau is 120712*2048 = 247218176. Only the true district matches 120712 -> a unique district.

(5) DERIVATION - the real reading order. Read the matched district's twelve labels in a TWO-KEY spectral order: principal eigenvector of the weighted adjacency A (weighted eigenvector centrality, sign-fixed positive) DESCENDING, rounded to 4 dp, ties broken by the Fiedler vector (2nd eigenvector of the normalised Laplacian) ASCENDING. The blueprint was chosen so two junctions share the same 4-dp centrality, so a single-key order mis-orders them. Two-key order -> junction sequence [768, 1031, 1339, 115, 195, 240, 402, 436, 511, 1567, 1625, 2227] -> body 'sp3ctr4l_fr33w4y_gr4ph_150m0rph' -> flag FTA{sp3ctr4l_fr33w4y_gr4ph_150m0rph}.

TRAPS - how to detect and avoid each:
  * TRAP 1 (naive decoy flag). The twelve fragments are the SAME pieces the generator re-orders, and junction ids are relabelled so that reading the TRUE district's labels in ascending junction-id order spells FTA{fr33w4y_gr4ph_sp3ctr4l_150m0rph} - a well-formed WRONG flag. Naive/automated pipelines, and anyone following the field note, print this FIRST. Detection: the claimed 'ascending id' order is fiction; the correct order is spectral.
  * TRAP 2 (dead-end district). The scaled district (all weights x2) passes invariant A but fails invariant B (tau x2048). Read in its own correct spectral order it spells FTA{sp3ctr4l_gr4ph_fr33w4y_150m0rph} - a second well-formed WRONG flag. Detection: apply invariant B.
  * TRAP 3 (bait spec). PROTOCOL.md carries a 'RECOVERED FIELD NOTE (crew 5)' that (a) claims the normalised-Laplacian spectrum is the ONLY uniqueness test and other invariants are folklore, and (b) instructs the reader to output the matched district's labels in ascending junction-id order. Both claims are false; following either yields TRAP 1 or the dead end. Detection: verify uniqueness independently (invariant B) and never trust an embedded note that removes the discriminator.
  * Secondary trap. Ordering by centrality alone (single key) leaves the 4-dp tie unbroken and yields the malformed token FTA{sp3ctr4l_fr33w4y_gr4ph_m0r150ph}. Detection: the two-key tie-break.

HUMAN SOLVABILITY. Everything needed ships in the three files. A skilled analyst (i) runs the documented topology + fingerprint test, (ii) notices a second district survives and reaches for an independent invariant, (iii) recognises the dead end as a uniform rescale and picks a scale-sensitive weighted invariant (spanning-tree count is the natural one), and (iv) resolves the ordering tie with a second spectral key. No network access or guessing is required.

### Progressive hints (shown in CTFd)

1. Degrees will not help you - every junction has the same degree, so degree filtering is a decoy. Edge weights and local structure are your only pruning tools.
2. A single spectral signature is not a unique key here: more than one district clears the weighted normalised-Laplacian fingerprint in PROTOCOL.md, and one of the near-correct districts is a clean scaled copy of another - normalisation is blind to a global rescaling of every edge weight, so reach for a second weighted invariant that a uniform scaling would actually change and check it against the blueprint before trusting a match. Any note insisting no second check is needed is a decoy.
3. The field note in PROTOCOL.md is not trustworthy: the true reading order is not junction-id order. The order is fixed by the district's own spectrum, and two fragments sit in a four-decimal dead heat, so a single spectral key will mis-order them.

---

## H03 · Impound Evidence Matryoshka — 160 points

**Category:** Multi-stage forensics | **Location:** Los Santos Police Department  
**Correct flag:** `FTA{m4try0shk4_f1v3_l4y3rs_c4rv3d}`  
**Required evidence:** `impound_camera.png`, `EVIDENCE_NOTE.txt`, `RECOVERY_INSTRUCTIONS.txt`

### Solving procedure

Organizer walkthrough of H03 (9 shells, strictly ordered; every key flows down from the shell above). Shipped: impound_camera.png (carrier), EVIDENCE_NOTE.txt (honest method), RECOVERY_INSTRUCTIONS.txt (a deliberately lying 'official' card).

S1 GEO GATE (EXIF GPS -> MASK). The PNG EXIF holds GPS lat 34 deg 03 min 07.92 sec N and lon 118 deg 14 min 37.32 sec W. Decimal: lat 34.0522, lon 118.2437. CODE = pad5(round(abs(lat)*10000) mod 100000) + pad5(round(abs(lon)*10000) mod 100000) = '40522' + '82437' = '4052282437'. The tEXt chunk 'gate.card' is HEX of GATE_NONCE(16) || AES-256-CTR ciphertext. Key = PBKDF2-HMAC-SHA256('GEO-4052282437', salt 'impound-geogate-7', 100000 iters, dkLen 32); the blob's first 16 bytes are the initial counter. Decrypt -> 16-byte MASK = 5c3fb17e02d49a6f8e1c70b3d5a2f490. MASK is used twice later: to unmask the Shell-2 payload AND as the Shell-5 GCM AAD.

S2 GATED + MASKED LSB. 2 least-significant bits are stored in every RGB channel; pixels are scanned COLUMN-MAJOR (down a column, then the next column right), channels R,G,B. A slot is numbered by its 0-based position in that scan; ONLY slots where (i mod STRIDE == OFFSET) carry the real payload, every other slot repeats a BAIT string (so a blanket LSB dump yields junk). STRIDE/OFFSET are not in the image; derive them from Shell 7's frequency table: D = row count = 67, T = sum of counts = 696, STRIDE = (D mod 7) + 2 = 6, OFFSET = T mod STRIDE = 0. Read the selected slots MSB-first: first 4 bytes = big-endian LEN, remaining LEN bytes are MASK-masked; unmask with plain[j] = masked[j] XOR MASK[j mod 16]. Output = TAG(16) || CTR_BLOB, where TAG = a17f0c3d9b452e6812c4a90f73e1d5b8.

S3 AES-256-CTR (CODE -> BADGE). Key = PBKDF2-HMAC-SHA256('IMPOUND-4052282437', salt 'lspd-impound-2026', 100000, 32). CTR_BLOB = counter(16) || ciphertext; decrypt -> BADGE = 'VAULT-K9-4471'.

S4 TRAILING ZONE: TWO ARCHIVES. After IEND is a scratch sector dump, then two legacy ZipCrypto archives. The decoy block delimited by --#EVIDENCE-BAG--# ... --#BAG-END--# is opened by the PUBLIC password 4471 (printed on its own manifest) and only yields bait. The real block delimited by --#VAULT-BEGIN--# ... --#VAULT-END--# is opened by the BADGE recovered in Shell 3. Inside the vault: layer4.bin (real cargo, an AES-GCM blob) and bait.txt (ignore).

S5 AES-256-GCM (nonce from Shell 2, AAD from Shell 1). layer4.bin = ciphertext || tag(16). Key = PBKDF2-HMAC-SHA256(BADGE + ':' + CODE, salt 'evac-vault-7731', 100000, 32). GCM nonce = SHA256(b'gcm' || TAG)[:12]. AAD = MASK (supplying the wrong mask fails the tag check). Plaintext is a second PNG: a black/white MTX-1 matrix.

S6 MTX-1 MATRIX (-> ROUTE_KEY | STREAM). 81x81 modules with a 4-module white quiet zone. Row 0 and column 0 are SYNC ladders (module i is BLACK iff i is EVEN); rotate the grid until both ladders match to fix orientation. Every module with x>=1 AND y>=1 carries one data bit, read ROW-MAJOR (y ascending, then x ascending), byte-aligned MSB-first: first 16 bits = big-endian length L, then L ASCII chars. The text is ROUTE_KEY || '|' || base64url(STREAM); split on the FIRST '|'. Here ROUTE_KEY = 'ROUTE-9F3A1C' (keys Shell 8).

S7 HUFFMAN (-> SEAL_TOKEN | SEALED_SOURCE). base64url-decode STREAM: first 16 bits = big-endian symbol count C, then C Huffman symbols read MSB-first (left edge = bit 0, right edge = bit 1), decoded with the note's frequency table. Rebuild the tree from frequencies ONLY: repeatedly merge the two lowest-frequency nodes; on a tie prefer the earlier-inserted node (leaves inserted first in ascending ASCII order, internal nodes in creation order). The text is SEAL_TOKEN || '|' || base64(SEALED_SOURCE); split on the FIRST '|'. Here SEAL_TOKEN = 'SEAL-7B2D04'.

S8 SEALED SOURCE (AES-256-CTR). SEALED_SOURCE = nonce(16) || ciphertext. Key = PBKDF2-HMAC-SHA256(ROUTE_KEY, salt 'matryoshka-seal', 100000, 32); the first 16 bytes are the initial counter. Plaintext is Python source.

S9 RUN WITH THE SEAL. Execute the source passing SEAL_TOKEN as sys.argv[1]. It SHA256-hashes the token and, only for the exact SEAL_TOKEN, XOR-reconstructs and prints the true flag; any other token (or none) prints the decoy FTA{wr0ng_cl34r4nc3_t0k3n}. A correct run: python stage.py SEAL-7B2D04 -> FTA{m4try0shk4_f1v3_l4y3rs_c4rv3d}.

TRAPS (5):
1. decoy-metadata: the PngInfo 'flag' tEXt and an EXIF ImageDescription both carry well-formed decoy flags (FTA{l5b_pl41n_dump_b41t_7f}, FTA{3x1f_gps_tr4p_d3c0y}). A metadata scrape finds a 'flag' first. Detect/avoid: no metadata flag is the real one; it is not the same string the chain produces.
2. decoy-ZIP (valid container, looks like progress): the EVIDENCE-BAG archive is a VALID extractable ZipCrypto ZIP; its manifest.txt advertises recovered_flag=FTA{3v1d3nc3_b4g_4471_0p3n3d}, and a README inside pushes a wrong method. Detect/avoid: the public password 4471 does NOT open the real vault (the vault needs the derived BADGE), so the bag is bait.
3. canary-note: RECOVERY_INSTRUCTIONS.txt openly and confidently claims the PngInfo field is 'authoritative', that payload bytes should be XORed with 0x5A, and that STRIDE/OFFSET are 8/0. All three claims are wrong. Detect/avoid: trust the field note; the 'quick-cut card' is a lie.
4. blanket-LSB: dumping ALL LSBs with no gating and no mask returns the repeating bait string, never the payload.
5. token-gate: Shell 9 prints the decoy unless fed the exact SEAL_TOKEN, catching a solver who drops the token while peeling two shells down.

Following S1->S9 with the derived keys yields FTA{m4try0shk4_f1v3_l4y3rs_c4rv3d}.

### Progressive hints (shown in CTFd)

1. Read the recovered field note end to end before touching a single byte; it is the only honest description of the stack. The separate quick-cut card contradicts it, so decide which of the two is authoritative before you believe a 'flag'.
2. Not every artefact is real. A metadata field, a manifest inside one of the trailing archives, and an inner member all hand you flags that are not the answer. Two archives sit after the image's IEND marker and only one of them is opened by the value you derive from the picture. Treat any flag you find early as bait until it survives the entire chain.
3. The chain is strictly ordered and does not shortcut. The low-bit payload cannot be read without a mask and a stride/offset that are recovered from other shells, and the final program refuses to print the real flag unless it is handed the exact token recovered two shells above it. If your last step prints a flag without being given a token, you are looking at a decoy.

---

## H04 · LEGAL RAGGING — 160 points

**Category:** Cryptography | **Location:** Fleeca Bank  
**Correct flag:** `FTA{rs4_crt_f4ult_l3g4l_r4gg1ng}`  
**Required evidence:** `bank_gateway.py`, `guest.token`, `AUDIT_BRIEF.txt`

### Solving procedure

Call sign_debug on a fixed message to collect a correct and a faulty signature; un-blind each (sig_blind * r^-1 mod n) first. Faults land in p or q, so gcd(bad^e - m mod n, n) may return either prime — accept both and check p*q == n. Recover d, derive the live audit nonce one byte at a time via the verify_debug timing oracle, assemble ADMIN_MESSAGE with that nonce + a fresh timestamp, sign it as role 'admin', and submit to read the flag from the FTA_H04_FLAG environment variable. Decoys: a legacy signed token that verifies but is refused, and wrong leads in AUDIT_BRIEF.txt.

### Progressive hints (shown in CTFd)

1. The debug route blinds what it signs; undo the blinding before any faulty half becomes visible. It also faults rarely, and in either half.
2. The order must carry a nonce that only the second, timing-based route will reveal, and it changes every process.
3. A correctly-signed order under the wrong role — or with a stale/wrong nonce — is still refused. The brief's parameters are bait.

### Offline bonus hint (reward for the on-site physical task)

OFFLINE BONUS HINT (reward for the crew fitness check / equivalent logic task): The debug route faults in EITHER half, so never assume your gcd landed on p — check p*q == n and keep whichever prime falls out. If a gcd returns n itself (both halves faulted at once), throw that signature away and collect another. The timing route leaks the nonce one byte at a time against a candidate guess, so treat it as a yes/no per candidate byte instead of brute-forcing the whole value. The freshness window stated in AUDIT_BRIEF.txt is real — build and submit the order immediately after you sign it.

_Read this to the crew (or hand it over) once they complete the task. It is not imported into CTFd and does not deduct points._

---

## H05 · Last Ride Out — 160 points

**Category:** Multilayer cryptography | **Location:** Final Getaway  
**Correct flag:** `FTA{mult1_p4rty_3sc4p3_pr0t0c0l}`  
**Required evidence:** `intercept.bin`, `final_payload.enc`, `ESCAPE_PROTOCOL.md`, `FORMAT_SPEC.txt`

### Solving procedure

Parse the TLV transcript: shares A/B are bound (32B element + 16B tag = 48B) while C/D are reduced (bare 32B) and re-advertised. The agreement value is Y = XA^5 * XB^11 * XC^13 * XD^17 mod p; the key is K = HKDF(salt, Y, info||sid). Choose an attacker-known target and solve for the injected C share XC = (Y* * R^-1)^(13^-1 mod (p-1)). Confirm against record 0x0020 (0x0021/0x0022 are decoys), then AES-256-GCM decrypt final_payload.enc and finally AES-256-CBC the inner blob.

### Progressive hints (shown in CTFd)

1. More than three voices are on the line. Read the framing: some contributions carry a binding tag and some do not — the unbound ones are trusted.
2. The session secret is a weighted product of the contributions, not a sum; steering it means solving for a share value rather than picking one.
3. There are decoy key-confirmations. The real one sits between them, and the payload is nested twice.

### Offline bonus hint (reward for the on-site physical task)

OFFLINE BONUS HINT (reward for collecting and solving the paper riddle from the organizer desk): Exactly two of the four contributions ship REDUCED — a bare 32-byte element with no binding tag, re-advertised on the wire. Those are the two seats you can steer; the other two are bound (32-byte element + 16-byte tag) and already fixed, so F is a weighted product of one per-seat exponent applied in seat order and you only need to solve for a single reduced share's value. Pick a target session secret you can compute yourself, then invert that seat's exponent modulo (p-1): XC = (Y* · R⁻¹)^(13⁻¹ mod (p-1)). The genuine agreement confirmation sits between two decoys, and the payload is AES-GCM on the outside and AES-CBC on the inside.

_Read this to the crew (or hand it over) once they complete the task. It is not imported into CTFd and does not deduct points._

---

## E06 · Payphone Static — 50 points

**Category:** Steganography | **Location:** Little Seoul  
**Correct flag:** `FTA{p4yph0n3_st4t1c_dtmf_tr4p}`  
**Required evidence:** `payphone.wav`, `EXCHANGE.txt`

### Solving procedure

Split the WAV by silence into three DTMF blocks; discard block A (handshake). Block B is 6 digits = three (key,offset) pairs -> the 3-letter pad word via EXCHANGE.txt's 10x3 keypad; that word seeds SHA256(word+'payphone') as the keystream. Block C is the decimal form of zlib(flag) XOR keystream. Convert block C to bytes, XOR the keystream, zlib-decompress. Decoys: the LSB payload 'FTA{d34d_b34t_0n_th3_w1r3}' and EXCHANGE.txt's printed 'confirmed courier phrase'.

### Progressive hints (shown in CTFd)

1. A blanket DTMF decode concatenates three blocks and fails. A long dead interval separates a handshake from the operational traffic — discard everything before the double gap.
2. The handshake is bait, and so is the flag written into the sample's lowest bits. The real key is not a number: the operational block is a sequence of (key, offset) digit pairs read off the exchange's private pad.
3. The payload digits are one large decimal number. The key you assembled seeds a hash keystream (an XOR), and decompression is the very last step.

---

## E07 · Wanted Poster — 50 points

**Category:** Steganography | **Location:** Vinewood Hills  
**Correct flag:** `FTA{w4nt3d_p0st3r_hue_k3y_v1g3n3r3}`  
**Required evidence:** `wanted_poster.png`, `DEPUTIZE.txt`

### Solving procedure

Read the 'ciphertext' text chunk (or OCR the CIPHERTEXT line). Sample the bottom seal swatch row; hue bin int(hue/360*26) -> the keyword. Vigenere-decrypt the letters of the ciphertext with that keyword, then rail-fence (rails=3) decode -> flag. Decoys: DEPUTIZE.txt's 'FREEWAY' watchword and its printed flag line, plus the LSB decoy 'FTA{p0st3r_lsb_b41t}'.

### Progressive hints (shown in CTFd)

1. The watchword printed in the note is wrong on purpose. Only the seal's colours carry the real one — sample the swatch row and map each hue bin to a letter.
2. Two classical ciphers are stacked: undo the substitution first, then the transposition.
3. The poster's lowest bit-plane holds a decoy flag. Ignore it.

---

## E08 · Dead Drop Uplink — 50 points

**Category:** Network forensics | **Location:** La Mesa  
**Correct flag:** `FTA{d34d_dr0p_upl1nk_s3ss10n}`  
**Required evidence:** `dead_drop.pcap`, `UPLINK_SPEC.txt`

### Solving procedure

Parse the pcap's Ethernet/IPv4/UDP; collect custom payloads (MAGIC | SESSION | SEQ | CRC16 | FRAGMENT). Find the CONTROL packet (udp/4444) and base64+rot13-decode the session key; match its SESSION id to select the genuine DATA packets (udp/4445). Verify CRC-16, order by SEQ, XOR the SHA256(key) keystream, zlib-decompress. Decoy: the 0xD1E0 / udp-4446 session reassembles to 'FTA{r3pl4y3d_s3ss10n_b41t}'.

### Progressive hints (shown in CTFd)

1. Two sessions share the framing, and the spec's port and magic lead to the decoy. The genuine session is the one whose control packet actually carries a key.
2. The key is folded twice — undo both. Then CRC-validate the data fragments before you trust a single one.
3. Fragments must be ordered by their sequence field, and the keystream is keyed by the session key at each fragment's global offset.

---

## E09 · Chop Shop Terminal — 50 points

**Category:** Web security | **Location:** Strawberry  
**Correct flag:** `FTA{ch0p_sh0p_t0k3n_f31st3l_r3v3rs3}`  
**Required evidence:** `terminal.html`, `chopshop.js`

### Solving procedure

Deobfuscate chopshop.js: un-rotate the string array (rotation 3) and un-mask the seed (stored = seed XOR 0xa5a5f00d). Regenerate the xorshift32 keystream, XOR the embedded TARGET hex, base64-decode -> flag. Decoys: the dead-branch 'FTA{sh0p_b41t_d34d_c0d3}' and the comment 'FTA{c0mm3nt_s4ys_th15}'.

### Progressive hints (shown in CTFd)

1. The comment and the dead branch are plants. The page's real decision is an arithmetic comparison against an embedded digest.
2. The keystream is a small integer generator seeded by a value that is itself masked. Recover the seed before generating anything.
3. Invert the same order the checker applies: base64 first, then the masked keystream, then compare.

---

## E10 · Towing Yard Ignition — 50 points

**Category:** Reverse engineering | **Location:** El Burro Heights  
**Correct flag:** `FTA{t0w1ng_y4rd_byt3c0d3_1gn1t10n}`  
**Required evidence:** `ignition.vmb`, `YARD_NOTES.txt`, `disassemble.py`

### Solving procedure

The .vmb layout is MAGIC | OPKEY | CONST(4) | CHECK(4) | len(2) | bytecode, with every byte at offset >= 5 XORed by OPKEY. Implement the VM with the CORRECTED opcode table (the note swaps ADD/XOR and wrongly claims operands are stored verbatim), run the program, and confirm FNV-1a-32(CONST) == CHECK. The correct VM prints 'FTA{t0w1ng_y4rd_byt3c0d3_1gn1t10n}'; the naive table trips the gate and yields 'FTA{1gn1t1on_1mm0b1l1z3r_b41t}'.

### Progressive hints (shown in CTFd)

1. The provided disassembler's table is wrong in exactly one place; its listing is a dead end.
2. The blob's header is obfuscated the same way as its instructions — read the key from the header and unmask before you decode anything.
3. The module self-checks: the true phrase must satisfy FNV-1a-32 == the header CHECK. Use that to tell a correct decode from the decoy.

---

## E11 · Ghost Relay — 50 points

**Category:** Network forensics | **Location:** Paleto Bay  
**Correct flag:** `FTA{gh0st_r3l4y_l1v3_c4ptur3}`  
**Required evidence:** `ghost_relay.pcap`

### Solving procedure

Open ghost_relay.pcap in Wireshark (or tcpdump). Collect the COURIER RELAY PROTOCOL frames (MAGIC | SESSION | SEQ | CRC16 | FRAGMENT; magic 0xCB01, session 0xC11A). The CONTROL frame (SEQ=0xFFFF, udp/7000) carries base64(rot13(hex(SK))); decode the 16-byte key. Merge the CRC-valid DATA fragments from udp/7001 (even SEQ) and udp/7002 (odd SEQ), order by SEQ, XOR the SHA256(SK) keystream and zlib-inflate. Decoy: the udp/7003 burst (magic 0xCB02) reassembles to 'FTA{r3pl4y3d_r3l4y_b41t_d0_n0t_subm1t}'.

### Progressive hints (shown in CTFd)

1. The capture holds one relay burst. Read it at the frame level; the parcel is split across two carriers.
2. Merge the fragments arriving on udp/7001 and udp/7002 by their sequence field, and pick the key out of the single control fragment on udp/7000.
3. A legacy replay burst on udp/7003 frames itself with a different magic and inflates to a bait flag. Trust the CRC, not the port number.

---

## E12 · Relay Archive — 50 points

**Category:** Network forensics | **Location:** Grapeseed  
**Correct flag:** `FTA{r3l4y_4rch1v3_m3rg3d_0ff4x}`  
**Required evidence:** `relay_archive.pcap`, `COURIER_RELAY.txt`

### Solving procedure

Parse relay_archive.pcap (Ethernet/IPv4/UDP). Collect COURIER RELAY PROTOCOL frames (magic 0xCB01); group by SESSION. The genuine parcel is the only one whose CRC-valid DATA fragments arrive across BOTH udp/7001 and udp/7002; its tag equals the Ghost Relay (E11) capture tag (0xC11A). Decode the key from its CONTROL fragment base64(rot13(hex(SK))), order fragments by SEQ, XOR the SHA256(SK) keystream, zlib-inflate. Decoys: the single-carrier udp/7003 replays inflate to 'FTA{l3g4cy_r3pl4y_p4th_b41t}' and 'FTA{0ld_r3l4y_buff3r_b41t}' agent-bait printed in COURIER_RELAY.txt.

### Progressive hints (shown in CTFd)

1. Every parcel in the dump uses the same framing and the same magic; the port the notes insist on is the legacy replay path, where the bait lives.
2. The genuine parcel is the only one delivered across TWO carriers (udp/7001 and udp/7002), and it reuses the session tag captured in Ghost Relay.
3. The key is folded twice (base64 then a rotation); CRC-check the fragments before you trust a byte, then order by SEQ, XOR and inflate.

---

## M06 · Nightshift Loader — Part 1 — 100 points

**Category:** Malware analysis | **Location:** Mirror Park  
**Correct flag:** `FTA{n1ghtsh1ft_l04d3r_unp4ck3d_t0k3n}`  
**Required evidence:** `nightshift_loader.bin`, `LOADER_NOTES.txt`, `unpack_stub.py`

### Solving procedure

Parse the NSLF container: magic (4B), version (u16 LE), rort byte at offset 6, then a section table of (4-byte tag | u32 LE length | body): KEYT, CHST, PACK, DBUG. Un-rotate the KEYT table left by rort (the note's use-as-stored route fails the CRC gate). XOR PACK[4:] with the SHA-256 counter keystream of that key and verify zlib.crc32(body) == the stored u32 in PACK[:4]. The decoded body is base-40 text over the 40-char alphabet stored in CHST; decode it to a payload of 'FLAG:<flag>' and 'TOKEN:<32 hex>'. The 16-byte TOKEN is required by Part 2. DBUG is a decoy (base64 XOR 0x5a) that yields the bait flag. Bait: the stub prints FTA{n1ghtsh1ft_l04d3r_d3bug_b41t_d0_n0t_subm1t}.

### Progressive hints (shown in CTFd)

1. The table you are told to use as stored is not usable as stored: one byte in the header decides how it must be turned before any key material is correct, and the abandoned stub ignores that byte completely.
2. A checksum gate sits between the two transforms. If you are brute-forcing a byte order until it merely looks like text, stop — the gate already knows whether you are right.
3. What comes out is not ASCII. The container carries its own private alphabet, and once you decode with it, the dispatch order and a short token sit on the lines that follow.

---

## M07 · Nightshift Config — Part 2 — 100 points

**Category:** Malware analysis | **Location:** Elysian Island  
**Correct flag:** `FTA{n1ghtsh1ft_c2_c0nf1g_r4m_x0r}`  
**Required evidence:** `nightshift_config.bin`, `ram_slice.bin`, `CONFIG_NOTES.txt`

### Solving procedure

Read the NSCF container (magic + version + section table): TAGV, LEGC, LIVE. From ram_slice.bin (magic NSRAM1, u16 count, then 16-byte heap records of name|status|8 data|check byte = (sum(data) XOR 0x5a) & 0xff) take the four records with status 1 and names KEY0..KEY3 and XOR their 8-byte bodies together to rebuild the smeared key. The freed shadow K2SH record is a trap: it is KEY2 with one nibble flipped and only opens the LEGC decoy. Authenticate the gate first — TAGV must equal HMAC-SHA256(mac_key → sha256('NS-CFG-MAC'||key), 'ns-config-tag')[:16] — then derive key = sha256('NS-CFG-KEY'||Token||ram_key) and AES-like decrypt LIVE: key stream = sha256 counter mode keyed by (key, 8-byte IV), tag = the last 16 bytes. Payload carries 'FLAG:', 'C2:<host>:<port>', 'SESSION:<32 hex>'. The endpoint + 16-byte session id feed Part 3. Bait: LEGC (trap-keyed) and the note's 'live' claim both yield FTA{n1ghtsh1ft_c2_c0nf1g_b41t_d0_n0t_subm1t}.

### Progressive hints (shown in CTFd)

1. The passphrase is not one value. Every live allocation must be combined, and a corrupt one announces itself before you trust it — the fifth record sitting near the live four is not live.
2. One field in that stray record is a single nibble off from its twin, and it is there on purpose. Feeding the stray key material gives a key that decrypts to noise, not to the config.
3. The container gates you twice: one sealed section authenticates against the dispatch order alone as a checkpoint, and only then does the genuine payload open — under a key derived from the order and the rebuilt memory key together.

---

## M08 · Nightshift C2 — Part 3 — 100 points

**Category:** Malware analysis | **Location:** Port of Los Santos  
**Correct flag:** `FTA{n1ghtsh1ft_c2_s3ss10n_ch41n3d_fr4m3s}`  
**Required evidence:** `nightshift_c2.pcap`, `C2_NOTES.txt`

### Solving procedure

Parse the pcap, reassemble each TCP 4-tuple, and read NC2 frames: magic 'NC2\x01', ftype, u32 LE seq, 16-byte nonce, u16 LE ciphertext length, ciphertext, 16-byte tag. mac_key = sha256('NS-C2-MAC'||sid); frame tag = HMAC-SHA256(mac_key, header||ciphertext)[:16]. Use Part 2's endpoint (198.51.100.7:4444) to select the genuine flow and Part 2's session id as the key. Drop ftype-0 diagnostics, drop frames failing the tag, dedupe by seq, then decrypt in seq order: key stream = sha256 counter mode over ('NS-C2-KS'||prev_tag||nonce||seq||i), where prev_tag starts as the session id and becomes the previous authenticated frame's tag. The ftype-3 exfil plaintext carries the flag. Bait: the plaintext notice's FTA{n1ghtsh1ft_c2_s3ss10n_b41t_d0_n0t_subm1t} and the retired 203.0.113.9:4445 flow.

### Progressive hints (shown in CTFd)

1. Do not trust a frame you cannot authenticate. An HMAC tag covers every real frame, and it is keyed by the session id from Part 2 — replays and the tampered frame simply drop out.
2. The key stream is chained: each frame mixes the previous authenticated frame's tag, so the frames must be decrypted strictly in order, not gathered and sorted after the fact.
3. One flow on the wire belongs to a different session that never authenticates under your key. The plaintext diagnostic broadcast is a plant; its archived flag is bait and will be rejected.

---

# BONUS WAVE — revealed at T+60min · $25 each

Four of these (B01-B04) ship an on-site browser mini-game; the game reveals a key the player then applies by hand to the downloaded artefact. The remainder are standalone downloads.

## B01 · Simon Says: Dispatch Edition — 25 points

**Category:** Interactive game | **Location:** Dispatch Desk  
**Correct flag:** `FTA{s1m0n_s4ys_d15p4tch_qu3u3}`  
**Required evidence:** `dispatch_tape.txt`

### Solving procedure

Win the on-site Simon game (repeat the 8-tone sequence with no error) to reveal the 16-byte ASCII key 5IM0N-D15P4TCH-K. dispatch_tape.txt holds hex == flag XOR (key repeated); XOR the repeating key over the decoded bytes to recover the flag.

### Progressive hints (shown in CTFd)

1. The tape is XOR-masked with a fixed ASCII key. The game hands you that key — but only if you keep the sequence perfect.
2. Watch the four tones, not the colours; one wrong note resets the whole desk.
3. Once you hold the key, XOR it byte-for-byte across the hex in dispatch_tape.txt.

---

## B02 · The Reflex Job — 25 points

**Category:** Interactive game | **Location:** Alarm Grid  
**Correct flag:** `FTA{r3fl3x_j0b_0n3_m1ll1s3c0nd_w1nd0w}`  
**Required evidence:** `reflex_log.txt`

### Solving procedure

Hit the reaction target in under 200 ms to print the 16-byte key R3FL3X-W1ND0W-26. reflex_log.txt hex == flag XOR (key repeated); XOR to recover the flag.

### Progressive hints (shown in CTFd)

1. The log is XOR-masked; the game prints the exact key only on a clean, fast hit.
2. Speed matters to the millisecond — the window is unforgiving.
3. XOR the repeating ASCII key across the hex in reflex_log.txt.

---

## B03 · Captain's Log, Star Date Whatever — 25 points

**Category:** Interactive game | **Location:** Bridge Terminal  
**Correct flag:** `FTA{c4pt41ns_l0g_c0mm4nd_sh3ll}`  
**Required evidence:** `starship_manifest.txt`

### Solving procedure

In the on-site terminal issue: help -> scan -> unlock --code 4702 -> override warp. `override warp` prints key WARP-C0RE-K3Y-26. starship_manifest.txt hex == flag XOR (key repeated); XOR to recover.

### Progressive hints (shown in CTFd)

1. Type `help` first; the terminal is honest about what it understands.
2. One command needs the ship's override code — it is written where a captain would keep it.
3. The manifest is XOR-masked with the 16-byte key the terminal prints on unlock.

---

## B04 · Achievement Unlocked: Touched Grass — 25 points

**Category:** Interactive game | **Location:** The Outside  
**Correct flag:** `FTA{4ch13v3m3nt_unl0ck3d_t0uch3d_gr4ss}`  
**Required evidence:** `achievements.json`

### Solving procedure

In the on-site patched-achievement gag, leave the page untouched for 30 continuous seconds (any input resets). The achievement T0UCH3D-GR4SS-26 is then revealed as the key. achievements.json hex == flag XOR (key repeated); XOR to recover.

### Progressive hints (shown in CTFd)

1. The rarest achievements are not earned by doing something. They are earned by not doing anything.
2. Any input — any click or key at all — resets the timer. Leave it alone.
3. The JSON is XOR-masked with the achievement string the launcher finally prints.

---

## B05 · Niko's Pizza Receipt — 25 points

**Category:** Misc | **Location:** Pizza This  
**Correct flag:** `FTA{n1k0s_p1zz4_r3c31pt_0v3rch4rg3}`  
**Required evidence:** `receipt.txt`

### Solving procedure

receipt.txt lists qty x unit_price per line plus a printed TOTAL and an OVERCHARGE_BLOB (hex). The true itemised sum is 4317 cents; the printed TOTAL is 5654; the overcharge is 1337 cents. XOR the blob with the 4-byte little-endian value 1337, repeated, to recover the flag.

### Progressive hints (shown in CTFd)

1. Add up qty x unit price yourself; do not trust the printed TOTAL.
2. The overcharge is a whole number of cents, and it is the key.
3. XOR OVERCHARGE_BLOB with the overcharge as a 4-byte little-endian value, repeated.

---

## B06 · Wi-Fi Named 'FBI Surveillance Van' — 25 points

**Category:** Cryptography | **Location:** Los Santos Suburbs  
**Correct flag:** `FTA{w1f1_n4m3d_fb1_surv31ll4nc3_v4n}`  
**Required evidence:** `handshake.hc22000`, `wordlist.txt`

### Solving procedure

handshake.hc22000 stores SALT=<hex> and BLOB=<hex>. For each candidate passphrase in wordlist.txt compute ks = PBKDF2-HMAC-SHA256(passphrase.encode(), salt, 60000, dklen=32) and XOR it across BLOB. The passphrase 'surveillance-van-2026' yields a plaintext starting FTA{ (the flag); every other candidate yields garbage.

### Progressive hints (shown in CTFd)

1. The capture is a toy, not a real 4-way handshake: one salt plus one ciphertext blob.
2. The passphrase is in the supplied wordlist, and it is exactly the kind of thing this network owner would pick.
3. Keystream = PBKDF2-HMAC-SHA256(passphrase, salt, 60000, dklen=32); XOR it across the blob; the right passphrase yields text beginning FTA{.

---

## B07 · Rick Roll Protocol — 25 points

**Category:** Cryptography | **Location:** The Internet  
**Correct flag:** `FTA{r1ckr0ll_pr0t0c0l_n3v3r_g0nn4_g1v3}`  
**Required evidence:** `lyrics_cipher.txt`

### Solving procedure

lyrics_cipher.txt = Vigenere(rail_fence(flag, width=5), key='nevergonnagiveyouup'). Reverse the rail fence (width 5) first, then Vigenere-decrypt with key 'nevergonnagiveyouup' to recover the flag. A decoy line decodes to a fake flag if you skip the transposition.

### Progressive hints (shown in CTFd)

1. Two layers sit here: a transposition over a substitution.
2. The substitution key is the exact lyric phrase everyone in Los Santos knows but refuses to type.
3. Undo a rail-fence of width 5 first, then Vigenere-decrypt with key 'nevergonnagiveyouup'.

---

## B08 · 404 Flag Not Found — 25 points

**Category:** Web security | **Location:** Some Server  
**Correct flag:** `FTA{404_fl4g_n0t_f0und_b4s364_h34d3rs}`  
**Required evidence:** `raw_http_response.txt`

### Solving procedure

raw_http_response.txt is a raw HTTP/1.1 response. Header X-Courier-Route = base64(base64(flag)); decode it twice. The rendered body contains a decoy FTA{404_fake_page}.

### Progressive hints (shown in CTFd)

1. It is a raw HTTP response, not HTML. Read the headers, not the pretty page.
2. A non-standard header carries the payload, and it is encoded twice.
3. Decode the X-Courier-Route header value as base64, then base64 again. The body's 'flag' is bait.

---

## B09 · Facebook Marketplace Rugpull — 25 points

**Category:** OSINT | **Location:** Marketplace  
**Correct flag:** `FTA{fb_m4rk3tpl4c3_rugpull_pr1c3}`  
**Required evidence:** `listing.json`, `chat_log.txt`

### Solving procedure

listing.json shows ask 4200 and holds COURIER_BLOB (base64 of flag XOR keystream). chat_log.txt reveals 'final price: $3699'. XOR COURIER_BLOB (after base64-decoding) with the 4-byte little-endian value 3699, repeated, to recover the flag.

### Progressive hints (shown in CTFd)

1. The asking price is not the agreed price. The seller said the real number in chat.
2. The agreed price is a whole number of dollars and it is the key.
3. XOR the listing's base64 blob with the agreed price as a 4-byte little-endian value, repeated.

---

## B10 · Grand Theft Alpaca: Install Linux — 25 points

**Category:** Reverse engineering | **Location:** A Basement  
**Correct flag:** `FTA{gr4nd_th3ft_4lp4c4_1nst4ll_l1nux}`  
**Required evidence:** `installer_script.sh`

### Solving procedure

installer_script.sh contains interleaved decoy jokes (rm -rf jokes, a fake FTA{...} comment) and a real payload: echo '<b64>' | base64 -d | base64 -d. Double-decode the final base64 line to recover the flag.

### Progressive hints (shown in CTFd)

1. Most lines are jokes. Only the ones that actually pipe data matter.
2. The payload is handed around with echo | base64 -d, twice.
3. There are decoy flags in the comments. The real one decodes from the final base64 line.

---
