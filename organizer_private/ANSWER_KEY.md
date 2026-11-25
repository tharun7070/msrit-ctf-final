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
**Required evidence:** `lspd_auth.log`, `audit_delta.bin`, `CHAIN_SPEC.txt`

### Solving procedure

Recover the 2-byte salt by brute force until the block-1 checkpoint root matches CHAIN_SPEC.txt, then verify chain_i = HMAC-SHA256(key=salt, msg=prev||entry_data) and each 100-entry checkpoint root. Repair the two broken blocks (forged seqs 604/655/812) via the triply-nested delta: columnar transpose (width 7) -> index XOR ((i*0x5D+0x1F) mod 256) -> RLE. Derive the flag from entries with the exact class token '_ACCEPT' classified by the low bit of sha256(code)[0], combining the specified column and XORing class-0 vs class-1. Decoy: the contiguous _REACCEPT run collapses to a fake flag.

### Progressive hints (shown in CTFd)

1. Do not merely recompute a plain hash chain — it is keyed, and an unkeyed chain happily accepts the forgeries. The salt is not stored: recover it from the published checkpoint roots (the space is tiny).
2. More than one block is broken, and per-block roots mean you must repair each independently. Chain and block roots must both hold.
3. The delta is nested three deep (RLE, an index-derived XOR, and a columnar transpose). The flag comes from a predicate spanning an exact class token and a cross-field hash class — not from the obvious contiguous run of easy entries.

---

## M04 · Underground XOR Radio — 100 points

**Category:** Cryptography | **Location:** Underground Market  
**Correct flag:** `FTA{lfsr23_b3rl3k4mp_m4ss3y_r4d10}`  
**Required evidence:** `radio_packet.bin`, `keystream_sample.bin`, `SIGNAL_SPEC.txt`

### Solving procedure

Read the 12-byte sync header for lane_off/burst/beacon-degree+taps. Burst de-multiplex the wire with the header offset. Recover R0(deg 11) and R1(deg 13) via Berlekamp-Massey on at least 2*deg bits; recover the deg-23 beacon lane by solving its GF(2) output system with the published taps. Regenerate the full keystream, invert the fixed 8-byte lane transpose, then XOR against radio_packet.bin. SIGNAL_SPEC.txt is a decoy (wrong taps/seeds/burst, plus a decoy flag fragment).

### Progressive hints (shown in CTFd)

1. Three shift registers, not two, take turns in fixed-length bursts. The starting lane is in cleartext in the packet header — read it before you de-multiplex.
2. The captured sample is far too short for the largest register: recover the two small lanes with Berlekamp-Massey, but solve the big lane as a small linear system over GF(2), using the taps published in the sync header.
3. A fixed 8-byte lane transpose sits between the XOR and the wire — invert it before you XOR. The spec's taps, seeds and burst are decoys.

---

## M05 · Debugging the Dispatch — 100 points

**Category:** Programming | **Location:** Lester's Hideout  
**Correct flag:** `FTA{c0ncurr3ncy_r4c3_d15p4tch_f1x}`  
**Required evidence:** `broken_dispatch.py`, `dispatch_packets.json`, `README.txt`

### Solving procedure

Serialise the entire critical section (the per-lane tally dict AND the running ledger) so the seal is consistent; the fixed dispatcher emits base85(zlib(json)) containing stage2.py. Fix all three stage-2 bugs: the 32-bit rotate missing its & 0xFFFFFFFF, the length-prefixed record parsed big-endian at offset 2 (should be little-endian at offset 3), and the conditional off-by-one that reads the trailer a byte late when the length is a multiple of 4. Then undo the final wrap: base64 -> rotating-key XOR -> stage-3 run-length expansion. Decoys: a partial fix prints ARCHIVED_VALUE, and the notes carry a fake flag.

### Progressive hints (shown in CTFd)

1. The loss is a race across TWO shared structures; guard the entire critical section. A partial fix yields ARCHIVED_VALUE.
2. The emitted program has three independent bugs: an arithmetic width, a length field read at the wrong offset and endianness, and a conditional off-by-one that only triggers when a length is a multiple of four — test more than one input.
3. When all three bugs are fixed the payload is still wrapped once more (a run-length expansion plus a rotating key) before it becomes the flag.

---

## H01 · Zancudo Deadbolt — 160 points

**Category:** Reverse engineering | **Location:** Fort Zancudo Military Base  
**Correct flag:** `FTA{z4nclud0_vm_d34db0lt_unl0ck}`  
**Required evidence:** `zancudo_gate`, `OPERATIONS.txt`

### Solving procedure

Defeat four independent anti-debug gates (ptrace, /proc/self/status TracerPid, a timing probe, and a parent-process-name check) — any trip diverts to a fake success path that emits a WRONG flag. VM1's result XOR-masks VM2's bytecode. The vault (need/SBOX/K/TARGET/checksum/mix) is XOR-encrypted in .rodata and decrypted at runtime with an xorshift64 keystream seeded by splitmix64(C, argv length, env byte, v1, v2). The layered check is: length gate -> FNV-1a checksum -> (SBOX[in[i]]*K[i]) mod 251 -> HMAC-like hmix. The passphrase is the flag.

### Progressive hints (shown in CTFd)

1. It lies when it is being watched. Any tracing tool that trips a trap is handed a confident, WRONG answer — do not trust a 'success'.
2. Two virtual machines, one seeding the other, and the vault tables are decrypted at runtime rather than stored in the file.
3. The check runs four transforms deep; reverse them in order, and reproduce how the binary derives its vault key at run time.

---

## H02 · The Recursive Freeway — 160 points

**Category:** Algorithms | **Location:** Final Getaway  
**Correct flag:** `FTA{sp3ctr4l_fr33w4y_gr4ph_150m0rph}`  
**Required evidence:** `junctions.json`, `template.json`, `PROTOCOL.md`

### Solving procedure

The junctions form a 4-regular weighted network; a topological induced-subgraph search finds 5 matches (4 near-miss decoys differing by one edge/weight). Narrow to the unique district whose weighted normalised Laplacian spectrum matches the blueprint's (rounded), then order the district's node labels by descending weighted eigenvector centrality (Perron-positive sign convention) and assemble the flag per PROTOCOL.md.

### Progressive hints (shown in CTFd)

1. Degrees will not help you — every junction looks alike. Local structure and edge weights must do the pruning.
2. Several districts are almost the blueprint; only one matches the weighted spectral fingerprint exactly.
3. The blueprint's labels are read in an order given by an invariant of the matched district, not by node index.

---

## H03 · Impound Evidence Matryoshka — 160 points

**Category:** Multi-stage forensics | **Location:** Los Santos Police Department  
**Correct flag:** `FTA{m4try0shk4_f1v3_l4y3rs_c4rv3d}`  
**Required evidence:** `impound_camera.png`, `EVIDENCE_NOTE.txt`

### Solving procedure

Gated PNG LSB (stride/offset from the note's frequency table) -> AES-256-CTR (PBKDF2 key from the metadata-derived passphrase) -> password-gated ZIP in the trailing bytes (password = the badge recovered at layer 2) -> AES-256-GCM (nonce = SHA256('gcm'||TAG)[:12], TAG from layer 1) -> MTX-1 matrix code -> Huffman decode using the frequency table from the note -> run the recovered Python stage, which deterministically prints the flag. Decoys: PngInfo 'flag', EXIF description, trailing-bytes tag, and a ZIP bait file, each a fake flag.

### Progressive hints (shown in CTFd)

1. A plain low-bit sweep returns bait. Only certain pixel slots carry the payload — the note's frequency table sets the stride and offset, but not the codes.
2. Keys depend on the layer before: later shells use nonces recovered earlier, so the chain must be walked in order.
3. Three artefacts are deliberate dead ends. The real final layer is code, and code must be executed.

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
