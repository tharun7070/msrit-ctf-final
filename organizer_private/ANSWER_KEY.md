# PRIVATE ANSWER KEY · DO NOT DISTRIBUTE

**Security classification: organizer only.** Contains all 15 exact flags and reference walkthroughs for fictional offline labs. Do not upload to CTFd attachments, GitHub, or student shares. Correct score for each mission is listed below; total bounty $1,550.

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

register (safe) -> sync (stores a derived alias) -> load (interpolates the stored alias raw). Bypass the custom scrubber with a /*...*/ comment (it strips -- and ; but not /* */) to run a second-order UNION injection against the escrow table advertised in config.core_ledger. Authenticate with trunc(sha256('fleeca-h2'|per_user_salt|pw|user[::-1]|server_pepper))[:20] using salt+pepper read from fleeca.db, and present a valid token = HMAC(secret_key, user|nonce). Decoys: honeypot admin/sunshine and a fake vault table.

### Progressive hints (shown in CTFd)

1. Registering is not exploiting. A later sync writes a derived copy, and only that copy is ever placed into the vulnerable query.
2. The scrubber has a blind spot, and the loader quietly undoes one of its own protections when it reads the value back.
3. The password hash is keyed by a per-user salt and a server pepper you must read out of the database, and a valid HMAC session token is a separate, mandatory gate.

---

## M02 · Airport Ghost Flight — 100 points

**Category:** Network forensics | **Location:** Los Santos International Airport  
**Correct flag:** `FTA{b1n_pr0t0_crc32_gh0st_fl1ght}`  
**Required evidence:** `airport_traffic.pcap`, `MANIFEST.txt`

### Solving procedure

Parse the classic pcap. Outer frame: magic 0xDEAD1A70 LE, type 0x0A, seal = CRC32(frame[0:12] || payload) SKIPPING the 2-byte route field. Inner frame: magic 0x1A70C0DE LE, ver==1, itype 0x5C. XOR the inner data with an LCG keystream keyed by the inner sequence, then order by the inner seq (ignore the outer seq). Decoys: a naive-whole-frame-CRC group reassembling to a fake flag, plus bad-seal / wrong-type frames.

### Progressive hints (shown in CTFd)

1. Two magics, two layers. Walk the bytes by hand; nothing here is a well-known protocol tree.
2. The seal covers only part of the frame — a whole-frame checksum rejects the genuine packets and, tellingly, accepts a decoy set.
3. The mask is keyed by the inner sequence, not the seal, and the outermost order field is bait.

---

## M03 · LSPD Midnight Audit — 100 points

**Category:** Log forensics | **Location:** Los Santos Police Department  
**Correct flag:** `FTA{h4sh_ch41n_t4mp3r_l5pd_aud1t}`  
**Required evidence:** `lspd_auth.log`, `audit_delta.bin`, `CHAIN_SPEC.txt`

### Solving procedure

Verify chain_i = HMAC-SHA256(prev_chain || entry_data, salt) with the salt recovered from the log header/CHAIN_SPEC, and verify per-block checkpoint roots (every 100 entries). Locate the three forged entries at the chain/root breaks. Decode audit_delta.bin as nested RLE + index-derived XOR and apply it to repair. Derive the flag by selecting entries whose code ends '_ACCEPT' AND whose third field hashes into a given class, then combining the specified column per CHAIN_SPEC. Decoys: forged lines that pass an unkeyed chain, plus a decoy event sequence yielding a fake flag.

### Progressive hints (shown in CTFd)

1. Do not merely recompute a plain hash chain — it is keyed with a salt you must recover, and an unkeyed chain happily accepts the forgeries.
2. There is a second integrity layer: periodic checkpoint roots over blocks. Chain and trouble-free block roots must both hold.
3. The delta is nested (an outer RLE plus an index-derived transform), and the flag comes from a predicate spanning several fields, not from neighbouring characters.

---

## M04 · Underground XOR Radio — 100 points

**Category:** Cryptography | **Location:** Underground Market  
**Correct flag:** `FTA{lfsr23_b3rl3k4mp_m4ss3y_r4d10}`  
**Required evidence:** `radio_packet.bin`, `keystream_sample.bin`, `SIGNAL_SPEC.txt`

### Solving procedure

From the exposed leading bytes of keystream_sample.bin, de-multiplex even/odd byte lanes and run Berlekamp-Massey on each lane: recover a degree-23 LFSR (taps 23,5) and a degree-17 LFSR (taps 17,3), regenerate the full keystream, invert the fixed 8-byte lane transpose, then XOR against radio_packet.bin. SIGNAL_SPEC.txt lists wrong taps/seeds and a decoy flag fragment.

### Progressive hints (shown in CTFd)

1. Two shift registers drive the mask, interleaved byte-by-byte. De-multiplex the stream before attempting to recover either one.
2. The captured sample is incomplete, and a fixed lane transpose sits between the XOR and the wire — invert it before you XOR.
3. The spec's parameters are a decoy. Trust the structure you recover, not the sheet.

---

## M05 · Debugging the Dispatch — 100 points

**Category:** Programming | **Location:** Lester's Hideout  
**Correct flag:** `FTA{c0ncurr3ncy_r4c3_d15p4tch_f1x}`  
**Required evidence:** `broken_dispatch.py`, `dispatch_packets.json`, `README.txt`

### Solving procedure

Serialise the entire critical section (the per-lane tally dict AND the running ledger), so the seal is consistent; the fixed dispatcher emits base85(zlib(json)) containing stage2.py. Fix both stage-2 bugs — the fixed-width 32-bit rotate missing its & 0xFFFFFFFF, and the length-prefixed record parsed big-endian at offset 2 rather than little-endian at offset 3 — then undo the final base64 + rotating-XOR wrap. Decoys: a partial fix yields ARCHIVED_VALUE, and the notes carry a fake flag.

### Progressive hints (shown in CTFd)

1. The loss is a race across TWO shared structures, not one. Guarding a single counter still leaves you wrong.
2. The emitted program has two independent bugs: one about arithmetic width and one about how a length field is read.
3. When both bugs are fixed the payload is still wrapped exactly once more before it becomes the flag.

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

---
