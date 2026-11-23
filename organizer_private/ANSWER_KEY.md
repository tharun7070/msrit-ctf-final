# PRIVATE ANSWER KEY · DO NOT DISTRIBUTE

**Security classification: organizer only.** Contains all 15 exact flags and reference walkthroughs for fictional offline labs. Do not upload to CTFd attachments, GitHub, or student shares. Correct score for each mission is listed below; total bounty $1,550.

## E01 · Lester’s Pager Panic — 50 points

**Category:** Cryptography | **Location:** Lester's Hideout  
**Correct flag:** `FTA{41_c1ph3r_b4s3_cust0m_m0d_p4g3r_l3st3r_2026}`  
**Required evidence:** `dispatch.csv`, `decoder`

### Solving procedure

Filter rows where (col_A*col_B) mod col_C == 7; sort by (col_D % 2, -col_E); base-41 decode each payload via the reversed decoder; concatenate.

### Progressive hints (shown in CTFd)

1. Most of the log is noise. The real rows are the ones where three columns happen to satisfy one quiet arithmetic rule — and nothing in the file tells you which columns.
2. The decoder hides both its alphabet and its base. Disassemble it; you are not meant to guess them.
3. Order matters twice over: the drop is sorted on two columns with opposite directions before the payloads are decoded and joined.

---

## E02 · Vinewood Shift Change — 50 points

**Category:** Cryptography | **Location:** Vinewood Boulevard  
**Correct flag:** `FTA{4ff1n3_v1n3w00d_sh1ft_c0nv0y_99}`  
**Required evidence:** `taxi_ledger.txt`, `frequency_sample.bin`

### Solving procedure

Pick the row whose SHA1(timestamp) ends in a3; affine-decrypt (a=7,b=11) with parameters derived from frequency_sample.bin; ignore the Caesar-5 decoy.

### Progressive hints (shown in CTFd)

1. Trust the checksum, not the eye. Every genuine line pins its own timestamp to a short fingerprint that must satisfy one quiet condition.
2. The cipher is not a simple rotation — but a separate sample block is long enough for frequency analysis to hand you both of its parameters.
3. There is a trap line that decodes cleanly under the obvious method. It contains no real flag.

---

## E03 · Sandy Shores Hidden Stash — 50 points

**Category:** Linux forensics | **Location:** Sandy Shores  
**Correct flag:** `FTA{ext2_st4sh_r3c0v3r3d_s4ndy_51}`  
**Required evidence:** `safehouse.img`

### Solving procedure

Carve the deleted /ledger.dat from safehouse.img, zlib-decompress, XOR every byte with the key computed from activity.log line 42's hostname (ord(3rd char) ^ ord(7th char)); decode.

### Progressive hints (shown in CTFd)

1. It is a real filesystem, not an archive. Deleted inodes still carry pointers to their data if you know where to look.
2. The recovered bytes are compressed and then masked with a single byte. That byte is not in the deleted file — it lives in a surviving log.
3. The mask is derived arithmetically from a field on one specific line of that log, not read literally.

---

## E04 · Del Perro Camera Roll — 50 points

**Category:** Steganography | **Location:** Del Perro Pier  
**Correct flag:** `FTA{lsb_c0lumn_m4j0r_ut7_p13r}`  
**Required evidence:** `camera_roll.png`, `README.txt`

### Solving procedure

Read column-major; take 2 LSBs from R, then G, then B, MSB-first; parse a 2-byte big-endian length then a UTF-7 payload.

### Progressive hints (shown in CTFd)

1. Standard LSB tools will find noise and stop. The bits live in a non-standard number of low bits, read a non-standard way.
2. Read the pixels down the columns, not across the rows — a watermark under a single colour channel nudges you toward the right direction.
3. Once you have the bitstream it is not UTF-8. It is an older, stranger text encoding.

---

## E05 · Wrong Extension, Right Exit — 50 points

**Category:** File forensics | **Location:** Los Santos Customs  
**Correct flag:** `FTA{p0lygl0t_pdf_zip_aes_v4ult}`  
**Required evidence:** `impound_dossier.pdf`

### Solving procedure

Treat impound_dossier.pdf as ZIP; AES-128-CBC decrypt vault.enc with key=MD5(serial from the PDF form field) and IV=first 16 bytes; open vault.db; resolve delivery_hash=SHA1(plate||route); read the flag column.

### Progressive hints (shown in CTFd)

1. Extensions lie. A real PDF reader and a real unzipper each see a valid file, and the bytes disagree with the name.
2. The decryption key is not hidden — it is on the visible form. Parse the PDF field; do not just grep the raw text.
3. What comes back is a database. The flag sits behind a hash that joins two tables by an unusual key.

---

## M01 · Fleeca Vault Glitch — 100 points

**Category:** Web security | **Location:** Fleeca Bank  
**Correct flag:** `FTA{s3c0nd_0rd3r_fl33c4_byp4ss}`  
**Required evidence:** `fleeca_kiosk.py`, `fleeca.db`, `common_pw.txt`

### Solving procedure

Register a payload username, trigger the load-profile step so the stored value is interpolated into the second query, and authenticate with the custom hash sha256(pw + user[::-1] + 'GTA_SALT_v2')[:16]. Both gates must pass before the flag is returned.

### Progressive hints (shown in CTFd)

1. Registration is safe. The bug is on the second visit, when stored data is reused inside a query that was never parameterised.
2. The hash is not any known algorithm. Treat the script itself as its documentation.
3. You need both a working credential and a broken query — either alone returns nothing.

---

## M02 · Airport Ghost Flight — 100 points

**Category:** Network forensics | **Location:** Los Santos International Airport  
**Correct flag:** `FTA{b1n_pr0t0_crc32_gh0st_fl1ght}`  
**Required evidence:** `airport_traffic.pcap`, `MANIFEST.txt`

### Solving procedure

Parse the classic pcap; keep frames whose magic is 0xDEAD1A70, whose CRC32 checks out and whose type is 0x0A; order by the little-endian uint32 at payload offset 6; XOR payload[10:] with the frame's CRC32 bytes; concatenate.

### Progressive hints (shown in CTFd)

1. It is not HTTP. Walk the bytes by hand and look for a four-byte signature that marks the tower's own messages.
2. Not every sealed message is genuine: some fail their seal, and some carry the wrong message class. Trust only the verified ones.
3. The seal is also the mask, and the messages carry their own order — capture order is a red herring.

---

## M03 · LSPD Midnight Audit — 100 points

**Category:** Log forensics | **Location:** Los Santos Police Department  
**Correct flag:** `FTA{h4sh_ch41n_t4mp3r_l5pd_aud1t}`  
**Required evidence:** `lspd_auth.log`, `audit_delta.bin`, `CHAIN_SPEC.txt`

### Solving procedure

Implement SHA256(prev_chain_hash + entry_data) verification; find the three forged entries at the chain breaks; apply the RLE-encoded audit_delta.bin to repair them; XOR adjacent event_code characters of the ACCEPT entries to recover the flag.

### Progressive hints (shown in CTFd)

1. Do not read the log — recompute it. Each entry's chain hash must equal the hash of the previous chain hash plus the entry data.
2. The chain breaks exactly where it was forged. The binary delta is not a plain patch; decode its custom run-length format first.
3. After repair the flag hides across the accepted events: their event codes, folded pairwise.

---

## M04 · Underground XOR Radio — 100 points

**Category:** Cryptography | **Location:** Underground Market  
**Correct flag:** `FTA{lfsr23_b3rl3k4mp_m4ss3y_r4d10}`  
**Required evidence:** `radio_packet.bin`, `keystream_sample.bin`, `SIGNAL_SPEC.txt`

### Solving procedure

XOR keystream_sample.bin with the known header from SIGNAL_SPEC.txt to obtain the keystream; run Berlekamp-Massey over GF(2) to recover the degree-23 LFSR (taps {23,5}) and its state; regenerate the full keystream; XOR it against radio_packet.bin.

### Progressive hints (shown in CTFd)

1. This is not a repeating human key. The keystream comes from a shift register, and the sample hands you its output bits.
2. The register is large enough that brute force is hopeless — recover its structure algorithmically from the bit sequence.
3. Once you can predict the stream, the rest is a flat XOR.

---

## M05 · Debugging the Dispatch — 100 points

**Category:** Programming | **Location:** Lester's Hideout  
**Correct flag:** `FTA{c0ncurr3ncy_r4c3_d15p4tch_f1x}`  
**Required evidence:** `broken_dispatch.py`, `dispatch_packets.json`, `README.txt`

### Solving procedure

Guard the shared counter with a lock; the fixed dispatcher emits a base85+zlib JSON blob containing stage2.py; correct stage2's checksum so it masks to 32 bits explicitly; its output is the flag.

### Progressive hints (shown in CTFd)

1. The loss is a race, not a logic slip — the shared counter moves without protection. More threads make it worse, not better.
2. What the fixed dispatcher produces is not the flag. It is another program, and that program has its own bug.
3. The second bug is about arithmetic width: the value must be computed as if the register were 32 bits wide, which Python will not do for you.

---

## H01 · Zancudo Deadbolt — 160 points

**Category:** Reverse engineering | **Location:** Fort Zancudo Military Base  
**Correct flag:** `FTA{z4nclud0_vm_d34db0lt_unl0ck}`  
**Required evidence:** `zancudo_gate`, `OPERATIONS.txt`

### Solving procedure

Defeat both anti-debug traps; locate the .data vault (a unique 256-byte permutation of 0..255 preceded by a u32 length); per byte compute r = TARGET[i] * K[i]^-1 mod 251 and invert the S-box; the recovered string is the flag.

### Progressive hints (shown in CTFd)

1. It phones home before it opens. If a debugger is on the line it stays shut and feeds you a story instead of the truth.
2. The real decision hides behind a single flattened switch — reach past the dispatcher and you will find the station's tables in writable data.
3. A 256-byte permutation guards a prime modulus. Undo the shuffle, then undo the multiplication beneath that prime, byte by byte.

---

## H02 · The Recursive Freeway — 160 points

**Category:** Algorithms | **Location:** Final Getaway  
**Correct flag:** `FTA{sp3ctr4l_fr33w4y_gr4ph_150m0rph}`  
**Required evidence:** `junctions.json`, `template.json`, `PROTOCOL.md`

### Solving procedure

Pre-filter candidate nodes by degree sequence and clustering coefficient; find the unique induced 12-node subgraph isomorphic to template.json; verify it via the ordered Laplacian eigenvalue fingerprint; build the flag from the subgraph's node labels per PROTOCOL.md.

### Progressive hints (shown in CTFd)

1. Match the blueprint topologically first — degree sequence and local structure prune almost everything.
2. The blueprint is isomorphic to exactly one subgraph. If several look plausible, the deciding evidence is spectral.
3. The ordered eigenvalues of the matching subgraph's Laplacian are the fingerprint; the flag itself is built from that subgraph's node labels exactly as PROTOCOL.md specifies.

---

## H03 · Impound Evidence Matryoshka — 160 points

**Category:** Multi-stage forensics | **Location:** Los Santos Police Department  
**Correct flag:** `FTA{m4try0shk4_f1v3_l4y3rs_c4rv3d}`  
**Required evidence:** `impound_camera.png`, `EVIDENCE_NOTE.txt`

### Solving procedure

LSB column-major 2-bit extraction, then AES-256-CTR (PBKDF2 key from the metadata-derived passphrase), then an MTX-1 matrix code, then a Huffman decode using the tree from EVIDENCE_NOTE.txt, then run the recovered Python stage, which deterministically prints the flag.

### Progressive hints (shown in CTFd)

1. The PNG hides something in its low bits — but the layout is not standard. The note's frequency table is a tree, not a code.
2. One layer is encrypted; its passphrase is derived from metadata coordinates, not from the picture.
3. Two of the intermediate artefacts are deliberate dead ends. The real final layer is code, and code must be executed.

---

## H04 · LEGAL RAGGING — 160 points

**Category:** Cryptography | **Location:** Fleeca Bank  
**Correct flag:** `FTA{rs4_crt_f4ult_l3g4l_r4gg1ng}`  
**Required evidence:** `bank_gateway.py`, `guest.token`, `AUDIT_BRIEF.txt`

### Solving procedure

Call sign_debug on a fixed message to obtain one correct and one faulty signature; p = gcd(bad^e - m mod n, n); q = n//p; d = inv(e,(p-1)(q-1)); sign ADMIN_MESSAGE; submit the token; the gateway returns the flag held in the FTA_H04_FLAG environment variable.

### Progressive hints (shown in CTFd)

1. The debug route is not constant. Collect signatures of one fixed message until one of them disagrees with itself.
2. A faulty CRT half still agrees with the truth modulo one prime factor. The difference between a bad signature and the message shares a factor with the public modulus.
3. Once you own the key, sign what the vault actually wants — and note that the verifier offers a second, weaker confirmation.

---

## H05 · Last Ride Out — 160 points

**Category:** Multilayer cryptography | **Location:** Final Getaway  
**Correct flag:** `FTA{mult1_p4rty_3sc4p3_pr0t0c0l}`  
**Required evidence:** `intercept.bin`, `final_payload.enc`, `ESCAPE_PROTOCOL.md`, `FORMAT_SPEC.txt`

### Solving procedure

Parse the TLV transcript; identify the three parties; recognise that party C's key material is accepted unauthenticated; substitute an attacker-known C share so the effective session key equals a known value; AES-GCM decrypt final_payload.enc using the prepended 96-bit nonce.

### Progressive hints (shown in CTFd)

1. The transcript is TLV-framed. FORMAT_SPEC.txt tells you the shape of the frames — not what each type means; you will have to work that out.
2. Three parties contribute. Two are bound to the transcript; one is taken on faith and never verified.
3. If you can choose that unverified contribution, you can steer the shared key to a value of your own — then the payload opens.

---
