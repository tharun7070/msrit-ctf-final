#!/usr/bin/env python3
"""Integration builder for the FLAG THEFT AUTO challenge replacement.

Single source of truth for the 15 rebuilt challenges. From the data below it
regenerates (data only -- no component structure, no styling):

  * organizer_private/CTFD_IMPORT/manifest.json     (private flags)
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
LEVELS = {"E": "EASY", "M": "MEDIUM", "H": "HARD"}

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
         topic="Two-stage stored injection + DB-keyed hashing + session gate", points=100, mission=6,
         thumb="/images/lucia-3.webp",
         briefing="Fleeca's offline kiosk has two faces: a careful registration desk and a careless profile loader that trusts what it reads back. Registering is safe — the bug lives on a LATER visit, after a second sync step stores a derived copy of your data that is then interpolated raw. The login hash is home-grown and keyed with secrets that live only inside the database, and reaching the vault needs a valid session token on top of the injection. A honeypot admin account is waiting to waste your afternoon.",
         objective="Trip the two-stage stored-data flaw, satisfy the database-keyed hash, present a valid session, and retrieve the escrow record.",
         files=["fleeca_kiosk.py", "fleeca.db", "common_pw.txt"],
         hints=["Registering is not exploiting. A later sync writes a derived copy, and only that copy is ever placed into the vulnerable query.",
                "The scrubber has a blind spot, and the loader quietly undoes one of its own protections when it reads the value back.",
                "The password hash is keyed by a per-user salt and a server pepper you must read out of the database, and a valid HMAC session token is a separate, mandatory gate."],
         solution="register (safe) -> sync (stores a derived alias) -> load (interpolates the stored alias raw). Bypass the custom scrubber with a /*...*/ comment (it strips -- and ; but not /* */) to run a second-order UNION injection against the escrow table advertised in config.core_ledger. Authenticate with trunc(sha256('fleeca-h2'|per_user_salt|pw|user[::-1]|server_pepper))[:20] using salt+pepper read from fleeca.db, and present a valid token = HMAC(secret_key, user|nonce). Decoys: honeypot admin/sunshine and a fake vault table."),
    dict(cid="M02", title="Airport Ghost Flight", level="Medium", act="The Big Heist",
         location="Los Santos International Airport", category="Network forensics",
         topic="Nested frames + scoped seal + sequence-keyed mask", points=100, mission=7,
         thumb="/images/jason-1.webp",
         briefing="LSIA's tower talks to a plane radar insists isn't there. The capture is raw wire with two layers of framing: the tower's own packets ride inside ordinary TCP, and inside those sits yet another frame with its own magic. The seal is computed over part of each frame, not all of it, and the payload is masked by the inner sequence rather than by the seal. Most packets are fakes, and the outer ordering field is a deliberate lie.",
         objective="Walk both framing layers, keep only the genuinely-sealed messages, and reconstruct the ghost flight's callsign.",
         files=["airport_traffic.pcap", "MANIFEST.txt"],
         hints=["Two magics, two layers. Walk the bytes by hand; nothing here is a well-known protocol tree.",
                "The seal covers only part of the frame — a whole-frame checksum rejects the genuine packets and, tellingly, accepts a decoy set.",
                "The mask is keyed by the inner sequence, not the seal, and the outermost order field is bait."],
         solution="Parse the classic pcap. Outer frame: magic 0xDEAD1A70 LE, type 0x0A, seal = CRC32(frame[0:12] || payload) SKIPPING the 2-byte route field. Inner frame: magic 0x1A70C0DE LE, ver==1, itype 0x5C. XOR the inner data with an LCG keystream keyed by the inner sequence, then order by the inner seq (ignore the outer seq). Decoys: a naive-whole-frame-CRC group reassembling to a fake flag, plus bad-seal / wrong-type frames."),
    dict(cid="M03", title="LSPD Midnight Audit", level="Medium", act="The Big Heist",
         location="Los Santos Police Department", category="Log forensics",
         topic="Keyed hash chain + block checkpoints + nested delta", points=100, mission=8,
         thumb="/images/jason-2.webp",
         briefing="LSPD's overnight auth log claims to be tamper-evident: every line is chained to the previous one by a hash, and periodic checkpoints root each block. Three lines are lies. A plain unkeyed recomputation will 'verify' those forgeries, which is exactly the trap — the chain is keyed by a salt you must find, and both the chain and the block roots must agree. A sidecar delta holds what the originals should have said, but it is nested, and the flag is not a tidy pairwise XOR of adjacent characters.",
         objective="Verify the keyed chain and its checkpoints, repair the forgeries via the nested delta, and derive the encoded flag from a cross-field predicate.",
         files=["lspd_auth.log", "audit_delta.bin", "CHAIN_SPEC.txt"],
         hints=["Do not merely recompute a plain hash chain — it is keyed with a salt you must recover, and an unkeyed chain happily accepts the forgeries.",
                "There is a second integrity layer: periodic checkpoint roots over blocks. Chain and trouble-free block roots must both hold.",
                "The delta is nested (an outer RLE plus an index-derived transform), and the flag comes from a predicate spanning several fields, not from neighbouring characters."],
         solution="Verify chain_i = HMAC-SHA256(prev_chain || entry_data, salt) with the salt recovered from the log header/CHAIN_SPEC, and verify per-block checkpoint roots (every 100 entries). Locate the three forged entries at the chain/root breaks. Decode audit_delta.bin as nested RLE + index-derived XOR and apply it to repair. Derive the flag by selecting entries whose code ends '_ACCEPT' AND whose third field hashes into a given class, then combining the specified column per CHAIN_SPEC. Decoys: forged lines that pass an unkeyed chain, plus a decoy event sequence yielding a fake flag."),
    dict(cid="M04", title="Underground XOR Radio", level="Medium", act="The Big Heist",
         location="Underground Market", category="Cryptography",
         topic="Interleaved LFSRs + partial KPA + lane transpose", points=100, mission=9,
         thumb="/images/jason-3.webp",
         briefing="A black-market radio burst is only a few hundred bytes, but its keystream came from two machines, not one, and they are multiplexed byte-by-byte on the wire. Only part of a known header was captured alongside it, and a fixed lane transpose sits between the XOR and the bytes you see. The signal spec is bait: it lists parameters that are confidently wrong.",
         objective="De-multiplex the two generators, recover both from the partial sample, undo the transpose, and decrypt the packet.",
         files=["radio_packet.bin", "keystream_sample.bin", "SIGNAL_SPEC.txt"],
         hints=["Two shift registers drive the mask, interleaved byte-by-byte. De-multiplex the stream before attempting to recover either one.",
                "The captured sample is incomplete, and a fixed lane transpose sits between the XOR and the wire — invert it before you XOR.",
                "The spec's parameters are a decoy. Trust the structure you recover, not the sheet."],
         solution="From the exposed leading bytes of keystream_sample.bin, de-multiplex even/odd byte lanes and run Berlekamp-Massey on each lane: recover a degree-23 LFSR (taps 23,5) and a degree-17 LFSR (taps 17,3), regenerate the full keystream, invert the fixed 8-byte lane transpose, then XOR against radio_packet.bin. SIGNAL_SPEC.txt lists wrong taps/seeds and a decoy flag fragment."),
    dict(cid="M05", title="Debugging the Dispatch", level="Medium", act="The Big Heist",
         location="Lester's Hideout", category="Programming",
         topic="Two-structure race + dual-bug stage 2 + final wrap", points=100, mission=10,
         thumb="/images/lucia-1.webp",
         briefing="Lester's dispatcher rebuilds a message from unordered packets, but it loses packets under load and its output is still wrapped in more of its own mistakes. The loss is a race across two shared structures, so locking a single increment will not be enough. What the fixed dispatcher emits is another program with two independent bugs, and even a correctly fixed program leaves the result wrapped one more time.",
         objective="Fix the dispatcher so it runs deterministically, then repair the two independent bugs in the program it produces, and unwrap the final layer.",
         files=["broken_dispatch.py", "dispatch_packets.json", "README.txt"],
         hints=["The loss is a race across TWO shared structures, not one. Guarding a single counter still leaves you wrong.",
                "The emitted program has two independent bugs: one about arithmetic width and one about how a length field is read.",
                "When both bugs are fixed the payload is still wrapped exactly once more before it becomes the flag."],
         solution="Serialise the entire critical section (the per-lane tally dict AND the running ledger), so the seal is consistent; the fixed dispatcher emits base85(zlib(json)) containing stage2.py. Fix both stage-2 bugs — the fixed-width 32-bit rotate missing its & 0xFFFFFFFF, and the length-prefixed record parsed big-endian at offset 2 rather than little-endian at offset 3 — then undo the final base64 + rotating-XOR wrap. Decoys: a partial fix yields ARCHIVED_VALUE, and the notes carry a fake flag."),
    dict(cid="H01", title="Zancudo Deadbolt", level="Hard", act="The Final Getaway",
         location="Fort Zancudo Military Base", category="Reverse engineering",
         topic="Anti-analysis traps + chained VMs + runtime-keyed vault", points=160, mission=11,
         thumb="/images/lucia-2.webp",
         briefing="Fort Zancudo's Hangar 13 deadbolt runs firmware nobody has logged into since the desert went sideways. Your only copy is a stripped native binary that refuses to be watched and asks for a single operator passphrase. It is under no obligation to tell you the truth about why it says no — and when it is being watched, it lies with a straight face and a confident banner. Behind the flattened dispatchers are two chained virtual machines, and the station's tables are not sitting in plaintext in the file.",
         objective="Defeat the anti-analysis traps, reverse both virtual machines, and recover the operator passphrase.",
         files=["zancudo_gate", "OPERATIONS.txt"],
         hints=["It lies when it is being watched. Any tracing tool that trips a trap is handed a confident, WRONG answer — do not trust a 'success'.",
                "Two virtual machines, one seeding the other, and the vault tables are decrypted at runtime rather than stored in the file.",
                "The check runs four transforms deep; reverse them in order, and reproduce how the binary derives its vault key at run time."],
         solution="Defeat four independent anti-debug gates (ptrace, /proc/self/status TracerPid, a timing probe, and a parent-process-name check) — any trip diverts to a fake success path that emits a WRONG flag. VM1's result XOR-masks VM2's bytecode. The vault (need/SBOX/K/TARGET/checksum/mix) is XOR-encrypted in .rodata and decrypted at runtime with an xorshift64 keystream seeded by splitmix64(C, argv length, env byte, v1, v2). The layered check is: length gate -> FNV-1a checksum -> (SBOX[in[i]]*K[i]) mod 251 -> HMAC-like hmix. The passphrase is the flag."),
    dict(cid="H02", title="The Recursive Freeway", level="Hard", act="The Final Getaway",
         location="Final Getaway", category="Algorithms",
         topic="Weighted graph isomorphism + spectral fingerprint", points=160, mission=12,
         thumb="/images/lucia-3.webp",
         briefing="The getaway routing grid is a weighted graph in which every junction looks alike — degrees are useless as a filter. Somewhere inside sits a district that matches a stolen blueprint exactly, and several near-miss districts differ from it by a single edge or a single weight. Only the weighted spectral signature decides, and the blueprint's labels are read in an order that is not the node index. Brute force will not finish in time.",
         objective="Find the unique weight-consistent matching district and derive the clearance flag from it exactly as PROTOCOL.md specifies.",
         files=["junctions.json", "template.json", "PROTOCOL.md"],
         hints=["Degrees will not help you — every junction looks alike. Local structure and edge weights must do the pruning.",
                "Several districts are almost the blueprint; only one matches the weighted spectral fingerprint exactly.",
                "The blueprint's labels are read in an order given by an invariant of the matched district, not by node index."],
         solution="The junctions form a 4-regular weighted network; a topological induced-subgraph search finds 5 matches (4 near-miss decoys differing by one edge/weight). Narrow to the unique district whose weighted normalised Laplacian spectrum matches the blueprint's (rounded), then order the district's node labels by descending weighted eigenvector centrality (Perron-positive sign convention) and assemble the flag per PROTOCOL.md."),
    dict(cid="H03", title="Impound Evidence Matryoshka", level="Hard", act="The Final Getaway",
         location="Los Santos Police Department", category="Multi-stage forensics",
         topic="7-layer chained stego + cryptographic nesting", points=160, mission=13,
         thumb="/images/jason-1.webp",
         briefing="LSPD impounded a camera with a single frame and a note claiming the case was closed. Seven layers deep, three of them are bait. A blanket low-bit dump is poisoned; the note's frequency table gives the stride, not the codes; and each later shell is keyed by something recovered from the shell before it, so you cannot start in the middle. Only one path yields something that runs.",
         objective="Peel the chained layers, discard the decoys, and run the final stage to reveal the flag.",
         files=["impound_camera.png", "EVIDENCE_NOTE.txt"],
         hints=["A plain low-bit sweep returns bait. Only certain pixel slots carry the payload — the note's frequency table sets the stride and offset, but not the codes.",
                "Keys depend on the layer before: later shells use nonces recovered earlier, so the chain must be walked in order.",
                "Three artefacts are deliberate dead ends. The real final layer is code, and code must be executed."],
         solution="Gated PNG LSB (stride/offset from the note's frequency table) -> AES-256-CTR (PBKDF2 key from the metadata-derived passphrase) -> password-gated ZIP in the trailing bytes (password = the badge recovered at layer 2) -> AES-256-GCM (nonce = SHA256('gcm'||TAG)[:12], TAG from layer 1) -> MTX-1 matrix code -> Huffman decode using the frequency table from the note -> run the recovered Python stage, which deterministically prints the flag. Decoys: PngInfo 'flag', EXIF description, trailing-bytes tag, and a ZIP bait file, each a fake flag."),
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
         solution="Parse the TLV transcript: shares A/B are bound (32B element + 16B tag = 48B) while C/D are reduced (bare 32B) and re-advertised. The agreement value is Y = XA^5 * XB^11 * XC^13 * XD^17 mod p; the key is K = HKDF(salt, Y, info||sid). Choose an attacker-known target and solve for the injected C share XC = (Y* * R^-1)^(13^-1 mod (p-1)). Confirm against record 0x0020 (0x0021/0x0022 are decoys), then AES-256-GCM decrypt final_payload.enc and finally AES-256-CBC the inner blob."),
]

# The H04/H05 offline notices live inside each challenge's `briefing` string, so
# they flow once into the website card (challengeMeta.js), the participant
# MISSION.md and the CTFd description -- no duplicate blocks.
def description(ch):
    files_lines = "\n".join(f"- `{f}`" for f in ch["files"])
    return (
        f"# {ch['cid']} · {ch['title']}\n\n"
        f"**Level:** {ch['level']} · **Points:** {ch['points']} · **Category:** {ch['category']}  \n"
        f"**Location:** {ch['location']} · **Focus:** {ch['topic']}\n\n"
        f"## Mission briefing\n{ch['briefing']}\n\n"
        f"## Objective\n{ch['objective']} Submit exactly one recovered flag to CTFd, in the form "
        f"`FTA{{...}}`. The braces and capitalization matter. Do not submit explanations.\n\n"
        f"## Evidence files\n{files_lines}\n\n"
        f"## Scope and safety\n"
        f"Work only on the downloaded challenge artifacts. All targets, identities and addresses are "
        f"fictional. No scanning, account access, or attacks against a real network are required or "
        f"allowed.\n\n"
        f"Hints are unlockable on the event platform; they are not required to solve the mission.\n"
    )


# ---------------------------------------------------------------------------
# 2. manifest.json + attachments_sha256.csv
# ---------------------------------------------------------------------------
def build_manifest():
    challenges = []
    for ch in CH:
        lvl = LEVELS[ch["cid"][0]]
        challenges.append({
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
    man = {"event": "FLAG THEFT AUTO", "challenges": challenges}
    out = ROOT / "organizer_private" / "CTFD_IMPORT" / "manifest.json"
    out.write_text(json.dumps(man, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("wrote", out.relative_to(ROOT))

    rows = ["id,filename,size_bytes,sha256"]
    for ch in CH:
        lvl = LEVELS[ch["cid"][0]]
        for f in ch["files"]:
            p = SRC / lvl / ch["cid"] / f
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            rows.append(f"{ch['cid']},{f},{p.stat().st_size},{h}")
    (out.parent / "attachments_sha256.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    print("wrote attachments_sha256.csv")
    return man


# ---------------------------------------------------------------------------
# 3. challengeMeta.js  (data only -- resolver/constants preserved)
# ---------------------------------------------------------------------------
def js(s):
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n") + "'"


def build_meta_js():
    blocks = []
    for ch in CH:
        key = js(f"{ch['cid']} | {ch['title']}")
        block = (
            f"  {key}: {{\n"
            f"    fta_id: {js(ch['cid'])}, level: {js(ch['level'])}, act: {js(ch['act'])},\n"
            f"    location: {js(ch['location'])}, topic: {js(ch['topic'])},\n"
            f"    missionNum: {ch['mission']}, reward: {ch['points']},\n"
            f"    thumbnail: {js(ch['thumb'])},\n"
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

    arr = []
    for i, ch in enumerate(CH, start=1):
        arr.append(
            "  {\n"
            f"    id: {i}, ctfd_id: {i}, fta_id: {js(ch['cid'])}, name: {js(ch['cid'] + ' | ' + ch['title'])},\n"
            f"    level: {js(ch['level'])}, act: {js(ch['act'])}, location: {js(ch['location'])},\n"
            f"    category: {js(ch['category'])}, topic: {js(ch['topic'])}, value: {ch['points']}, reward: {ch['points']},\n"
            f"    files: [{', '.join(js(f) for f in ch['files'])}], thumbnail: {js(ch['thumb'])},\n"
            f"    briefing: {js(ch['briefing'])},\n"
            f"    objective: {js(ch['objective'])},\n"
            f"    hints: [{', '.join(js(h) for h in ch['hints'])}],\n"
            "  },"
        )
    arr_s = "\n".join(arr)

    body = f"""/**
 * Local metadata for all 15 challenges.
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
 * 3. fta_id prefix (E01, M03, H05)
 * 4. Mission index (1-15)
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

  // 3. Match by fta_id prefix (e.g. "E01 | ...", "E01", or "m02")
  const idMatch = s.match(/([EMH]\\d{{2}})/i);
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

// Canonical ordered list of all 15 authentic challenges
export const ALL_15_CHALLENGES = [
{arr_s}
];

export const LEVEL_ORDER = {{ Easy: 1, Medium: 2, Hard: 3 }};
export const LEVEL_COLORS = {{
  Easy:   {{ border: 'rgba(57,255,20,0.4)',  text: '#39ff14', bg: 'rgba(57,255,20,0.08)' }},
  Medium: {{ border: 'rgba(255,165,0,0.4)',  text: '#ffa500', bg: 'rgba(255,165,0,0.08)' }},
  Hard:   {{ border: 'rgba(255,68,68,0.5)',  text: '#ff4444', bg: 'rgba(255,68,68,0.08)' }},
}};
export const ACT_INFO = {{
  'The Street Job':    {{ num: 'I',   total: '$250', count: 5 }},
  'The Big Heist':     {{ num: 'II',  total: '$500', count: 5 }},
  'The Final Getaway': {{ num: 'III', total: '$800', count: 5 }},
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
    for ch in CH:
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
    for ch in CH:
        lines.append(f"| {ch['cid']} | {ch['level']} | {ch['title']} | {ch['topic']} | {ch['points']} |")
    lines += ["",
              "Open each mission folder to read `MISSION.md` and access only its evidence attachments. "
              "CTFd provides three progressive hints per mission."]
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
           "**Security classification: organizer only.** Contains all 15 exact flags and reference "
           "walkthroughs for fictional offline labs. Do not upload to CTFd attachments, GitHub, or "
           "student shares. Correct score for each mission is listed below; total bounty $1,550.", ""]
    for ch in CH:
        out += [f"## {ch['cid']} · {ch['title']} — {ch['points']} points", "",
                f"**Category:** {ch['category']} | **Location:** {ch['location']}  ",
                f"**Correct flag:** `{FLAGS[ch['cid']]}`  ",
                f"**Required evidence:** " + ", ".join(f"`{f}`" for f in ch["files"]), "",
                "### Solving procedure", "", ch["solution"], "",
                "### Progressive hints (shown in CTFd)", ""]
        out += [f"{i}. {h}" for i, h in enumerate(ch["hints"], 1)]
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
        for ch in CH:
            lvl = LEVELS[ch["cid"][0]]
            w.writerow([ch["cid"], f"{ch['cid']} | {ch['title']}", ch["level"], ch["act"],
                        ch["location"], ch["category"], ch["topic"], ch["points"],
                        len(ch["files"]), ";".join(ch["files"]), len(ch["hints"]),
                        FLAGS[ch["cid"]], f"challenges/{lvl}/{ch['cid']}", ch["solution"]])
    print("wrote CHALLENGE_MATRIX.csv")


def main():
    assert len(CH) == 15
    assert sum(c["points"] for c in CH) == 1550
    build_manifest()
    build_meta_js()
    for r in ROOTS:
        sync_tree(r)
    build_answer_key()
    build_matrix()
    print("INTEGRATION DATA BUILD OK")


if __name__ == "__main__":
    main()
