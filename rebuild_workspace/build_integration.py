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
         briefing="LSPD's overnight auth log claims to be tamper-evident: every line is chained by a keyed hash and periodic roots pin each block — but the salt is nowhere in the file, so a plain unkeyed recomputation cheerfully 'verifies' the forgeries. Two blocks are broken, not one. The sidecar delta that holds the originals is nested three deep, and a long run of easy-looking entries is bait that collapses to a flag that is not this audit's.",
         objective="Recover the salt from the checkpoint roots, repair every broken block, and derive the encoded flag from a cross-field predicate.",
         files=["lspd_auth.log", "audit_delta.bin", "CHAIN_SPEC.txt"],
         hints=["Do not merely recompute a plain hash chain — it is keyed, and an unkeyed chain happily accepts the forgeries. The salt is not stored: recover it from the published checkpoint roots (the space is tiny).",
                "More than one block is broken, and per-block roots mean you must repair each independently. Chain and block roots must both hold.",
                "The delta is nested three deep (RLE, an index-derived XOR, and a columnar transpose). The flag comes from a predicate spanning an exact class token and a cross-field hash class — not from the obvious contiguous run of easy entries."],
         solution="Recover the 2-byte salt by brute force until the block-1 checkpoint root matches CHAIN_SPEC.txt, then verify chain_i = HMAC-SHA256(key=salt, msg=prev||entry_data) and each 100-entry checkpoint root. Repair the two broken blocks (forged seqs 604/655/812) via the triply-nested delta: columnar transpose (width 7) -> index XOR ((i*0x5D+0x1F) mod 256) -> RLE. Derive the flag from entries with the exact class token '_ACCEPT' classified by the low bit of sha256(code)[0], combining the specified column and XORing class-0 vs class-1. Decoy: the contiguous _REACCEPT run collapses to a fake flag."),
    dict(cid="M04", title="Underground XOR Radio", level="Medium", act="The Big Heist",
         location="Underground Market", category="Cryptography",
         topic="Three interleaved LFSRs + header lane offset + partial KPA + lane transpose", points=100, mission=9,
         thumb="/images/jason-3.webp",
         briefing="A black-market radio burst is only a few hundred bytes, but its keystream came from three machines, multiplexed in fixed-length bursts whose starting lane is written in the one part of the packet that is not encrypted. Only a sliver of a known header was captured, so one register must be reconstructed by linear algebra rather than assumed. A fixed lane transpose sits between the XOR and the wire, and the signal spec is bait: it lists parameters that are confidently wrong.",
         objective="Read the sync header, de-multiplex the three generators, recover each register, undo the transpose, and decrypt the packet.",
         files=["radio_packet.bin", "keystream_sample.bin", "SIGNAL_SPEC.txt"],
         hints=["Three shift registers, not two, take turns in fixed-length bursts. The starting lane is in cleartext in the packet header — read it before you de-multiplex.",
                "The captured sample is far too short for the largest register: recover the two small lanes with Berlekamp-Massey, but solve the big lane as a small linear system over GF(2), using the taps published in the sync header.",
                "A fixed 8-byte lane transpose sits between the XOR and the wire — invert it before you XOR. The spec's taps, seeds and burst are decoys."],
         solution="Read the 12-byte sync header for lane_off/burst/beacon-degree+taps. Burst de-multiplex the wire with the header offset. Recover R0(deg 11) and R1(deg 13) via Berlekamp-Massey on at least 2*deg bits; recover the deg-23 beacon lane by solving its GF(2) output system with the published taps. Regenerate the full keystream, invert the fixed 8-byte lane transpose, then XOR against radio_packet.bin. SIGNAL_SPEC.txt is a decoy (wrong taps/seeds/burst, plus a decoy flag fragment)."),
    dict(cid="M05", title="Debugging the Dispatch", level="Medium", act="The Big Heist",
         location="Lester's Hideout", category="Programming",
         topic="Serialised race + three-bug stage 2 + stage-3 unwrap", points=100, mission=10,
         thumb="/images/lucia-1.webp",
         briefing="Lester's dispatcher rebuilds a message from unordered packets, but under load it loses packets through a race across two shared structures — locking a single counter is not enough. The fixed dispatcher then emits a program with three independent bugs, the third of which only fires when a length lands on a four-byte boundary, so testing one input misleads you. Even a fully correct program leaves the result wrapped one more time. A partial fix prints ARCHIVED_VALUE, and a decoy sits in the notes.",
         objective="Fix the dispatcher race so it runs deterministically, repair all three bugs in the program it produces, and unwrap the final layer.",
         files=["broken_dispatch.py", "dispatch_packets.json", "README.txt"],
         hints=["The loss is a race across TWO shared structures; guard the entire critical section. A partial fix yields ARCHIVED_VALUE.",
                "The emitted program has three independent bugs: an arithmetic width, a length field read at the wrong offset and endianness, and a conditional off-by-one that only triggers when a length is a multiple of four — test more than one input.",
                "When all three bugs are fixed the payload is still wrapped once more (a run-length expansion plus a rotating key) before it becomes the flag."],
         solution="Serialise the entire critical section (the per-lane tally dict AND the running ledger) so the seal is consistent; the fixed dispatcher emits base85(zlib(json)) containing stage2.py. Fix all three stage-2 bugs: the 32-bit rotate missing its & 0xFFFFFFFF, the length-prefixed record parsed big-endian at offset 2 (should be little-endian at offset 3), and the conditional off-by-one that reads the trailer a byte late when the length is a multiple of 4. Then undo the final wrap: base64 -> rotating-key XOR -> stage-3 run-length expansion. Decoys: a partial fix prints ARCHIVED_VALUE, and the notes carry a fake flag."),
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
