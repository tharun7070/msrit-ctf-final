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
         topic="Custom base-41 encoding + modular filter", points=50, mission=1,
         thumb="/images/jason-1.webp",
         briefing="Lester's pager dumped a night of dispatch chatter, but only a fraction of it is his. The genuine courier packets never announce themselves — they are the rows whose numbers quietly agree, and even those are written in a private alphabet nobody documented. A stripped decoder was salvaged with the log; reverse it before you trust anything it says.",
         objective="Isolate the genuine courier rows, order them correctly, and recover the single dispatch message.",
         files=["dispatch.csv", "decoder"],
         hints=["Most of the log is noise. The real rows are the ones where three columns happen to satisfy one quiet arithmetic rule — and nothing in the file tells you which columns.",
                "The decoder hides both its alphabet and its base. Disassemble it; you are not meant to guess them.",
                "Order matters twice over: the drop is sorted on two columns with opposite directions before the payloads are decoded and joined."],
         solution="Filter rows where (col_A*col_B) mod col_C == 7; sort by (col_D % 2, -col_E); base-41 decode each payload via the reversed decoder; concatenate."),
    dict(cid="E02", title="Vinewood Shift Change", level="Easy", act="The Street Job",
         location="Vinewood Boulevard", category="Cryptography",
         topic="Affine cipher + checksum filtering", points=50, mission=2,
         thumb="/images/jason-2.webp",
         briefing="Vinewood's night-shift taxi ledger is mostly legitimate fares. One car was never supposed to be logged, and its manifest line is encrypted with a shift nobody wrote down. A decoy line decrypts perfectly under the lazy assumption — and leads nowhere.",
         objective="Find the genuine intercepted line, break its cipher, and recover the manifest.",
         files=["taxi_ledger.txt", "frequency_sample.bin"],
         hints=["Trust the checksum, not the eye. Every genuine line pins its own timestamp to a short fingerprint that must satisfy one quiet condition.",
                "The cipher is not a simple rotation — but a separate sample block is long enough for frequency analysis to hand you both of its parameters.",
                "There is a trap line that decodes cleanly under the obvious method. It contains no real flag."],
         solution="Pick the row whose SHA1(timestamp) ends in a3; affine-decrypt (a=7,b=11) with parameters derived from frequency_sample.bin; ignore the Caesar-5 decoy."),
    dict(cid="E03", title="Sandy Shores Hidden Stash", level="Easy", act="The Street Job",
         location="Sandy Shores", category="Linux forensics",
         topic="ext2 image + deleted-file recovery", points=50, mission=3,
         thumb="/images/jason-3.webp",
         briefing="The Sandy Shores safehouse yielded a dead laptop, imaged before the drive could be wiped. The file you want is already deleted — but nothing is truly gone until the blocks are reused. A dock worker's log survives on the image and is more useful than it looks.",
         objective="Recover the deleted payload from the disk image and reverse its masking.",
         files=["safehouse.img"],
         hints=["It is a real filesystem, not an archive. Deleted inodes still carry pointers to their data if you know where to look.",
                "The recovered bytes are compressed and then masked with a single byte. That byte is not in the deleted file — it lives in a surviving log.",
                "The mask is derived arithmetically from a field on one specific line of that log, not read literally."],
         solution="Carve the deleted /ledger.dat from safehouse.img, zlib-decompress, XOR every byte with the key computed from activity.log line 42's hostname (ord(3rd char) ^ ord(7th char)); decode."),
    dict(cid="E04", title="Del Perro Camera Roll", level="Easy", act="The Street Job",
         location="Del Perro Pier", category="Steganography",
         topic="PNG LSB (column-major 2-bit) + UTF-7", points=50, mission=4,
         thumb="/images/lucia-1.webp",
         briefing="Del Perro's pier camera caught nothing suspicious, but the file is heavier than its picture deserves. A payload rides in the low bits of its colour channels, laid out in an order no stego tool expects, wrapped in a text encoding from a forgotten decade.",
         objective="Extract the hidden message from the PNG and decode it.",
         files=["camera_roll.png", "README.txt"],
         hints=["Standard LSB tools will find noise and stop. The bits live in a non-standard number of low bits, read a non-standard way.",
                "Read the pixels down the columns, not across the rows — a watermark under a single colour channel nudges you toward the right direction.",
                "Once you have the bitstream it is not UTF-8. It is an older, stranger text encoding."],
         solution="Read column-major; take 2 LSBs from R, then G, then B, MSB-first; parse a 2-byte big-endian length then a UTF-7 payload."),
    dict(cid="E05", title="Wrong Extension, Right Exit", level="Easy", act="The Street Job",
         location="Los Santos Customs", category="File forensics",
         topic="PDF/ZIP polyglot + AES + SQLite", points=50, mission=5,
         thumb="/images/lucia-2.webp",
         briefing="A customs courier filed a manifest that is two files at once: it opens as a clean customs form and, to a different reader, as something else entirely. Folded inside is an encrypted archive — keyed by a serial the form prints in plain sight, if you can actually read the field and not just the text.",
         objective="Unwrap the polyglot, decrypt the inner archive, and query the recovered database.",
         files=["impound_dossier.pdf"],
         hints=["Extensions lie. A real PDF reader and a real unzipper each see a valid file, and the bytes disagree with the name.",
                "The decryption key is not hidden — it is on the visible form. Parse the PDF field; do not just grep the raw text.",
                "What comes back is a database. The flag sits behind a hash that joins two tables by an unusual key."],
         solution="Treat impound_dossier.pdf as ZIP; AES-128-CBC decrypt vault.enc with key=MD5(serial from the PDF form field) and IV=first 16 bytes; open vault.db; resolve delivery_hash=SHA1(plate||route); read the flag column."),
    dict(cid="M01", title="Fleeca Vault Glitch", level="Medium", act="The Big Heist",
         location="Fleeca Bank", category="Web security",
         topic="Second-order SQL injection + custom hashing", points=100, mission=6,
         thumb="/images/lucia-3.webp",
         briefing="Fleeca's offline kiosk has two faces: a careful registration desk and a careless profile loader that trusts what it reads back. Its login uses a home-grown password hash no cracker will recognise. To reach the vault you must trip both.",
         objective="Exploit the loader's stored-data flaw and satisfy the custom hash, then retrieve the audit record.",
         files=["fleeca_kiosk.py", "fleeca.db", "common_pw.txt"],
         hints=["Registration is safe. The bug is on the second visit, when stored data is reused inside a query that was never parameterised.",
                "The hash is not any known algorithm. Treat the script itself as its documentation.",
                "You need both a working credential and a broken query — either alone returns nothing."],
         solution="Register a payload username, trigger the load-profile step so the stored value is interpolated into the second query, and authenticate with the custom hash sha256(pw + user[::-1] + 'GTA_SALT_v2')[:16]. Both gates must pass before the flag is returned."),
    dict(cid="M02", title="Airport Ghost Flight", level="Medium", act="The Big Heist",
         location="Los Santos International Airport", category="Network forensics",
         topic="Custom binary protocol + CRC32 gating", points=100, mission=7,
         thumb="/images/jason-1.webp",
         briefing="LSIA's tower talks to a plane radar insists isn't there. The capture is raw wire, not a tidy protocol tree: the tower's own packets ride inside ordinary TCP, sealed with a checksum, numbered, and masked with that very seal. Most of them are fakes.",
         objective="Reconstruct the ghost flight's callsign from the capture.",
         files=["airport_traffic.pcap", "MANIFEST.txt"],
         hints=["It is not HTTP. Walk the bytes by hand and look for a four-byte signature that marks the tower's own messages.",
                "Not every sealed message is genuine: some fail their seal, and some carry the wrong message class. Trust only the verified ones.",
                "The seal is also the mask, and the messages carry their own order — capture order is a red herring."],
         solution="Parse the classic pcap; keep frames whose magic is 0xDEAD1A70, whose CRC32 checks out and whose type is 0x0A; order by the little-endian uint32 at payload offset 6; XOR payload[10:] with the frame's CRC32 bytes; concatenate."),
    dict(cid="M03", title="LSPD Midnight Audit", level="Medium", act="The Big Heist",
         location="Los Santos Police Department", category="Log forensics",
         topic="Hash-chain verification + tamper reconstruction", points=100, mission=8,
         thumb="/images/jason-2.webp",
         briefing="LSPD's overnight auth log claims to be tamper-evident: every line is chained to the previous one by a hash. Three lines are lies, and the chain knows it. A sidecar delta holds what the originals should have said.",
         objective="Verify the chain, locate and repair the forgeries, and extract the encoded flag.",
         files=["lspd_auth.log", "audit_delta.bin", "CHAIN_SPEC.txt"],
         hints=["Do not read the log — recompute it. Each entry's chain hash must equal the hash of the previous chain hash plus the entry data.",
                "The chain breaks exactly where it was forged. The binary delta is not a plain patch; decode its custom run-length format first.",
                "After repair the flag hides across the accepted events: their event codes, folded pairwise."],
         solution="Implement SHA256(prev_chain_hash + entry_data) verification; find the three forged entries at the chain breaks; apply the RLE-encoded audit_delta.bin to repair them; XOR adjacent event_code characters of the ACCEPT entries to recover the flag."),
    dict(cid="M04", title="Underground XOR Radio", level="Medium", act="The Big Heist",
         location="Underground Market", category="Cryptography",
         topic="LFSR keystream + Berlekamp-Massey", points=100, mission=9,
         thumb="/images/jason-3.webp",
         briefing="A black-market radio burst is only a few hundred bytes, but its keystream came from a machine, not a passphrase. A short sample of a known header was captured alongside it — enough to rebuild the generator itself.",
         objective="Reconstruct the keystream generator and decrypt the packet.",
         files=["radio_packet.bin", "keystream_sample.bin", "SIGNAL_SPEC.txt"],
         hints=["This is not a repeating human key. The keystream comes from a shift register, and the sample hands you its output bits.",
                "The register is large enough that brute force is hopeless — recover its structure algorithmically from the bit sequence.",
                "Once you can predict the stream, the rest is a flat XOR."],
         solution="XOR keystream_sample.bin with the known header from SIGNAL_SPEC.txt to obtain the keystream; run Berlekamp-Massey over GF(2) to recover the degree-23 LFSR (taps {23,5}) and its state; regenerate the full keystream; XOR it against radio_packet.bin."),
    dict(cid="M05", title="Debugging the Dispatch", level="Medium", act="The Big Heist",
         location="Lester's Hideout", category="Programming",
         topic="Concurrency race + 32-bit checksum", points=100, mission=10,
         thumb="/images/lucia-1.webp",
         briefing="Lester's dispatcher is meant to rebuild a message from unordered packets, but it loses some under load, and its output is still wrapped in two more layers of its own mistakes. Two programs, two bugs, one flag.",
         objective="Fix the dispatcher, run it deterministically, then repair the second-stage program it produces.",
         files=["broken_dispatch.py", "dispatch_packets.json", "README.txt"],
         hints=["The loss is a race, not a logic slip — the shared counter moves without protection. More threads make it worse, not better.",
                "What the fixed dispatcher produces is not the flag. It is another program, and that program has its own bug.",
                "The second bug is about arithmetic width: the value must be computed as if the register were 32 bits wide, which Python will not do for you."],
         solution="Guard the shared counter with a lock; the fixed dispatcher emits a base85+zlib JSON blob containing stage2.py; correct stage2's checksum so it masks to 32 bits explicitly; its output is the flag."),
    dict(cid="H01", title="Zancudo Deadbolt", level="Hard", act="The Final Getaway",
         location="Fort Zancudo Military Base", category="Reverse engineering",
         topic="Obfuscated ELF + anti-debug + custom VM", points=160, mission=11,
         thumb="/images/lucia-2.webp",
         briefing="Fort Zancudo's Hangar 13 deadbolt runs firmware nobody has logged into since the desert went sideways. Your only copy is a stripped native binary that refuses to be watched and asks for a single operator passphrase. It is under no obligation to tell you the truth about why it says no.",
         objective="Reverse the station's check and recover the operator passphrase.",
         files=["zancudo_gate", "OPERATIONS.txt"],
         hints=["It phones home before it opens. If a debugger is on the line it stays shut and feeds you a story instead of the truth.",
                "The real decision hides behind a single flattened switch — reach past the dispatcher and you will find the station's tables in writable data.",
                "A 256-byte permutation guards a prime modulus. Undo the shuffle, then undo the multiplication beneath that prime, byte by byte."],
         solution="Defeat both anti-debug traps; locate the .data vault (a unique 256-byte permutation of 0..255 preceded by a u32 length); per byte compute r = TARGET[i] * K[i]^-1 mod 251 and invert the S-box; the recovered string is the flag."),
    dict(cid="H02", title="The Recursive Freeway", level="Hard", act="The Final Getaway",
         location="Final Getaway", category="Algorithms",
         topic="Graph isomorphism + spectral fingerprint", points=160, mission=12,
         thumb="/images/lucia-3.webp",
         briefing="The getaway routing grid is a graph of hundreds of junctions. Somewhere inside it sits a district that matches a stolen blueprint exactly — and only its spectral signature proves it. Brute force will not finish in time.",
         objective="Find the unique matching subgraph and derive the clearance flag from it.",
         files=["junctions.json", "template.json", "PROTOCOL.md"],
         hints=["Match the blueprint topologically first — degree sequence and local structure prune almost everything.",
                "The blueprint is isomorphic to exactly one subgraph. If several look plausible, the deciding evidence is spectral.",
                "The ordered eigenvalues of the matching subgraph's Laplacian are the fingerprint; the flag itself is built from that subgraph's node labels exactly as PROTOCOL.md specifies."],
         solution="Pre-filter candidate nodes by degree sequence and clustering coefficient; find the unique induced 12-node subgraph isomorphic to template.json; verify it via the ordered Laplacian eigenvalue fingerprint; build the flag from the subgraph's node labels per PROTOCOL.md."),
    dict(cid="H03", title="Impound Evidence Matryoshka", level="Hard", act="The Final Getaway",
         location="Los Santos Police Department", category="Multi-stage forensics",
         topic="5-layer stego + cryptographic nesting", points=160, mission=13,
         thumb="/images/jason-1.webp",
         briefing="LSPD impounded a camera with a single frame and a note claiming the case was closed. Five layers deep, three of them are bait. Only one path yields something that runs.",
         objective="Peel the layers, ignore the decoys, and run the final stage to reveal the flag.",
         files=["impound_camera.png", "EVIDENCE_NOTE.txt"],
         hints=["The PNG hides something in its low bits — but the layout is not standard. The note's frequency table is a tree, not a code.",
                "One layer is encrypted; its passphrase is derived from metadata coordinates, not from the picture.",
                "Two of the intermediate artefacts are deliberate dead ends. The real final layer is code, and code must be executed."],
         solution="LSB column-major 2-bit extraction, then AES-256-CTR (PBKDF2 key from the metadata-derived passphrase), then an MTX-1 matrix code, then a Huffman decode using the tree from EVIDENCE_NOTE.txt, then run the recovered Python stage, which deterministically prints the flag."),
    dict(cid="H04", title="LEGAL RAGGING", level="Hard", act="The Final Getaway",
         location="Fleeca Bank", category="Cryptography",
         topic="RSA-CRT fault attack + timing oracle", points=160, mission=14,
         thumb="/images/jason-2.webp",
         briefing="Fleeca's mock gateway signs bank orders with RSA-CRT and keeps a 'debug' signing route it was never supposed to ship. Occasionally that route lies about one of its two internal halves. Two signatures of the same order are enough to undo the key — and a second weakness in verification confirms the forgery.\n\nSPECIAL OFFLINE HINT — CREW FITNESS CHECK\n\nVisit the organizer desk to unlock an optional hint. One willing team representative can complete 10 push-ups, or choose an equivalent non-physical logic task. The organizer will provide the hint privately. This activity is optional, supervised and compliant with college rules — there is no pressure, humiliation or compulsory physical activity.",
         objective="Recover the signing key from the faulty debug route, forge an admin order, and unlock the vault.",
         files=["bank_gateway.py", "guest.token", "AUDIT_BRIEF.txt"],
         hints=["The debug route is not constant. Collect signatures of one fixed message until one of them disagrees with itself.",
                "A faulty CRT half still agrees with the truth modulo one prime factor. The difference between a bad signature and the message shares a factor with the public modulus.",
                "Once you own the key, sign what the vault actually wants — and note that the verifier offers a second, weaker confirmation."],
         solution="Call sign_debug on a fixed message to obtain one correct and one faulty signature; p = gcd(bad^e - m mod n, n); q = n//p; d = inv(e,(p-1)(q-1)); sign ADMIN_MESSAGE; submit the token; the gateway returns the flag held in the FTA_H04_FLAG environment variable."),
    dict(cid="H05", title="Last Ride Out", level="Hard", act="The Final Getaway",
         location="Final Getaway", category="Multilayer cryptography",
         topic="3-party protocol break + AES-GCM", points=160, mission=15,
         thumb="/images/jason-3.webp",
         briefing="The getaway's final message crossed a three-party key agreement. A captured transcript and the encrypted payload survive, and the protocol has one seat nobody ever checked. Sit in it, and the session key becomes yours to choose.\n\nCLASSIFIED OFFLINE INTEL\n\nCollect a confidential paper riddle from the organizer desk. Solve it to receive an additional hint for this mission.",
         objective="Parse the transcript, find the unchecked contribution, bias the session key, and decrypt the payload.",
         files=["intercept.bin", "final_payload.enc", "ESCAPE_PROTOCOL.md", "FORMAT_SPEC.txt"],
         hints=["The transcript is TLV-framed. FORMAT_SPEC.txt tells you the shape of the frames — not what each type means; you will have to work that out.",
                "Three parties contribute. Two are bound to the transcript; one is taken on faith and never verified.",
                "If you can choose that unverified contribution, you can steer the shared key to a value of your own — then the payload opens."],
         solution="Parse the TLV transcript; identify the three parties; recognise that party C's key material is accepted unauthenticated; substitute an attacker-known C share so the effective session key equals a known value; AES-GCM decrypt final_payload.enc using the prepended 96-bit nonce."),
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
