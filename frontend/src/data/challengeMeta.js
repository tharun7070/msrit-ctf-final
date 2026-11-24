/**
 * Local metadata for all 15 challenges.
 * This file contains ONLY participant-safe information:
 * challenge names, locations, descriptions visible in MISSION.md.
 * NO flags, NO solutions, NO private data.
 *
 * Keys match CTFd challenge names (supporting both ASCII and Unicode punctuation).
 */
export const CHALLENGE_META = {
  'E01 | Lester’s Pager Panic': {
    fta_id: 'E01', level: 'Easy', act: 'The Street Job',
    location: 'Lester\'s Hideout', topic: 'Dual modular filter + per-row stream permutation',
    missionNum: 1, reward: 50,
    thumbnail: '/images/jason-1.webp',
    briefing: 'Lester\'s pager dumped a whole night of dispatch chatter and only a sliver of it is his. The genuine courier packets never announce themselves: a real row must satisfy more than one arithmetic secret at once, and the ones that satisfy only one are poisoned. Even the wording is hostile — the payloads use a private alphabet that is then scrambled again, row by row, by a rule the salvaged decoder will not hand you. The drop is also re-ordered under a third, hidden key and padded with a marker you have to notice before you can trust a single byte.',
    objective: 'Recover the single dispatch message. Nothing in the log names the columns, the permutation, or the order.',
    hints: ['One condition is not enough. More than one arithmetic rule must hold together for a row to be genuine, and the near-misses that satisfy just one will corrupt your output.', 'The decoder reveals the alphabet and radix only. Every payload is then re-scrambled per row; recover the row-dependent permutation before you trust a decoded character.', 'Order is decided by three keys with a fixed tie-break, and the assembled plaintext carries a short marker you must recognise and strip.'],
    files: ['dispatch.csv', 'decoder'],
  },
  'E01 | Lester\'s Pager Panic': {
    fta_id: 'E01', level: 'Easy', act: 'The Street Job',
    location: 'Lester\'s Hideout', topic: 'Dual modular filter + per-row stream permutation',
    missionNum: 1, reward: 50,
    thumbnail: '/images/jason-1.webp',
    briefing: 'Lester\'s pager dumped a whole night of dispatch chatter and only a sliver of it is his. The genuine courier packets never announce themselves: a real row must satisfy more than one arithmetic secret at once, and the ones that satisfy only one are poisoned. Even the wording is hostile — the payloads use a private alphabet that is then scrambled again, row by row, by a rule the salvaged decoder will not hand you. The drop is also re-ordered under a third, hidden key and padded with a marker you have to notice before you can trust a single byte.',
    objective: 'Recover the single dispatch message. Nothing in the log names the columns, the permutation, or the order.',
    hints: ['One condition is not enough. More than one arithmetic rule must hold together for a row to be genuine, and the near-misses that satisfy just one will corrupt your output.', 'The decoder reveals the alphabet and radix only. Every payload is then re-scrambled per row; recover the row-dependent permutation before you trust a decoded character.', 'Order is decided by three keys with a fixed tie-break, and the assembled plaintext carries a short marker you must recognise and strip.'],
    files: ['dispatch.csv', 'decoder'],
  },
  'E02 | Vinewood Shift Change': {
    fta_id: 'E02', level: 'Easy', act: 'The Street Job',
    location: 'Vinewood Boulevard', topic: 'Dual fingerprint gate + transposition-over-substitution',
    missionNum: 2, reward: 50,
    thumbnail: '/images/jason-2.webp',
    briefing: 'Vinewood\'s night-shift taxi ledger is almost all legitimate fares. One car was never meant to be logged and its manifest line is wrapped in a shift nobody wrote down. A decoy line decrypts perfectly under the lazy assumption and leads nowhere. Worse, the line is not merely substituted: a transposition sits on top, so a single-stage break returns scrambled text. The sample block is rigged the same way, so the textbook frequency attack will confidently hand you a parameter pair that is simply wrong.',
    objective: 'Find the genuine intercepted line, unwind both stages of its cipher, and recover the manifest.',
    hints: ['One fingerprint is not enough: the genuine line must satisfy two independent conditions, one on its timestamp and one on its route.', 'A substitution sits under a transposition. Undo only the substitution and you get scrambled output; you must identify the transposition width as well.', 'The sample is transposed too. Run frequency analysis without untransposing it first and you will recover a plausible but false (a,b).'],
    files: ['taxi_ledger.txt', 'frequency_sample.bin'],
  },
  'E03 | Sandy Shores Hidden Stash': {
    fta_id: 'E03', level: 'Easy', act: 'The Street Job',
    location: 'Sandy Shores', topic: 'ext2 recovery + multi-byte keyed mask',
    missionNum: 3, reward: 50,
    thumbnail: '/images/jason-3.webp',
    briefing: 'The Sandy Shores safehouse yielded a dead laptop, imaged before the drive could be wiped. Several files were deleted, and only one stash is genuine — the others are the kind of bait that rewards a shallow carve. The real payload is masked with a repeating key whose every byte is computed from two separate fields on a surviving dock-worker log, and then wrapped in two more reversible layers before it is readable. The deletion order tells you nothing; a wasted carve tells you a lot.',
    objective: 'Recover the genuine deleted payload from the image, identify it among the decoys, and reverse its full masking chain.',
    hints: ['More than one deleted file survives. The genuine stash matches a numeric field recorded elsewhere on the image; the bait does not.', 'The mask is not a single byte. It repeats, and each key byte is computed from two distinct fields on the same surviving line.', 'After unmasking you are still not done: the bytes sit inside two more reversible transforms before they are text.'],
    files: ['safehouse.img'],
  },
  'E04 | Del Perro Camera Roll': {
    fta_id: 'E04', level: 'Easy', act: 'The Street Job',
    location: 'Del Perro Pier', topic: 'Gated bit-plane stego + geometry-keyed mask',
    missionNum: 4, reward: 50,
    thumbnail: '/images/lucia-1.webp',
    briefing: 'Del Perro\'s pier camera caught nothing suspicious, but the file is heavier than its picture deserves. The payload does not ride in every pixel and not in the lowest plane — only certain \'blessed\' pixels carry it, and a blanket low-bit sweep returns bait. What you finally extract is masked with a key built from the image\'s own geometry plus a logged salt, and then wrapped twice, in a decompressor and a text encoding from a forgotten decade.',
    objective: 'Extract the hidden message and reverse every layer, ignoring the traps placed for the obvious tool.',
    hints: ['A plain LSB dump finds bait. Only some pixels are used; a watermark hints at the selection rule but does not spell it out.', 'The bits are not in the lowest two bit-planes, and what you extract is XOR-masked with a key derived from the image\'s dimensions plus a salt left in metadata.', 'Once unmasked, two wraps remain: a decompressor and an older text encoding.'],
    files: ['camera_roll.png', 'README.txt'],
  },
  'E05 | Wrong Extension, Right Exit': {
    fta_id: 'E05', level: 'Easy', act: 'The Street Job',
    location: 'Los Santos Customs', topic: 'Triple-format polyglot + PBKDF2 AES + 3-table database',
    missionNum: 5, reward: 50,
    thumbnail: '/images/lucia-2.webp',
    briefing: 'A customs courier filed a manifest that is three files at once: a clean customs form, to another reader something else entirely, and to a third yet another thing. `file` will not save you here. Folded inside is an encrypted archive whose passphrase is not printed anywhere — it is assembled from two separate values the form holds apart, pushed through a slow KDF, with the IV carried somewhere other than the ciphertext. What comes back is a database, and the flag sits behind a join no single table can answer.',
    objective: 'Unwrap the polyglot, derive the key from the two separated fields, decrypt the archive, and resolve the three-way join.',
    hints: ['Extensions lie, and so does `file`: this document is valid as three different formats at once.', 'The passphrase is not one value. Combine two separate fields from the PDF through a slow KDF, and find the IV somewhere other than the ciphertext.', 'What comes back is a database full of decoys. Only a three-table join on an unusual token reaches the real record.'],
    files: ['impound_dossier.pdf'],
  },
  'M01 | Fleeca Vault Glitch': {
    fta_id: 'M01', level: 'Medium', act: 'The Big Heist',
    location: 'Fleeca Bank', topic: 'Two-stage stored injection + DB-keyed hashing + session gate',
    missionNum: 6, reward: 100,
    thumbnail: '/images/lucia-3.webp',
    briefing: 'Fleeca\'s offline kiosk has two faces: a careful registration desk and a careless profile loader that trusts what it reads back. Registering is safe — the bug lives on a LATER visit, after a second sync step stores a derived copy of your data that is then interpolated raw. The login hash is home-grown and keyed with secrets that live only inside the database, and reaching the vault needs a valid session token on top of the injection. A honeypot admin account is waiting to waste your afternoon.',
    objective: 'Trip the two-stage stored-data flaw, satisfy the database-keyed hash, present a valid session, and retrieve the escrow record.',
    hints: ['Registering is not exploiting. A later sync writes a derived copy, and only that copy is ever placed into the vulnerable query.', 'The scrubber has a blind spot, and the loader quietly undoes one of its own protections when it reads the value back.', 'The password hash is keyed by a per-user salt and a server pepper you must read out of the database, and a valid HMAC session token is a separate, mandatory gate.'],
    files: ['fleeca_kiosk.py', 'fleeca.db', 'common_pw.txt'],
  },
  'M02 | Airport Ghost Flight': {
    fta_id: 'M02', level: 'Medium', act: 'The Big Heist',
    location: 'Los Santos International Airport', topic: 'Nested frames + scoped seal + sequence-keyed mask',
    missionNum: 7, reward: 100,
    thumbnail: '/images/jason-1.webp',
    briefing: 'LSIA\'s tower talks to a plane radar insists isn\'t there. The capture is raw wire with two layers of framing: the tower\'s own packets ride inside ordinary TCP, and inside those sits yet another frame with its own magic. The seal is computed over part of each frame, not all of it, and the payload is masked by the inner sequence rather than by the seal. Most packets are fakes, and the outer ordering field is a deliberate lie.',
    objective: 'Walk both framing layers, keep only the genuinely-sealed messages, and reconstruct the ghost flight\'s callsign.',
    hints: ['Two magics, two layers. Walk the bytes by hand; nothing here is a well-known protocol tree.', 'The seal covers only part of the frame — a whole-frame checksum rejects the genuine packets and, tellingly, accepts a decoy set.', 'The mask is keyed by the inner sequence, not the seal, and the outermost order field is bait.'],
    files: ['airport_traffic.pcap', 'MANIFEST.txt'],
  },
  'M03 | LSPD Midnight Audit': {
    fta_id: 'M03', level: 'Medium', act: 'The Big Heist',
    location: 'Los Santos Police Department', topic: 'Keyed hash chain + block checkpoints + nested delta',
    missionNum: 8, reward: 100,
    thumbnail: '/images/jason-2.webp',
    briefing: 'LSPD\'s overnight auth log claims to be tamper-evident: every line is chained to the previous one by a hash, and periodic checkpoints root each block. Three lines are lies. A plain unkeyed recomputation will \'verify\' those forgeries, which is exactly the trap — the chain is keyed by a salt you must find, and both the chain and the block roots must agree. A sidecar delta holds what the originals should have said, but it is nested, and the flag is not a tidy pairwise XOR of adjacent characters.',
    objective: 'Verify the keyed chain and its checkpoints, repair the forgeries via the nested delta, and derive the encoded flag from a cross-field predicate.',
    hints: ['Do not merely recompute a plain hash chain — it is keyed with a salt you must recover, and an unkeyed chain happily accepts the forgeries.', 'There is a second integrity layer: periodic checkpoint roots over blocks. Chain and trouble-free block roots must both hold.', 'The delta is nested (an outer RLE plus an index-derived transform), and the flag comes from a predicate spanning several fields, not from neighbouring characters.'],
    files: ['lspd_auth.log', 'audit_delta.bin', 'CHAIN_SPEC.txt'],
  },
  'M04 | Underground XOR Radio': {
    fta_id: 'M04', level: 'Medium', act: 'The Big Heist',
    location: 'Underground Market', topic: 'Interleaved LFSRs + partial KPA + lane transpose',
    missionNum: 9, reward: 100,
    thumbnail: '/images/jason-3.webp',
    briefing: 'A black-market radio burst is only a few hundred bytes, but its keystream came from two machines, not one, and they are multiplexed byte-by-byte on the wire. Only part of a known header was captured alongside it, and a fixed lane transpose sits between the XOR and the bytes you see. The signal spec is bait: it lists parameters that are confidently wrong.',
    objective: 'De-multiplex the two generators, recover both from the partial sample, undo the transpose, and decrypt the packet.',
    hints: ['Two shift registers drive the mask, interleaved byte-by-byte. De-multiplex the stream before attempting to recover either one.', 'The captured sample is incomplete, and a fixed lane transpose sits between the XOR and the wire — invert it before you XOR.', 'The spec\'s parameters are a decoy. Trust the structure you recover, not the sheet.'],
    files: ['radio_packet.bin', 'keystream_sample.bin', 'SIGNAL_SPEC.txt'],
  },
  'M05 | Debugging the Dispatch': {
    fta_id: 'M05', level: 'Medium', act: 'The Big Heist',
    location: 'Lester\'s Hideout', topic: 'Two-structure race + dual-bug stage 2 + final wrap',
    missionNum: 10, reward: 100,
    thumbnail: '/images/lucia-1.webp',
    briefing: 'Lester\'s dispatcher rebuilds a message from unordered packets, but it loses packets under load and its output is still wrapped in more of its own mistakes. The loss is a race across two shared structures, so locking a single increment will not be enough. What the fixed dispatcher emits is another program with two independent bugs, and even a correctly fixed program leaves the result wrapped one more time.',
    objective: 'Fix the dispatcher so it runs deterministically, then repair the two independent bugs in the program it produces, and unwrap the final layer.',
    hints: ['The loss is a race across TWO shared structures, not one. Guarding a single counter still leaves you wrong.', 'The emitted program has two independent bugs: one about arithmetic width and one about how a length field is read.', 'When both bugs are fixed the payload is still wrapped exactly once more before it becomes the flag.'],
    files: ['broken_dispatch.py', 'dispatch_packets.json', 'README.txt'],
  },
  'H01 | Zancudo Deadbolt': {
    fta_id: 'H01', level: 'Hard', act: 'The Final Getaway',
    location: 'Fort Zancudo Military Base', topic: 'Anti-analysis traps + chained VMs + runtime-keyed vault',
    missionNum: 11, reward: 160,
    thumbnail: '/images/lucia-2.webp',
    briefing: 'Fort Zancudo\'s Hangar 13 deadbolt runs firmware nobody has logged into since the desert went sideways. Your only copy is a stripped native binary that refuses to be watched and asks for a single operator passphrase. It is under no obligation to tell you the truth about why it says no — and when it is being watched, it lies with a straight face and a confident banner. Behind the flattened dispatchers are two chained virtual machines, and the station\'s tables are not sitting in plaintext in the file.',
    objective: 'Defeat the anti-analysis traps, reverse both virtual machines, and recover the operator passphrase.',
    hints: ['It lies when it is being watched. Any tracing tool that trips a trap is handed a confident, WRONG answer — do not trust a \'success\'.', 'Two virtual machines, one seeding the other, and the vault tables are decrypted at runtime rather than stored in the file.', 'The check runs four transforms deep; reverse them in order, and reproduce how the binary derives its vault key at run time.'],
    files: ['zancudo_gate', 'OPERATIONS.txt'],
  },
  'H02 | The Recursive Freeway': {
    fta_id: 'H02', level: 'Hard', act: 'The Final Getaway',
    location: 'Final Getaway', topic: 'Weighted graph isomorphism + spectral fingerprint',
    missionNum: 12, reward: 160,
    thumbnail: '/images/lucia-3.webp',
    briefing: 'The getaway routing grid is a weighted graph in which every junction looks alike — degrees are useless as a filter. Somewhere inside sits a district that matches a stolen blueprint exactly, and several near-miss districts differ from it by a single edge or a single weight. Only the weighted spectral signature decides, and the blueprint\'s labels are read in an order that is not the node index. Brute force will not finish in time.',
    objective: 'Find the unique weight-consistent matching district and derive the clearance flag from it exactly as PROTOCOL.md specifies.',
    hints: ['Degrees will not help you — every junction looks alike. Local structure and edge weights must do the pruning.', 'Several districts are almost the blueprint; only one matches the weighted spectral fingerprint exactly.', 'The blueprint\'s labels are read in an order given by an invariant of the matched district, not by node index.'],
    files: ['junctions.json', 'template.json', 'PROTOCOL.md'],
  },
  'H03 | Impound Evidence Matryoshka': {
    fta_id: 'H03', level: 'Hard', act: 'The Final Getaway',
    location: 'Los Santos Police Department', topic: '7-layer chained stego + cryptographic nesting',
    missionNum: 13, reward: 160,
    thumbnail: '/images/jason-1.webp',
    briefing: 'LSPD impounded a camera with a single frame and a note claiming the case was closed. Seven layers deep, three of them are bait. A blanket low-bit dump is poisoned; the note\'s frequency table gives the stride, not the codes; and each later shell is keyed by something recovered from the shell before it, so you cannot start in the middle. Only one path yields something that runs.',
    objective: 'Peel the chained layers, discard the decoys, and run the final stage to reveal the flag.',
    hints: ['A plain low-bit sweep returns bait. Only certain pixel slots carry the payload — the note\'s frequency table sets the stride and offset, but not the codes.', 'Keys depend on the layer before: later shells use nonces recovered earlier, so the chain must be walked in order.', 'Three artefacts are deliberate dead ends. The real final layer is code, and code must be executed.'],
    files: ['impound_camera.png', 'EVIDENCE_NOTE.txt'],
  },
  'H04 | LEGAL RAGGING': {
    fta_id: 'H04', level: 'Hard', act: 'The Final Getaway',
    location: 'Fleeca Bank', topic: 'Blinded RSA-CRT fault + timing oracle + freshness gate',
    missionNum: 14, reward: 160,
    thumbnail: '/images/jason-2.webp',
    briefing: 'Fleeca\'s mock gateway signs bank orders with RSA-CRT and keeps a \'debug\' signing route it was never supposed to ship. That route blinds what it signs and, occasionally, lies about one of its two internal halves — rarely, and in either half. A second route leaks, byte by byte, a live nonce the vault order must carry, and the verifier now also demands the right role and a fresh timestamp. Two signatures are no longer enough on their own.\n\nSPECIAL OFFLINE HINT — CREW FITNESS CHECK\n\nVisit the organizer desk to unlock an optional hint. One willing team representative can complete 10 push-ups, or choose an equivalent non-physical logic task. The organizer will provide the hint privately. This activity is optional, supervised and compliant with college rules — there is no pressure, humiliation or compulsory physical activity.',
    objective: 'Recover the signing key from the blinded, faulty debug route, satisfy the nonce and freshness gates, forge an admin order, and unlock the vault.',
    hints: ['The debug route blinds what it signs; undo the blinding before any faulty half becomes visible. It also faults rarely, and in either half.', 'The order must carry a nonce that only the second, timing-based route will reveal, and it changes every process.', 'A correctly-signed order under the wrong role — or with a stale/wrong nonce — is still refused. The brief\'s parameters are bait.'],
    files: ['bank_gateway.py', 'guest.token', 'AUDIT_BRIEF.txt'],
  },
  'H05 | Last Ride Out': {
    fta_id: 'H05', level: 'Hard', act: 'The Final Getaway',
    location: 'Final Getaway', topic: '4-party agreement break + HKDF + nested AES',
    missionNum: 15, reward: 160,
    thumbnail: '/images/jason-3.webp',
    briefing: 'The getaway\'s final message crossed a four-party key agreement. A captured transcript and the encrypted payload survive, and two of the four seats were never checked — read the framing and you will see which contributions are bound and which are taken on faith and re-advertised. The shared secret is not a neat sum but a weighted product, so sitting in an unchecked seat means solving for a value, not merely choosing one. The payload is nested twice, and some of the confirmations are decoys.\n\nCLASSIFIED OFFLINE INTEL\n\nCollect a confidential paper riddle from the organizer desk. Solve it to receive an additional hint for this mission.',
    objective: 'Parse the transcript, identify the unauthenticated seats, steer the weighted session key, and decrypt the nested payload.',
    hints: ['More than three voices are on the line. Read the framing: some contributions carry a binding tag and some do not — the unbound ones are trusted.', 'The session secret is a weighted product of the contributions, not a sum; steering it means solving for a share value rather than picking one.', 'There are decoy key-confirmations. The real one sits between them, and the payload is nested twice.'],
    files: ['intercept.bin', 'final_payload.enc', 'ESCAPE_PROTOCOL.md', 'FORMAT_SPEC.txt'],
  },
};

/**
 * Normalizes strings by replacing curly quotes/apostrophes with ASCII quotes
 */
export function normalizeName(str) {
  if (!str) return '';
  return String(str)
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201C\u201D]/g, '"')
    .trim()
    .toLowerCase();
}

/**
 * Bulletproof resolver that matches challenge metadata by:
 * 1. Direct name match
 * 2. Normalized name match (handling unicode vs ascii apostrophes)
 * 3. fta_id prefix (E01, M03, H05)
 * 4. Mission index (1-15)
 */
export function getChallengeMeta(identifier) {
  if (!identifier) return {};
  const s = String(identifier).trim();

  // 1. Direct key match
  if (CHALLENGE_META[s]) return CHALLENGE_META[s];

  // 2. Normalized match
  const norm = normalizeName(s);
  for (const [key, meta] of Object.entries(CHALLENGE_META)) {
    if (normalizeName(key) === norm) return meta;
  }

  // 3. Match by fta_id prefix (e.g. "E01 | ...", "E01", or "m02")
  const idMatch = s.match(/([EMH]\d{2})/i);
  if (idMatch) {
    const ftaId = idMatch[1].toUpperCase();
    for (const meta of Object.values(CHALLENGE_META)) {
      if (meta.fta_id === ftaId) return meta;
    }
  }

  // 4. Match by missionNum
  const num = parseInt(s, 10);
  if (!isNaN(num)) {
    for (const meta of Object.values(CHALLENGE_META)) {
      if (meta.missionNum === num) return meta;
    }
  }

  return {};
}

// Canonical ordered list of all 15 authentic challenges
export const ALL_15_CHALLENGES = [
  {
    id: 1, ctfd_id: 1, fta_id: 'E01', name: 'E01 | Lester’s Pager Panic',
    level: 'Easy', act: 'The Street Job', location: 'Lester\'s Hideout',
    category: 'Cryptography', topic: 'Dual modular filter + per-row stream permutation', value: 50, reward: 50,
    files: ['dispatch.csv', 'decoder'], thumbnail: '/images/jason-1.webp',
    briefing: 'Lester\'s pager dumped a whole night of dispatch chatter and only a sliver of it is his. The genuine courier packets never announce themselves: a real row must satisfy more than one arithmetic secret at once, and the ones that satisfy only one are poisoned. Even the wording is hostile — the payloads use a private alphabet that is then scrambled again, row by row, by a rule the salvaged decoder will not hand you. The drop is also re-ordered under a third, hidden key and padded with a marker you have to notice before you can trust a single byte.',
    objective: 'Recover the single dispatch message. Nothing in the log names the columns, the permutation, or the order.',
    hints: ['One condition is not enough. More than one arithmetic rule must hold together for a row to be genuine, and the near-misses that satisfy just one will corrupt your output.', 'The decoder reveals the alphabet and radix only. Every payload is then re-scrambled per row; recover the row-dependent permutation before you trust a decoded character.', 'Order is decided by three keys with a fixed tie-break, and the assembled plaintext carries a short marker you must recognise and strip.'],
  },
  {
    id: 2, ctfd_id: 2, fta_id: 'E02', name: 'E02 | Vinewood Shift Change',
    level: 'Easy', act: 'The Street Job', location: 'Vinewood Boulevard',
    category: 'Cryptography', topic: 'Dual fingerprint gate + transposition-over-substitution', value: 50, reward: 50,
    files: ['taxi_ledger.txt', 'frequency_sample.bin'], thumbnail: '/images/jason-2.webp',
    briefing: 'Vinewood\'s night-shift taxi ledger is almost all legitimate fares. One car was never meant to be logged and its manifest line is wrapped in a shift nobody wrote down. A decoy line decrypts perfectly under the lazy assumption and leads nowhere. Worse, the line is not merely substituted: a transposition sits on top, so a single-stage break returns scrambled text. The sample block is rigged the same way, so the textbook frequency attack will confidently hand you a parameter pair that is simply wrong.',
    objective: 'Find the genuine intercepted line, unwind both stages of its cipher, and recover the manifest.',
    hints: ['One fingerprint is not enough: the genuine line must satisfy two independent conditions, one on its timestamp and one on its route.', 'A substitution sits under a transposition. Undo only the substitution and you get scrambled output; you must identify the transposition width as well.', 'The sample is transposed too. Run frequency analysis without untransposing it first and you will recover a plausible but false (a,b).'],
  },
  {
    id: 3, ctfd_id: 3, fta_id: 'E03', name: 'E03 | Sandy Shores Hidden Stash',
    level: 'Easy', act: 'The Street Job', location: 'Sandy Shores',
    category: 'Linux forensics', topic: 'ext2 recovery + multi-byte keyed mask', value: 50, reward: 50,
    files: ['safehouse.img'], thumbnail: '/images/jason-3.webp',
    briefing: 'The Sandy Shores safehouse yielded a dead laptop, imaged before the drive could be wiped. Several files were deleted, and only one stash is genuine — the others are the kind of bait that rewards a shallow carve. The real payload is masked with a repeating key whose every byte is computed from two separate fields on a surviving dock-worker log, and then wrapped in two more reversible layers before it is readable. The deletion order tells you nothing; a wasted carve tells you a lot.',
    objective: 'Recover the genuine deleted payload from the image, identify it among the decoys, and reverse its full masking chain.',
    hints: ['More than one deleted file survives. The genuine stash matches a numeric field recorded elsewhere on the image; the bait does not.', 'The mask is not a single byte. It repeats, and each key byte is computed from two distinct fields on the same surviving line.', 'After unmasking you are still not done: the bytes sit inside two more reversible transforms before they are text.'],
  },
  {
    id: 4, ctfd_id: 4, fta_id: 'E04', name: 'E04 | Del Perro Camera Roll',
    level: 'Easy', act: 'The Street Job', location: 'Del Perro Pier',
    category: 'Steganography', topic: 'Gated bit-plane stego + geometry-keyed mask', value: 50, reward: 50,
    files: ['camera_roll.png', 'README.txt'], thumbnail: '/images/lucia-1.webp',
    briefing: 'Del Perro\'s pier camera caught nothing suspicious, but the file is heavier than its picture deserves. The payload does not ride in every pixel and not in the lowest plane — only certain \'blessed\' pixels carry it, and a blanket low-bit sweep returns bait. What you finally extract is masked with a key built from the image\'s own geometry plus a logged salt, and then wrapped twice, in a decompressor and a text encoding from a forgotten decade.',
    objective: 'Extract the hidden message and reverse every layer, ignoring the traps placed for the obvious tool.',
    hints: ['A plain LSB dump finds bait. Only some pixels are used; a watermark hints at the selection rule but does not spell it out.', 'The bits are not in the lowest two bit-planes, and what you extract is XOR-masked with a key derived from the image\'s dimensions plus a salt left in metadata.', 'Once unmasked, two wraps remain: a decompressor and an older text encoding.'],
  },
  {
    id: 5, ctfd_id: 5, fta_id: 'E05', name: 'E05 | Wrong Extension, Right Exit',
    level: 'Easy', act: 'The Street Job', location: 'Los Santos Customs',
    category: 'File forensics', topic: 'Triple-format polyglot + PBKDF2 AES + 3-table database', value: 50, reward: 50,
    files: ['impound_dossier.pdf'], thumbnail: '/images/lucia-2.webp',
    briefing: 'A customs courier filed a manifest that is three files at once: a clean customs form, to another reader something else entirely, and to a third yet another thing. `file` will not save you here. Folded inside is an encrypted archive whose passphrase is not printed anywhere — it is assembled from two separate values the form holds apart, pushed through a slow KDF, with the IV carried somewhere other than the ciphertext. What comes back is a database, and the flag sits behind a join no single table can answer.',
    objective: 'Unwrap the polyglot, derive the key from the two separated fields, decrypt the archive, and resolve the three-way join.',
    hints: ['Extensions lie, and so does `file`: this document is valid as three different formats at once.', 'The passphrase is not one value. Combine two separate fields from the PDF through a slow KDF, and find the IV somewhere other than the ciphertext.', 'What comes back is a database full of decoys. Only a three-table join on an unusual token reaches the real record.'],
  },
  {
    id: 6, ctfd_id: 6, fta_id: 'M01', name: 'M01 | Fleeca Vault Glitch',
    level: 'Medium', act: 'The Big Heist', location: 'Fleeca Bank',
    category: 'Web security', topic: 'Two-stage stored injection + DB-keyed hashing + session gate', value: 100, reward: 100,
    files: ['fleeca_kiosk.py', 'fleeca.db', 'common_pw.txt'], thumbnail: '/images/lucia-3.webp',
    briefing: 'Fleeca\'s offline kiosk has two faces: a careful registration desk and a careless profile loader that trusts what it reads back. Registering is safe — the bug lives on a LATER visit, after a second sync step stores a derived copy of your data that is then interpolated raw. The login hash is home-grown and keyed with secrets that live only inside the database, and reaching the vault needs a valid session token on top of the injection. A honeypot admin account is waiting to waste your afternoon.',
    objective: 'Trip the two-stage stored-data flaw, satisfy the database-keyed hash, present a valid session, and retrieve the escrow record.',
    hints: ['Registering is not exploiting. A later sync writes a derived copy, and only that copy is ever placed into the vulnerable query.', 'The scrubber has a blind spot, and the loader quietly undoes one of its own protections when it reads the value back.', 'The password hash is keyed by a per-user salt and a server pepper you must read out of the database, and a valid HMAC session token is a separate, mandatory gate.'],
  },
  {
    id: 7, ctfd_id: 7, fta_id: 'M02', name: 'M02 | Airport Ghost Flight',
    level: 'Medium', act: 'The Big Heist', location: 'Los Santos International Airport',
    category: 'Network forensics', topic: 'Nested frames + scoped seal + sequence-keyed mask', value: 100, reward: 100,
    files: ['airport_traffic.pcap', 'MANIFEST.txt'], thumbnail: '/images/jason-1.webp',
    briefing: 'LSIA\'s tower talks to a plane radar insists isn\'t there. The capture is raw wire with two layers of framing: the tower\'s own packets ride inside ordinary TCP, and inside those sits yet another frame with its own magic. The seal is computed over part of each frame, not all of it, and the payload is masked by the inner sequence rather than by the seal. Most packets are fakes, and the outer ordering field is a deliberate lie.',
    objective: 'Walk both framing layers, keep only the genuinely-sealed messages, and reconstruct the ghost flight\'s callsign.',
    hints: ['Two magics, two layers. Walk the bytes by hand; nothing here is a well-known protocol tree.', 'The seal covers only part of the frame — a whole-frame checksum rejects the genuine packets and, tellingly, accepts a decoy set.', 'The mask is keyed by the inner sequence, not the seal, and the outermost order field is bait.'],
  },
  {
    id: 8, ctfd_id: 8, fta_id: 'M03', name: 'M03 | LSPD Midnight Audit',
    level: 'Medium', act: 'The Big Heist', location: 'Los Santos Police Department',
    category: 'Log forensics', topic: 'Keyed hash chain + block checkpoints + nested delta', value: 100, reward: 100,
    files: ['lspd_auth.log', 'audit_delta.bin', 'CHAIN_SPEC.txt'], thumbnail: '/images/jason-2.webp',
    briefing: 'LSPD\'s overnight auth log claims to be tamper-evident: every line is chained to the previous one by a hash, and periodic checkpoints root each block. Three lines are lies. A plain unkeyed recomputation will \'verify\' those forgeries, which is exactly the trap — the chain is keyed by a salt you must find, and both the chain and the block roots must agree. A sidecar delta holds what the originals should have said, but it is nested, and the flag is not a tidy pairwise XOR of adjacent characters.',
    objective: 'Verify the keyed chain and its checkpoints, repair the forgeries via the nested delta, and derive the encoded flag from a cross-field predicate.',
    hints: ['Do not merely recompute a plain hash chain — it is keyed with a salt you must recover, and an unkeyed chain happily accepts the forgeries.', 'There is a second integrity layer: periodic checkpoint roots over blocks. Chain and trouble-free block roots must both hold.', 'The delta is nested (an outer RLE plus an index-derived transform), and the flag comes from a predicate spanning several fields, not from neighbouring characters.'],
  },
  {
    id: 9, ctfd_id: 9, fta_id: 'M04', name: 'M04 | Underground XOR Radio',
    level: 'Medium', act: 'The Big Heist', location: 'Underground Market',
    category: 'Cryptography', topic: 'Interleaved LFSRs + partial KPA + lane transpose', value: 100, reward: 100,
    files: ['radio_packet.bin', 'keystream_sample.bin', 'SIGNAL_SPEC.txt'], thumbnail: '/images/jason-3.webp',
    briefing: 'A black-market radio burst is only a few hundred bytes, but its keystream came from two machines, not one, and they are multiplexed byte-by-byte on the wire. Only part of a known header was captured alongside it, and a fixed lane transpose sits between the XOR and the bytes you see. The signal spec is bait: it lists parameters that are confidently wrong.',
    objective: 'De-multiplex the two generators, recover both from the partial sample, undo the transpose, and decrypt the packet.',
    hints: ['Two shift registers drive the mask, interleaved byte-by-byte. De-multiplex the stream before attempting to recover either one.', 'The captured sample is incomplete, and a fixed lane transpose sits between the XOR and the wire — invert it before you XOR.', 'The spec\'s parameters are a decoy. Trust the structure you recover, not the sheet.'],
  },
  {
    id: 10, ctfd_id: 10, fta_id: 'M05', name: 'M05 | Debugging the Dispatch',
    level: 'Medium', act: 'The Big Heist', location: 'Lester\'s Hideout',
    category: 'Programming', topic: 'Two-structure race + dual-bug stage 2 + final wrap', value: 100, reward: 100,
    files: ['broken_dispatch.py', 'dispatch_packets.json', 'README.txt'], thumbnail: '/images/lucia-1.webp',
    briefing: 'Lester\'s dispatcher rebuilds a message from unordered packets, but it loses packets under load and its output is still wrapped in more of its own mistakes. The loss is a race across two shared structures, so locking a single increment will not be enough. What the fixed dispatcher emits is another program with two independent bugs, and even a correctly fixed program leaves the result wrapped one more time.',
    objective: 'Fix the dispatcher so it runs deterministically, then repair the two independent bugs in the program it produces, and unwrap the final layer.',
    hints: ['The loss is a race across TWO shared structures, not one. Guarding a single counter still leaves you wrong.', 'The emitted program has two independent bugs: one about arithmetic width and one about how a length field is read.', 'When both bugs are fixed the payload is still wrapped exactly once more before it becomes the flag.'],
  },
  {
    id: 11, ctfd_id: 11, fta_id: 'H01', name: 'H01 | Zancudo Deadbolt',
    level: 'Hard', act: 'The Final Getaway', location: 'Fort Zancudo Military Base',
    category: 'Reverse engineering', topic: 'Anti-analysis traps + chained VMs + runtime-keyed vault', value: 160, reward: 160,
    files: ['zancudo_gate', 'OPERATIONS.txt'], thumbnail: '/images/lucia-2.webp',
    briefing: 'Fort Zancudo\'s Hangar 13 deadbolt runs firmware nobody has logged into since the desert went sideways. Your only copy is a stripped native binary that refuses to be watched and asks for a single operator passphrase. It is under no obligation to tell you the truth about why it says no — and when it is being watched, it lies with a straight face and a confident banner. Behind the flattened dispatchers are two chained virtual machines, and the station\'s tables are not sitting in plaintext in the file.',
    objective: 'Defeat the anti-analysis traps, reverse both virtual machines, and recover the operator passphrase.',
    hints: ['It lies when it is being watched. Any tracing tool that trips a trap is handed a confident, WRONG answer — do not trust a \'success\'.', 'Two virtual machines, one seeding the other, and the vault tables are decrypted at runtime rather than stored in the file.', 'The check runs four transforms deep; reverse them in order, and reproduce how the binary derives its vault key at run time.'],
  },
  {
    id: 12, ctfd_id: 12, fta_id: 'H02', name: 'H02 | The Recursive Freeway',
    level: 'Hard', act: 'The Final Getaway', location: 'Final Getaway',
    category: 'Algorithms', topic: 'Weighted graph isomorphism + spectral fingerprint', value: 160, reward: 160,
    files: ['junctions.json', 'template.json', 'PROTOCOL.md'], thumbnail: '/images/lucia-3.webp',
    briefing: 'The getaway routing grid is a weighted graph in which every junction looks alike — degrees are useless as a filter. Somewhere inside sits a district that matches a stolen blueprint exactly, and several near-miss districts differ from it by a single edge or a single weight. Only the weighted spectral signature decides, and the blueprint\'s labels are read in an order that is not the node index. Brute force will not finish in time.',
    objective: 'Find the unique weight-consistent matching district and derive the clearance flag from it exactly as PROTOCOL.md specifies.',
    hints: ['Degrees will not help you — every junction looks alike. Local structure and edge weights must do the pruning.', 'Several districts are almost the blueprint; only one matches the weighted spectral fingerprint exactly.', 'The blueprint\'s labels are read in an order given by an invariant of the matched district, not by node index.'],
  },
  {
    id: 13, ctfd_id: 13, fta_id: 'H03', name: 'H03 | Impound Evidence Matryoshka',
    level: 'Hard', act: 'The Final Getaway', location: 'Los Santos Police Department',
    category: 'Multi-stage forensics', topic: '7-layer chained stego + cryptographic nesting', value: 160, reward: 160,
    files: ['impound_camera.png', 'EVIDENCE_NOTE.txt'], thumbnail: '/images/jason-1.webp',
    briefing: 'LSPD impounded a camera with a single frame and a note claiming the case was closed. Seven layers deep, three of them are bait. A blanket low-bit dump is poisoned; the note\'s frequency table gives the stride, not the codes; and each later shell is keyed by something recovered from the shell before it, so you cannot start in the middle. Only one path yields something that runs.',
    objective: 'Peel the chained layers, discard the decoys, and run the final stage to reveal the flag.',
    hints: ['A plain low-bit sweep returns bait. Only certain pixel slots carry the payload — the note\'s frequency table sets the stride and offset, but not the codes.', 'Keys depend on the layer before: later shells use nonces recovered earlier, so the chain must be walked in order.', 'Three artefacts are deliberate dead ends. The real final layer is code, and code must be executed.'],
  },
  {
    id: 14, ctfd_id: 14, fta_id: 'H04', name: 'H04 | LEGAL RAGGING',
    level: 'Hard', act: 'The Final Getaway', location: 'Fleeca Bank',
    category: 'Cryptography', topic: 'Blinded RSA-CRT fault + timing oracle + freshness gate', value: 160, reward: 160,
    files: ['bank_gateway.py', 'guest.token', 'AUDIT_BRIEF.txt'], thumbnail: '/images/jason-2.webp',
    briefing: 'Fleeca\'s mock gateway signs bank orders with RSA-CRT and keeps a \'debug\' signing route it was never supposed to ship. That route blinds what it signs and, occasionally, lies about one of its two internal halves — rarely, and in either half. A second route leaks, byte by byte, a live nonce the vault order must carry, and the verifier now also demands the right role and a fresh timestamp. Two signatures are no longer enough on their own.\n\nSPECIAL OFFLINE HINT — CREW FITNESS CHECK\n\nVisit the organizer desk to unlock an optional hint. One willing team representative can complete 10 push-ups, or choose an equivalent non-physical logic task. The organizer will provide the hint privately. This activity is optional, supervised and compliant with college rules — there is no pressure, humiliation or compulsory physical activity.',
    objective: 'Recover the signing key from the blinded, faulty debug route, satisfy the nonce and freshness gates, forge an admin order, and unlock the vault.',
    hints: ['The debug route blinds what it signs; undo the blinding before any faulty half becomes visible. It also faults rarely, and in either half.', 'The order must carry a nonce that only the second, timing-based route will reveal, and it changes every process.', 'A correctly-signed order under the wrong role — or with a stale/wrong nonce — is still refused. The brief\'s parameters are bait.'],
  },
  {
    id: 15, ctfd_id: 15, fta_id: 'H05', name: 'H05 | Last Ride Out',
    level: 'Hard', act: 'The Final Getaway', location: 'Final Getaway',
    category: 'Multilayer cryptography', topic: '4-party agreement break + HKDF + nested AES', value: 160, reward: 160,
    files: ['intercept.bin', 'final_payload.enc', 'ESCAPE_PROTOCOL.md', 'FORMAT_SPEC.txt'], thumbnail: '/images/jason-3.webp',
    briefing: 'The getaway\'s final message crossed a four-party key agreement. A captured transcript and the encrypted payload survive, and two of the four seats were never checked — read the framing and you will see which contributions are bound and which are taken on faith and re-advertised. The shared secret is not a neat sum but a weighted product, so sitting in an unchecked seat means solving for a value, not merely choosing one. The payload is nested twice, and some of the confirmations are decoys.\n\nCLASSIFIED OFFLINE INTEL\n\nCollect a confidential paper riddle from the organizer desk. Solve it to receive an additional hint for this mission.',
    objective: 'Parse the transcript, identify the unauthenticated seats, steer the weighted session key, and decrypt the nested payload.',
    hints: ['More than three voices are on the line. Read the framing: some contributions carry a binding tag and some do not — the unbound ones are trusted.', 'The session secret is a weighted product of the contributions, not a sum; steering it means solving for a share value rather than picking one.', 'There are decoy key-confirmations. The real one sits between them, and the payload is nested twice.'],
  },
];

export const LEVEL_ORDER = { Easy: 1, Medium: 2, Hard: 3 };
export const LEVEL_COLORS = {
  Easy:   { border: 'rgba(57,255,20,0.4)',  text: '#39ff14', bg: 'rgba(57,255,20,0.08)' },
  Medium: { border: 'rgba(255,165,0,0.4)',  text: '#ffa500', bg: 'rgba(255,165,0,0.08)' },
  Hard:   { border: 'rgba(255,68,68,0.5)',  text: '#ff4444', bg: 'rgba(255,68,68,0.08)' },
};
export const ACT_INFO = {
  'The Street Job':    { num: 'I',   total: '$250', count: 5 },
  'The Big Heist':     { num: 'II',  total: '$500', count: 5 },
  'The Final Getaway': { num: 'III', total: '$800', count: 5 },
};
