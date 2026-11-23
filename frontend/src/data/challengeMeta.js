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
    location: 'Lester\'s Hideout', topic: 'Custom base-41 encoding + modular filter',
    missionNum: 1, reward: 50,
    thumbnail: '/images/jason-1.webp',
    briefing: 'Lester\'s pager dumped a night of dispatch chatter, but only a fraction of it is his. The genuine courier packets never announce themselves — they are the rows whose numbers quietly agree, and even those are written in a private alphabet nobody documented. A stripped decoder was salvaged with the log; reverse it before you trust anything it says.',
    objective: 'Isolate the genuine courier rows, order them correctly, and recover the single dispatch message.',
    hints: ['Most of the log is noise. The real rows are the ones where three columns happen to satisfy one quiet arithmetic rule — and nothing in the file tells you which columns.', 'The decoder hides both its alphabet and its base. Disassemble it; you are not meant to guess them.', 'Order matters twice over: the drop is sorted on two columns with opposite directions before the payloads are decoded and joined.'],
    files: ['dispatch.csv', 'decoder'],
  },
  'E01 | Lester\'s Pager Panic': {
    fta_id: 'E01', level: 'Easy', act: 'The Street Job',
    location: 'Lester\'s Hideout', topic: 'Custom base-41 encoding + modular filter',
    missionNum: 1, reward: 50,
    thumbnail: '/images/jason-1.webp',
    briefing: 'Lester\'s pager dumped a night of dispatch chatter, but only a fraction of it is his. The genuine courier packets never announce themselves — they are the rows whose numbers quietly agree, and even those are written in a private alphabet nobody documented. A stripped decoder was salvaged with the log; reverse it before you trust anything it says.',
    objective: 'Isolate the genuine courier rows, order them correctly, and recover the single dispatch message.',
    hints: ['Most of the log is noise. The real rows are the ones where three columns happen to satisfy one quiet arithmetic rule — and nothing in the file tells you which columns.', 'The decoder hides both its alphabet and its base. Disassemble it; you are not meant to guess them.', 'Order matters twice over: the drop is sorted on two columns with opposite directions before the payloads are decoded and joined.'],
    files: ['dispatch.csv', 'decoder'],
  },
  'E02 | Vinewood Shift Change': {
    fta_id: 'E02', level: 'Easy', act: 'The Street Job',
    location: 'Vinewood Boulevard', topic: 'Affine cipher + checksum filtering',
    missionNum: 2, reward: 50,
    thumbnail: '/images/jason-2.webp',
    briefing: 'Vinewood\'s night-shift taxi ledger is mostly legitimate fares. One car was never supposed to be logged, and its manifest line is encrypted with a shift nobody wrote down. A decoy line decrypts perfectly under the lazy assumption — and leads nowhere.',
    objective: 'Find the genuine intercepted line, break its cipher, and recover the manifest.',
    hints: ['Trust the checksum, not the eye. Every genuine line pins its own timestamp to a short fingerprint that must satisfy one quiet condition.', 'The cipher is not a simple rotation — but a separate sample block is long enough for frequency analysis to hand you both of its parameters.', 'There is a trap line that decodes cleanly under the obvious method. It contains no real flag.'],
    files: ['taxi_ledger.txt', 'frequency_sample.bin'],
  },
  'E03 | Sandy Shores Hidden Stash': {
    fta_id: 'E03', level: 'Easy', act: 'The Street Job',
    location: 'Sandy Shores', topic: 'ext2 image + deleted-file recovery',
    missionNum: 3, reward: 50,
    thumbnail: '/images/jason-3.webp',
    briefing: 'The Sandy Shores safehouse yielded a dead laptop, imaged before the drive could be wiped. The file you want is already deleted — but nothing is truly gone until the blocks are reused. A dock worker\'s log survives on the image and is more useful than it looks.',
    objective: 'Recover the deleted payload from the disk image and reverse its masking.',
    hints: ['It is a real filesystem, not an archive. Deleted inodes still carry pointers to their data if you know where to look.', 'The recovered bytes are compressed and then masked with a single byte. That byte is not in the deleted file — it lives in a surviving log.', 'The mask is derived arithmetically from a field on one specific line of that log, not read literally.'],
    files: ['safehouse.img'],
  },
  'E04 | Del Perro Camera Roll': {
    fta_id: 'E04', level: 'Easy', act: 'The Street Job',
    location: 'Del Perro Pier', topic: 'PNG LSB (column-major 2-bit) + UTF-7',
    missionNum: 4, reward: 50,
    thumbnail: '/images/lucia-1.webp',
    briefing: 'Del Perro\'s pier camera caught nothing suspicious, but the file is heavier than its picture deserves. A payload rides in the low bits of its colour channels, laid out in an order no stego tool expects, wrapped in a text encoding from a forgotten decade.',
    objective: 'Extract the hidden message from the PNG and decode it.',
    hints: ['Standard LSB tools will find noise and stop. The bits live in a non-standard number of low bits, read a non-standard way.', 'Read the pixels down the columns, not across the rows — a watermark under a single colour channel nudges you toward the right direction.', 'Once you have the bitstream it is not UTF-8. It is an older, stranger text encoding.'],
    files: ['camera_roll.png', 'README.txt'],
  },
  'E05 | Wrong Extension, Right Exit': {
    fta_id: 'E05', level: 'Easy', act: 'The Street Job',
    location: 'Los Santos Customs', topic: 'PDF/ZIP polyglot + AES + SQLite',
    missionNum: 5, reward: 50,
    thumbnail: '/images/lucia-2.webp',
    briefing: 'A customs courier filed a manifest that is two files at once: it opens as a clean customs form and, to a different reader, as something else entirely. Folded inside is an encrypted archive — keyed by a serial the form prints in plain sight, if you can actually read the field and not just the text.',
    objective: 'Unwrap the polyglot, decrypt the inner archive, and query the recovered database.',
    hints: ['Extensions lie. A real PDF reader and a real unzipper each see a valid file, and the bytes disagree with the name.', 'The decryption key is not hidden — it is on the visible form. Parse the PDF field; do not just grep the raw text.', 'What comes back is a database. The flag sits behind a hash that joins two tables by an unusual key.'],
    files: ['impound_dossier.pdf'],
  },
  'M01 | Fleeca Vault Glitch': {
    fta_id: 'M01', level: 'Medium', act: 'The Big Heist',
    location: 'Fleeca Bank', topic: 'Second-order SQL injection + custom hashing',
    missionNum: 6, reward: 100,
    thumbnail: '/images/lucia-3.webp',
    briefing: 'Fleeca\'s offline kiosk has two faces: a careful registration desk and a careless profile loader that trusts what it reads back. Its login uses a home-grown password hash no cracker will recognise. To reach the vault you must trip both.',
    objective: 'Exploit the loader\'s stored-data flaw and satisfy the custom hash, then retrieve the audit record.',
    hints: ['Registration is safe. The bug is on the second visit, when stored data is reused inside a query that was never parameterised.', 'The hash is not any known algorithm. Treat the script itself as its documentation.', 'You need both a working credential and a broken query — either alone returns nothing.'],
    files: ['fleeca_kiosk.py', 'fleeca.db', 'common_pw.txt'],
  },
  'M02 | Airport Ghost Flight': {
    fta_id: 'M02', level: 'Medium', act: 'The Big Heist',
    location: 'Los Santos International Airport', topic: 'Custom binary protocol + CRC32 gating',
    missionNum: 7, reward: 100,
    thumbnail: '/images/jason-1.webp',
    briefing: 'LSIA\'s tower talks to a plane radar insists isn\'t there. The capture is raw wire, not a tidy protocol tree: the tower\'s own packets ride inside ordinary TCP, sealed with a checksum, numbered, and masked with that very seal. Most of them are fakes.',
    objective: 'Reconstruct the ghost flight\'s callsign from the capture.',
    hints: ['It is not HTTP. Walk the bytes by hand and look for a four-byte signature that marks the tower\'s own messages.', 'Not every sealed message is genuine: some fail their seal, and some carry the wrong message class. Trust only the verified ones.', 'The seal is also the mask, and the messages carry their own order — capture order is a red herring.'],
    files: ['airport_traffic.pcap', 'MANIFEST.txt'],
  },
  'M03 | LSPD Midnight Audit': {
    fta_id: 'M03', level: 'Medium', act: 'The Big Heist',
    location: 'Los Santos Police Department', topic: 'Hash-chain verification + tamper reconstruction',
    missionNum: 8, reward: 100,
    thumbnail: '/images/jason-2.webp',
    briefing: 'LSPD\'s overnight auth log claims to be tamper-evident: every line is chained to the previous one by a hash. Three lines are lies, and the chain knows it. A sidecar delta holds what the originals should have said.',
    objective: 'Verify the chain, locate and repair the forgeries, and extract the encoded flag.',
    hints: ['Do not read the log — recompute it. Each entry\'s chain hash must equal the hash of the previous chain hash plus the entry data.', 'The chain breaks exactly where it was forged. The binary delta is not a plain patch; decode its custom run-length format first.', 'After repair the flag hides across the accepted events: their event codes, folded pairwise.'],
    files: ['lspd_auth.log', 'audit_delta.bin', 'CHAIN_SPEC.txt'],
  },
  'M04 | Underground XOR Radio': {
    fta_id: 'M04', level: 'Medium', act: 'The Big Heist',
    location: 'Underground Market', topic: 'LFSR keystream + Berlekamp-Massey',
    missionNum: 9, reward: 100,
    thumbnail: '/images/jason-3.webp',
    briefing: 'A black-market radio burst is only a few hundred bytes, but its keystream came from a machine, not a passphrase. A short sample of a known header was captured alongside it — enough to rebuild the generator itself.',
    objective: 'Reconstruct the keystream generator and decrypt the packet.',
    hints: ['This is not a repeating human key. The keystream comes from a shift register, and the sample hands you its output bits.', 'The register is large enough that brute force is hopeless — recover its structure algorithmically from the bit sequence.', 'Once you can predict the stream, the rest is a flat XOR.'],
    files: ['radio_packet.bin', 'keystream_sample.bin', 'SIGNAL_SPEC.txt'],
  },
  'M05 | Debugging the Dispatch': {
    fta_id: 'M05', level: 'Medium', act: 'The Big Heist',
    location: 'Lester\'s Hideout', topic: 'Concurrency race + 32-bit checksum',
    missionNum: 10, reward: 100,
    thumbnail: '/images/lucia-1.webp',
    briefing: 'Lester\'s dispatcher is meant to rebuild a message from unordered packets, but it loses some under load, and its output is still wrapped in two more layers of its own mistakes. Two programs, two bugs, one flag.',
    objective: 'Fix the dispatcher, run it deterministically, then repair the second-stage program it produces.',
    hints: ['The loss is a race, not a logic slip — the shared counter moves without protection. More threads make it worse, not better.', 'What the fixed dispatcher produces is not the flag. It is another program, and that program has its own bug.', 'The second bug is about arithmetic width: the value must be computed as if the register were 32 bits wide, which Python will not do for you.'],
    files: ['broken_dispatch.py', 'dispatch_packets.json', 'README.txt'],
  },
  'H01 | Zancudo Deadbolt': {
    fta_id: 'H01', level: 'Hard', act: 'The Final Getaway',
    location: 'Fort Zancudo Military Base', topic: 'Obfuscated ELF + anti-debug + custom VM',
    missionNum: 11, reward: 160,
    thumbnail: '/images/lucia-2.webp',
    briefing: 'Fort Zancudo\'s Hangar 13 deadbolt runs firmware nobody has logged into since the desert went sideways. Your only copy is a stripped native binary that refuses to be watched and asks for a single operator passphrase. It is under no obligation to tell you the truth about why it says no.',
    objective: 'Reverse the station\'s check and recover the operator passphrase.',
    hints: ['It phones home before it opens. If a debugger is on the line it stays shut and feeds you a story instead of the truth.', 'The real decision hides behind a single flattened switch — reach past the dispatcher and you will find the station\'s tables in writable data.', 'A 256-byte permutation guards a prime modulus. Undo the shuffle, then undo the multiplication beneath that prime, byte by byte.'],
    files: ['zancudo_gate', 'OPERATIONS.txt'],
  },
  'H02 | The Recursive Freeway': {
    fta_id: 'H02', level: 'Hard', act: 'The Final Getaway',
    location: 'Final Getaway', topic: 'Graph isomorphism + spectral fingerprint',
    missionNum: 12, reward: 160,
    thumbnail: '/images/lucia-3.webp',
    briefing: 'The getaway routing grid is a graph of hundreds of junctions. Somewhere inside it sits a district that matches a stolen blueprint exactly — and only its spectral signature proves it. Brute force will not finish in time.',
    objective: 'Find the unique matching subgraph and derive the clearance flag from it.',
    hints: ['Match the blueprint topologically first — degree sequence and local structure prune almost everything.', 'The blueprint is isomorphic to exactly one subgraph. If several look plausible, the deciding evidence is spectral.', 'The ordered eigenvalues of the matching subgraph\'s Laplacian are the fingerprint; the flag itself is built from that subgraph\'s node labels exactly as PROTOCOL.md specifies.'],
    files: ['junctions.json', 'template.json', 'PROTOCOL.md'],
  },
  'H03 | Impound Evidence Matryoshka': {
    fta_id: 'H03', level: 'Hard', act: 'The Final Getaway',
    location: 'Los Santos Police Department', topic: '5-layer stego + cryptographic nesting',
    missionNum: 13, reward: 160,
    thumbnail: '/images/jason-1.webp',
    briefing: 'LSPD impounded a camera with a single frame and a note claiming the case was closed. Five layers deep, three of them are bait. Only one path yields something that runs.',
    objective: 'Peel the layers, ignore the decoys, and run the final stage to reveal the flag.',
    hints: ['The PNG hides something in its low bits — but the layout is not standard. The note\'s frequency table is a tree, not a code.', 'One layer is encrypted; its passphrase is derived from metadata coordinates, not from the picture.', 'Two of the intermediate artefacts are deliberate dead ends. The real final layer is code, and code must be executed.'],
    files: ['impound_camera.png', 'EVIDENCE_NOTE.txt'],
  },
  'H04 | LEGAL RAGGING': {
    fta_id: 'H04', level: 'Hard', act: 'The Final Getaway',
    location: 'Fleeca Bank', topic: 'RSA-CRT fault attack + timing oracle',
    missionNum: 14, reward: 160,
    thumbnail: '/images/jason-2.webp',
    briefing: 'Fleeca\'s mock gateway signs bank orders with RSA-CRT and keeps a \'debug\' signing route it was never supposed to ship. Occasionally that route lies about one of its two internal halves. Two signatures of the same order are enough to undo the key — and a second weakness in verification confirms the forgery.\n\nSPECIAL OFFLINE HINT — CREW FITNESS CHECK\n\nVisit the organizer desk to unlock an optional hint. One willing team representative can complete 10 push-ups, or choose an equivalent non-physical logic task. The organizer will provide the hint privately. This activity is optional, supervised and compliant with college rules — there is no pressure, humiliation or compulsory physical activity.',
    objective: 'Recover the signing key from the faulty debug route, forge an admin order, and unlock the vault.',
    hints: ['The debug route is not constant. Collect signatures of one fixed message until one of them disagrees with itself.', 'A faulty CRT half still agrees with the truth modulo one prime factor. The difference between a bad signature and the message shares a factor with the public modulus.', 'Once you own the key, sign what the vault actually wants — and note that the verifier offers a second, weaker confirmation.'],
    files: ['bank_gateway.py', 'guest.token', 'AUDIT_BRIEF.txt'],
  },
  'H05 | Last Ride Out': {
    fta_id: 'H05', level: 'Hard', act: 'The Final Getaway',
    location: 'Final Getaway', topic: '3-party protocol break + AES-GCM',
    missionNum: 15, reward: 160,
    thumbnail: '/images/jason-3.webp',
    briefing: 'The getaway\'s final message crossed a three-party key agreement. A captured transcript and the encrypted payload survive, and the protocol has one seat nobody ever checked. Sit in it, and the session key becomes yours to choose.\n\nCLASSIFIED OFFLINE INTEL\n\nCollect a confidential paper riddle from the organizer desk. Solve it to receive an additional hint for this mission.',
    objective: 'Parse the transcript, find the unchecked contribution, bias the session key, and decrypt the payload.',
    hints: ['The transcript is TLV-framed. FORMAT_SPEC.txt tells you the shape of the frames — not what each type means; you will have to work that out.', 'Three parties contribute. Two are bound to the transcript; one is taken on faith and never verified.', 'If you can choose that unverified contribution, you can steer the shared key to a value of your own — then the payload opens.'],
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
    category: 'Cryptography', topic: 'Custom base-41 encoding + modular filter', value: 50, reward: 50,
    files: ['dispatch.csv', 'decoder'], thumbnail: '/images/jason-1.webp',
    briefing: 'Lester\'s pager dumped a night of dispatch chatter, but only a fraction of it is his. The genuine courier packets never announce themselves — they are the rows whose numbers quietly agree, and even those are written in a private alphabet nobody documented. A stripped decoder was salvaged with the log; reverse it before you trust anything it says.',
    objective: 'Isolate the genuine courier rows, order them correctly, and recover the single dispatch message.',
    hints: ['Most of the log is noise. The real rows are the ones where three columns happen to satisfy one quiet arithmetic rule — and nothing in the file tells you which columns.', 'The decoder hides both its alphabet and its base. Disassemble it; you are not meant to guess them.', 'Order matters twice over: the drop is sorted on two columns with opposite directions before the payloads are decoded and joined.'],
  },
  {
    id: 2, ctfd_id: 2, fta_id: 'E02', name: 'E02 | Vinewood Shift Change',
    level: 'Easy', act: 'The Street Job', location: 'Vinewood Boulevard',
    category: 'Cryptography', topic: 'Affine cipher + checksum filtering', value: 50, reward: 50,
    files: ['taxi_ledger.txt', 'frequency_sample.bin'], thumbnail: '/images/jason-2.webp',
    briefing: 'Vinewood\'s night-shift taxi ledger is mostly legitimate fares. One car was never supposed to be logged, and its manifest line is encrypted with a shift nobody wrote down. A decoy line decrypts perfectly under the lazy assumption — and leads nowhere.',
    objective: 'Find the genuine intercepted line, break its cipher, and recover the manifest.',
    hints: ['Trust the checksum, not the eye. Every genuine line pins its own timestamp to a short fingerprint that must satisfy one quiet condition.', 'The cipher is not a simple rotation — but a separate sample block is long enough for frequency analysis to hand you both of its parameters.', 'There is a trap line that decodes cleanly under the obvious method. It contains no real flag.'],
  },
  {
    id: 3, ctfd_id: 3, fta_id: 'E03', name: 'E03 | Sandy Shores Hidden Stash',
    level: 'Easy', act: 'The Street Job', location: 'Sandy Shores',
    category: 'Linux forensics', topic: 'ext2 image + deleted-file recovery', value: 50, reward: 50,
    files: ['safehouse.img'], thumbnail: '/images/jason-3.webp',
    briefing: 'The Sandy Shores safehouse yielded a dead laptop, imaged before the drive could be wiped. The file you want is already deleted — but nothing is truly gone until the blocks are reused. A dock worker\'s log survives on the image and is more useful than it looks.',
    objective: 'Recover the deleted payload from the disk image and reverse its masking.',
    hints: ['It is a real filesystem, not an archive. Deleted inodes still carry pointers to their data if you know where to look.', 'The recovered bytes are compressed and then masked with a single byte. That byte is not in the deleted file — it lives in a surviving log.', 'The mask is derived arithmetically from a field on one specific line of that log, not read literally.'],
  },
  {
    id: 4, ctfd_id: 4, fta_id: 'E04', name: 'E04 | Del Perro Camera Roll',
    level: 'Easy', act: 'The Street Job', location: 'Del Perro Pier',
    category: 'Steganography', topic: 'PNG LSB (column-major 2-bit) + UTF-7', value: 50, reward: 50,
    files: ['camera_roll.png', 'README.txt'], thumbnail: '/images/lucia-1.webp',
    briefing: 'Del Perro\'s pier camera caught nothing suspicious, but the file is heavier than its picture deserves. A payload rides in the low bits of its colour channels, laid out in an order no stego tool expects, wrapped in a text encoding from a forgotten decade.',
    objective: 'Extract the hidden message from the PNG and decode it.',
    hints: ['Standard LSB tools will find noise and stop. The bits live in a non-standard number of low bits, read a non-standard way.', 'Read the pixels down the columns, not across the rows — a watermark under a single colour channel nudges you toward the right direction.', 'Once you have the bitstream it is not UTF-8. It is an older, stranger text encoding.'],
  },
  {
    id: 5, ctfd_id: 5, fta_id: 'E05', name: 'E05 | Wrong Extension, Right Exit',
    level: 'Easy', act: 'The Street Job', location: 'Los Santos Customs',
    category: 'File forensics', topic: 'PDF/ZIP polyglot + AES + SQLite', value: 50, reward: 50,
    files: ['impound_dossier.pdf'], thumbnail: '/images/lucia-2.webp',
    briefing: 'A customs courier filed a manifest that is two files at once: it opens as a clean customs form and, to a different reader, as something else entirely. Folded inside is an encrypted archive — keyed by a serial the form prints in plain sight, if you can actually read the field and not just the text.',
    objective: 'Unwrap the polyglot, decrypt the inner archive, and query the recovered database.',
    hints: ['Extensions lie. A real PDF reader and a real unzipper each see a valid file, and the bytes disagree with the name.', 'The decryption key is not hidden — it is on the visible form. Parse the PDF field; do not just grep the raw text.', 'What comes back is a database. The flag sits behind a hash that joins two tables by an unusual key.'],
  },
  {
    id: 6, ctfd_id: 6, fta_id: 'M01', name: 'M01 | Fleeca Vault Glitch',
    level: 'Medium', act: 'The Big Heist', location: 'Fleeca Bank',
    category: 'Web security', topic: 'Second-order SQL injection + custom hashing', value: 100, reward: 100,
    files: ['fleeca_kiosk.py', 'fleeca.db', 'common_pw.txt'], thumbnail: '/images/lucia-3.webp',
    briefing: 'Fleeca\'s offline kiosk has two faces: a careful registration desk and a careless profile loader that trusts what it reads back. Its login uses a home-grown password hash no cracker will recognise. To reach the vault you must trip both.',
    objective: 'Exploit the loader\'s stored-data flaw and satisfy the custom hash, then retrieve the audit record.',
    hints: ['Registration is safe. The bug is on the second visit, when stored data is reused inside a query that was never parameterised.', 'The hash is not any known algorithm. Treat the script itself as its documentation.', 'You need both a working credential and a broken query — either alone returns nothing.'],
  },
  {
    id: 7, ctfd_id: 7, fta_id: 'M02', name: 'M02 | Airport Ghost Flight',
    level: 'Medium', act: 'The Big Heist', location: 'Los Santos International Airport',
    category: 'Network forensics', topic: 'Custom binary protocol + CRC32 gating', value: 100, reward: 100,
    files: ['airport_traffic.pcap', 'MANIFEST.txt'], thumbnail: '/images/jason-1.webp',
    briefing: 'LSIA\'s tower talks to a plane radar insists isn\'t there. The capture is raw wire, not a tidy protocol tree: the tower\'s own packets ride inside ordinary TCP, sealed with a checksum, numbered, and masked with that very seal. Most of them are fakes.',
    objective: 'Reconstruct the ghost flight\'s callsign from the capture.',
    hints: ['It is not HTTP. Walk the bytes by hand and look for a four-byte signature that marks the tower\'s own messages.', 'Not every sealed message is genuine: some fail their seal, and some carry the wrong message class. Trust only the verified ones.', 'The seal is also the mask, and the messages carry their own order — capture order is a red herring.'],
  },
  {
    id: 8, ctfd_id: 8, fta_id: 'M03', name: 'M03 | LSPD Midnight Audit',
    level: 'Medium', act: 'The Big Heist', location: 'Los Santos Police Department',
    category: 'Log forensics', topic: 'Hash-chain verification + tamper reconstruction', value: 100, reward: 100,
    files: ['lspd_auth.log', 'audit_delta.bin', 'CHAIN_SPEC.txt'], thumbnail: '/images/jason-2.webp',
    briefing: 'LSPD\'s overnight auth log claims to be tamper-evident: every line is chained to the previous one by a hash. Three lines are lies, and the chain knows it. A sidecar delta holds what the originals should have said.',
    objective: 'Verify the chain, locate and repair the forgeries, and extract the encoded flag.',
    hints: ['Do not read the log — recompute it. Each entry\'s chain hash must equal the hash of the previous chain hash plus the entry data.', 'The chain breaks exactly where it was forged. The binary delta is not a plain patch; decode its custom run-length format first.', 'After repair the flag hides across the accepted events: their event codes, folded pairwise.'],
  },
  {
    id: 9, ctfd_id: 9, fta_id: 'M04', name: 'M04 | Underground XOR Radio',
    level: 'Medium', act: 'The Big Heist', location: 'Underground Market',
    category: 'Cryptography', topic: 'LFSR keystream + Berlekamp-Massey', value: 100, reward: 100,
    files: ['radio_packet.bin', 'keystream_sample.bin', 'SIGNAL_SPEC.txt'], thumbnail: '/images/jason-3.webp',
    briefing: 'A black-market radio burst is only a few hundred bytes, but its keystream came from a machine, not a passphrase. A short sample of a known header was captured alongside it — enough to rebuild the generator itself.',
    objective: 'Reconstruct the keystream generator and decrypt the packet.',
    hints: ['This is not a repeating human key. The keystream comes from a shift register, and the sample hands you its output bits.', 'The register is large enough that brute force is hopeless — recover its structure algorithmically from the bit sequence.', 'Once you can predict the stream, the rest is a flat XOR.'],
  },
  {
    id: 10, ctfd_id: 10, fta_id: 'M05', name: 'M05 | Debugging the Dispatch',
    level: 'Medium', act: 'The Big Heist', location: 'Lester\'s Hideout',
    category: 'Programming', topic: 'Concurrency race + 32-bit checksum', value: 100, reward: 100,
    files: ['broken_dispatch.py', 'dispatch_packets.json', 'README.txt'], thumbnail: '/images/lucia-1.webp',
    briefing: 'Lester\'s dispatcher is meant to rebuild a message from unordered packets, but it loses some under load, and its output is still wrapped in two more layers of its own mistakes. Two programs, two bugs, one flag.',
    objective: 'Fix the dispatcher, run it deterministically, then repair the second-stage program it produces.',
    hints: ['The loss is a race, not a logic slip — the shared counter moves without protection. More threads make it worse, not better.', 'What the fixed dispatcher produces is not the flag. It is another program, and that program has its own bug.', 'The second bug is about arithmetic width: the value must be computed as if the register were 32 bits wide, which Python will not do for you.'],
  },
  {
    id: 11, ctfd_id: 11, fta_id: 'H01', name: 'H01 | Zancudo Deadbolt',
    level: 'Hard', act: 'The Final Getaway', location: 'Fort Zancudo Military Base',
    category: 'Reverse engineering', topic: 'Obfuscated ELF + anti-debug + custom VM', value: 160, reward: 160,
    files: ['zancudo_gate', 'OPERATIONS.txt'], thumbnail: '/images/lucia-2.webp',
    briefing: 'Fort Zancudo\'s Hangar 13 deadbolt runs firmware nobody has logged into since the desert went sideways. Your only copy is a stripped native binary that refuses to be watched and asks for a single operator passphrase. It is under no obligation to tell you the truth about why it says no.',
    objective: 'Reverse the station\'s check and recover the operator passphrase.',
    hints: ['It phones home before it opens. If a debugger is on the line it stays shut and feeds you a story instead of the truth.', 'The real decision hides behind a single flattened switch — reach past the dispatcher and you will find the station\'s tables in writable data.', 'A 256-byte permutation guards a prime modulus. Undo the shuffle, then undo the multiplication beneath that prime, byte by byte.'],
  },
  {
    id: 12, ctfd_id: 12, fta_id: 'H02', name: 'H02 | The Recursive Freeway',
    level: 'Hard', act: 'The Final Getaway', location: 'Final Getaway',
    category: 'Algorithms', topic: 'Graph isomorphism + spectral fingerprint', value: 160, reward: 160,
    files: ['junctions.json', 'template.json', 'PROTOCOL.md'], thumbnail: '/images/lucia-3.webp',
    briefing: 'The getaway routing grid is a graph of hundreds of junctions. Somewhere inside it sits a district that matches a stolen blueprint exactly — and only its spectral signature proves it. Brute force will not finish in time.',
    objective: 'Find the unique matching subgraph and derive the clearance flag from it.',
    hints: ['Match the blueprint topologically first — degree sequence and local structure prune almost everything.', 'The blueprint is isomorphic to exactly one subgraph. If several look plausible, the deciding evidence is spectral.', 'The ordered eigenvalues of the matching subgraph\'s Laplacian are the fingerprint; the flag itself is built from that subgraph\'s node labels exactly as PROTOCOL.md specifies.'],
  },
  {
    id: 13, ctfd_id: 13, fta_id: 'H03', name: 'H03 | Impound Evidence Matryoshka',
    level: 'Hard', act: 'The Final Getaway', location: 'Los Santos Police Department',
    category: 'Multi-stage forensics', topic: '5-layer stego + cryptographic nesting', value: 160, reward: 160,
    files: ['impound_camera.png', 'EVIDENCE_NOTE.txt'], thumbnail: '/images/jason-1.webp',
    briefing: 'LSPD impounded a camera with a single frame and a note claiming the case was closed. Five layers deep, three of them are bait. Only one path yields something that runs.',
    objective: 'Peel the layers, ignore the decoys, and run the final stage to reveal the flag.',
    hints: ['The PNG hides something in its low bits — but the layout is not standard. The note\'s frequency table is a tree, not a code.', 'One layer is encrypted; its passphrase is derived from metadata coordinates, not from the picture.', 'Two of the intermediate artefacts are deliberate dead ends. The real final layer is code, and code must be executed.'],
  },
  {
    id: 14, ctfd_id: 14, fta_id: 'H04', name: 'H04 | LEGAL RAGGING',
    level: 'Hard', act: 'The Final Getaway', location: 'Fleeca Bank',
    category: 'Cryptography', topic: 'RSA-CRT fault attack + timing oracle', value: 160, reward: 160,
    files: ['bank_gateway.py', 'guest.token', 'AUDIT_BRIEF.txt'], thumbnail: '/images/jason-2.webp',
    briefing: 'Fleeca\'s mock gateway signs bank orders with RSA-CRT and keeps a \'debug\' signing route it was never supposed to ship. Occasionally that route lies about one of its two internal halves. Two signatures of the same order are enough to undo the key — and a second weakness in verification confirms the forgery.\n\nSPECIAL OFFLINE HINT — CREW FITNESS CHECK\n\nVisit the organizer desk to unlock an optional hint. One willing team representative can complete 10 push-ups, or choose an equivalent non-physical logic task. The organizer will provide the hint privately. This activity is optional, supervised and compliant with college rules — there is no pressure, humiliation or compulsory physical activity.',
    objective: 'Recover the signing key from the faulty debug route, forge an admin order, and unlock the vault.',
    hints: ['The debug route is not constant. Collect signatures of one fixed message until one of them disagrees with itself.', 'A faulty CRT half still agrees with the truth modulo one prime factor. The difference between a bad signature and the message shares a factor with the public modulus.', 'Once you own the key, sign what the vault actually wants — and note that the verifier offers a second, weaker confirmation.'],
  },
  {
    id: 15, ctfd_id: 15, fta_id: 'H05', name: 'H05 | Last Ride Out',
    level: 'Hard', act: 'The Final Getaway', location: 'Final Getaway',
    category: 'Multilayer cryptography', topic: '3-party protocol break + AES-GCM', value: 160, reward: 160,
    files: ['intercept.bin', 'final_payload.enc', 'ESCAPE_PROTOCOL.md', 'FORMAT_SPEC.txt'], thumbnail: '/images/jason-3.webp',
    briefing: 'The getaway\'s final message crossed a three-party key agreement. A captured transcript and the encrypted payload survive, and the protocol has one seat nobody ever checked. Sit in it, and the session key becomes yours to choose.\n\nCLASSIFIED OFFLINE INTEL\n\nCollect a confidential paper riddle from the organizer desk. Solve it to receive an additional hint for this mission.',
    objective: 'Parse the transcript, find the unchecked contribution, bias the session key, and decrypt the payload.',
    hints: ['The transcript is TLV-framed. FORMAT_SPEC.txt tells you the shape of the frames — not what each type means; you will have to work that out.', 'Three parties contribute. Two are bound to the transcript; one is taken on faith and never verified.', 'If you can choose that unverified contribution, you can steer the shared key to a value of your own — then the payload opens.'],
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
