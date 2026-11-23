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
    location: "Lester's Hideout", topic: 'Base64 decoding',
    missionNum: 1, reward: 50,
    thumbnail: '/images/jason-1.webp',
    briefing: 'A courier scattered the dispatch into numbered transmissions. Reassemble the real courier packets by sequence and decode the Base64 message. Ignore broadcast noise.',
    objective: 'Filter courier=YES, order seq as numbers, Base64-decode each payload and join.',
    hints: ['The courier column identifies actual orders, not public broadcasts.', 'Order courier packets by numeric sequence before decoding.', 'Each payload is independently Base64-encoded; decode each and concatenate.'],
    files: ['dispatch.csv'],
  },
  'E01 | Lester\'s Pager Panic': {
    fta_id: 'E01', level: 'Easy', act: 'The Street Job',
    location: "Lester's Hideout", topic: 'Base64 decoding',
    missionNum: 1, reward: 50,
    thumbnail: '/images/jason-1.webp',
    briefing: 'A courier scattered the dispatch into numbered transmissions. Reassemble the real courier packets by sequence and decode the Base64 message. Ignore broadcast noise.',
    objective: 'Filter courier=YES, order seq as numbers, Base64-decode each payload and join.',
    hints: ['The courier column identifies actual orders, not public broadcasts.', 'Order courier packets by numeric sequence before decoding.', 'Each payload is independently Base64-encoded; decode each and concatenate.'],
    files: ['dispatch.csv'],
  },
  'E02 | Vinewood Shift Change': {
    fta_id: 'E02', level: 'Easy', act: 'The Street Job',
    location: 'Vinewood Boulevard', topic: 'Caesar cipher',
    missionNum: 2, reward: 50,
    thumbnail: '/images/jason-2.webp',
    briefing: 'A taxi ledger contains three intercepted messages. The wanted driver used the route marked MIDNIGHT. Recover that message using a Caesar rotation.',
    objective: 'Identify the MIDNIGHT line, shift alphabetic letters back five positions.',
    hints: ['Only the MIDNIGHT route is part of the job.', 'Four road wheels plus the one spare tell you the rotation.', 'Undo a shift of five letters on the MIDNIGHT ciphertext.'],
    files: ['taxi_ledger.txt'],
  },
  'E03 | Sandy Shores Hidden Stash': {
    fta_id: 'E03', level: 'Easy', act: 'The Street Job',
    location: 'Sandy Shores', topic: 'Hidden files',
    missionNum: 3, reward: 50,
    thumbnail: '/images/jason-3.webp',
    briefing: 'A zipped safehouse folder looks empty except for innocent receipts. The valuable manifest is concealed from ordinary directory listings.',
    objective: 'unzip safehouse.zip; find .drop_manifest; use xxd -r -p on its hex line.',
    hints: ['Use unzip; then inspect the extracted directory, not the ZIP listing alone.', 'Try ls -la inside the safehouse folder.', 'The dotfile contains hex bytes; use xxd -r -p or bytes.fromhex().'],
    files: ['safehouse.zip'],
  },
  'E04 | Del Perro Camera Roll': {
    fta_id: 'E04', level: 'Easy', act: 'The Street Job',
    location: 'Del Perro Pier', topic: 'PNG metadata',
    missionNum: 4, reward: 50,
    thumbnail: '/images/lucia-1.webp',
    briefing: 'A security-camera still has an unhelpful picture, but the technician left a dispatch string in PNG metadata. Inspect metadata fields rather than guessing pixels.',
    objective: 'Read PNG dispatch_note tEXt metadata, Base32 decode.',
    hints: ['PNG text metadata can carry notes separate from pixel data.', 'Inspect via exiftool, identify -verbose, or Pillow image.info.', 'Decode the Base32 string stored under dispatch_note.'],
    files: ['pier_camera.png'],
  },
  'E05 | Wrong Extension, Right Exit': {
    fta_id: 'E05', level: 'Easy', act: 'The Street Job',
    location: 'Los Santos Customs', topic: 'File signatures',
    missionNum: 5, reward: 50,
    thumbnail: '/images/lucia-2.webp',
    briefing: 'An informant labeled a cargo archive as a JPEG to get it past inspection. Identify what it actually is, open it, and read the hexadecimal shipment code.',
    objective: 'file customs_camera.jpg; unzip; decode receipt hex.',
    hints: ['File extensions can lie. Check the first bytes with file or xxd.', 'The bytes start with a ZIP signature; unzip the archive.', 'The verified receipt has a hex-encoded message. Decode it.'],
    files: ['customs_camera.jpg'],
  },
  'M01 | Fleeca Vault Glitch': {
    fta_id: 'M01', level: 'Medium', act: 'The Big Heist',
    location: 'Fleeca Bank', topic: 'SQL injection simulation',
    missionNum: 6, reward: 100,
    thumbnail: '/images/lucia-3.webp',
    briefing: "Fleeca's offline kiosk accepts a locker owner and PIN. An old SQL query incorrectly trusts the owner field. Use this local-only simulation to retrieve the audit record.",
    objective: "Run python fleeca_kiosk.py, owner: ' OR 1=1 -- ; PIN anything.",
    hints: ['Read the SQL query built inside fleeca_kiosk.py.', "A quote can break out of the owner string; -- starts a SQLite comment.", 'Try an always-true condition in the owner field and a disposable PIN.'],
    files: ['fleeca_kiosk.py', 'fleeca.db'],
  },
  'M02 | Airport Ghost Flight': {
    fta_id: 'M02', level: 'Medium', act: 'The Big Heist',
    location: 'Los Santos International Airport', topic: 'HTTP / PCAP',
    missionNum: 7, reward: 100,
    thumbnail: '/images/jason-1.webp',
    briefing: 'A capture from a fictional airport LAN contains mixed flight dispatches. Follow the HTTP requests for flight LS-447; sort chunks and decode its cargo header.',
    objective: 'Wireshark http filter X-Flight LS-447; order X-Chunk and Base64 decode X-Cargo.',
    hints: ['All traffic is unencrypted HTTP inside the provided capture.', 'Filter requests on X-Flight: LS-447, then sort X-Chunk numerically.', 'Each X-Cargo header is Base64 for one chunk of the answer.'],
    files: ['airport_dispatch.pcap'],
  },
  'M03 | LSPD Midnight Audit': {
    fta_id: 'M03', level: 'Medium', act: 'The Big Heist',
    location: 'Los Santos Police Department', topic: 'Event correlation',
    missionNum: 8, reward: 100,
    thumbnail: '/images/jason-2.webp',
    briefing: 'LSPD recovered an auth log with hundreds of entries. Correlate case 714 success events, exclude tampered failures, and decode the sequential hexadecimal fragments.',
    objective: 'Filter case=714 source=FORENSIC result=ACCEPT; order part; join fraghex; fromhex.',
    hints: ['Correlate the case and identity markers in CASE_BRIEF.txt.', 'Keep case=714, host=lspd-evidence, account=case_clerk, source=FORENSIC, result=ACCEPT.', 'Sort part numbers before combining fraghex fields and converting hex to text.'],
    files: ['lspd_auth.log', 'CASE_BRIEF.txt'],
  },
  'M04 | Underground XOR Radio': {
    fta_id: 'M04', level: 'Medium', act: 'The Big Heist',
    location: 'Underground Market', topic: 'Repeating-key XOR',
    missionNum: 9, reward: 100,
    thumbnail: '/images/jason-3.webp',
    briefing: 'A black-market radio packet uses a repeating XOR key. The key bytes are recorded out of order on a checkpoint sheet; restore the route order and decrypt.',
    objective: 'Construct ordered hex key from CSV; repeated XOR radio_packet.bin.',
    hints: ['The CSV lists numeric stop order and one hexadecimal key byte per stop.', 'Build the key by sorting checkpoint_keys.csv on stop, then bytes.fromhex.', 'XOR each ciphertext byte with key[i % len(key)].'],
    files: ['radio_packet.bin', 'checkpoint_keys.csv'],
  },
  'M05 | Debugging the Dispatch': {
    fta_id: 'M05', level: 'Medium', act: 'The Big Heist',
    location: "Lester's Hideout", topic: 'Python debugging',
    missionNum: 10, reward: 100,
    thumbnail: '/images/lucia-1.webp',
    briefing: 'A courier script is intended to reconstruct a Base64 dispatch from unordered JSON packets, but three tiny defects corrupt the answer. Repair the processing logic.',
    objective: 'Fix lexicographic sorting, last-item omission, and base64 padding in broken_dispatch.py.',
    hints: ['Check how sequence numbers compare when left as strings.', 'The dispatcher must include every packet, including the last one.', 'URL-safe Base64 often needs missing padding restored.'],
    files: ['broken_dispatch.py', 'dispatch_packets.json', 'README_DEBUG.txt'],
  },
  'H01 | Zancudo Deadbolt': {
    fta_id: 'H01', level: 'Hard', act: 'The Final Getaway',
    location: 'Fort Zancudo Military Base', topic: 'ELF binary',
    missionNum: 11, reward: 160,
    thumbnail: '/images/lucia-2.webp',
    briefing: 'A fictional military gate terminal has no source code and asks for a twelve-character authorization phrase. Reverse its byte-check logic to unlock the terminal.',
    objective: 'Disassemble the XOR check; recover password bytes from fixed table, execute ELF.',
    hints: ['Use file, strings, and objdump -d (or Ghidra). This is a Linux ELF.', 'The passphrase loop compares each input byte after a position-dependent XOR.', 'Invert the XOR against the 12 comparison constants, then run the binary.'],
    files: ['zancudo_gate', 'OPERATIONS.txt'],
  },
  'H02 | The Recursive Freeway': {
    fta_id: 'H02', level: 'Hard', act: 'The Final Getaway',
    location: 'Final Getaway', topic: 'Memoized DAG recursion',
    missionNum: 12, reward: 160,
    thumbnail: '/images/lucia-3.webp',
    briefing: 'An auto-routing system models a freeway with 70 dependent junctions. Follow the exact recursive arithmetic in PROTOCOL.md, memoize to avoid repeated work.',
    objective: 'Memoized DAG evaluator to calculate destination; format final 8-hex value and hash suffix.',
    hints: ['Terminal nodes have literal values; branch nodes depend on two earlier nodes.', 'Memoize the function F(node) and apply the 32-bit mask at every branch.', 'The final flag is derived from the destination value and its SHA-256 suffix exactly as PROTOCOL.md specifies.'],
    files: ['junctions.json', 'PROTOCOL.md'],
  },
  'H03 | Impound Evidence Matryoshka': {
    fta_id: 'H03', level: 'Hard', act: 'The Final Getaway',
    location: 'Los Santos Police Department', topic: 'Polyglot archives',
    missionNum: 13, reward: 160,
    thumbnail: '/images/jason-1.webp',
    briefing: 'LSPD buried a case packet in a camera PNG. Recover the embedded archive, peel the compression layers, and decode the matching case payload.',
    objective: 'Open PNG as ZIP; open case_144 .gz as gzip; read tar member dossier.json; a85decode + zlib.decompress.',
    hints: ['A PNG may contain trailing bytes after IEND. Try zipfile or unzip on the PNG.', 'Within case_144, one .gz member holds a TAR archive.', 'Find dossier.json and Base85-decode then zlib-decompress the recorded payload.'],
    files: ['impound_camera.png', 'EVIDENCE_NOTE.txt'],
  },
  'H04 | Fleeca Trust Fall': {
    fta_id: 'H04', level: 'Hard', act: 'The Final Getaway',
    location: 'Fleeca Bank', topic: 'Unsigned token logic',
    missionNum: 14, reward: 160,
    thumbnail: '/images/jason-2.webp',
    briefing: 'A local mock bank gateway makes a dangerous assumption about client-supplied authorization tokens. Audit source, identify the trust-boundary mistake, and demonstrate it only within the provided CLI.',
    objective: 'Create base64url header {alg:none,typ:JWT}, payload {role:admin,sub:auditor}, empty signature; run local gateway.',
    hints: ['The token has three dot-separated Base64URL segments.', 'Review the alg=none branch and the role assertion.', 'Forge a token whose header selects none and whose payload claims role=admin.'],
    files: ['bank_gateway.py', 'guest.token', 'audit_vault.bin', 'AUDIT_BRIEF.txt'],
  },
  'H05 | Last Ride Out': {
    fta_id: 'H05', level: 'Hard', act: 'The Final Getaway',
    location: 'Final Getaway', topic: 'Route-key derivation and layers',
    missionNum: 15, reward: 160,
    thumbnail: '/images/jason-3.webp',
    briefing: 'A getaway message crossed multiple radio encodings. The valid vehicle must satisfy the route constraints; use its plate and terminal to derive the XOR key and reverse the remaining layers.',
    objective: 'Choose qualifying route; base85 decode intercept, decompress, XOR SHA256(plate:terminal) digest.',
    hints: ['Select only a vehicle with wanted=0, fuel_km>=route_km and clearance=YES.', 'Use SHA-256 of PLATE:TERMINAL as the repeating XOR stream key.', 'Reverse the packet order: Base85 decode, zlib decompress, then XOR with the derived digest bytes.'],
    files: ['getaway_routes.csv', 'intercept.txt', 'LAYER_NOTES.md'],
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
    level: 'Easy', act: 'The Street Job', location: "Lester's Hideout",
    category: 'Cryptography', topic: 'Base64 decoding', value: 50, reward: 50,
    files: ['dispatch.csv'], thumbnail: '/images/jason-1.webp',
    briefing: 'A courier scattered the dispatch into numbered transmissions. Reassemble the real courier packets by sequence and decode the Base64 message. Ignore broadcast noise.',
    objective: 'Filter courier=YES, order seq as numbers, Base64-decode each payload and join.',
    hints: ['The courier column identifies actual orders, not public broadcasts.', 'Order courier packets by numeric sequence before decoding.', 'Each payload is independently Base64-encoded; decode each and concatenate.'],
  },
  {
    id: 2, ctfd_id: 2, fta_id: 'E02', name: 'E02 | Vinewood Shift Change',
    level: 'Easy', act: 'The Street Job', location: 'Vinewood Boulevard',
    category: 'Cryptography', topic: 'Caesar cipher', value: 50, reward: 50,
    files: ['taxi_ledger.txt'], thumbnail: '/images/jason-2.webp',
    briefing: 'A taxi ledger contains three intercepted messages. The wanted driver used the route marked MIDNIGHT. Recover that message using a Caesar rotation.',
    objective: 'Identify the MIDNIGHT line, shift alphabetic letters back five positions.',
    hints: ['Only the MIDNIGHT route is part of the job.', 'Four road wheels plus the one spare tell you the rotation.', 'Undo a shift of five letters on the MIDNIGHT ciphertext.'],
  },
  {
    id: 3, ctfd_id: 3, fta_id: 'E03', name: 'E03 | Sandy Shores Hidden Stash',
    level: 'Easy', act: 'The Street Job', location: 'Sandy Shores',
    category: 'Linux forensics', topic: 'Hidden files', value: 50, reward: 50,
    files: ['safehouse.zip'], thumbnail: '/images/jason-3.webp',
    briefing: 'A zipped safehouse folder looks empty except for innocent receipts. The valuable manifest is concealed from ordinary directory listings.',
    objective: 'unzip safehouse.zip; find .drop_manifest; use xxd -r -p on its hex line.',
    hints: ['Use unzip; then inspect the extracted directory, not the ZIP listing alone.', 'Try ls -la inside the safehouse folder.', 'The dotfile contains hex bytes; use xxd -r -p or bytes.fromhex().'],
  },
  {
    id: 4, ctfd_id: 4, fta_id: 'E04', name: 'E04 | Del Perro Camera Roll',
    level: 'Easy', act: 'The Street Job', location: 'Del Perro Pier',
    category: 'Digital forensics', topic: 'PNG metadata', value: 50, reward: 50,
    files: ['pier_camera.png'], thumbnail: '/images/lucia-1.webp',
    briefing: 'A security-camera still has an unhelpful picture, but the technician left a dispatch string in PNG metadata. Inspect metadata fields rather than guessing pixels.',
    objective: 'Read PNG dispatch_note tEXt metadata, Base32 decode.',
    hints: ['PNG text metadata can carry notes separate from pixel data.', 'Inspect via exiftool, identify -verbose, or Pillow image.info.', 'Decode the Base32 string stored under dispatch_note.'],
  },
  {
    id: 5, ctfd_id: 5, fta_id: 'E05', name: 'E05 | Wrong Extension, Right Exit',
    level: 'Easy', act: 'The Street Job', location: 'Los Santos Customs',
    category: 'File forensics', topic: 'File signatures', value: 50, reward: 50,
    files: ['customs_camera.jpg'], thumbnail: '/images/lucia-2.webp',
    briefing: 'An informant labeled a cargo archive as a JPEG to get it past inspection. Identify what it actually is, open it, and read the hexadecimal shipment code.',
    objective: 'file customs_camera.jpg; unzip; decode receipt hex.',
    hints: ['File extensions can lie. Check the first bytes with file or xxd.', 'The bytes start with a ZIP signature; unzip the archive.', 'The verified receipt has a hex-encoded message. Decode it.'],
  },
  {
    id: 6, ctfd_id: 6, fta_id: 'M01', name: 'M01 | Fleeca Vault Glitch',
    level: 'Medium', act: 'The Big Heist', location: 'Fleeca Bank',
    category: 'Web security', topic: 'SQL injection simulation', value: 100, reward: 100,
    files: ['fleeca_kiosk.py', 'fleeca.db'], thumbnail: '/images/lucia-3.webp',
    briefing: "Fleeca's offline kiosk accepts a locker owner and PIN. An old SQL query incorrectly trusts the owner field. Use this local-only simulation to retrieve the audit record.",
    objective: "Run python fleeca_kiosk.py, owner: ' OR 1=1 -- ; PIN anything.",
    hints: ['Read the SQL query built inside fleeca_kiosk.py.', "A quote can break out of the owner string; -- starts a SQLite comment.", 'Try an always-true condition in the owner field and a disposable PIN.'],
  },
  {
    id: 7, ctfd_id: 7, fta_id: 'M02', name: 'M02 | Airport Ghost Flight',
    level: 'Medium', act: 'The Big Heist', location: 'Los Santos International Airport',
    category: 'Network forensics', topic: 'HTTP / PCAP', value: 100, reward: 100,
    files: ['airport_dispatch.pcap'], thumbnail: '/images/jason-1.webp',
    briefing: 'A capture from a fictional airport LAN contains mixed flight dispatches. Follow the HTTP requests for flight LS-447; sort chunks and decode its cargo header.',
    objective: 'Wireshark http filter X-Flight LS-447; order X-Chunk and Base64 decode X-Cargo.',
    hints: ['All traffic is unencrypted HTTP inside the provided capture.', 'Filter requests on X-Flight: LS-447, then sort X-Chunk numerically.', 'Each X-Cargo header is Base64 for one chunk of the answer.'],
  },
  {
    id: 8, ctfd_id: 8, fta_id: 'M03', name: 'M03 | LSPD Midnight Audit',
    level: 'Medium', act: 'The Big Heist', location: 'Los Santos Police Department',
    category: 'Log forensics', topic: 'Event correlation', value: 100, reward: 100,
    files: ['lspd_auth.log', 'CASE_BRIEF.txt'], thumbnail: '/images/jason-2.webp',
    briefing: 'LSPD recovered an auth log with hundreds of entries. Correlate case 714 success events, exclude tampered failures, and decode the sequential hexadecimal fragments.',
    objective: 'Filter case=714 source=FORENSIC result=ACCEPT; order part; join fraghex; fromhex.',
    hints: ['Correlate the case and identity markers in CASE_BRIEF.txt.', 'Keep case=714, host=lspd-evidence, account=case_clerk, source=FORENSIC, result=ACCEPT.', 'Sort part numbers before combining fraghex fields and converting hex to text.'],
  },
  {
    id: 9, ctfd_id: 9, fta_id: 'M04', name: 'M04 | Underground XOR Radio',
    level: 'Medium', act: 'The Big Heist', location: 'Underground Market',
    category: 'Cryptography', topic: 'Repeating-key XOR', value: 100, reward: 100,
    files: ['radio_packet.bin', 'checkpoint_keys.csv'], thumbnail: '/images/jason-3.webp',
    briefing: 'A black-market radio packet uses a repeating XOR key. The key bytes are recorded out of order on a checkpoint sheet; restore the route order and decrypt.',
    objective: 'Construct ordered hex key from CSV; repeated XOR radio_packet.bin.',
    hints: ['The CSV lists numeric stop order and one hexadecimal key byte per stop.', 'Build the key by sorting checkpoint_keys.csv on stop, then bytes.fromhex.', 'XOR each ciphertext byte with key[i % len(key)].'],
  },
  {
    id: 10, ctfd_id: 10, fta_id: 'M05', name: 'M05 | Debugging the Dispatch',
    level: 'Medium', act: 'The Big Heist', location: "Lester's Hideout",
    category: 'Programming', topic: 'Python debugging', value: 100, reward: 100,
    files: ['broken_dispatch.py', 'dispatch_packets.json', 'README_DEBUG.txt'], thumbnail: '/images/lucia-1.webp',
    briefing: 'A courier script is intended to reconstruct a Base64 dispatch from unordered JSON packets, but three tiny defects corrupt the answer. Repair the processing logic.',
    objective: 'Fix lexicographic sorting, last-item omission, and base64 padding in broken_dispatch.py.',
    hints: ['Check how sequence numbers compare when left as strings.', 'The dispatcher must include every packet, including the last one.', 'URL-safe Base64 often needs missing padding restored.'],
  },
  {
    id: 11, ctfd_id: 11, fta_id: 'H01', name: 'H01 | Zancudo Deadbolt',
    level: 'Hard', act: 'The Final Getaway', location: 'Fort Zancudo Military Base',
    category: 'Reverse engineering', topic: 'ELF binary', value: 160, reward: 160,
    files: ['zancudo_gate', 'OPERATIONS.txt'], thumbnail: '/images/lucia-2.webp',
    briefing: 'A fictional military gate terminal has no source code and asks for a twelve-character authorization phrase. Reverse its byte-check logic to unlock the terminal.',
    objective: 'Disassemble the XOR check; recover password bytes from fixed table, execute ELF.',
    hints: ['Use file, strings, and objdump -d (or Ghidra). This is a Linux ELF.', 'The passphrase loop compares each input byte after a position-dependent XOR.', 'Invert the XOR against the 12 comparison constants, then run the binary.'],
  },
  {
    id: 12, ctfd_id: 12, fta_id: 'H02', name: 'H02 | The Recursive Freeway',
    level: 'Hard', act: 'The Final Getaway', location: 'Final Getaway',
    category: 'Algorithms', topic: 'Memoized DAG recursion', value: 160, reward: 160,
    files: ['junctions.json', 'PROTOCOL.md'], thumbnail: '/images/lucia-3.webp',
    briefing: 'An auto-routing system models a freeway with 70 dependent junctions. Follow the exact recursive arithmetic in PROTOCOL.md, memoize to avoid repeated work.',
    objective: 'Memoized DAG evaluator to calculate destination; format final 8-hex value and hash suffix.',
    hints: ['Terminal nodes have literal values; branch nodes depend on two earlier nodes.', 'Memoize the function F(node) and apply the 32-bit mask at every branch.', 'The final flag is derived from the destination value and its SHA-256 suffix exactly as PROTOCOL.md specifies.'],
  },
  {
    id: 13, ctfd_id: 13, fta_id: 'H03', name: 'H03 | Impound Evidence Matryoshka',
    level: 'Hard', act: 'The Final Getaway', location: 'Los Santos Police Department',
    category: 'Multi-stage forensics', topic: 'Polyglot archives', value: 160, reward: 160,
    files: ['impound_camera.png', 'EVIDENCE_NOTE.txt'], thumbnail: '/images/jason-1.webp',
    briefing: 'LSPD buried a case packet in a camera PNG. Recover the embedded archive, peel the compression layers, and decode the matching case payload.',
    objective: 'Open PNG as ZIP; open case_144 .gz as gzip; read tar member dossier.json; a85decode + zlib.decompress.',
    hints: ['A PNG may contain trailing bytes after IEND. Try zipfile or unzip on the PNG.', 'Within case_144, one .gz member holds a TAR archive.', 'Find dossier.json and Base85-decode then zlib-decompress the recorded payload.'],
  },
  {
    id: 14, ctfd_id: 14, fta_id: 'H04', name: 'H04 | Fleeca Trust Fall',
    level: 'Hard', act: 'The Final Getaway', location: 'Fleeca Bank',
    category: 'Secure code review', topic: 'Unsigned token logic', value: 160, reward: 160,
    files: ['bank_gateway.py', 'guest.token', 'audit_vault.bin', 'AUDIT_BRIEF.txt'], thumbnail: '/images/jason-2.webp',
    briefing: 'A local mock bank gateway makes a dangerous assumption about client-supplied authorization tokens. Audit source, identify the trust-boundary mistake, and demonstrate it only within the provided CLI.',
    objective: 'Create base64url header {alg:none,typ:JWT}, payload {role:admin,sub:auditor}, empty signature; run local gateway.',
    hints: ['The token has three dot-separated Base64URL segments.', 'Review the alg=none branch and the role assertion.', 'Forge a token whose header selects none and whose payload claims role=admin.'],
  },
  {
    id: 15, ctfd_id: 15, fta_id: 'H05', name: 'H05 | Last Ride Out',
    level: 'Hard', act: 'The Final Getaway', location: 'Final Getaway',
    category: 'Multilayer cryptography', topic: 'Route-key derivation and layers', value: 160, reward: 160,
    files: ['getaway_routes.csv', 'intercept.txt', 'LAYER_NOTES.md'], thumbnail: '/images/jason-3.webp',
    briefing: 'A getaway message crossed multiple radio encodings. The valid vehicle must satisfy the route constraints; use its plate and terminal to derive the XOR key and reverse the remaining layers.',
    objective: 'Choose qualifying route; base85 decode intercept, decompress, XOR SHA256(plate:terminal) digest.',
    hints: ['Select only a vehicle with wanted=0, fuel_km>=route_km and clearance=YES.', 'Use SHA-256 of PLATE:TERMINAL as the repeating XOR stream key.', 'Reverse the packet order: Base85 decode, zlib decompress, then XOR with the derived digest bytes.'],
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
