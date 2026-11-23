# Local Test Report — FLAG THEFT AUTO (15 rebuilt challenges)

**Date:** 2026-11-23
**Method:** artifact-only (black-box) reconstruction. `organizer_private/validate_challenges.py`
re-implements all 15 attacks from scratch, importing **none** of the private generator helpers
(`lib_fta`) and reading **only** the participant files shipped in `challenges/<LEVEL>/<CID>/`.
It then asserts each recovered flag equals the organizer manifest flag and writes
`organizer_private/CTFD_IMPORT/validation_results.json`. A "green" run therefore proves the
challenges are solvable from what participants actually receive.

Run command:

```
python organizer_private\validate_challenges.py      # 15/15 must PASS
```

## Per-challenge result

| ID | Challenge | Reconstructed attack (from shipped files only) | Files | Result |
|---|---|---|---|---|
| E01 | Lester’s Pager Panic | Filter rows where `(A*B) mod C == 7`; sort by `(D%2, -E)`; base-41 decode reversed alphabet + join | dispatch.csv, decoder | **PASS** |
| E02 | Vinewood Shift Change | Pick row whose `SHA1(timestamp)` ends `a3`; affine inverse `a=7,b=11` (params from sample); ignore Caesar-5 decoy | taxi_ledger.txt, frequency_sample.bin | **PASS** |
| E03 | Sandy Shores Hidden Stash | Carve deleted `/ledger.dat` from ext2 image; zlib-inflate; XOR mask from `activity.log` line 42 hostname | safehouse.img | **PASS** |
| E04 | Del Perro Camera Roll | Column-major 2-LSB extract (R,G,B MSB-first); 2-byte length + UTF-7 payload | camera_roll.png, README.txt | **PASS** |
| E05 | Wrong Extension, Right Exit | ZIP polyglot on the PDF; AES-128-CBC decrypt with MD5(serial) key; query SQLite, resolve `delivery_hash` | impound_dossier.pdf | **PASS** |
| M01 | Fleeca Vault Glitch | Crack custom hash `sha256(pw+user[::-1]+"GTA_SALT_v2")[:16]`; second-order UNION SQLi to read vault | fleeca_kiosk.py, fleeca.db, common_pw.txt | **PASS** |
| M02 | Airport Ghost Flight | Raw IPv4/TCP PCAP parse; magic `0xDEAD1A70` + valid CRC32 + type `0x0A`; order by LE seq; XOR with CRC32 mask | airport_traffic.pcap, MANIFEST.txt | **PASS** |
| M03 | LSPD Midnight Audit | SHA256 hash-chain verify; locate 3 forgeries; RLE-decode `audit_delta.bin`; fold ACCEPT event codes | lspd_auth.log, audit_delta.bin, CHAIN_SPEC.txt | **PASS** |
| M04 | Underground XOR Radio | Recover keystream from known header; Berlekamp–Massey → LFSR degree 23; extend; XOR packet | radio_packet.bin, keystream_sample.bin, SIGNAL_SPEC.txt | **PASS** |
| M05 | Debugging the Dispatch | Fix shared-counter race with a lock; decode stage2 (base85+zlib); mask checksum to 32 bits | broken_dispatch.py, dispatch_packets.json, README.txt | **PASS** |
| H01 | Zancudo Deadbolt | Defeat anti-debug; find `.data` 256-byte permutation vault; per byte `TARGET*K^-1 mod 251` + S-box inverse; execute ELF | zancudo_gate, OPERATIONS.txt | **PASS** |
| H02 | The Recursive Freeway | Degree pre-filter; unique induced subgraph isomorphism (GraphMatcher); verify Laplacian fingerprint; build flag from labels | junctions.json, template.json, PROTOCOL.md | **PASS** |
| H03 | Impound Evidence Matryoshka | 5 layers: column-major 2-LSB → EXIF/GPS passphrase → PBKDF2+AES-256-CTR → MTX-1 → Huffman → run stage | impound_camera.png, EVIDENCE_NOTE.txt | **PASS** |
| H04 | LEGAL RAGGING | Combine faulty + good CRT signatures; `p = gcd(bad^e - m, n)`; rebuild `d`; forge admin order | bank_gateway.py, guest.token, AUDIT_BRIEF.txt | **PASS** |
| H05 | Last Ride Out | Parse TLV transcript; spot unauthenticated re-advertised party-C share; rebuild key; AES-GCM decrypt | intercept.bin, final_payload.enc, ESCAPE_PROTOCOL.md, FORMAT_SPEC.txt | **PASS** |

```
>>> ALL 15 BLACK-BOX SOLVERS PASSED - 1,550 points, no leak
```

## Integrity, scoring and leak checks

- `organizer_private/validate_challenges.py` hygiene pass: **15 challenges**, **15 unique flags**,
  **1,550 points**, tiers **5 EASY / 5 MEDIUM / 5 HARD**, every `MISSION.md` matches its manifest
  description, every listed evidence file exists and is non-empty.
- No canonical `FTA{...}` flag occurs anywhere under `challenges/`, `frontend/public/`,
  `frontend/dist/` or `frontend/src/` (binary `.pdf` skipped as text).
- `scripts/validate_challenges.py`: manifest OK (15 / $1,550), 15 non-empty evidence sets,
  frontend source audit clean.
- `tests/test_dist_security.py`: **zero** private flags in the production dist bundle.
- Wrong-flag rejection: the validator's `_record()` asserts the recovered flag matches the manifest
  exactly and conforms to `FTA\{[a-z0-9_]+\}`; any mismatch fails the run.

## CTFd import checks

- `organizer_private/CTFD_IMPORT/import_ctfd.py` (dry run — no network, flags never printed):
  `15 validated manifests / 1,550 points`, per-challenge file + hint counts correct, **H04 shows
  "H04 | LEGAL RAGGING"**.
- `organizer_private/CTFD_IMPORT/test_importer.py` (mock API):
  `PASS: 15 challenge creates, 15 flags, 45 hints, 36 files, 15 publications; no flag logging.`

## Offline (physical) hint confidentiality

- `H04_ORGANIZER_LEGAL_RAGGING.md` (actual RSA hint, alternative logic task, verification, solution)
  and `H05_*` riddle files live only in `organizer_private/offline/`.
- Scans of `challenges/`, `frontend/public/`, `frontend/dist/`, `frontend/src/` find **no**
  organizer/riddle/answer-key filenames and **no** private hint text. Only the *public* notice
  strings ("SPECIAL OFFLINE HINT — CREW FITNESS CHECK", "CLASSIFIED OFFLINE INTEL") appear in the
  H04/H05 participant `MISSION.md`, as required.
- `H05_PRINTABLE_RIDDLE.pdf` verified: valid 1-page `%PDF-1.4`, ends `%%EOF`, contains the pass-phrase
  answer words, and contains **no** `FTA{` substring.

## Hint locking, score deduction and submission lockout

- Mission hints are **locked** by default and rendered as classified intel. Unlocking a hint prompts the
  team, then calls CTFd's `POST /api/v1/unlocks` (`type: hints`); CTFd applies the hint's server-side
  `cost` and deducts **10 / 20 / 30** points (Easy / Medium / Hard) from the team's score.
- The importer attaches a non-zero `cost` to every hint, so the deduction is enforced server-side (the
  client cannot unlock a hint for free).
- Flag submission enforces a per-mission cooldown: **three wrong submissions lock that mission's flag
  terminal for 120 seconds**, with a live countdown, disabled input/button, and `localStorage`
  persistence across reloads. A correct or already-solved submission clears the counter.
- Flag format is `FTA{...}` everywhere (UI placeholder, rule text, docs, and the `FTA\{[a-z0-9_]+\}`
  validation regex in `validate_challenges.py`).

## Website regression

- Frontend source changes for this feature are confined to
  `frontend/src/pages/MissionBriefing.jsx` (locked/paid hints + 3-wrong/120s lockout + `FTA{...}`
  labels); prior data-only change was `frontend/src/data/challengeMeta.js`. No routing, layout,
  component or CSS change; no new UI library.

## What is NOT tested / limitations

- No live CTFd server was available, so real API auth, attachment storage, hint unlocking,
  UI rendering and team scoring need the host's preflight smoke test.
- Not a mathematical proof against an unintended bypass; treat participant reports of alternate
  paths fairly. H02/H03 solvers assert the unique intended path, not exhaustive bypass absence.
- Windows-native execution of the Linux ELF (`zancudo_gate`) uses WSL; the ELF is executed live in
  the validator.
- Difficulty tiers are designer estimates; run an organizer-only pilot with 2–3 students.

## Re-run everything

```
python organizer_private\validate_challenges.py
python scripts\validate_challenges.py
python tests\test_dist_security.py
python organizer_private\CTFD_IMPORT\import_ctfd.py          # dry run
python organizer_private\CTFD_IMPORT\test_importer.py        # mock API
```

`organizer_private/CTFD_IMPORT/validation_results.json` records per-mission methods and private
derived flags; **never distribute it**.
