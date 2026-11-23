# Local Test Report — FLAG THEFT AUTO

**Method:** artifact-only reconstruction via `ORGANIZER/validate_challenges.py`, not the private builder. Correct outputs compared to the organizer-only manifest. A wrong-input negative check was performed for the local SQLi kiosk, ELF gate and JWT-like gateway. ZIP formats, image metadata and TCP/IPv4 checksums were checked. Every listed attachment exists and is nonempty; scans confirm no **exact correct flag** occurs verbatim in participant materials.

| ID | Challenge | Test | Result |
|---|---|---|---|
| E01 | Lester’s Pager Panic | Filter courier=YES, order seq as numbers, Base64-decode each payload and join. | **PASS** |
| E02 | Vinewood Shift Change | Identify the MIDNIGHT line, shift alphabetic letters back five positions. | **PASS** |
| E03 | Sandy Shores Hidden Stash | unzip safehouse.zip; find .drop_manifest; use xxd -r -p on its hex line. | **PASS** |
| E04 | Del Perro Camera Roll | Read PNG dispatch_note tEXt metadata, Base32 decode. | **PASS** |
| E05 | Wrong Extension, Right Exit | file customs_camera.jpg; unzip; decode receipt hex. | **PASS** |
| M01 | Fleeca Vault Glitch | Run python fleeca_kiosk.py, owner: ' OR 1=1 -- ; PIN anything. | **PASS** |
| M02 | Airport Ghost Flight | Wireshark http filter X-Flight LS-447; order X-Chunk and Base64 decode X-Cargo. | **PASS** |
| M03 | LSPD Midnight Audit | Filter case=714 source=FORENSIC result=ACCEPT; order part; join fraghex; fromhex. | **PASS** |
| M04 | Underground XOR Radio | Construct ordered hex key from CSV; repeated XOR radio_packet.bin. | **PASS** |
| M05 | Debugging the Dispatch | Fix lexicographic sorting, last-item omission, and base64 padding in broken_dispatch.py. | **PASS** |
| H01 | Zancudo Deadbolt | Disassemble the XOR check; recover password bytes from fixed table, execute ELF. | **PASS** |
| H02 | The Recursive Freeway | Memoized DAG evaluator to calculate destination; format final 8-hex value and hash suffix. | **PASS** |
| H03 | Impound Evidence Matryoshka | Open PNG as ZIP; open case_144 .gz as gzip; read tar member dossier.json; a85decode + zlib.decompress. | **PASS** |
| H04 | Fleeca Trust Fall | Create base64url header {alg:none,typ:JWT}, payload {role:admin,sub:auditor}, empty signature; run local gateway. | **PASS** |
| H05 | Last Ride Out | Choose qualifying route; base85 decode intercept, decompress, XOR SHA256(plate:terminal) digest. | **PASS** |

### Additional checks performed

- All 15 independently reconstructed flags exactly matched their intended values, with valid case-sensitive flag syntax.
- `validate_challenges.py` verifies 15 unique correct flags and 1,550 fixed points, checks 28 attached evidence files, tests a real ELF execution, checks the PCAP protocol checksums and filters all 507 log lines.
- CTFd importer's dry run produced 15 challenge records without making network requests or printing flags.
- Mock-session CTFd API test simulated 15 challenge creates, 15 flag uploads, 45 hint uploads, 28 file uploads, 15 publication operations; all assertions **PASS**.

### What is NOT tested / limitations

- **No real live CTFd server was available** in this environment, so real API authentication, file storage, hint unlocking, UI layout and team scoring require the event host's preflight smoke test.
- No independent human playtest, real 100-minute difficulty timing, Windows native execution of Linux ELF, or Wireshark GUI decoding were measured. Difficulty categories are designer estimates; conduct an organizer-only pilot with 2–3 students.
- Unique flags, algorithm determinism and the route's unique qualifying vehicle were checked programmatically; this is not a mathematical proof that an unintended bypass cannot exist for any program. Treat reports of alternate paths fairly.
- Tests run locally on Linux using Python 3 and standard tooling. PCAP protocol validity is tested, but Wireshark UI is not available in this environment.

**Re-run:** `python ORGANIZER/validate_challenges.py` followed by `python ORGANIZER/CTFD_IMPORT/test_importer.py`. The JSON output `ORGANIZER/CTFD_IMPORT/validation_results.json` records per-mission methods and private derived flags; never distribute it.

### Release verification

After producing the full private ZIP, it was extracted with `unzip` into a clean test directory and all 15 artifact-only solvers were run again successfully. The importer dry run and mock API test also passed from the extracted package. The standalone participant archive was scanned for the exact fifteen correct flags and organizer path names; none was found. The private master remains confidential.

The offline scoreboard fallback script was tested with two teams, duplicate attempts, a wrong answer and timestamp-based ranking; the expected result passed.
