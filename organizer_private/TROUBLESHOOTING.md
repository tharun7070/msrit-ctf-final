# Troubleshooting

| Symptom | Diagnosis | Fix |
|---|---|---|
| CTFd login inaccessible | Server not reachable, firewall/port 8000, DNS | Access by LAN IP, check `docker compose ps` and `logs`; check firewall |
| API importer 401/403 | Token absent, expired, not admin | Generate admin Access Token, set `CTFD_TOKEN` correctly; keep secret |
| API importer fails halfway | Version issue or failed attachment | Read error challenge ID, inspect hidden partial record; clean it then rerun; no silent duplicates |
| Existing challenge collision | Re-run against populated board | Import against a clean instance, or manually remove intended duplicate safely |
| Wrong MIME or file extension | Intentionally misleading artifact in E05/H03 | Do not rename or re-encode; use file signatures and `zipfile` |
| `.drop_manifest` not found | Hidden Unix dotfile | `ls -la safehouse`; Python `zipfile.namelist()` |
| PNG metadata missing | Image re-saved by chat/media tool | Download original attached PNG directly, do not screenshot/compress; verify SHA256 |
| PCAP has no packets | Broken/corrupted download | Re-upload original `.pcap`, open with Wireshark or offline parser |
| H01 `Exec format error` | Linux ELF on native Windows/macOS ARM | Use WSL2 Ubuntu on x86-64, x86 Linux VM, supervised event machine |
| M05 decoder raises `Incorrect padding` | Intended bug | Restore missing Base64 URL padding |
| SQLi CLI seemingly stuck | Waiting for owner and PIN | Enter both prompts; test only the included local `fleeca_kiosk.py` |
| Hint button absent | Hint association or CTFd permissions | Check three hints under challenge admin (each with a `cost` so unlocking deducts points) |
| Duplicate score after offline mode | Offline + CTFd merge | Judge reconciles unique team/challenge solves before publishing |
| Flag rejected | Extra spaces, wrong case/mission, incorrect decoding | Check braces and case; compare private answer only through head judge |

**If importer cannot be tested live:** use manual CTFd Admin > Challenges creation as documented. The local 15/15 validation does not guarantee server plugins or attachment storage function.
