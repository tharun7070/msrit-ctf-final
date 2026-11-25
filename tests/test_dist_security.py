import json
import sys
from pathlib import Path

dist = Path(r"d:\ctf\FLAG_THEFT_AUTO_FINAL\frontend\dist")
import_dir = Path(r"d:\ctf\FLAG_THEFT_AUTO_FINAL\organizer_private\CTFD_IMPORT")

flags = []
for name in ("manifest.json", "manifest_bonus.json"):
    path = import_dir / name
    if path.is_file():
        flags += [c["flag"] for c in json.loads(path.read_text(encoding="utf-8"))["challenges"]]

found = []
for p in dist.rglob("*"):
    if p.is_file():
        content = p.read_text(encoding="utf-8", errors="ignore")
        for f in flags:
            if f in content:
                found.append((p.name, f))

if found:
    print(f"[-] LEAK DETECTED: {found}")
    sys.exit(1)
else:
    print(f"[+] SUCCESS: Zero private flags ({len(flags)}) leaked in production dist bundle.")
