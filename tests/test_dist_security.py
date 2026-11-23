import json
import sys
from pathlib import Path

dist = Path(r"d:\ctf\FLAG_THEFT_AUTO_FINAL\frontend\dist")
manifest = Path(r"d:\ctf\FLAG_THEFT_AUTO_FINAL\organizer_private\CTFD_IMPORT\manifest.json")

data = json.loads(manifest.read_text(encoding="utf-8"))
flags = [c["flag"] for c in data["challenges"]]

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
    print("[+] SUCCESS: Zero private flags leaked in production dist bundle.")
