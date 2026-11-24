#!/usr/bin/env python3
"""FLAG THEFT AUTO — Challenge Validator & Integrity Verifier
Verifies that:
1. Exactly 25 missions exist across Easy, Medium, and Hard tiers (12/8/5).
2. All participant evidence files are in place and non-empty.
3. Scoring adds up to exactly $2,200 ($600 Easy + $800 Medium + $800 Hard).
4. No private flags or solutions are leaked in frontend source files.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = ROOT / "organizer_private" / "CTFD_IMPORT" / "manifest.json"
CHALLENGES_DIR = ROOT / "challenges"
FRONTEND_DIR = ROOT / "frontend" / "src"

def test_manifest():
    print("[*] Validating manifest...")
    if not MANIFEST_PATH.is_file():
        print(f"[-] Missing manifest at {MANIFEST_PATH}")
        return False, []

    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    challenges = data.get("challenges", [])
    if len(challenges) != 25:
        print(f"[-] Expected 25 challenges, found {len(challenges)}")
        return False, []

    total_pts = sum(c["points"] for c in challenges)
    if total_pts != 2200:
        print(f"[-] Expected 2200 points, found {total_pts}")
        return False, []

    easy = [c for c in challenges if c["level"] == "Easy"]
    med = [c for c in challenges if c["level"] == "Medium"]
    hard = [c for c in challenges if c["level"] == "Hard"]

    if len(easy) != 12 or len(med) != 8 or len(hard) != 5:
        print(f"[-] Tier mismatch: {len(easy)} Easy, {len(med)} Medium, {len(hard)} Hard")
        return False, []

    print(f"[+] Manifest OK: 25 challenges, exactly $2,200 total bounty.")
    return True, challenges

def test_attachments(challenges):
    print("[*] Verifying participant challenge evidence files...")
    all_ok = True
    for c in challenges:
        cid = c["id"]
        level = c["level"].upper()
        cdir = CHALLENGES_DIR / level / cid
        
        mission_md = cdir / "MISSION.md"
        if not mission_md.is_file():
            print(f"[-] Missing MISSION.md for {cid} in {cdir}")
            all_ok = False

        for fn in c["files"]:
            fpath = cdir / fn
            if not fpath.is_file():
                print(f"[-] Missing evidence file: {fpath}")
                all_ok = False
            elif fpath.stat().st_size == 0:
                print(f"[-] Empty evidence file: {fpath}")
                all_ok = False

    if all_ok:
        print("[+] All 25 challenges have verified, non-empty participant evidence files.")
    return all_ok

def test_no_flags_in_frontend(challenges):
    print("[*] Auditing frontend source for leaked private flags...")
    flags = [c["flag"] for c in challenges if "flag" in c]
    leak_found = False

    for src_file in FRONTEND_DIR.rglob("*"):
        if src_file.is_file() and src_file.suffix in [".js", ".jsx", ".ts", ".tsx", ".html", ".css"]:
            content = src_file.read_text(encoding="utf-8", errors="ignore")
            for fl in flags:
                if fl in content:
                    print(f"[-] LEAK DETECTED: Flag '{fl}' found in {src_file}")
                    leak_found = True

    if not leak_found:
        print("[+] Security audit passed: No private flags found anywhere in frontend code.")
    return not leak_found

def main():
    print("=" * 60)
    print(" FLAG THEFT AUTO // PRE-FLIGHT VERIFICATION SUITE")
    print("=" * 60)

    ok_m, chs = test_manifest()
    if not ok_m:
        sys.exit(1)

    ok_a = test_attachments(chs)
    ok_s = test_no_flags_in_frontend(chs)

    print("=" * 60)
    if ok_m and ok_a and ok_s:
        print(">>> ALL PRE-FLIGHT AUDIT CHECKS PASSED SUCCESSFULLY <<<")
        sys.exit(0)
    else:
        print(">>> AUDIT FAILED — CHECK ERRORS ABOVE <<<")
        sys.exit(1)

if __name__ == "__main__":
    main()
