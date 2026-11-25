#!/usr/bin/env python3
"""H03 validator — proves the hardened chain is solvable, that wrong answers are
rejected, that the real flag leaks nowhere, and that each of the planted traps
actually catches a naive solver."""
import io
import re
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L
import solve_h03 as S
from solve_h03 import solve

OUT = L.out_dir("H03")
PNG = OUT / "impound_camera.png"
FLAG_B = L.FLAGS["H03"].encode()


def submit(candidate: str) -> bool:
    """Simulated CTFd answer check (exact match, case-sensitive)."""
    return candidate == L.FLAGS["H03"]


def _all_flags_in(blob: bytes):
    return re.findall(rb"FTA\{[a-z0-9_]+\}", blob)


def main():
    good = solve()
    assert good == L.FLAGS["H03"], good
    assert submit(good) is True

    # wrong answers must be rejected
    wrong = ("X" + good[1:])
    assert wrong != good
    assert submit(wrong) is False
    assert submit(good.lower()) is False
    assert submit(good.rstrip("}")) is False

    # --- anti-leak: the real flag must appear in NO shipped file -------------
    shipped = [p for p in OUT.iterdir() if p.is_file()]
    for p in shipped:
        assert FLAG_B not in p.read_bytes(), f"leak in {p.name}"

    # --- trap 1: a well-formed decoy flag found FIRST by a metadata scrape ---
    from PIL import Image
    im = Image.open(PNG)
    meta_flag = im.info.get("flag")
    assert meta_flag and meta_flag != L.FLAGS["H03"], "missing decoy 'flag' tEXt"
    assert re.fullmatch(r"FTA\{[a-z0-9_]+\}", meta_flag), meta_flag
    exif_desc = im.info.get("exif")
    assert exif_desc and b"FTA{" in exif_desc, "missing decoy EXIF description"

    # --- trap 2: a VALID extractable archive with a plausible fake flag ------
    canary = (OUT / "RECOVERY_INSTRUCTIONS.txt").read_text(encoding="utf-8")
    assert "4471" in canary, "canary must advertise the public bag password"
    data = PNG.read_bytes()
    z0 = data.index(S.BAG_OPEN) + len(S.BAG_OPEN)
    z1 = data.index(S.BAG_CLOSE, z0)
    bag = zipfile.ZipFile(io.BytesIO(data[z0:z1]))
    bag.setpassword(b"4471")
    manifest = bag.read("manifest.txt")
    assert b"README" not in manifest                      # different member
    bag_flags = _all_flags_in(manifest)
    assert bag_flags, "bag archive payload has no flag"
    assert FLAG_B not in manifest, "REAL flag leaked into the decoy archive"
    # the public bag password must NOT open the real vault
    vz0 = data.index(S.VAULT_OPEN) + len(S.VAULT_OPEN)
    vz1 = data.index(S.VAULT_CLOSE, vz0)
    vault = zipfile.ZipFile(io.BytesIO(data[vz0:vz1]))
    vault.setpassword(b"4471")
    try:
        vault.read("layer4.bin")
        raise AssertionError("public bag password opened the real vault!")
    except (RuntimeError, zipfile.BadZipFile):
        pass

    # --- trap 3: the canary advertises a WRONG method/next step --------------
    assert "0x5A" in canary, "canary must advertise the wrong XOR method"
    assert "authoritative" in canary.lower(), "canary must claim to be authoritative"
    canary_flags = _all_flags_in(canary.encode())
    assert all(f != FLAG_B for f in canary_flags), "canary leaked the real flag"

    # --- trap 4: a blanket LSB dump (no gating, no mask) yields only bait ----
    img = Image.open(PNG).convert("RGB")
    px = img.load()
    bits = []
    for y in range(img.height):
        for x in range(img.width):
            for c in px[x, y]:
                bits.append((c >> 1) & 1)
                bits.append(c & 1)
    raw = bytearray()
    for i in range(0, (len(bits) // 8) * 8, 8):
        raw.append(int("".join(str(b) for b in bits[i:i + 8]), 2))
    assert FLAG_B not in bytes(raw), "blanket LSB dump revealed the real flag"

    # --- trap 5: the final stage is token-gated (wrong/absent -> decoy) ------
    src, seal_token = S.walk_to_stage()
    assert FLAG_B not in src.encode(), "stage source embeds the real flag"
    for bad_token in ("", "NOT-THE-SEAL", seal_token.lower()):
        out = S.run_stage(src, bad_token)
        assert FLAG_B not in out.encode(), f"wrong token {bad_token!r} produced the flag"
        assert "FTA{" in out, "wrong token should still print a decoy"
    assert FLAG_B in S.run_stage(src, seal_token).encode(), "correct token failed"

    print(f"[H03] VALIDATE OK (good='{good}', wrong rejected='{wrong}'; "
          f"traps: decoy-metadata, decoy-ZIP, canary-note, blanket-LSB, token-gate)")


if __name__ == "__main__":
    main()
