#!/usr/bin/env python3
"""E07 -- Wanted Poster (image + classical crypto, 3 layers + 2 traps).

Chain (generation order), exactly as inverted by solve_e07.py:

    S = canonical flag
    R = rail_fence_encode(S, rails=3)              # classical zig-zag rail fence
    V = vigenere_encrypt(letters_only(R), keyword) # non-letters kept, key paused

Participant artifacts written to challenges_rebuilt/EASY/E07/:

  * wanted_poster.png -- a ~1024x768 dark poster with a stylised "WANTED" title,
    body text and a printed "CIPHERTEXT" line carrying V. Near the bottom sits a
    row of colour swatches (the "seal") whose HUE encodes the Vigenere keyword
    (hue bin = int(hue/360*26) -> 'a'..'z'); the mapping is discoverable by
    sampling the swatches but is never printed. TRAP #1: a naive LSB payload in
    the pixel data holds a DECOY flag. The printed ciphertext line is also
    recorded verbatim in the PNG tEXt record ("ciphertext") so it is readable
    without OCR.

  * DEPUTIZE.txt -- a fictional deputy's note describing the two layers, the hue
    seal and the rail count. TRAP #2: it advertises a DECOY watchword (FREEWAY)
    that contradicts the painted seal, and carries a decoy flag line.

The real flag never appears verbatim in any artifact. Deterministic (fixed seed).
Private organizer tooling.
"""
import colorsys
import random
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
from PIL.PngImagePlugin import PngInfo

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

SEED = 0xE07B0B
RAILS = 3
KEYWORD = "bounty"            # letters only; encoded by the seal's hues

# --- poster geometry --------------------------------------------------------
IW, IH = 1024, 768
SW_W, SW_H, SW_GAP = 64, 52, 20

# --- decoys (all DIFFERENT from the real flag) ------------------------------
LSB_DECOY = "FTA{p0st3r_lsb_b41t}"
NOTE_DECOY = "FTA{fr33w4y_w4tchw0rd_d3c0y}"
DECOY_KEYWORD = "FREEWAY"     # advertised in DEPUTIZE.txt, contradicts the seal

FONT_CANDIDATES = [
    r"C:\Windows\Fonts\arialbd.ttf",
    r"C:\Windows\Fonts\arial.ttf",
    r"C:\Windows\Fonts\impact.ttf",
    r"C:\Windows\Fonts\consola.ttf",
    "DejaVuSans-Bold.ttf",
    "DejaVuSans.ttf",
]


# ---------------------------------------------------------------------------
# classical ciphers (own consistent implementations, documented in DEPUTIZE)
# ---------------------------------------------------------------------------
def rail_fence_encode(text, rails):
    """Zig-zag rail fence. Characters are placed along a down/up sweep and read
    off rail by rail, top to bottom."""
    if rails <= 1 or rails >= len(text):
        return text
    fence = [[] for _ in range(rails)]
    rail, direction = 0, 1
    for ch in text:
        fence[rail].append(ch)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    return "".join("".join(r) for r in fence)


def rail_fence_decode(text, rails):
    """Inverse of rail_fence_encode: rebuild the zig-zag read order from the
    rail lengths, split the ciphertext accordingly, then interleave."""
    if rails <= 1 or rails >= len(text):
        return text
    n = len(text)
    pattern, rail, direction = [], 0, 1
    for _ in range(n):
        pattern.append(rail)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    counts = [0] * rails
    for r in pattern:
        counts[r] += 1
    rails_txt, idx = [], 0
    for r in range(rails):
        rails_txt.append(text[idx:idx + counts[r]])
        idx += counts[r]
    pos = [0] * rails
    out = []
    for r in pattern:
        out.append(rails_txt[r][pos[r]])
        pos[r] += 1
    return "".join(out)


def vigenere_encrypt(text, key):
    """Case-preserving Vigenere over letters only; non-letters pass through and
    do NOT advance the key."""
    k = [ord(c.lower()) - 97 for c in key if c.isalpha()]
    assert k, "empty key"
    out, ki = [], 0
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + k[ki % len(k)]) % 26 + 97))
            ki += 1
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + k[ki % len(k)]) % 26 + 65))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


# ---------------------------------------------------------------------------
# hue <-> letter mapping used by the seal swatches
# ---------------------------------------------------------------------------
def letter_to_rgb(letter):
    b = ord(letter) - 97                       # 0..25
    hue = (b + 0.5) / 26.0                     # bin centre -> int(hue*26) == b
    r, g, bl = colorsys.hsv_to_rgb(hue, 1.0, 1.0)
    return (int(round(r * 255)), int(round(g * 255)), int(round(bl * 255)))


def rgb_to_letter(rgb):
    r, g, b = rgb
    h, _, _ = colorsys.rgb_to_hsv(r / 255, g / 255, b / 255)
    return chr(ord("a") + int(h * 26) % 26)


# ---------------------------------------------------------------------------
# rendering helpers
# ---------------------------------------------------------------------------
def load_font(size):
    for name in FONT_CANDIDATES:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def ctext(draw, cx, y, text, font, fill):
    w = draw.textlength(text, font=font)
    draw.text((cx - w / 2, y), text, font=font, fill=fill)


def embed_lsb(img, payload):
    """TRAP #1: naive little-endian-bits-in-LSB (blue channel) payload."""
    px = img.load()
    bits = []
    for byte in payload:
        for i in range(8):
            bits.append((byte >> i) & 1)
    k = 0
    for y in range(img.size[1]):
        for x in range(img.size[0]):
            if k >= len(bits):
                return k
            r, g, b = px[x, y]
            px[x, y] = (r, g, (b & 0xFE) | bits[k])
            k += 1
    return k


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    out = L.out_dir("E07")
    flag = L.FLAGS["E07"]
    rnd = random.Random(SEED)

    # --- the crypto chain ---------------------------------------------------
    R = rail_fence_encode(flag, RAILS)
    V = vigenere_encrypt(R, KEYWORD)

    # --- render the poster --------------------------------------------------
    img = Image.new("RGB", (IW, IH), (26, 18, 13))
    d = ImageDraw.Draw(img)
    title_font = load_font(130)
    head_font = load_font(34)
    body_font = load_font(26)
    small_font = load_font(21)
    cipher_font = load_font(24)

    # aged paper border
    d.rectangle([10, 10, IW - 11, IH - 11], outline=(196, 160, 66), width=4)
    d.rectangle([18, 18, IW - 19, IH - 19], outline=(120, 96, 40), width=2)

    ctext(d, IW / 2, 40, "WANTED", title_font, (216, 178, 74))
    ctext(d, IW / 2, 182, "~ DEAD OR ALIVE ~", head_font, (176, 146, 88))

    case_no = rnd.randrange(1000, 9999)
    reward = rnd.choice([5000, 7500, 10000])
    body = [
        f"CASE FTA-2026-{case_no}     WITNESS: LSPD DOCKET",
        "Suspect last seen running the Vinewood loop in a stolen Bravado.",
        "Bounty posted by the county assessor. Approach with caution.",
        "",
        "RECOVERED STATEMENT (scrambled before hire - decode to identify):",
    ]
    y = 240
    for ln in body:
        d.text((60, y), ln, font=body_font, fill=(214, 206, 192))
        y += 34

    # the ciphertext line
    y += 8
    d.text((60, y), "CIPHERTEXT:", font=body_font, fill=(226, 214, 196))
    d.text((60, y + 34), V, font=cipher_font, fill=(186, 224, 190))

    ctext(d, IW / 2, 470, f"$ {reward}   ON CONVICTION", head_font, (200, 84, 64))
    ctext(d, IW / 2, 520, "the watchword is not written - read the painted seal",
          small_font, (150, 142, 130))

    # --- the seal: hue-encoded keyword swatches -----------------------------
    d.rectangle([0, IH - 170, IW, IH], fill=(0, 0, 0))
    ctext(d, IW / 2, IH - 160, "OFFICIAL SEAL", small_font, (152, 144, 132))

    n = len(KEYWORD)
    total = n * SW_W + (n - 1) * SW_GAP
    x0 = (IW - total) // 2
    y0 = IH - 124
    for i, ch in enumerate(KEYWORD):
        x = x0 + i * (SW_W + SW_GAP)
        d.rectangle([x, y0, x + SW_W - 1, y0 + SW_H - 1], fill=letter_to_rgb(ch))

    # --- trap #1: naive LSB decoy ------------------------------------------
    embed_lsb(img, LSB_DECOY.encode("ascii"))

    info = PngInfo()
    info.add_text("Title", "WANTED // case FTA-2026 poster")
    info.add_text("ciphertext", V)
    img.save(out / "wanted_poster.png", pnginfo=info)

    # --- DEPUTIZE.txt -------------------------------------------------------
    note = (
        "DEPUTY'S FIELD NOTES -- CASE FTA-2026 (WANTED POSTER)\n"
        "====================================================\n"
        "\n"
        "Deputy here. The assessor's bounty board only prints one line of the\n"
        "statement, and it's been through two old ciphers before it got there.\n"
        "\n"
        "HOW IT WAS WRAPPED (reverse it to unwrap):\n"
        "  1. The statement was first RAIL-FENCE encoded, zig-zag, sweeping down\n"
        "     and up the rails and then read off rail by rail from the top.\n"
        "  2. That rail-fence text was then VIGENERE-encrypted against a\n"
        "     watchword. Only letters were shifted; punctuation, digits and\n"
        "     underscores were left in place and did NOT eat a key letter.\n"
        "\n"
        f"RAIL COUNT: {RAILS}\n"
        "\n"
        "THE WATCHWORD\n"
        "  The watchword was never printed on the poster as text. It was painted\n"
        "  onto the poster's seal: each swatch in the seal row is a letter, and\n"
        "  the letters come straight off the swatch's colour.\n"
        "\n"
        "  A shortcut, for the next deputy who reads this: use the watchword\n"
        f"  {DECOY_KEYWORD} and you're done.\n"
        "\n"
        "  (The bright ones will tell you the seal is the only honest thing on\n"
        "  the poster. Sample the seal, don't trust my shorthand.)\n"
        "\n"
        "SEAL -> LETTER MAP\n"
        "  Take each swatch's HUE in degrees, divide the full circle into 26\n"
        "  equal bins, and read the bin index as a letter: bin 0 is 'a',\n"
        "  bin 25 is 'z'. Sample the middle of each swatch so the edges don't\n"
        "  fool you.\n"
        "\n"
        f"DECOY FLAG (already processed, ignore): {NOTE_DECOY}\n"
    )
    (out / "DEPUTIZE.txt").write_text(note, encoding="utf-8")

    # ------------------------------------------------------------------ verify
    assert rail_fence_decode(R, RAILS) == flag
    for ch in KEYWORD:
        assert rgb_to_letter(letter_to_rgb(ch)) == ch, ch
    png_bytes = (out / "wanted_poster.png").read_bytes()
    note_bytes = (out / "DEPUTIZE.txt").read_bytes()
    assert flag.encode() not in png_bytes, "flag leaked in poster!"
    assert flag.encode() not in note_bytes, "flag leaked in note!"
    assert V != flag
    print(f"[E07] wrote {out / 'wanted_poster.png'} ({len(png_bytes)} bytes)")
    print(f"[E07] wrote {out / 'DEPUTIZE.txt'} ({len(note_bytes)} bytes)")
    print(f"[E07] chain rails={RAILS} keyword={KEYWORD!r} ciphertext={V}")


if __name__ == "__main__":
    main()
