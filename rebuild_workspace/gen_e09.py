#!/usr/bin/env python3
"""E09 - Chop Shop Terminal (obfuscated client-side JS checker).

A participant is handed a small "chop shop" web page (terminal.html) that loads
chopshop.js. The JS verifies a token by:

    C  ->  base64(C)  ->  XOR with a xorshift32 keystream  ->  hex

and compares the result against a TARGET hex string baked into the script.

The catch: chopshop.js is obfuscated (rotated string array, hex identifiers,
an IIFE-wrapped PRNG and a second arithmetic layer over the seed), it carries
two traps (a dead-branch decoy flag + a fake "working key" comment) and the
real flag NEVER appears verbatim.

Algorithm (defined here so the solver can mirror it EXACTLY):

  1. C       = candidate string (the canonical flag).
  2. B       = base64(C.encode())
  3. S0      = fixed 32-bit seed (this file's S0).
  4. K       = xorshift32 keystream seeded with S0, length len(B)
               (each byte = low 8 bits of the state after one round).
  5. T       = bytes(b ^ k for b, k in zip(B, K));  TARGET = T.hex()

Obfuscation contract mirrored by solve_e09.py:
  * The TARGET hex and the STORED seed live in the string array `_0x4b1d`.
  * The array is rotated LEFT by ROT before use: rotated[i] = raw[(i+ROT)%n].
    * rotated[4] holds TARGET, rotated[1] holds STORED (= S0 ^ SEED_XOR).
  * SEED_XOR is a literal in the script (the "second arithmetic layer").

All randomness is fixed, so output is byte-for-byte reproducible.
Private organizer tooling.
"""
import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

# --- algorithm constants (mirrored by solve_e09.py) -------------------------
S0 = 0x1234ABCD          # actual xorshift32 seed
SEED_XOR = 0xA5A5F00D    # second layer: STORED = S0 ^ SEED_XOR
ROT = 3                  # left rotation applied to the string array
IDX_SEED = 1             # index in the ROTATED array holding STORED (hex)
IDX_TARGET = 4           # index in the ROTATED array holding TARGET (hex)

# --- decoys (never the real flag) -------------------------------------------
DECOY_FLAG_1 = "FTA{sh0p_r3c31pt_d3c0y_2026}"   # string-array filler
DECOY_FLAG_2 = "FTA{sh0p_b41t_d34d_c0d3}"       # TRAP #1 dead branch
TRAP_COMMENT = "FTA{c0mm3nt_s4ys_th15}"         # TRAP #2 fake working key


def xorshift32_keystream(seed: int, n: int) -> bytes:
    """xorshift32 (13,17,5); one byte per round = low 8 bits of the state."""
    x = seed & 0xFFFFFFFF
    out = bytearray()
    for _ in range(n):
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= (x >> 17)
        x ^= (x << 5) & 0xFFFFFFFF
        x &= 0xFFFFFFFF
        out.append(x & 0xFF)
    return bytes(out)


def encrypt(candidate: bytes) -> str:
    """base64 -> xorshift32 keystream XOR -> hex. Returns TARGET hex."""
    b = base64.b64encode(candidate)
    k = xorshift32_keystream(S0, len(b))
    t = bytes(x ^ y for x, y in zip(b, k))
    return t.hex()


# ---------------------------------------------------------------------------
# chopshop.js
# ---------------------------------------------------------------------------
JS_TEMPLATE = r"""// chopshop.js - Chop Shop terminal token verifier (build 0xE09).
// working key: FTA{c0mm3nt_s4ys_th15}
// NOTE: this build uses an old dev credential line above; rotate it out.
var _0x4b1d = ["__DECOY1__", "__TARGET__", "north-loop", "dockside", "__STORED__", "harbor-spur"];
(function (_0xa7c3, _0x2f10) {
  for (var _0x9e = 0; _0x9e < _0x2f10; _0x9e++) {
    _0xa7c3.push(_0xa7c3.shift());
  }
})(_0x4b1d, __ROT__);
var _0x5c = (function (_0x1d2e) {
  var _0x8fa1 = _0x1d2e >>> 0;
  return function (_0x3b90) {
    var _0x7dc = [];
    for (var _0xe11a = 0; _0xe11a < _0x3b90; _0xe11a++) {
      _0x8fa1 ^= (_0x8fa1 << 13); _0x8fa1 >>>= 0;
      _0x8fa1 ^= (_0x8fa1 >>> 17); _0x8fa1 >>>= 0;
      _0x8fa1 ^= (_0x8fa1 << 5); _0x8fa1 >>>= 0;
      _0x7dc.push(_0x8fa1 & 255);
    }
    return _0x7dc;
  };
})((parseInt(_0x4b1d[__IDX_SEED__], 16) ^ __MASK__) >>> 0);
function _0x2a9c(_0x77e1) {
  if (false) { return 'FTA{sh0p_b41t_d34d_c0d3}'; }
  try {
    var _0x18ab = btoa(_0x77e1);
    var _0x6c02 = _0x5c(_0x18ab.length);
    var _0x33d7 = "";
    for (var _0x2210 = 0; _0x2210 < _0x18ab.length; _0x2210++) {
      var _0x15f = _0x18ab.charCodeAt(_0x2210) ^ _0x6c02[_0x2210];
      _0x33d7 += ("0" + (_0x15f & 255).toString(16)).slice(-2);
    }
    return _0x33d7 === _0x4b1d[__IDX_TARGET__];
  } catch (_0x0bad) {
    return false;
  }
}
if (typeof window !== 'undefined') { window.check = _0x2a9c; }
"""

HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Chop Shop Terminal</title>
<style>
  html, body { margin: 0; height: 100%; background: #0a0e0a; color: #7CFC7C;
    font-family: "Courier New", ui-monospace, monospace; }
  .wrap { max-width: 720px; margin: 6vh auto; padding: 0 18px; }
  h1 { font-size: 20px; letter-spacing: 3px; color: #b6ffb6; text-transform: uppercase; }
  .sub { color: #3f7a3f; font-size: 12px; margin-bottom: 22px; }
  .console { background: #051105; border: 1px solid #1f5c1f; border-radius: 6px;
    padding: 18px; box-shadow: inset 0 0 40px #0b2b0b; }
  .row { display: flex; gap: 10px; margin-top: 12px; }
  input { flex: 1; background: #0a1a0a; color: #d8ffd8; border: 1px solid #2f7a2f;
    padding: 10px 12px; border-radius: 4px; font-family: inherit; font-size: 14px; }
  input:focus { outline: none; border-color: #7CFC7C; }
  button { background: #145214; color: #d8ffd8; border: 1px solid #2f7a2f;
    padding: 10px 16px; border-radius: 4px; cursor: pointer; font-family: inherit;
    letter-spacing: 2px; }
  button:hover { background: #1c6b1c; }
  #log { margin-top: 16px; white-space: pre-wrap; min-height: 24px; font-weight: bold; }
  .ok { color: #7CFC7C; }
  .no { color: #ff5b5b; }
  .hint { color: #3f7a3f; font-size: 12px; margin-top: 18px; }
</style>
</head>
<body>
  <div class="wrap">
    <h1>Chop Shop Terminal</h1>
    <div class="sub">SANTOS CUSTOMS // token verifier v0xE09 :: offline build</div>
    <div class="console">
      <div>$ validate --token</div>
      <div class="row">
        <input id="tok" placeholder="paste shop token" autocomplete="off" spellcheck="false">
        <button id="go">VERIFY</button>
      </div>
      <div id="log">&gt; awaiting token...</div>
    </div>
    <div class="hint">client-side check only. no network. entries stay on the bench.</div>
  </div>
<script src="chopshop.js"></script>
<script>
  function _run() {
    var v = document.getElementById('tok').value;
    var log = document.getElementById('log');
    var ok = false;
    try { ok = check(v); } catch (e) { ok = false; }
    if (ok) { log.className = 'ok'; log.textContent = 'ACCESS GRANTED'; }
    else { log.className = 'no'; log.textContent = 'DENIED'; }
  }
  document.getElementById('go').addEventListener('click', _run);
  document.getElementById('tok').addEventListener('keydown', function (e) {
    if (e.key === 'Enter') { _run(); }
  });
</script>
</body>
</html>
"""


def build_js(target_hex: str, stored_hex: str) -> str:
    js = JS_TEMPLATE
    js = js.replace("__DECOY1__", DECOY_FLAG_1)
    js = js.replace("__TARGET__", target_hex)
    js = js.replace("__STORED__", stored_hex)
    js = js.replace("__ROT__", str(ROT))
    js = js.replace("__IDX_SEED__", str(IDX_SEED))
    js = js.replace("__IDX_TARGET__", str(IDX_TARGET))
    js = js.replace("__MASK__", "0x%08x" % SEED_XOR)
    return js


def main():
    out = L.out_dir("E09")
    flag = L.FLAGS["E09"]

    target_hex = encrypt(flag.encode())
    stored = S0 ^ SEED_XOR
    stored_hex = "%08x" % stored

    js = build_js(target_hex, stored_hex)
    html = HTML_TEMPLATE

    # ---------------------------------------------------------------- verify
    assert flag not in js and flag not in html, "flag leaked verbatim!"
    assert DECOY_FLAG_1 in js and DECOY_FLAG_2 in js and TRAP_COMMENT in js
    assert DECOY_FLAG_2 != flag and TRAP_COMMENT != flag

    (out / "chopshop.js").write_text(js, encoding="utf-8")
    (out / "terminal.html").write_text(html, encoding="utf-8")
    print("wrote", out / "chopshop.js")
    print("wrote", out / "terminal.html")
    print("[E09] layers: base64 -> xorshift32 keystream -> XOR -> hex; "
          "string-array rotation=%d, seed xor=0x%08x, IIFE PRNG, 2 traps"
          % (ROT, SEED_XOR))


if __name__ == "__main__":
    main()
