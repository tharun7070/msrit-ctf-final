#!/usr/bin/env python3
"""H04 - LEGAL RAGGING (hardened RSA-CRT fault attack + two-part oracle).

Private organizer tooling. Builds the participant-facing artifact set:

    bank_gateway.py   - the token gateway (module + local HTTP endpoints)
    guest.token       - one valid guest credential (JSON + signature)
    AUDIT_BRIEF.txt    - the in-fiction discovery note

Hardening layers stacked into the gateway:
  1. Blinded, low-rate signing oracle - sign_debug signs (m * r^e) and hands
     back the blinding factor r, so the raw signature is not directly of m;
     the solver must un-blind before the classic gcd fault attack works.
  2. Faults may land in EITHER CRT half (p or q); gcd can return either prime
     and the solver must handle both.
  3. Two-part oracle - sign_debug plus a quiet verify_debug byte-oracle that
     leaks the live per-process audit nonce one byte at a time.  That nonce is
     one of the fields the vault order is assembled from.
  4. Verifier hardening - role gate, nonce gate and a timestamp freshness
     window.  A correctly signed order for the wrong role, or a stale order,
     is refused.
  5. Decoys - AUDIT_BRIEF suggests a wrong fault rate, a wrong fixed faulty
     half and a wrong (legacy) NONCE; the gateway also pins a stale legacy
     admin token that verifies but is rejected by submit().

The flag itself is never written here - the gateway reads it from the
environment variable ``FTA_H04_FLAG`` at submit time.
"""
import base64
import importlib.util
import json
import sys
from pathlib import Path

sys.path.insert(0, r"d:\ctf\FLAG_THEFT_AUTO_FINAL\rebuild_workspace")
import lib_fta as L

CID = "H04"
SEED = 20260404
BITS = 1024
FAULT_RATE = 0.03
GUEST_PREFIX = "REF:"
GUEST_MESSAGE = "REF:guest:los_santos:view_only:4421"

# The vault order is assembled from several fields; the NONCE field is only
# recoverable from the live gateway (placeholder filled at submit time).
ADMIN_MESSAGE = "ACTION=VAULT_TRANSFER;ROLE=admin;SRC=MAZE_BANK;AMT=1000000;NONCE=__NONCE__"

# A stale legacy order (pre-hardening).  Signed correctly, so it still passes
# the generic verifier, but submit() refuses it - a decoy for lazy solvers.
LEGACY_MESSAGE = "ACTION=VAULT_TRANSFER;ROLE=admin;SRC=MAZE_BANK;AMT=1000000;NONCE=LS2026"

# Keystream used to obscure the private CRT parameters inside the artifact.
KEY_MASK = b"MAZE_BANK_LOS_SANTOS_AUDIT_2026"

GATEWAY_TEMPLATE = r'''#!/usr/bin/env python3
"""Maze Bank of Los Santos - account token gateway (participant build).

Holds a 1024-bit RSA key and issues / verifies short-lived bearer tokens.
Import it as a module, or run it to expose the local HTTP endpoints:

    GET  /pubkey       -> {n, e, bits}
    POST /sign_debug   -> {"message": "...", "seed": <int>?} -> {signature, blind, fault, half}
    POST /verify_debug -> {"candidate": "<hex>"}            -> {match}
    POST /verify       -> {"token": {...}}                  -> {ok}
    POST /submit       -> {"token": {...}}                  -> {flag} | {error}
    GET  /guest        -> a freshly issued guest token

A token is a JSON object:  {"role": "...", "msg": "...", "sig": "<hex>"}.
An admin order additionally carries {"nonce": "<hex>", "ts": <int>}.
"""
import base64
import json
import math
import os
import random
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

N = __N__
E = __E__
K = (N.bit_length() + 7) // 8

# Opaque keystore - do not edit.
_OBF = "__OBF__"
_MASK = __MASK__

GUEST_PREFIX = "__GP__"
GUEST_MESSAGE = "__GM__"
ADMIN_MESSAGE = "__ADMIN__"
FAULT_RATE = __FR__

GUARD_LEN = 6
FRESH_WINDOW = 300

# Live per-process audit nonce.  Re-rolled on every boot and never written to
# disk.  submit() refuses any order that does not carry it.
_GUARD = secrets.token_bytes(GUARD_LEN)


def _reveal():
    raw = base64.b64decode(_OBF)
    raw = bytes(x ^ _MASK[i % len(_MASK)] for i, x in enumerate(raw))
    p = int.from_bytes(raw[:64], "big")
    q = int.from_bytes(raw[64:128], "big")
    return p, q


_P, _Q = _reveal()
# The signing exponents are recovered from the two half-moduli.
_DP = pow(E, -1, _P - 1)
_DQ = pow(E, -1, _Q - 1)
_QINV = pow(_Q, -1, _P)


def public_params():
    return N, E


def _sign(m):
    """RSA signature assembled from the two half-exponent results."""
    m %= N
    sp = pow(m, _DP, _P)
    sq = pow(m, _DQ, _Q)
    h = (_QINV * (sp - sq)) % _P
    return (sq + h * _Q) % N


def _sign_with_one_half_broken(m, half, rnd):
    m %= N
    sp = pow(m, _DP, _P)
    sq = pow(m, _DQ, _Q)
    if half == "Sp":
        sp = (sp + 1 + rnd.randrange(_P - 1)) % _P
    else:
        sq = (sq + 1 + rnd.randrange(_Q - 1)) % _Q
    h = (_QINV * (sp - sq)) % _P
    return (sq + h * _Q) % N


def sign_debug(message, seed=None):
    """Leftover debug route: signs blinded reference (guest) traffic.

    The request is first blinded with a per-call factor r: the gateway signs
    (m * r^e) so the value handed back is NOT a direct signature of m.  The
    blinding factor is returned alongside so the caller can un-blind.  Roughly
    FAULT_RATE of requests come back with exactly one of the two half-results
    computed wrong (either half).  Given a seed the outcome is deterministic.
    """
    msg = message.encode() if isinstance(message, str) else bytes(message)
    if not msg.startswith(GUEST_PREFIX.encode()):
        raise PermissionError("sign_debug serves reference traffic only")
    m = int.from_bytes(msg, "big") % N
    rnd = random.Random(seed) if seed is not None else random.Random(secrets.randbits(64))
    r = rnd.randrange(2, N - 1)
    while math.gcd(r, N) != 1:
        r = rnd.randrange(2, N - 1)
    blinded = (m * pow(r, E, N)) % N
    fault = rnd.random() < FAULT_RATE
    half = None
    if fault:
        half = rnd.choice(("Sp", "Sq"))
        for _ in range(16):
            sig = _sign_with_one_half_broken(blinded, half, rnd)
            if sig != _sign(blinded):
                break
        else:
            fault = False
    if not fault:
        sig = _sign(blinded)
    return {"message": msg.decode("utf-8", "replace"),
            "signature": format(sig, "x"), "blind": format(r, "x"),
            "fault": fault, "half": half}


def verify(token):
    try:
        msg = token["msg"]
        sig_hex = token["sig"]
    except (TypeError, KeyError, IndexError):
        return False
    msg_b = msg.encode() if isinstance(msg, str) else bytes(msg)
    try:
        provided = int(sig_hex, 16)
    except (TypeError, ValueError):
        return False
    if provided <= 0 or provided >= N:
        return False
    expected = _sign(int.from_bytes(msg_b, "big"))
    a = expected.to_bytes(K, "big")
    b = provided.to_bytes(K, "big")
    # Deliberately NON-constant-time: bail out at the first differing byte so
    # the response time reveals how many leading bytes of a guess line up.
    for i in range(K):
        if a[i] != b[i]:
            return False
    return True


def verify_debug(candidate):
    """Quiet debug verifier for the live audit nonce.

    Compares a candidate nonce (hex string or bytes) against the live one and
    reports how many LEADING bytes matched before it stopped.  Deliberately
    early-exit, so rather than answering yes/no it leaks the nonce one byte at
    a time.
    """
    try:
        cand = bytes.fromhex(candidate) if isinstance(candidate, str) else bytes(candidate)
    except (TypeError, ValueError):
        return {"match": 0}
    matched = 0
    for i in range(min(GUARD_LEN, len(cand))):
        if cand[i] != _GUARD[i]:
            break
        matched += 1
    return {"match": matched}


def _nonce_hex():
    return _GUARD.hex()


def _admin_order():
    return ADMIN_MESSAGE.replace("__NONCE__", _nonce_hex())


def issue_guest_token():
    m = int.from_bytes(GUEST_MESSAGE.encode(), "big")
    return {"role": "guest", "msg": GUEST_MESSAGE, "sig": format(_sign(m), "x")}


# A stale legacy order pinned into the build.  It verifies (it really is signed
# by the key), but submit() refuses it: wrong nonce, wrong message, old stamp.
DECOY_TOKEN = __DECOY__


def submit(token):
    if not isinstance(token, dict):
        return None
    if token.get("role") != "admin":
        return None
    if token.get("nonce") != _nonce_hex():
        return None
    ts = token.get("ts")
    if not isinstance(ts, int) or abs(int(time.time()) - ts) > FRESH_WINDOW:
        return None
    if token.get("msg") != _admin_order():
        return None
    if not verify(token):
        return None
    return os.environ.get("FTA_H04_FLAG")


def _serve(host="127.0.0.1", port=8420):
    class Handler(BaseHTTPRequestHandler):
        def _json(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            route = self.path.rstrip("/")
            if route == "/pubkey":
                self._json(200, {"n": format(N, "x"), "e": E, "bits": N.bit_length()})
            elif route == "/guest":
                self._json(200, {"token": issue_guest_token()})
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0") or 0)
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw or b"{}")
            except Exception:
                payload = {}
            route = self.path.rstrip("/")
            if route == "/sign_debug":
                try:
                    out = sign_debug(payload.get("message", ""), payload.get("seed"))
                    self._json(200, out)
                except Exception as exc:  # noqa: BLE001
                    self._json(403, {"error": str(exc)})
            elif route == "/verify_debug":
                self._json(200, verify_debug(payload.get("candidate", "")))
            elif route == "/verify":
                self._json(200, {"ok": verify(payload.get("token", {}))})
            elif route == "/submit":
                flag = submit(payload.get("token", {}))
                self._json(200, {"flag": flag} if flag else {"error": "denied"})
            else:
                self._json(404, {"error": "not found"})

        def log_message(self, *args):
            pass

    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    _serve()
'''


def _obfuscate(p: int, q: int) -> str:
    blob = p.to_bytes(64, "big") + q.to_bytes(64, "big")
    masked = bytes(b ^ KEY_MASK[i % len(KEY_MASK)] for i, b in enumerate(blob))
    return base64.b64encode(masked).decode("ascii")


def _decoy_token(key: dict) -> dict:
    m = int.from_bytes(LEGACY_MESSAGE.encode(), "big")
    sig = pow(m, key["d"], key["n"])
    return {"role": "admin", "msg": LEGACY_MESSAGE,
            "sig": format(sig, "x"), "nonce": "LS2026", "ts": 0}


def build_gateway_source(key: dict) -> str:
    src = GATEWAY_TEMPLATE
    src = src.replace("__N__", str(key["n"]))
    src = src.replace("__E__", str(key["e"]))
    src = src.replace("__OBF__", _obfuscate(key["p"], key["q"]))
    src = src.replace("__MASK__", repr(KEY_MASK))
    src = src.replace("__GP__", GUEST_PREFIX)
    src = src.replace("__GM__", GUEST_MESSAGE)
    src = src.replace("__ADMIN__", ADMIN_MESSAGE)
    src = src.replace("__FR__", repr(FAULT_RATE))
    src = src.replace("__DECOY__", repr(_decoy_token(key)))
    return src


def _load_module(path: Path):
    spec = importlib.util.spec_from_file_location("bank_gateway_check", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    out = L.out_dir(CID)
    key = L.generate_rsa(bits=BITS, seed=SEED)

    gateway_path = out / "bank_gateway.py"
    gateway_path.write_text(build_gateway_source(key), encoding="utf-8")

    # Self-check: the embedded material decodes back to the same key.
    gw = _load_module(gateway_path)
    assert gw.public_params() == (key["n"], key["e"]), "public params mismatch"
    assert (gw._P, gw._Q) == (key["p"], key["q"]), "keystore mismatch"

    # The nonce oracle must be able to reveal the live guard, and a candidate
    # whose first byte is provably wrong must leak nothing.
    assert gw.verify_debug(gw._nonce_hex())["match"] == gw.GUARD_LEN, "nonce oracle broken"
    wrong = bytes([gw._GUARD[0] ^ 0xFF]) + bytes(gw.GUARD_LEN - 1)
    assert gw.verify_debug(wrong)["match"] == 0, "nonce oracle failed open"

    # Emit one valid guest credential.
    m = int.from_bytes(GUEST_MESSAGE.encode(), "big")
    sig = pow(m, key["d"], key["n"])
    guest = {"role": "guest", "msg": GUEST_MESSAGE, "sig": format(sig, "x")}
    assert gw.issue_guest_token()["sig"] == guest["sig"], "guest signature mismatch"
    assert gw.verify(guest) is True, "guest token must verify"
    (out / "guest.token").write_text(json.dumps(guest, indent=2) + "\n", encoding="utf-8")

    # The decoy must verify yet be refused by submit().
    assert gw.verify(gw.DECOY_TOKEN) is True, "decoy token should verify"
    assert gw.submit(gw.DECOY_TOKEN) is None, "decoy token must be refused"

    # In-fiction discovery brief (no algorithm names, includes deliberate decoys).
    (out / "AUDIT_BRIEF.txt").write_text(
        "MAZE BANK OF LOS SANTOS - SECURITY AUDIT BRIEF (case ref: H04)\n"
        "----------------------------------------------------------------\n"
        "The token service shipped as bank_gateway.py was pushed to production\n"
        "in a hurry. During a routine sweep the audit crew noticed a leftover\n"
        "debug route (/sign_debug) that is still wired up in the local build,\n"
        "and a quieter one (/verify_debug) nobody remembers approving.\n"
        "\n"
        "We recovered one working credential off a teller's shared drive:\n"
        "\n"
        "    guest.token\n"
        "\n"
        "It is only good for read-only teller traffic. The vault order the bank\n"
        "actually cares about is signed under a different role and carries a\n"
        "rotating audit nonce; the gateway will only hand over the registered\n"
        "marker when a correctly signed order is presented together with a\n"
        "fresh proof of that same nonce.\n"
        "\n"
        "Two leads the night crew scribbled down - treat them as rumours, not\n"
        "facts, because the shift that wrote them had been drinking:\n"
        "\n"
        "  * \"The debug route corrupts its answer about 10% of the time, and\n"
        "     whenever it does it is always the p-side half.\"\n"
        "  * \"The order the vault honours is the legacy string with\n"
        "     NONCE=LS2026; the stale order pinned in the build still works.\"\n"
        "\n"
        "Ask the debug route to sign reference traffic and compare what it hands\n"
        "back across a few requests before you trust any single answer - the raw\n"
        "answer is not the signature it looks like. The quiet route answers\n"
        "questions about the audit nonce slowly, one byte at a time.\n",
        encoding="utf-8",
    )

    print("[%s] wrote %s, guest.token, AUDIT_BRIEF.txt -> %s" % (CID, gateway_path.name, out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
