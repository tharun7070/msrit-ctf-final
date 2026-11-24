#!/usr/bin/env python3
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

N = 118865252427956305283327846975934473994270521522722245747390812674457890107233825953528809866006261830016586023032651486335162331525774667502009666733291850189465477298662339206176707808116681017185153458954182915918757410553466664933550967814606912227970525920542922783751873126477132138999917877768759105463
E = 65537
K = (N.bit_length() + 7) // 8

# Opaque keystore - do not edit.
_OBF = "4smoAdszdeJ6gspLE34ASUtgwnOjX6/Mzv1Vkn18gsSg/mxAXy5aUgpeJBRv4EfhBSZgjBJe7I4wGMvaGWIykqyZvWQaQ23rhWB1fE9/gbbfGJiRn1a8npHrMnNjL/IE6wdjujVcf6UZTeI3x/xLhK+1Fj5Mwl99VLM++h+mJEg="
_MASK = b'MAZE_BANK_LOS_SANTOS_AUDIT_2026'

GUEST_PREFIX = "REF:"
GUEST_MESSAGE = "REF:guest:los_santos:view_only:4421"
ADMIN_MESSAGE = "ACTION=VAULT_TRANSFER;ROLE=admin;SRC=MAZE_BANK;AMT=1000000;NONCE=__NONCE__"
FAULT_RATE = 0.03

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
DECOY_TOKEN = {'role': 'admin', 'msg': 'ACTION=VAULT_TRANSFER;ROLE=admin;SRC=MAZE_BANK;AMT=1000000;NONCE=LS2026', 'sig': '70c63569444d46742a0f9ad6d2c4ca847c116640816b23f2f8dfaac3b784ff1975219636be610056e486c53f1558f3da6cd2efca2bb8e3fb199bda59740851eebdf995bba45d6f0c1771d04ad8fd9c97968323a9e2931fab81e18ca084b606b6e91000a1cf3d16c9f9ced645fbf638efa6e03e75643f8d7f5f0202c128673a20', 'nonce': 'LS2026', 'ts': 0}


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
