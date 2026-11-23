#!/usr/bin/env python3
"""Maze Bank of Los Santos - account token gateway (participant build).

Holds a 1024-bit RSA key and issues / verifies short-lived bearer tokens.
Import it as a module, or run it to expose the local HTTP endpoints:

    GET  /pubkey      -> {n, e, bits}
    POST /sign_debug  -> {"message": "...", "seed": <int>?} -> {signature, fault, half}
    POST /verify      -> {"token": {...}}                  -> {ok}
    POST /submit      -> {"token": {...}}                  -> {flag} | {error}
    GET  /guest       -> a freshly issued guest token

A token is a JSON object:  {"role": "...", "msg": "...", "sig": "<hex>"}.
"""
import base64
import json
import os
import random
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

N = 118865252427956305283327846975934473994270521522722245747390812674457890107233825953528809866006261830016586023032651486335162331525774667502009666733291850189465477298662339206176707808116681017185153458954182915918757410553466664933550967814606912227970525920542922783751873126477132138999917877768759105463
E = 65537
K = (N.bit_length() + 7) // 8

# Opaque keystore - do not edit.
_OBF = "4smoAdszdeJ6gspLE34ASUtgwnOjX6/Mzv1Vkn18gsSg/mxAXy5aUgpeJBRv4EfhBSZgjBJe7I4wGMvaGWIykqyZvWQaQ23rhWB1fE9/gbbfGJiRn1a8npHrMnNjL/IE6wdjujVcf6UZTeI3x/xLhK+1Fj5Mwl99VLM++h+mJEg="
_MASK = b'MAZE_BANK_LOS_SANTOS_AUDIT_2026'

GUEST_PREFIX = "REF:"
GUEST_MESSAGE = "REF:guest:los_santos:view_only:4421"
ADMIN_MESSAGE = "ACTION=VAULT_TRANSFER;ROLE=admin;SRC=MAZE_BANK;AMT=1000000;NONCE=LS2026"
FAULT_RATE = 0.1


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
    """Leftover debug route: signs reference (guest) traffic.

    Roughly FAULT_RATE of requests come back with exactly one of the two
    half-results computed wrong.  Given a seed the outcome is deterministic.
    """
    msg = message.encode() if isinstance(message, str) else bytes(message)
    if not msg.startswith(GUEST_PREFIX.encode()):
        raise PermissionError("sign_debug serves reference traffic only")
    m = int.from_bytes(msg, "big")
    rnd = random.Random(seed) if seed is not None else random.Random(secrets.randbits(64))
    if rnd.random() < FAULT_RATE:
        half = rnd.choice(("Sp", "Sq"))
        for _ in range(16):
            sig = _sign_with_one_half_broken(m, half, rnd)
            if sig != _sign(m):
                return {"message": msg.decode("utf-8", "replace"),
                        "signature": format(sig, "x"), "fault": True, "half": half}
    return {"message": msg.decode("utf-8", "replace"),
            "signature": format(_sign(m), "x"), "fault": False, "half": None}


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


def issue_guest_token():
    m = int.from_bytes(GUEST_MESSAGE.encode(), "big")
    return {"role": "guest", "msg": GUEST_MESSAGE, "sig": format(_sign(m), "x")}


def submit(token):
    if not isinstance(token, dict):
        return None
    if token.get("role") != "admin":
        return None
    if token.get("msg") != ADMIN_MESSAGE:
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
