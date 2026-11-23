#!/usr/bin/env python3
"""
FLAG THEFT AUTO — local mock of the CTFd REST API (ORGANIZER / TEST ONLY).

Purpose: run the full React frontend against a working backend when a real
CTFd instance is not available, so login, missions, hints (paid), flag
submission, crew and leaderboard can all be exercised end-to-end.

This is NOT CTFd and must NEVER be exposed to participants during a real event.
It implements only the subset of /api/v1 endpoints the frontend calls, keeping
all state in memory. Real challenge flags/points/hints are read from
organizer_private/CTFD_IMPORT/manifest.json so submissions behave correctly.

Run:
    python organizer_private/mock_ctfd/mock_ctfd_server.py            # port 8000
    python organizer_private/mock_ctfd/mock_ctfd_server.py --port 8000

Demo logins (seeded):
    demo / demo1234            (no crew yet — tests create/join)
    vinewood_cap / demo1234    (crew: Vinewood Syndicate)
    nightfall_cap / demo1234   (crew: Nightfall Crew)
    pager_cap / demo1234       (crew: Pager Kings)
"""
from __future__ import annotations

import argparse
import json
import secrets
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "organizer_private" / "CTFD_IMPORT" / "manifest.json"

HINT_COST = {"Easy": 10, "Medium": 20, "Hard": 30}


# ── in-memory state ─────────────────────────────────────────────────────────
class State:
    def __init__(self) -> None:
        self.challenges: list[dict] = []          # CTFd-shaped challenge records
        self.hints: dict[int, dict] = {}          # hint_id -> {challenge_id, cost, content}
        self.users: dict[int, dict] = {}
        self.teams: dict[int, dict] = {}
        self.sessions: dict[str, int] = {}        # session token -> user_id
        self.solves: list[dict] = []              # {owner_kind, owner_id, challenge_id, user_id, date}
        self.unlocked: set[tuple[str, int, int]] = set()  # (owner_kind, owner_id, hint_id)
        self._next_user = 1
        self._next_team = 1
        self._load_challenges()
        self._seed()

    # ── challenge data from the real manifest ───────────────────────────────
    def _load_challenges(self) -> None:
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
        manifest = data["challenges"]
        for idx, ch in enumerate(manifest, start=1):
            cost = HINT_COST.get(ch["level"], 10)
            self.challenges.append(
                {
                    "id": idx,                     # numeric CTFd challenge id
                    "fta_id": ch["id"],            # E01..H05
                    "name": ch["name"],
                    "value": ch["points"],
                    "category": ch["category"],
                    "description": ch["description"],
                    "level": ch["level"],
                    "flag": ch["flag"],
                    "files": ch["files"],
                }
            )
            for i, hint in enumerate(ch.get("hints", []), start=1):
                hint_id = idx * 100 + i
                self.hints[hint_id] = {
                    "id": hint_id,
                    "challenge_id": idx,
                    "cost": cost,
                    "content": hint,
                }

    # ── demo seed ───────────────────────────────────────────────────────────
    def _add_user(self, name: str, password: str, team_id: int | None) -> int:
        uid = self._next_user
        self._next_user += 1
        self.users[uid] = {
            "id": uid,
            "name": name,
            "email": f"{name}@fta.local",
            "password": password,
            "team_id": team_id,
        }
        return uid

    def _add_team(self, name: str, password: str) -> int:
        tid = self._next_team
        self._next_team += 1
        self.teams[tid] = {"id": tid, "name": name, "password": password}
        return tid

    def _add_solve(self, owner_kind: str, owner_id: int, challenge_id: int, user_id: int) -> None:
        self.solves.append(
            {
                "owner_kind": owner_kind,
                "owner_id": owner_id,
                "challenge_id": challenge_id,
                "user_id": user_id,
                "date": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }
        )

    def _seed(self) -> None:
        t1 = self._add_team("Vinewood Syndicate", "crewpass")
        t2 = self._add_team("Nightfall Crew", "crewpass")
        t3 = self._add_team("Pager Kings", "crewpass")
        u1 = self._add_user("vinewood_cap", "demo1234", t1)
        u2 = self._add_user("nightfall_cap", "demo1234", t2)
        u3 = self._add_user("pager_cap", "demo1234", t3)
        self._add_user("demo", "demo1234", None)  # crew-less account for testing

        for cid in (1, 2, 3, 6):          # E01,E02,E03,M01 -> 250
            self._add_solve("team", t1, cid, u1)
        for cid in (1, 2, 6, 7):          # E01,E02,M01,M02 -> 300
            self._add_solve("team", t2, cid, u2)
        for cid in (1, 4, 5):             # E01,E04,E05 -> 150
            self._add_solve("team", t3, cid, u3)
        self.unlocked.add(("team", t3, 101))  # Pager Kings spent $10 on a hint

    # ── helpers ─────────────────────────────────────────────────────────────
    def challenge(self, cid: int) -> dict | None:
        return next((c for c in self.challenges if c["id"] == cid), None)

    def owner_of(self, user: dict) -> tuple[str, int]:
        if user.get("team_id"):
            return "team", user["team_id"]
        return "user", user["id"]

    def score(self, kind: str, oid: int) -> int:
        total = 0
        for s in self.solves:
            if s["owner_kind"] == kind and s["owner_id"] == oid:
                ch = self.challenge(s["challenge_id"])
                if ch:
                    total += ch["value"]
        for (k, o, hid) in self.unlocked:
            if k == kind and o == oid:
                total -= self.hints.get(hid, {}).get("cost", 0)
        return total

    def solves_for(self, kind: str, oid: int) -> list[dict]:
        return [
            {
                "challenge_id": s["challenge_id"],
                "user_id": s["user_id"],
                "team_id": oid if kind == "team" else None,
                "date": s["date"],
            }
            for s in self.solves
            if s["owner_kind"] == kind and s["owner_id"] == oid
        ]

    def is_solved(self, kind: str, oid: int, cid: int) -> bool:
        return any(
            s["owner_kind"] == kind and s["owner_id"] == oid and s["challenge_id"] == cid
            for s in self.solves
        )

    def team_public(self, tid: int) -> dict:
        t = self.teams[tid]
        return {
            "id": tid,
            "name": t["name"],
            "score": self.score("team", tid),
            "solves": self.solves_for("team", tid),
        }

    def standings(self) -> list[dict]:
        rows = [self.team_public(tid) for tid in self.teams]
        rows.sort(key=lambda r: (-r["score"], r["id"]))
        return rows


STATE = State()


# ── HTTP handler ────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    server_version = "FTA-MockCTFd/1.0"

    def log_message(self, fmt: str, *args) -> None:  # keep console readable
        return

    # -- low-level helpers --
    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            return {}

    def _current_user(self) -> dict | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            return None
        token = cookie.get("fta_session")
        if not token:
            return None
        uid = STATE.sessions.get(token.value)
        return STATE.users.get(uid) if uid else None

    # -- verb dispatch --
    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self) -> None:
        self._route("GET")

    def do_POST(self) -> None:
        self._route("POST")

    def do_PATCH(self) -> None:
        self._route("PATCH")

    def _cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin") or "http://localhost:3000")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-CSRFToken")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")

    # -- routing --
    def _route(self, method: str) -> None:
        path = urlparse(self.path).path
        parts = [p for p in path.split("/") if p]

        # /logout and /login are proxied too
        if path == "/logout":
            raw = self.headers.get("Cookie")
            if raw:
                c = SimpleCookie()
                c.load(raw)
                tok = c.get("fta_session")
                if tok:
                    STATE.sessions.pop(tok.value, None)
            return self._send(200, {"success": True})

        if len(parts) < 2 or parts[0] != "api" or parts[1] != "v1":
            return self._send(404, {"success": False, "errors": ["Not found"]})
        seg = parts[2:]

        try:
            return self._api(method, seg)
        except Exception as exc:  # never crash the test server
            return self._send(500, {"success": False, "errors": [f"mock error: {exc}"]})

    def _api(self, method: str, seg: list[str]) -> None:
        head = seg[0] if seg else ""

        # ── settings / config (health) ──
        if head == "settings" and method == "GET":
            return self._send(200, {"success": True, "data": {}})
        if head == "configs" and method == "GET":
            return self._send(200, {"success": True, "data": {}})

        # ── auth ──
        if seg[:2] == ["auth", "login"] and method == "POST":
            return self._login()
        if seg[:2] == ["auth", "logout"] and method == "POST":
            return self._send(200, {"success": True})

        # ── users ──
        if head == "users":
            return self._users(method, seg)

        # ── teams ──
        if head == "teams":
            return self._teams(method, seg)

        # ── challenges ──
        if head == "challenges":
            return self._challenges(method, seg)

        # ── hints ──
        if head == "hints" and len(seg) >= 2 and method == "GET":
            return self._hint_content(int(seg[1]))

        # ── unlocks ──
        if head == "unlocks" and method == "POST":
            return self._unlock()

        # ── scoreboard ──
        if head == "scoreboard" and method == "GET":
            return self._send(200, {"success": True, "data": STATE.standings()})

        return self._send(404, {"success": False, "errors": ["Unknown endpoint"]})

    # ── handlers ────────────────────────────────────────────────────────────
    def _login(self) -> None:
        body = self._json()
        name = (body.get("name") or "").strip()
        password = body.get("password") or ""
        user = next((u for u in STATE.users.values() if u["name"] == name), None)
        if not user or user["password"] != password:
            return self._send(403, {"success": False, "errors": ["Your username or password is incorrect"]})
        token = secrets.token_hex(16)
        STATE.sessions[token] = user["id"]
        body_bytes = json.dumps({"success": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("Set-Cookie", f"fta_session={token}; Path=/; HttpOnly; SameSite=Lax")
        self._cors()
        self.end_headers()
        self.wfile.write(body_bytes)

    def _users(self, method: str, seg: list[str]) -> None:
        if method == "GET" and len(seg) == 2 and seg[1] == "me":
            user = self._current_user()
            if not user:
                return self._send(401, {"success": False, "errors": ["Please login"]})
            return self._send(200, {"success": True, "data": self._user_public(user)})
        if method == "POST" and len(seg) == 1:
            body = self._json()
            name = (body.get("name") or "").strip()
            if not name or not body.get("password"):
                return self._send(400, {"success": False, "errors": ["name and password required"]})
            if any(u["name"] == name for u in STATE.users.values()):
                return self._send(400, {"success": False, "errors": ["That name is already taken"]})
            uid = STATE._add_user(name, body["password"], None)
            return self._send(200, {"success": True, "data": self._user_public(STATE.users[uid])})
        # GET /users/<id>/solves
        if method == "GET" and len(seg) == 3 and seg[2] == "solves":
            return self._send(200, {"success": True, "data": STATE.solves_for("user", int(seg[1]))})
        return self._send(404, {"success": False, "errors": ["Unknown users endpoint"]})

    def _user_public(self, user: dict) -> dict:
        return {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "team_id": user.get("team_id"),
        }

    def _teams(self, method: str, seg: list[str]) -> None:
        user = self._current_user()
        if seg[1:2] == ["me"] and method == "GET":
            if not user or not user.get("team_id"):
                return self._send(404, {"success": False, "errors": ["User is not on a team"]})
            return self._send(200, {"success": True, "data": STATE.team_public(user["team_id"])})
        if seg[1:2] == ["join"] and method == "POST":
            body = self._json()
            name = (body.get("name") or "").strip()
            team = next((t for t in STATE.teams.values() if t["name"] == name), None)
            if not team or team["password"] != (body.get("password") or ""):
                return self._send(403, {"success": False, "errors": ["Incorrect team name or password"]})
            if user:
                user["team_id"] = team["id"]
            return self._send(200, {"success": True, "data": STATE.team_public(team["id"])})
        if len(seg) == 1 and method == "POST":
            body = self._json()
            name = (body.get("name") or "").strip()
            if not name:
                return self._send(400, {"success": False, "errors": ["name required"]})
            if any(t["name"] == name for t in STATE.teams.values()):
                return self._send(400, {"success": False, "errors": ["Team name already taken"]})
            tid = STATE._add_team(name, body.get("password") or "")
            if user:
                user["team_id"] = tid
            return self._send(200, {"success": True, "data": STATE.team_public(tid)})
        # GET /teams/<id>/members or /solves
        if len(seg) == 3 and method == "GET":
            tid = int(seg[1])
            if tid not in STATE.teams:
                return self._send(404, {"success": False, "errors": ["Team not found"]})
            if seg[2] == "members":
                members = [
                    {"id": u["id"], "name": u["name"], "score": STATE.score("user", u["id"])}
                    for u in STATE.users.values()
                    if u.get("team_id") == tid
                ]
                return self._send(200, {"success": True, "data": members})
            if seg[2] == "solves":
                return self._send(200, {"success": True, "data": STATE.solves_for("team", tid)})
        return self._send(404, {"success": False, "errors": ["Unknown teams endpoint"]})

    def _challenges(self, method: str, seg: list[str]) -> None:
        if method == "GET" and len(seg) == 1:
            user = self._current_user()
            data = []
            for c in STATE.challenges:
                solved = False
                if user:
                    kind, oid = STATE.owner_of(user)
                    solved = STATE.is_solved(kind, oid, c["id"])
                data.append(
                    {
                        "id": c["id"],
                        "name": c["name"],
                        "value": c["value"],
                        "category": c["category"],
                        "description": c["description"],
                        "type": "standard",
                        "state": "visible",
                        "solves": sum(1 for s in STATE.solves if s["challenge_id"] == c["id"]),
                        "solved_by_me": solved,
                    }
                )
            return self._send(200, {"success": True, "data": data})

        if len(seg) >= 2:
            if seg[1] == "attempt" and method == "POST":
                return self._attempt()
            try:
                cid = int(seg[1])
            except ValueError:
                return self._send(404, {"success": False, "errors": ["Unknown challenges endpoint"]})
            c = STATE.challenge(cid)
            if not c:
                return self._send(404, {"success": False, "errors": ["Challenge not found"]})
            if len(seg) == 2 and method == "GET":
                return self._send(200, {"success": True, "data": {
                    "id": c["id"], "name": c["name"], "value": c["value"],
                    "category": c["category"], "description": c["description"],
                    "type": "standard", "state": "visible",
                }})
            if len(seg) == 3 and seg[2] == "files" and method == "GET":
                data = [
                    {
                        "id": cid * 100 + i,
                        "name": fn,
                        "type": "challenge",
                        # Serve from the static mirror the frontend already hosts.
                        "location": f"/challenges/{c['level'].upper()}/{c['fta_id']}/{fn}",
                    }
                    for i, fn in enumerate(c["files"], start=1)
                ]
                return self._send(200, {"success": True, "data": data})
            if len(seg) == 3 and seg[2] == "hints" and method == "GET":
                return self._send(200, {"success": True, "data": self._hints_for(cid)})
        return self._send(404, {"success": False, "errors": ["Unknown challenges endpoint"]})

    def _hints_for(self, cid: int) -> list[dict]:
        user = self._current_user()
        kind, oid = STATE.owner_of(user) if user else ("none", 0)
        out = []
        for h in STATE.hints.values():
            if h["challenge_id"] != cid:
                continue
            unlocked = (kind, oid, h["id"]) in STATE.unlocked
            out.append({
                "id": h["id"],
                "cost": h["cost"],
                "challenge_id": cid,
                "content": h["content"] if unlocked else None,
            })
        out.sort(key=lambda x: x["id"])
        return out

    def _hint_content(self, hint_id: int) -> None:
        user = self._current_user()
        h = STATE.hints.get(hint_id)
        if not h:
            return self._send(404, {"success": False, "errors": ["Hint not found"]})
        kind, oid = STATE.owner_of(user) if user else ("none", 0)
        unlocked = (kind, oid, hint_id) in STATE.unlocked
        return self._send(200, {"success": True, "data": {
            "id": hint_id,
            "cost": h["cost"],
            "challenge_id": h["challenge_id"],
            "content": h["content"] if unlocked else None,
        }})

    def _unlock(self) -> None:
        user = self._current_user()
        if not user:
            return self._send(401, {"success": False, "errors": ["Please login"]})
        body = self._json()
        if body.get("type") != "hints":
            return self._send(400, {"success": False, "errors": ["Only hint unlocks are supported"]})
        try:
            hint_id = int(body.get("target"))
        except (TypeError, ValueError):
            return self._send(400, {"success": False, "errors": ["Invalid target"]})
        h = STATE.hints.get(hint_id)
        if not h:
            return self._send(404, {"success": False, "errors": ["Hint not found"]})
        kind, oid = STATE.owner_of(user)
        STATE.unlocked.add((kind, oid, hint_id))     # cost applied in score()
        return self._send(200, {"success": True, "data": {"unlocked": hint_id, "cost": h["cost"]}})

    def _attempt(self) -> None:
        user = self._current_user()
        if not user:
            return self._send(401, {"success": False, "errors": ["Please login"]})
        body = self._json()
        try:
            cid = int(body.get("challenge_id"))
        except (TypeError, ValueError):
            return self._send(400, {"success": False, "errors": ["challenge_id required"]})
        submission = (body.get("submission") or "").strip()
        c = STATE.challenge(cid)
        if not c:
            return self._send(404, {"success": False, "errors": ["Challenge not found"]})
        kind, oid = STATE.owner_of(user)
        if submission == c["flag"]:
            if STATE.is_solved(kind, oid, cid):
                return self._send(200, {"success": True, "data": {
                    "status": "already_solved",
                    "message": "You already solved this challenge",
                }})
            STATE._add_solve(kind, oid, cid, user["id"])
            return self._send(200, {"success": True, "data": {
                "status": "correct",
                "message": "Correct! +%d points" % c["value"],
            }})
        return self._send(200, {"success": True, "data": {
            "status": "incorrect",
            "message": "Incorrect flag, try again.",
        }})


def main() -> None:
    ap = argparse.ArgumentParser(description="Local mock CTFd API for FLAG THEFT AUTO testing")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print("=" * 66)
    print(" FLAG THEFT AUTO — MOCK CTFd API (TEST ONLY, not real CTFd)")
    print("=" * 66)
    print(f" Listening on http://{args.host}:{args.port}  (Vite proxies /api here)")
    print(" Loaded challenges:", len(STATE.challenges), "| hints:", len(STATE.hints))
    print(" Demo logins (username / password):")
    print("   demo / demo1234           (no crew — test create & join)")
    print("   vinewood_cap / demo1234   (crew: Vinewood Syndicate)")
    print("   nightfall_cap / demo1234  (crew: Nightfall Crew)")
    print("   pager_cap / demo1234      (crew: Pager Kings)")
    print(" Real flags from manifest are accepted on submit. Ctrl+C to stop.")
    print("=" * 66)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[stopped]")
        server.shutdown()


if __name__ == "__main__":
    main()
