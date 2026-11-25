# FLAG THEFT AUTO — Event Day Runbook

## Schedule (150-Minute Competition)

| Time Window | Phase | Activities |
|---|---|---|
| **T - 60 min** | System Prep | Verify Docker stack, test participant Wi-Fi, run pre-flight audit. |
| **T - 15 min** | Briefing (15m) | Welcome teams, announce rules, distribute team credentials / invitation keys. |
| **T - 00 min** | Launch (10m) | Teams log in, access `/crew`, confirm 2–3 member roster. |
| **T + 10 min** | Heist Active (100m) | Core competition window: solve challenges, submit flags, monitor live scoreboard. |
| **T + 70 min** | Bonus Wave Reveal | 10 hidden bonus missions ($25 each) auto-publish; announce the bonus round. |
| **T + 110 min**| Final Buffer (15m) | Freeze scoreboard if desired, resolve pending submissions. |
| **T + 125 min**| Getaway & Closing (10m) | Unfreeze scoreboard, announce winners, distribute awards. |

---

## Organizer Roles & Responsibilities

1. **Lead Operator**: Monitors CTFd Admin panel at `http://<SERVER_IP>:8000/admin`.
2. **Support Technician**: Helps teams with network connectivity or credential issues.
3. **Challenge Proctor**: Verifies winner writeups and confirms no foul play or local network disruption.

---

## Common Event-Day Operations

### Freezing the Scoreboard
During the final 15 minutes to preserve suspense:
1. Open CTFd Admin Panel -> `Settings` -> `Competition`.
2. Set `Scoreboard Freeze` to active.
3. The participant `/leaderboard` page will preserve the frozen standings until thawed.

### Exporting Final Results
1. In CTFd Admin Panel -> `Config` -> `Backup` -> Export CSV or ZIP.
2. Run `organizer_private/verify_submissions.py` to cross-validate team solve timestamps against official answer hashes.

### Bonus Wave Reveal
Ten bonus missions ($25 each) ship hidden and publish automatically 60 minutes into the solve window. The `bonus-reveal` container handles this using `EVENT_START` (+ `BONUS_REVEAL_OFFSET_MINUTES`) from `.env` — no action is needed on the day.

1. Verify once at launch that admin shows the 10 bonus missions as `hidden` and a normal team cannot see them.
2. At T + 70 min, confirm they flipped to visible on the participant board.
3. If they did not appear, reveal manually:
   ```powershell
   $env:CTFD_URL = 'http://127.0.0.1:8000'
   $env:CTFD_TOKEN = '<admin token>'
   python organizer_private/CTFD_IMPORT/reveal_bonus.py --now --allow-http
   ```
   The reveal is idempotent, so re-running is safe.

### Emergency Incident Response
- **Forgotten Crew Passcode**: Admin can inspect or reset team passwords directly in CTFd Admin -> `Teams`.
- **Accidental Team Over-enrollment**: Admin can remove extra members in CTFd Admin to enforce the 3-person limit.
- **Service Restart**:
  ```powershell
  docker compose restart nginx ctfd
  ```
