# FLAG THEFT AUTO — Event Day Runbook

## Schedule (150-Minute Competition)

| Time Window | Phase | Activities |
|---|---|---|
| **T - 60 min** | System Prep | Verify Docker stack, test participant Wi-Fi, run pre-flight audit. |
| **T - 15 min** | Briefing (15m) | Welcome teams, announce rules, distribute team credentials / invitation keys. |
| **T - 00 min** | Launch (10m) | Teams log in, access `/crew`, confirm 2–3 member roster. |
| **T + 10 min** | Heist Active (100m) | Core competition window: solve challenges, submit flags, monitor live scoreboard. |
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

### Emergency Incident Response
- **Forgotten Crew Passcode**: Admin can inspect or reset team passwords directly in CTFd Admin -> `Teams`.
- **Accidental Team Over-enrollment**: Admin can remove extra members in CTFd Admin to enforce the 3-person limit.
- **Service Restart**:
  ```powershell
  docker compose restart nginx ctfd
  ```
