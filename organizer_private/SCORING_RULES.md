# Scoring and Tie-Breaking

| Level | Missions | Value | Maximum |
|---|---:|---:|---:|
| The Street Job (Easy) | 5 | 50 | 250 |
| The Big Heist (Medium) | 5 | 100 | 500 |
| The Final Getaway (Hard) | 5 | 160 | 800 |
| **Total** | **15** | | **1,550** |

All challenges are **standard fixed-value** CTFd challenges. Three hints each, all with zero cost. First accepted flag per team per challenge grants the full value. No speed bonuses, first-blood bonuses, extra credit, or wrong-guess deductions.

At closing, higher total score ranks higher. Equal totals: the team whose last *score-increasing correct submission* happened earlier wins (earlier time reaching that total). If timestamps exactly match, award the tied place, or use team-name lexical order only for display without changing awards; communicate method in advance. Never use count of guesses or penalties not published in this document.

If a judge withdraws a broken challenge, apply the same policy to everyone: either replace it equally before resuming or exclude its points from all teams. Record adjudication in RUNBOOK incident log.

Backup offline scorer: `python ORGANIZER/verify_submissions.py --csv /path/to/offline_submissions.csv`. Input header `timestamp,team_id,challenge_id,flag`; timestamps must be ISO-8601 including offset, and only permitted submissions before the announced closing time are entered. **Do not put completed submission files in a public directory.**
