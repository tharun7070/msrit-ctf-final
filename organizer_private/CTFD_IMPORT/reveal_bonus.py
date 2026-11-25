#!/usr/bin/env python3
"""Auto-reveal the 10-challenge BONUS WAVE at T+offset. PRIVATE ORGANIZER TOOL.

The bonus challenges are imported HIDDEN by `import_ctfd.py --bonus`. This helper
sleeps until the scheduled reveal time and then flips every bonus challenge from
`hidden` to `visible`, so the wave appears mid-event with zero manual action.

Reveal time is resolved in this order:
  1. BONUS_REVEAL_AT   — absolute ISO-8601 timestamp (e.g. 2026-11-25T15:30:00+05:30)
  2. EVENT_START (+ BONUS_REVEAL_OFFSET_MINUTES, default 60) — ISO-8601 event start

Idempotent and restart-safe: if the reveal time has already passed it reveals
immediately, and already-visible challenges are skipped.
"""
import argparse,json,os,sys,time
from datetime import datetime,timedelta,timezone
from pathlib import Path
try:import requests
except ImportError:
 print('Install requests: python -m pip install -r requirements.txt',file=sys.stderr);sys.exit(2)

HERE=Path(__file__).resolve().parent
MANIFEST_BONUS=HERE/'manifest_bonus.json'

class APIError(Exception):pass

def req(session,url,method,path,**kwargs):
 try:
  r=session.request(method,url+path,timeout=25,**kwargs)
 except requests.RequestException as ex:raise APIError(f'{method} {path}: network error {ex.__class__.__name__}') from ex
 if r.status_code<200 or r.status_code>=300:
  raise APIError(f'{method} {path}: HTTP {r.status_code} (body withheld to protect secrets)')
 try:payload=r.json()
 except ValueError as ex:raise APIError(f'{method} {path}: non-JSON response') from ex
 if payload.get('success') is not True:
  raise APIError(f'{method} {path}: API success=false (details withheld)')
 return payload.get('data')

def parse_iso(value):
 text=value.strip().replace('Z','+00:00')
 when=datetime.fromisoformat(text)
 return when.replace(tzinfo=timezone.utc) if when.tzinfo is None else when

def resolve_reveal_at(args,manifest):
 explicit=args.reveal_at or os.environ.get('BONUS_REVEAL_AT')
 if explicit:return parse_iso(explicit)
 start=args.event_start or os.environ.get('EVENT_START')
 if not start:
  raise APIError('Set BONUS_REVEAL_AT (absolute) or EVENT_START (event start timestamp) so the reveal can be scheduled')
 offset=args.offset_minutes
 if offset is None:
  offset=int(os.environ.get('BONUS_REVEAL_OFFSET_MINUTES',manifest.get('reveal_offset_minutes',60)))
 return parse_iso(start)+timedelta(minutes=offset)

def wait_until(when):
 while True:
  remaining=(when-datetime.now(timezone.utc)).total_seconds()
  if remaining<=0:return
  print(f'[bonus] {int(remaining)}s until scheduled reveal at {when.isoformat()}',flush=True)
  time.sleep(min(remaining,60))

def run(args,session=None):
 man=json.loads(MANIFEST_BONUS.read_text())
 bonus=man['challenges']
 assert len(bonus)==10, 'manifest_bonus.json must hold exactly 10 challenges'
 names={c['name'] for c in bonus}
 # Validate connection settings up front so a misconfiguration fails fast,
 # not an hour later once the reveal is due.
 url=args.url.rstrip('/') if args.url else ''
 if not url.startswith(('https://','http://')):raise APIError('Use --url with absolute https:// or http:// address')
 if url.startswith('http://') and not args.allow_http:
  raise APIError('Plain HTTP can expose admin token; use HTTPS or --allow-http for trusted localhost/LAN only')
 token=args.token or os.environ.get('CTFD_TOKEN')
 if not token:raise APIError('Set CTFD_TOKEN environment variable; do not put token on command line')
 if args.now:
  print('[bonus] --now given: revealing immediately')
 else:
  reveal_at=resolve_reveal_at(args,man)
  print(f'[bonus] reveal scheduled for {reveal_at.isoformat()}',flush=True)
  wait_until(reveal_at)
 session=session or requests.Session()
 session.headers.update({'Authorization':'Token '+token})
 existing=req(session,url,'GET','/api/v1/challenges')
 by_name={e['name']:e for e in existing if isinstance(e,dict) and e.get('name')}
 revealed=0;missing=[]
 for ch in bonus:
  entry=by_name.get(ch['name'])
  if not entry:
   missing.append(ch['id']);continue
  if entry.get('state')=='visible':
   print(f"[bonus] {ch['id']} already visible — skip")
   continue
  req(session,url,'PATCH',f"/api/v1/challenges/{entry['id']}",json={'state':'visible'})
  revealed+=1
  print(f"[bonus] REVEALED {ch['id']} {ch['name']}")
 if missing:
  raise APIError(f'{len(missing)} bonus challenges missing from CTFd ({",".join(missing)}); run import_ctfd.py --bonus first')
 print(f'[bonus] DONE — {revealed} newly revealed / {len(names)} total')
 return {'revealed':revealed}

def main():
 parser=argparse.ArgumentParser(description='Scheduled BONUS WAVE reveal; waits until T+offset then publishes the hidden wave.')
 parser.add_argument('--url',default=os.environ.get('CTFD_URL'),help='CTFd base URL (or env CTFD_URL)')
 parser.add_argument('--token',help='CTFd admin token; prefer CTFD_TOKEN environment variable')
 parser.add_argument('--allow-http',action='store_true',help='allow plain HTTP only on trusted localhost/LAN')
 parser.add_argument('--reveal-at',help='absolute ISO-8601 reveal time (or env BONUS_REVEAL_AT)')
 parser.add_argument('--event-start',help='event start ISO-8601 (or env EVENT_START); offset is added to this')
 parser.add_argument('--offset-minutes',type=int,help='minutes after event start to reveal (default 60 / env BONUS_REVEAL_OFFSET_MINUTES)')
 parser.add_argument('--now',action='store_true',help='skip waiting and reveal immediately (manual trigger)')
 args=parser.parse_args()
 try:run(args)
 except (APIError,AssertionError,FileNotFoundError) as ex:print('ERROR:',ex,file=sys.stderr);sys.exit(1)
if __name__=='__main__':main()
