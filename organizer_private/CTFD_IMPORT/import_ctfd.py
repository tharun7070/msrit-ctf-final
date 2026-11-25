#!/usr/bin/env python3
"""CTFd 3.x admin API importer for FLAG THEFT AUTO. PRIVATE ORGANIZER TOOL.

Default is zero-network dry-run. Flags are read from private manifest, never logged.
"""
import argparse,json,os,sys
from pathlib import Path
try:import requests
except ImportError:
 print('Install requests: python -m pip install -r requirements.txt',file=sys.stderr);sys.exit(2)

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
MANIFEST=HERE/'manifest.json'
MANIFEST_BONUS=HERE/'manifest_bonus.json'

class APIError(Exception):pass

def req(session,url,method,path,**kwargs):
 # CTFd only honors the Authorization token on JSON requests; send Content-Type
 # application/json for plain calls (multipart file uploads keep their own type).
 if 'files' not in kwargs and 'data' not in kwargs:
  headers=dict(kwargs.get('headers') or {})
  headers.setdefault('Content-Type','application/json')
  kwargs['headers']=headers
 try:
  r=session.request(method,url+path,timeout=25,**kwargs)
 except requests.RequestException as ex:raise APIError(f'{method} {path}: network error {ex.__class__.__name__}') from ex
 if r.status_code<200 or r.status_code>=300:
  # Server may echo the secret flag in validation errors. Never print its body.
  raise APIError(f'{method} {path}: HTTP {r.status_code} (body withheld to protect secrets)')
 try:payload=r.json()
 except ValueError as ex:raise APIError(f'{method} {path}: non-JSON response') from ex
 if payload.get('success') is not True:
  raise APIError(f'{method} {path}: API success=false (details withheld)')
 return payload.get('data')

def ensure_manifest(root,manifest,expected_count=25,expected_points=2200):
 ids=set();expected=0
 for ch in manifest['challenges']:
  assert ch['id'] not in ids;ids.add(ch['id'])
  assert ch['flag'].startswith('FTA{') and ch['flag'].endswith('}')
  expected+=ch['points']
  directory=root/ch['directory']
  assert (directory/'MISSION.md').is_file()
  assert (directory/'MISSION.md').read_text()==ch['description']
  for fn in ch['files']:
   assert Path(fn).name==fn and (directory/fn).is_file() and (directory/fn).stat().st_size>0
  assert len(ch['hints'])==3
 assert len(ids)==expected_count and expected==expected_points
 return manifest['challenges']

def run(args,session=None):
 bonus=getattr(args,'bonus',False)
 manifest_path=MANIFEST_BONUS if bonus else MANIFEST
 man=json.loads(manifest_path.read_text())
 if bonus:
  challenges=ensure_manifest(ROOT,man,10,250)
  reveal=man.get('reveal_offset_minutes',60)
  print(f'FLAG THEFT AUTO BONUS WAVE: 10 validated manifests / 250 points (stays hidden until T+{reveal}min)')
 else:
  challenges=ensure_manifest(ROOT,man)
  print('FLAG THEFT AUTO: 25 validated manifests / 2,200 points')
 if not args.apply:
  print('DRY RUN — no network calls or changes; flags are never printed')
  for ch in challenges:
   hint_cost={'Easy':10,'Medium':20,'Hard':30}.get(ch['level'],10)
   print(f"  {ch['id']} {ch['name']} | {ch['points']} pts | {len(ch['files'])} files | 3 hints @ ${hint_cost} each")
  return {'created':0,'dry_run':True}
 url=args.url.rstrip('/') if args.url else ''
 if not url.startswith(('https://','http://')):raise APIError('Use --url with absolute https:// or http:// address')
 if url.startswith('http://') and not args.allow_http:
  raise APIError('Plain HTTP can expose admin token; use HTTPS or --allow-http for trusted localhost/LAN only')
 token=args.token or os.environ.get('CTFD_TOKEN')
 if not token:raise APIError('Set CTFD_TOKEN environment variable; do not put token on command line')
 session=session or requests.Session()
 session.headers.update({'Authorization':'Token '+token})
 print('Checking admin connection...')
 existing=req(session,url,'GET','/api/v1/challenges')
 names={e.get('name') for e in existing if isinstance(e,dict)}
 collision=[c['name'] for c in challenges if c['name'] in names]
 if collision:raise APIError(f'{len(collision)} challenges already exist; import requires a fresh board or manual cleanup')
 count=0
 for ch in challenges:
  name=ch['name']
  hint_cost={'Easy':10,'Medium':20,'Hard':30}.get(ch['level'],10)
  try:
   data=req(session,url,'POST','/api/v1/challenges',json={
    'name':name,'description':ch['description'],'value':ch['points'],
    'category':f"{ch['level'].upper()} | {ch['category']}",
    'type':'standard','state':'hidden','max_attempts':0,
   })
   challenge_id=data['id']
   # Only attach the private flag via privileged admin endpoint.
   req(session,url,'POST','/api/v1/flags',json={
    'challenge_id':challenge_id,'type':'static','content':ch['flag'],'data':''
   })
   # Costed hints: unlocking deducts hint_cost from the team's score (CTFd native).
   for index,hint in enumerate(ch['hints'],1):
    req(session,url,'POST','/api/v1/hints',json={
     'challenge_id':challenge_id,'type':'standard','title':f'Hint {index}',
     'content':hint,'cost':hint_cost,
    })
   for filename in ch['files']:
    path=ROOT/ch['directory']/filename
    with path.open('rb') as file:
     req(session,url,'POST','/api/v1/files',data={'type':'challenge','challenge_id':str(challenge_id)},files={'file':(filename,file)})
   if bonus:
    # Bonus wave stays hidden; reveal_bonus.py flips it visible at T+offset.
    print(f"[OK] {ch['id']} imported HIDDEN (awaits reveal): {len(ch['files'])} files, 3 hints")
   else:
    # The challenge becomes visible ONLY after all private/public parts succeed.
    req(session,url,'PATCH',f'/api/v1/challenges/{challenge_id}',json={'state':'visible'})
    print(f"[OK] {ch['id']} imported and published: {len(ch['files'])} files, 3 hints")
   count+=1
  except (APIError,KeyError) as ex:
   raise APIError(f"Import stopped at {ch['id']}. Partial challenge left hidden if creation succeeded. {ex}") from ex
 if bonus:
  print(f'ALL DONE — {count} bonus challenges imported hidden; they surface automatically at the scheduled reveal.')
 else:
  print(f'ALL DONE — {count} visible standard challenges; inspect them from a non-admin team account.')
 return {'created':count,'dry_run':False}

def main():
 parser=argparse.ArgumentParser(description='Private CTFd importer; dry-run is default.')
 parser.add_argument('--apply',action='store_true',help='Mutate CTFd instance (default just validates locally)')
 parser.add_argument('--url',default=os.environ.get('CTFD_URL'),help='CTFd base URL (or env CTFD_URL)')
 parser.add_argument('--token',help='CTFd admin token; prefer CTFD_TOKEN environment variable')
 parser.add_argument('--allow-http',action='store_true',help='allow plain HTTP only on trusted localhost/LAN')
 parser.add_argument('--bonus',action='store_true',help='import the 10-challenge bonus wave as HIDDEN (revealed later at T+offset)')
 args=parser.parse_args()
 try:run(args)
 except (APIError,AssertionError,FileNotFoundError) as ex:print('ERROR:',ex,file=sys.stderr);sys.exit(1)
if __name__=='__main__':main()
