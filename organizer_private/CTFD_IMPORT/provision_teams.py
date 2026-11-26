#!/usr/bin/env python3
"""CTFd 3.x admin-API team provisioning for FLAG THEFT AUTO. PRIVATE ORGANIZER TOOL.

Creates one team per crew with pre-issued login credentials so registration can be
closed and a single group cannot self-enroll twice. Default is a zero-network
dry-run; nothing is created until --apply is passed.

Roster sources (choose one):
  * --teams N           auto-generate N crews (CREW-01 .. CREW-N), one login each
  * --roster FILE       CSV: team_name,member1[,member2][,member3]

On --apply the script also sets registration_visibility=private so the public
sign-up route stops working; use --keep-registration to skip that.

Generated credentials are written to a private CSV (never printed to the console,
never committed). Superseded teams/users are left untouched.
"""
import argparse,csv,os,re,secrets,sys
from pathlib import Path
try:import requests
except ImportError:
 print('Install requests: python -m pip install -r requirements.txt',file=sys.stderr);sys.exit(2)

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
CREDS_DEFAULT=HERE.parent/'team_credentials.csv'
EMAIL_DOMAIN='flagtheftauto.cv'
MAX_MEMBERS=3

class APIError(Exception):pass

def req(session,url,method,path,**kwargs):
 # CTFd only honors the Authorization token on JSON requests; send Content-Type
 # application/json for plain calls.
 if 'files' not in kwargs and 'data' not in kwargs:
  headers=dict(kwargs.get('headers') or {})
  headers.setdefault('Content-Type','application/json')
  kwargs['headers']=headers
 try:
  r=session.request(method,url+path,timeout=25,**kwargs)
 except requests.RequestException as ex:raise APIError(f'{method} {path}: network error {ex.__class__.__name__}') from ex
 if r.status_code<200 or r.status_code>=300:
  # Server may echo raw values in validation errors. Never print the body.
  raise APIError(f'{method} {path}: HTTP {r.status_code} (body withheld to protect credentials)')
 try:payload=r.json()
 except ValueError as ex:raise APIError(f'{method} {path}: non-JSON response') from ex
 if payload.get('success') is not True:
  raise APIError(f'{method} {path}: API success=false (details withheld)')
 return payload.get('data')

def slugify(text,fallback='crew'):
 out=re.sub(r'[^a-z0-9]+','-',text.strip().lower()).strip('-')
 return out or fallback

def gen_password():return secrets.token_urlsafe(9)   # ~12 chars, well over any CTFd minimum

def load_roster(args):
 """-> [{'team':str,'members':[str,...]}] preserving order, validating 1..3 members."""
 if args.roster:
  rows=[]
  with open(args.roster,newline='',encoding='utf-8') as fh:
   for lineno,row in enumerate(csv.reader(fh),1):
    row=[c.strip() for c in row]
    if not row or not any(row):continue
    if lineno==1 and row[0].lower() in ('team','team_name','crew'):continue
    team=row[0];members=[m for m in row[1:] if m]
    if not team:raise ValueError(f'{args.roster}:{lineno}: empty team name')
    if not members:members=[slugify(team)]
    if len(members)>MAX_MEMBERS:raise ValueError(f'{args.roster}:{lineno}: >{MAX_MEMBERS} members')
    rows.append({'team':team,'members':members})
  if not rows:raise ValueError(f'{args.roster}: no teams found')
  return rows
 count=max(1,args.teams)
 return [{'team':f'CREW-{i:02d}','members':[f'crew{i:02d}']} for i in range(1,count+1)]

def build_plan(roster):
 """Assign unique names/emails/passwords; return (plan, team_passwords)."""
 seen_users=set();plan=[]
 for idx,entry in enumerate(roster,1):
  team_pw=gen_password()
  for member in entry['members']:
   # usernames must be globally unique in CTFd
   base=slugify(member)
   name=base;n=2
   while name in seen_users:
    name=f'{base}-{n}';n+=1
   seen_users.add(name)
   plan.append({
    'team':entry['team'],'team_password':team_pw,
    'name':name,'email':f'{slugify(entry["team"])}-{name}@{EMAIL_DOMAIN}',
    'password':gen_password(),
   })
 return plan

def write_credentials(path,plan):
 path.parent.mkdir(parents=True,exist_ok=True)
 with open(path,'w',newline='',encoding='utf-8') as fh:
  w=csv.writer(fh)
  w.writerow(['team','team_password','member_name','member_password','email'])
  for row in plan:
   w.writerow([row['team'],row['team_password'],row['name'],row['password'],row['email']])
 return path

def run(args,session=None):
 roster=load_roster(args)
 plan=build_plan(roster)
 teams={}
 for row in plan:teams.setdefault(row['team'],row['team_password'])
 print(f'FLAG THEFT AUTO: {len(teams)} teams / {len(plan)} logins planned')
 if not args.apply:
  print('DRY RUN — no network calls, no files written; credentials are not shown')
  for team in teams:
   members=[r['name'] for r in plan if r['team']==team]
   print(f"  {team} | {len(members)} login(s): {', '.join(members)}")
  return {'created_teams':0,'created_users':0,'dry_run':True}
 url=args.url.rstrip('/') if args.url else ''
 if not url.startswith(('https://','http://')):raise APIError('Use --url with absolute https:// or http:// address')
 if url.startswith('http://') and not args.allow_http:
  raise APIError('Plain HTTP can expose admin token; use HTTPS or --allow-http for trusted localhost/LAN only')
 token=args.token or os.environ.get('CTFD_TOKEN')
 if not token:raise APIError('Set CTFD_TOKEN environment variable; do not put token on command line')
 session=session or requests.Session()
 session.headers.update({'Authorization':'Token '+token})
 print('Checking admin connection...')
 existing_teams={t.get('name') for t in req(session,url,'GET','/api/v1/teams') if isinstance(t,dict)}
 existing_users={u.get('name') for u in req(session,url,'GET','/api/v1/users') if isinstance(u,dict)}
 new_teams={t:p for t,p in teams.items() if t not in existing_teams}
 new_plan=[r for r in plan if r['name'] not in existing_users]
 team_ids={t.get('name'):t.get('id') for t in req(session,url,'GET','/api/v1/teams') if isinstance(t,dict)}
 for team,password in new_teams.items():
  data=req(session,url,'POST','/api/v1/teams',json={'name':team,'password':password})
  team_ids[team]=data['id']
  print(f'[OK] team {team} created')
 for row in new_plan:
  req(session,url,'POST','/api/v1/users',json={
   'name':row['name'],'email':row['email'],'password':row['password'],
   'type':'user','verified':True,'hidden':False,'banned':False,'team_id':team_ids[row['team']],
  })
  print(f"[OK] login {row['name']} -> {row['team']}")
 if not args.keep_registration:
  req(session,url,'PATCH','/api/v1/configs',json={'registration_visibility':'private'})
  print('[OK] public registration disabled (registration_visibility=private)')
 creds=write_credentials(Path(args.out),plan)
 print(f'Credentials written to {creds}  (KEEP PRIVATE — distribute one row-group per crew)')
 return {'created_teams':len(team_ids),'created_users':len(plan),'dry_run':False,'credentials':str(creds)}

def main():
 parser=argparse.ArgumentParser(description='Private CTFd team provisioner; dry-run is default.')
 parser.add_argument('--apply',action='store_true',help='Create teams/users on CTFd (default just validates locally)')
 parser.add_argument('--teams',type=int,default=25,help='Auto-generate N crews when no --roster is given (default 25)')
 parser.add_argument('--roster',help='CSV roster: team_name,member1[,member2][,member3]')
 parser.add_argument('--out',default=str(CREDS_DEFAULT),help='Where to write the private credentials CSV')
 parser.add_argument('--keep-registration',action='store_true',help='Do NOT disable public registration on --apply')
 parser.add_argument('--url',default=os.environ.get('CTFD_URL'),help='CTFd base URL (or env CTFD_URL)')
 parser.add_argument('--token',help='CTFd admin token; prefer CTFD_TOKEN environment variable')
 parser.add_argument('--allow-http',action='store_true',help='allow plain HTTP only on trusted localhost/LAN')
 args=parser.parse_args()
 try:run(args)
 except (APIError,AssertionError,ValueError,FileNotFoundError) as ex:print('ERROR:',ex,file=sys.stderr);sys.exit(1)
if __name__=='__main__':main()
