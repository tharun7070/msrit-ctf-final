#!/usr/bin/env python3
"""PRIVATE: offline fallback scorer, requires private organizer manifest."""
import argparse,csv,json,datetime as dt,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
MAN=json.loads((ROOT/'ORGANIZER/CTFD_IMPORT/manifest.json').read_text())['challenges']
ANS={c['id']:c for c in MAN}

def rank(path,close=None):
 events=[]
 with open(path,newline='',encoding='utf-8-sig') as f:
  rdr=csv.DictReader(f)
  if set(rdr.fieldnames or [])!=set(['timestamp','team_id','challenge_id','flag']):
   raise ValueError('Required headers: timestamp,team_id,challenge_id,flag')
  for line,rec in enumerate(rdr,2):
   stamp=dt.datetime.fromisoformat(rec['timestamp'].strip().replace('Z','+00:00'))
   if stamp.tzinfo is None:raise ValueError(f'Line {line}: timestamp must include timezone offset')
   team=rec['team_id'].strip();cid=rec['challenge_id'].strip();flag=rec['flag'].strip()
   if not re.fullmatch('[A-Za-z0-9_-]{2,50}',team):raise ValueError(f'Line {line}: invalid team id')
   if cid not in ANS:raise ValueError(f'Line {line}: unknown challenge')
   if close and stamp>close:continue
   events.append((stamp.astimezone(dt.timezone.utc),line,team,cid,flag))
 events.sort(key=lambda e:(e[0],e[1]))
 board={};correct=0;invalid=0
 for when,_,team,cid,flag in events:
  record=board.setdefault(team,{'score':0,'solved':set(),'last':None})
  if cid in record['solved']:continue
  if flag!=ANS[cid]['flag']:invalid+=1;continue
  record['solved'].add(cid);record['score']+=ANS[cid]['points'];record['last']=when;correct+=1
 ordered=sorted(board.items(),key=lambda it:(-it[1]['score'],it[1]['last'] or dt.datetime.max.replace(tzinfo=dt.timezone.utc),it[0]))
 return {'teams':ordered,'correct':correct,'invalid':invalid}

def main():
 p=argparse.ArgumentParser();p.add_argument('--csv',required=True);p.add_argument('--close',help='ISO 8601 cutoff including timezone offset')
 args=p.parse_args()
 close=dt.datetime.fromisoformat(args.close.replace('Z','+00:00')) if args.close else None
 if close and close.tzinfo is None:p.error('close must include timezone offset')
 try:res=rank(args.csv,close)
 except (ValueError,OSError) as e:p.error(str(e))
 print('PRIVATE BACKUP SCOREBOARD (no flags printed)')
 print('Rank | Team | Points | Solves | Last accepted solve (UTC)')
 for idx,(team,info) in enumerate(res['teams'],1):
  stamp=info['last'].isoformat() if info['last'] else '—'
  print(f'{idx:>4} | {team} | {info["score"]:>4} | {len(info["solved"]):>2} | {stamp}')
 print('Valid unique solves:',res['correct'],'Invalid attempts:',res['invalid'])
if __name__=='__main__':main()
