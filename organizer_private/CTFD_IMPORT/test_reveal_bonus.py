#!/usr/bin/env python3
"""Mock exercise for the scheduled bonus reveal. NOT a real CTFd acceptance test."""
import contextlib,importlib.util,io,json,types
from pathlib import Path

HERE=Path(__file__).with_name('reveal_bonus.py')
spec=importlib.util.spec_from_file_location('reveal_bonus',HERE)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

BONUS=json.loads((HERE.parent/'manifest_bonus.json').read_text())['challenges']

class Response:
 status_code=200
 def __init__(self,data):self.data=data
 def json(self):return {'success':True,'data':self.data}

class FakeSession:
 """Reports the given bonus names as hidden; records every PATCH."""
 def __init__(self,names,state='hidden'):
  self.headers={};self.calls=[]
  self.existing=[{'id':900+i,'name':n,'state':state} for i,n in enumerate(names)]
 def request(self,method,url,timeout=25,**kw):
  path=url.split('/api/v1')[-1];self.calls.append((method,path,kw))
  if path=='/challenges' and method=='GET':return Response(self.existing)
  return Response({'id':1})

def run_with(session,now=True):
 args=types.SimpleNamespace(url='http://127.0.0.1:8000',token='TEST-TOKEN',allow_http=True,
  reveal_at=None,event_start=None,offset_minutes=None,now=now)
 with contextlib.redirect_stdout(io.StringIO()) as out:res=module.run(args,session=session)
 return res,out.getvalue()

# 1) hidden wave -> all 10 flipped visible, no flag leaks
s=FakeSession([c['name'] for c in BONUS])
res,out=run_with(s)
assert res['revealed']==10,res
patches=[c for c in s.calls if c[0]=='PATCH']
assert len(patches)==10,patches
assert all(c[2]['json']['state']=='visible' for c in patches)
assert all(c['flag'] not in out for c in BONUS)

# 2) already visible -> idempotent no-op
s2=FakeSession([c['name'] for c in BONUS],state='visible')
res2,out2=run_with(s2)
assert res2['revealed']==0,res2
assert not [c for c in s2.calls if c[0]=='PATCH']

# 3) wave not imported -> hard error instead of silent success
s3=FakeSession([])
try:
 run_with(s3);raise AssertionError('expected APIError for missing bonus challenges')
except module.APIError as ex:assert 'missing' in str(ex),ex

print('PASS: bonus reveal flips hidden->visible idempotently, skips visible, errors when not imported.')
