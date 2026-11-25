#!/usr/bin/env python3
"""Mock protocol exercise, NOT a real CTFd server acceptance test."""
import contextlib,importlib.util,io,json,types
from collections import Counter
from pathlib import Path

HERE=Path(__file__).with_name('import_ctfd.py')
spec=importlib.util.spec_from_file_location('ctfd_import',HERE)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

def manifest(name):return json.loads((HERE.parent/name).read_text())['challenges']

class Response:
 status_code=200
 def __init__(self,data):self.data=data
 def json(self):return {'success':True,'data':self.data}

class FakeSession:
 def __init__(self):self.headers={};self.calls=[];self.n=1000
 def request(self,method,url,timeout=25,**kw):
  path=url.split('/api/v1')[-1];self.calls.append((method,path,kw))
  if path=='/challenges' and method=='GET':return Response([])
  if path=='/challenges' and method=='POST':self.n+=1;return Response({'id':self.n})
  return Response({'id':self.n+50})

def stats_for(s):return Counter((m,p.split('/')[1]) for m,p,kw in s.calls)

def args_for(bonus):return types.SimpleNamespace(apply=True,url='http://127.0.0.1:8000',token='TEST-TOKEN',allow_http=True,bonus=bonus)

# ── main wave: 25 challenges imported AND published ──────────────────────────
main=manifest('manifest.json')
s=FakeSession()
with contextlib.redirect_stdout(io.StringIO()) as out:res=module.run(args_for(False),session=s)
assert res['created']==len(main)==25
assert all(c['flag'] not in out.getvalue() for c in main)
assert s.headers['Authorization']=='Token TEST-TOKEN'
st=stats_for(s)
assert st[('POST','challenges')]==25,st
assert st[('POST','flags')]==25,st
assert st[('POST','hints')]==75,st
assert st[('POST','files')]==sum(len(c['files']) for c in main),st
assert st[('PATCH','challenges')]==25,st
for m,p,kw in s.calls:
 if (m,p)==('POST','/files'):
  assert kw['data']['type']=='challenge';assert 'file' in kw['files']
 if (m,p)==('POST','/flags'):assert kw['json']['type']=='static'
 if (m,p)==('POST','/challenges'):assert kw['json']['state']=='hidden'
 if m=='PATCH':assert kw['json']['state']=='visible'

# ── bonus wave: 10 challenges imported HIDDEN (never published here) ─────────
bonus=manifest('manifest_bonus.json')
s2=FakeSession()
with contextlib.redirect_stdout(io.StringIO()) as out2:res2=module.run(args_for(True),session=s2)
assert res2['created']==len(bonus)==10
assert all(c['flag'] not in out2.getvalue() for c in bonus)
st2=stats_for(s2)
assert st2[('POST','challenges')]==10,st2
assert st2[('POST','flags')]==10,st2
assert st2[('POST','hints')]==30,st2
assert st2[('POST','files')]==sum(len(c['files']) for c in bonus),st2
assert st2[('PATCH','challenges')]==0,('bonus import must NOT publish; reveal_bonus.py does that later',st2)

print('PASS: mock API validates 25 published main creates + 10 hidden bonus creates; no flag logging.')
