#!/usr/bin/env python3
"""Mock protocol exercise, NOT a real CTFd server acceptance test."""
import contextlib,importlib.util,io,types
from pathlib import Path
p=Path(__file__).with_name('import_ctfd.py')
spec=importlib.util.spec_from_file_location('ctfd_import',p)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
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
s=FakeSession();args=types.SimpleNamespace(apply=True,url='http://127.0.0.1:8000',token='TEST-TOKEN',allow_http=True)
with contextlib.redirect_stdout(io.StringIO()) as io_out:res=module.run(args,session=s)
assert res['created']==15
assert all(flag not in io_out.getvalue() for flag in [c['flag'] for c in __import__('json').loads((p.parent/'manifest.json').read_text())['challenges']])
assert s.headers['Authorization']=='Token TEST-TOKEN'
from collections import Counter
stats=Counter((method,path.split('/')[1]) for method,path,kw in s.calls)
assert stats[('POST','challenges')]==15,stats
assert stats[('POST','flags')]==15,stats
assert stats[('POST','hints')]==45,stats
assert stats[('POST','files')]==36,stats
assert stats[('PATCH','challenges')]==15,stats
for method,path,kw in s.calls:
 if (method,path)==('POST','/files'):
  assert kw['data']['type']=='challenge'
  assert 'file' in kw['files']
 if (method,path)==('POST','/flags'):
  assert kw['json']['type']=='static'
 if (method,path)==('POST','/challenges'):
  assert kw['json']['state']=='hidden'
 if method=='PATCH':
  assert kw['json']['state']=='visible'
print('PASS: mock API validates 15 challenge creates, 15 flags, 45 hints, 36 files, 15 publications; no flag logging.')
