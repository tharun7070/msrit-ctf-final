#!/usr/bin/env python3
"""Black-box artifact solvers: no import of private challenge builder."""
import base64,csv,gzip,hashlib,io,json,re,sqlite3,struct,subprocess,sys,tarfile,zipfile,zlib
from pathlib import Path
from functools import lru_cache
from PIL import Image
ROOT=Path(__file__).resolve().parents[1]
PART=ROOT/'PARTICIPANT'
MAN=json.loads((ROOT/'ORGANIZER/CTFD_IMPORT/manifest.json').read_text())['challenges']
FL={x['id']:x['flag'] for x in MAN}
RESULTS=[]

def part(cid): return PART/({'E':'EASY','M':'MEDIUM','H':'HARD'}[cid[0]])/cid

def assert_equals(cid,output,detail):
 assert output==FL[cid],f'{cid}: got {output!r} vs secret'
 assert re.fullmatch(r'FLAG\{[a-z0-9_]+\}',output),cid
 RESULTS.append({'id':cid,'result':'PASS','derived_flag':output,'method':detail})
 print('PASS',cid,detail)

# E01
p=part('E01')
with (p/'dispatch.csv').open(newline='') as f:rows=list(csv.DictReader(f))
x=''.join(base64.b64decode(row['payload_b64']).decode() for row in sorted((r for r in rows if r['courier']=='YES'),key=lambda r:int(r['seq'])))
assert_equals('E01',x,'CSV filter + numeric sort + Base64 decode')
# E02
text=(part('E02')/'taxi_ledger.txt').read_text()
line=next(line.split(' | ',1)[1] for line in text.splitlines() if line.startswith('MIDNIGHT | '))
def rot(s,shift):
 out=[]
 for c in s:
  if 'A'<=c<='Z':out.append(chr((ord(c)-65+shift)%26+65))
  elif 'a'<=c<='z':out.append(chr((ord(c)-97+shift)%26+97))
  else:out.append(c)
 return ''.join(out)
x=re.search(r'FLAG\{[^}]+\}',rot(line,-5)).group(0)
assert_equals('E02',x,'MIDNIGHT route Caesar -5')
# E03
with zipfile.ZipFile(part('E03')/'safehouse.zip') as z:
 data=z.read('safehouse/.drop_manifest').decode()
 x=bytes.fromhex(data.split('DROP_CODE_HEX=')[1].strip()).decode()
assert_equals('E03',x,'ZIP hidden dotfile + hex conversion')
# E04
with Image.open(part('E04')/'pier_camera.png') as img:
 assert img.format=='PNG'
 x=base64.b32decode(img.info['dispatch_note']).decode()
assert_equals('E04',x,'Pillow PNG metadata + Base32 decode')
# E05
jpg=part('E05')/'customs_camera.jpg'; assert jpg.read_bytes().startswith(b'PK\x03\x04')
with zipfile.ZipFile(jpg) as z:
 x=bytes.fromhex(re.search(r'Drop-code \(hex\):\s*([a-f0-9]+)',z.read('customs/shipment_verified.txt').decode()).group(1)).decode()
assert_equals('E05',x,'ZIP signature sniff + verified receipt hex')
# M01
p=part('M01');script=p/'fleeca_kiosk.py'
denied=subprocess.run([sys.executable,str(script)],input='nobody\nnope\n',text=True,capture_output=True,timeout=5)
assert 'Access denied' in denied.stdout
allowed=subprocess.run([sys.executable,str(script)],input="' OR 1=1 --\nxxxx\n",text=True,capture_output=True,timeout=5)
x=re.search(r'FLAG\{[^}]+\}',allowed.stdout).group(0)
assert_equals('M01',x,'denial negative check + live local SQLi bypass')
# M02 PCAP manual parse; verify real IP and TCP checksums
blob=(part('M02')/'airport_dispatch.pcap').read_bytes()
assert struct.unpack('<I',blob[:4])[0]==0xa1b2c3d4

def checksum(data):
 if len(data)&1:data+=b'\x00'
 ss=sum(struct.unpack('!%dH'%(len(data)//2),data))
 while ss>>16:ss=(ss&65535)+(ss>>16)
 return (~ss)&65535
idx=24; found=[]; n=0
while idx<len(blob):
 sec,usec,cap,orig=struct.unpack_from('<IIII',blob,idx);idx+=16
 frame=blob[idx:idx+cap];idx+=cap
 assert len(frame)==cap==orig
 if frame[12:14]!=b'\x08\x00':continue
 ip=frame[14:];ihlen=(ip[0]&15)*4
 assert checksum(ip[:ihlen])==0,'bad IPv4 checksum'
 tcp=ip[ihlen:];tcpheadlen=(tcp[12]>>4)*4
 pseudo=ip[12:20]+struct.pack('!BBH',0,6,len(tcp))
 assert checksum(pseudo+tcp)==0,'bad TCP checksum'
 pay=tcp[tcpheadlen:]
 if pay.startswith(b'GET ') and b'X-Flight: LS-447\r\n' in pay:
  txt=pay.decode();headers=dict(line.split(': ',1) for line in txt.split('\r\n')[1:] if ': ' in line)
  found.append((int(headers['X-Chunk']),base64.b64decode(headers['X-Cargo']).decode()))
 n+=1
assert n>=20 and len(found)==3
x=''.join(chunk for _,chunk in sorted(found))
assert_equals('M02',x,f'{n} validated IP/TCP frames + LS-447 HTTP headers')
# M03 filter 714 FORENSIC ACCEPT
logs=(part('M03')/'lspd_auth.log').read_text().splitlines()
valid=[]
for line in logs:
 if 'case=714' in line and 'source=FORENSIC' in line and 'result=ACCEPT' in line:
  fields=dict(y.split('=',1) for y in line.split()[1:] if '=' in y)
  # random noise can collide with criteria! valid case clerk host only
  if fields['account']=='case_clerk' and fields['host']=='lspd-evidence':valid.append((int(fields['part']),fields['fraghex']))
assert len(valid)>=5
x=bytes.fromhex(''.join(fragment for _,fragment in sorted(valid))).decode()
assert_equals('M03',x,f'correlate {len(valid)} ordered case-clerk events in {len(logs)} lines')
# M04
with (part('M04')/'checkpoint_keys.csv').open(newline='') as f:r=list(csv.DictReader(f))
key=bytes(int(rec['keybyte_hex'],16) for rec in sorted(r,key=lambda row:int(row['stop'])))
raw=(part('M04')/'radio_packet.bin').read_bytes()
plain=bytes(b^key[i%len(key)] for i,b in enumerate(raw)).decode()
x=re.search(r'FLAG\{[^}]+\}',plain).group(0)
assert_equals('M04',x,'route-ordered XOR key + repeating decryption')
# M05 repairs performed without changing artifact, independent reimplementation
p=part('M05');packets=json.loads((p/'dispatch_packets.json').read_text())['packets']
enc=''.join(p['fragment'] for p in sorted(packets,key=lambda k:int(k['seq'])))
x=base64.urlsafe_b64decode(enc+'='*(-len(enc)%4)).decode()
# defects exposed by intentionally running broken script
broken=subprocess.run([sys.executable,str(p/'broken_dispatch.py')],capture_output=True,text=True,timeout=5)
assert x not in broken.stdout
assert_equals('M05',x,'integer sort + include last + restore URL-safe Base64 padding')
# H01 parse ELF actual .rodata by objcopy, get comparison table from disassembly address
p=part('H01')/'zancudo_gate'
p.chmod(p.stat().st_mode | 0o111)  # ZIP extraction may drop executable bits
objdump=subprocess.run(['objdump','-d','-M','intel',str(p)],text=True,capture_output=True,check=True).stdout
match=re.search(r'movzx\s+eax,BYTE PTR \[rax\+(0x[0-9a-f]+)\]',objdump)
assert match,'could not infer check table address from disassembly'
# Read ELF load segment containing target VA using readelf -lW
addr=int(match.group(1),16)
ph=subprocess.run(['readelf','-lW',str(p)],text=True,capture_output=True,check=True).stdout
segments=[]
for line in ph.splitlines():
 m=re.search(r'LOAD\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+0x[0-9a-f]+\s+0x([0-9a-f]+)',line)
 if m:segments.append(tuple(int(y,16) for y in m.groups()))
for offset,vaddr,size in segments:
 if vaddr<=addr< vaddr+size:break
else:raise AssertionError('no ELF segment')
check=p.read_bytes()[offset+(addr-vaddr):offset+(addr-vaddr)+12]
passcode=bytes(x^((0x31+7*i)&255) for i,x in enumerate(check)).decode()
wrong=subprocess.run([str(p),'aaaaaaaaaaaa'],text=True,capture_output=True,timeout=5)
assert wrong.returncode==1
right=subprocess.run([str(p),passcode],text=True,capture_output=True,timeout=5)
assert right.returncode==0
x=right.stdout.strip()
assert_equals('H01',x,'ELF disassembly target bytes, inverse position-XOR, execution')
# H02
obj=json.loads((part('H02')/'junctions.json').read_text())
@lru_cache(None)
def f(node):
 o=obj['junctions'][node]
 if o['kind']=='terminal':return o['seed']
 return ((17*f(o['left'])+31*f(o['right'])+o['salt'])^o['mask'])&0xffffffff
h=f"{f(obj['destination']):08x}"
x='FLAG{'+h+'_'+hashlib.sha256(h.encode()).hexdigest()[:8]+'}'
assert_equals('H02',x,f'evaluate {len(obj["junctions"])}-node DAG + SHA256 suffix')
# H03
with zipfile.ZipFile(part('H03')/'impound_camera.png') as z:
 zipped=z.read('case_144/triage_144.gz')
    
with tarfile.open(fileobj=io.BytesIO(gzip.decompress(zipped))) as t:
 doc=json.load(t.extractfile('sealed/dossier.json'))
assert doc['case_id']==144
x=zlib.decompress(base64.a85decode(doc['payload'])).decode()
assert_equals('H03',x,'PNG ZIP polyglot -> gzip -> tar -> ASCII85 -> zlib')
# H04 guest negative, forged local admin
p=part('H04');script=p/'bank_gateway.py';guest=(p/'guest.token').read_text().strip()
denied=subprocess.run([sys.executable,str(script),'--token',guest],capture_output=True,text=True,timeout=5)
assert 'Denied' in denied.stdout
mk=lambda o:base64.urlsafe_b64encode(json.dumps(o,separators=(',',':')).encode()).decode().rstrip('=')
forged=mk({'alg':'none','typ':'JWT'})+'.'+mk({'sub':'auditor','role':'admin'})+'.'
run=subprocess.run([sys.executable,str(script),'--token',forged],capture_output=True,text=True,timeout=5)
x=run.stdout.strip()
assert_equals('H04',x,'guest denial + alg=none unsigned role escalation')
# H05 route unique, decode three stages
p=part('H05')
with (p/'getaway_routes.csv').open(newline='') as f:rows=list(csv.DictReader(f))
q=[r for r in rows if r['wanted']=='0' and r['clearance']=='YES' and int(r['fuel_km'])>=int(r['route_km'])]
assert len(q)==1
key=hashlib.sha256((q[0]['plate']+':'+q[0]['terminal']).encode()).digest()
body=(p/'intercept.txt').read_text().split('---BEGIN-PACKET---')[1].split('---END-PACKET---')[0].strip()
crypt=zlib.decompress(base64.a85decode(body))
x=bytes(b^key[i%len(key)] for i,b in enumerate(crypt)).decode()
assert_equals('H05',x,'unique valid car + SHA256 key + ASCII85/zlib/XOR')
# Participant package hygiene
assert len(RESULTS)==15
for item in PART.rglob('*'):
 if item.is_file():
  for secret in FL.values():
   assert secret.encode() not in item.read_bytes(),f'plaintext flag leaked into {item.relative_to(ROOT)}'
# All referenced attachment files real
for item in MAN:
 d=ROOT/item['directory'];assert (d/'MISSION.md').exists()
 for filename in item['files']:
  p=d/filename
  assert p.is_file() and p.stat().st_size>0,f'missing {p}'
assert sum(item['points'] for item in MAN)==1550
assert len(set(FL.values()))==15
out=ROOT/'ORGANIZER/CTFD_IMPORT/validation_results.json'
out.write_text(json.dumps({'challenge_count':15,'all_pass':True,'file_integrity':'all attachments exist and nonempty','plaintext_leak_scan':'no actual correct flag appears verbatim in participant files','cases':RESULTS},indent=2)+'\n')
print('ALL 15 BLACK-BOX SOLVERS PASSED. No participant plaintext leak. 1550 points.')
