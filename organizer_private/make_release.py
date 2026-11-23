#!/usr/bin/env python3
"""Make three distributions and verify privacy boundary. Run from anywhere."""
from pathlib import Path
import csv,hashlib,io,json,zipfile
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT.parent
man=json.loads((ROOT/'ORGANIZER/CTFD_IMPORT/manifest.json').read_text())['challenges']

def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
for level in ['EASY','MEDIUM','HARD']:
 d=ROOT/'CHALLENGE_SOURCE'/level;d.mkdir(exist_ok=True)
 ids=[c for c in man if c['level'].upper()==level]
 (d/'README_PRIVATE.md').write_text('# PRIVATE SOURCE INDEX — '+level+'\n\nThis level is built by `../build_all.py` (one deterministic, centralized source generator).\n\n'+''.join(f"- {c['id']}: {c['name']} — {c['topic']}\n" for c in ids)+'\nNever distribute this directory to students.\n')
# Additional private source copy in Hard for reverse engineering
src=ROOT/'CHALLENGE_SOURCE/H01_gate_private.c';dest=ROOT/'CHALLENGE_SOURCE/HARD/H01_gate_private.c'
if src.exists():dest.write_bytes(src.read_bytes())

# Hash every mission file, including description, but exclude checksum file itself.
pfiles=sorted(p for p in (ROOT/'PARTICIPANT').rglob('*') if p.is_file() and p.name!='SHA256SUMS.txt')
lines=[f'{digest(p)}  {p.relative_to(ROOT/"PARTICIPANT").as_posix()}' for p in pfiles]
(ROOT/'PARTICIPANT/SHA256SUMS.txt').write_text('# SHA-256 checksums relative to PARTICIPANT/\n'+'\n'.join(lines)+'\n')
with (ROOT/'ORGANIZER/CTFD_IMPORT/attachments_sha256.csv').open('w',newline='') as f:
 w=csv.writer(f);w.writerow(['id','filename','size_bytes','sha256'])
 for c in man:
  for name in c['files']:
   p=ROOT/c['directory']/name;w.writerow([c['id'],name,p.stat().st_size,digest(p)])

# Do NOT include public ZIP generated in same directory inside private package to prevent recursion.
def pack(path,paths):
 with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED,compresslevel=7,strict_timestamps=False) as z:
  for f,arc in paths:
   z.write(f,arcname=arc)
 print(path.name, '%.2f MB'%(path.stat().st_size/1048576))
 return path

def tree(files,source,arcbase):
 for p in source.rglob('*'):
  if p.is_file(): files.append((p,(Path(arcbase)/p.relative_to(source)).as_posix()))
# Public ZIP only has PARTICIPANT/ subtree, not organizer or source or secrets.
pub=[];tree(pub,ROOT/'PARTICIPANT','PARTICIPANT')
pubz=pack(OUT/'FLAG_THEFT_AUTO_PARTICIPANT.zip',pub)
# Private organizer documentation; requires full ZIP for immediate importer use.
priv=[];tree(priv,ROOT/'ORGANIZER','ORGANIZER');tree(priv,ROOT/'CHALLENGE_SOURCE','CHALLENGE_SOURCE')
privz=pack(OUT/'FLAG_THEFT_AUTO_ORGANIZER_PRIVATE.zip',priv)
allfiles=[];tree(allfiles,ROOT,'FLAG_THEFT_AUTO')
fullz=pack(OUT/'FLAG_THEFT_AUTO_COMPLETE_PRIVATE.zip',allfiles)
# verify zip does not contain correct flags anywhere in members (including compressed contents as bytes)
secret=[c['flag'].encode() for c in man]
with zipfile.ZipFile(pubz) as z:
 members=z.namelist()
 assert all(name.startswith('PARTICIPANT/') for name in members)
 assert not any('ORGANIZER' in n or 'CHALLENGE_SOURCE' in n or 'manifest.json' in n for n in members)
 assert len(members)==len(pub)
 for name in members:
  content=z.read(name)
  assert not any(k in content for k in secret),f'SECRET LEAK: {name}'
with zipfile.ZipFile(fullz) as z:
 assert any(n.endswith('ORGANIZER/ANSWER_KEY.md') for n in z.namelist())
 assert any(n.endswith('ORGANIZER/CTFD_IMPORT/import_ctfd.py') for n in z.namelist())
 assert any(n.endswith('BRANDING/POSTER/flag_theft_auto_poster.png') for n in z.namelist())
 assert len(z.namelist()) >= 80
print('PASS — participant ZIP has no organizer paths nor plaintext exact flags; full ZIP includes keys, importer, and branding.')
