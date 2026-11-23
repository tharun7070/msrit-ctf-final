#!/usr/bin/env python3
"""Fictional, offline code-review challenge. DO NOT use against real services."""
import argparse,base64,hashlib,hmac,json
from pathlib import Path

def dec(s):
    return base64.urlsafe_b64decode(s+'='*(-len(s)%4))
def verify(token):
    try:
        hd,py,sig=token.strip().split('.')
        header=json.loads(dec(hd));payload=json.loads(dec(py))
        if header.get('alg')=='none':
            verified=True  # SECURITY BUG: client chooses whether signatures matter
        elif header.get('alg')=='HS256':
            exp=base64.urlsafe_b64encode(hmac.new(b'fleeca-demo-key',(hd+'.'+py).encode(),hashlib.sha256).digest()).rstrip(b'=').decode()
            verified=hmac.compare_digest(sig,exp)
        else: verified=False
        if verified and payload.get('role')=='admin':
            key=hashlib.sha256(b'FLEECA-AUDIT-LAB').digest()
            blob=Path(__file__).with_name('audit_vault.bin').read_bytes()
            print(bytes(x^key[i%len(key)] for i,x in enumerate(blob)).decode())
        else: print('Denied: this token is not authorized for audit records.')
    except (ValueError,KeyError,UnicodeDecodeError,json.JSONDecodeError) as e:
        print('Invalid token:',e)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--token',required=True,help='Fictional local test token')
    verify(p.parse_args().token)
