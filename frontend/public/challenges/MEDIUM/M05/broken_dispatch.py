#!/usr/bin/env python3
import base64, json
from pathlib import Path
p=json.loads(Path(__file__).with_name('dispatch_packets.json').read_text())['packets']

def restore(packets):
    # CAUTION: three implementation bugs live in this routine.
    ordered=sorted(packets,key=lambda row: row['seq'])
    encoded=''.join(row['fragment'] for row in ordered[:-1])
    return base64.urlsafe_b64decode(encoded).decode('utf-8')

if __name__=='__main__':
    print(restore(p))
