#!/usr/bin/env python3
"""Fictional offline bank-kiosk lab. No network access and no real accounts."""
import base64, sqlite3
from pathlib import Path
DB = Path(__file__).with_name('fleeca.db')
def check(owner, pin):
    con = sqlite3.connect(f'file:{DB}?mode=ro', uri=True)
    # Deliberate vulnerable query, authorized educational simulation ONLY.
    query = "SELECT receipt_b64 FROM lockers WHERE owner = '"+owner+"' AND pin = '"+pin+"' ORDER BY rowid DESC LIMIT 1"
    try:
        row = con.execute(query).fetchone()
        if row:
            print('Audit receipt:', base64.b64decode(row[0]).decode())
        else:
            print('Access denied')
    except sqlite3.Error as e:
        print('SQL error:', e)
    finally:
        con.close()
if __name__=='__main__':
    print('FLEECA OFFLINE KIOSK — fictional lab, local files only')
    check(input('Owner: '), input('PIN: '))
