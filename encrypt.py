#!/usr/bin/env python3
import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

if len(sys.argv) < 2:
    print(f"usage: {sys.argv[0]} <shellcode.bin>")
    sys.exit(1)

with open(sys.argv[1], "rb") as f:
    shellcode = f.read()

key = os.urandom(32)
iv  = os.urandom(16)
ct  = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(shellcode, 16))

out = sys.argv[1].rsplit(".", 1)[0] + "_enc.bin"
with open(out, "wb") as f:
    f.write(ct)

print(f"[+] encrypted: {out} ({len(ct)} bytes)")
print(f"[+] key: {key.hex()}")
print(f"[+] iv:  {iv.hex()}")
