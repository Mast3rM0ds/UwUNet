#!/usr/bin/env python3
# Build a minimal 64-bit PE DLL (Referee.dll stub) by hand.
#
# Purpose (bypass experiment): RecRoom.exe statically imports Referee.dll
# BY ORDINAL, but its own .text section lacks IMAGE_SCN_MEM_EXECUTE
# (flags C0000020 = WRITE|READ|CODE). Only the real (Themida'd) Referee.dll's
# DllMain re-protects the host image (that's Rec Room's in-process
# "activation"), otherwise wine faults on the entry point:
#   "Unhandled page fault on execute access to 0x140001264"
# This stub's DllMain does exactly that VirtualProtect and nothing else.
import struct, os

FILE   = "/tmp/opencode/gamedir/Referee.dll"
IMAGE_BASE = 0x1e0000000
SEC_VA  = 0x1000
SEC_RAW = 0x400

name_jji = b"jjiEVn\0"                       # @0x138
name_dll = b"Referee.dll\0"                  # @0x140

def rva(off): return SEC_VA + off

# ---- layout constants ----
# (import area removed — the host-exe .text fix is applied offline instead)

# ---- section body ----
body = bytearray()
def emit(bs): body.extend(bs)

# DllMain @0x00: return TRUE (no syscalls! wine traps raw `syscall` from PE
# code and misroutes rax as an NT syscall number)
emit(b"\xb8\x01\x00\x00\x00")                # mov  eax,1 (TRUE)
emit(b"\xc3")
assert len(body) <= 0x80, (len(body),)

# jjiEVn @0x80
while len(body) < 0x80: body.append(0x90)
emit(b"\x31\xc0")                            # xor eax,eax  (return 0)
emit(b"\xc3")

# export directory @0x100
while len(body) < 0x100: body.append(0x90)
emit(struct.pack("<IIHHIIIIIII",
    0, 0, 0, 0,
    rva(0x140), 1, 1, 1,                     # NameRVA, base, nfunc, nnames
    rva(0x128), rva(0x12C), rva(0x130)))     # funcs / names / ordinals
emit(struct.pack("<I", rva(0x80)))           # functions[0] -> jjiEVn
emit(struct.pack("<I", rva(0x138)))          # names[0] -> "jjiEVn"
emit(struct.pack("<H", 0))                   # ordinals[0]
while len(body) < 0x138: body.append(0x90)
emit(name_jji)
while len(body) < 0x140: body.append(0x90)
emit(name_dll)

# (no import area — remove)
while len(body) < SEC_RAW: body.append(0x90)

# ---- patches ----
# (none)

# ---- headers ----
dos = bytearray(b"MZ" + b"\x00" * 62)
struct.pack_into("<I", dos, 0x3C, 0x40)
opt = bytearray()
def o_add(fmt, *vals, off=None):
    if off is not None and len(opt) < off:
        opt.extend(b"\x00" * (off - len(opt)))
    opt.extend(struct.pack(fmt, *vals))

o_add("<H", 0x20B, off=0)
o_add("<BB", 8, 0, off=2)
o_add("<I", 0x40, off=4)
o_add("<I", len(body), off=8)
o_add("<I", 0, off=12)
o_add("<I", rva(0), off=16)      # AddressOfEntryPoint = DllMain
o_add("<I", SEC_VA, off=20)
o_add("<Q", IMAGE_BASE, off=24)
o_add("<I", 0x1000, off=32)
o_add("<I", 0x200, off=36)
o_add("<HH", 6, 0, off=40)
o_add("<HH", 6, 0, off=44)
o_add("<HH", 6, 0, off=48)
o_add("<I", 0, off=52)
o_add("<I", 0x2000, off=56)      # SizeOfImage
o_add("<I", SEC_RAW, off=60)     # SizeOfHeaders
o_add("<I", 0, off=64)
o_add("<H", 2, off=68)           # Subsystem GUI
o_add("<H", 0, off=70)
o_add("<Q", 0x100000, off=72)
o_add("<Q", 0x10000, off=80)
o_add("<Q", 0x100000, off=88)
o_add("<Q", 0x10000, off=96)
o_add("<I", 0, off=104)
o_add("<I", 16, off=108)
o_add("<II", rva(0x100), 0x50, off=112)  # dir0: export
o_add("<II", 0, 0, off=120)              # dir1: imports (none)
while len(opt) < 240: opt += b"\x00"

coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x2022)
sec_hdr = struct.pack("<8sIIIIIIHHI", b".uwu\0\0\0\0",
                      SEC_RAW, SEC_VA, SEC_RAW, SEC_RAW,
                      0, 0, 0, 0, 0x60000020)

out = bytearray(dos) + b"PE\x00\x00" + coff + bytes(opt) + sec_hdr
while len(out) % 0x400: out += b"\x00"
assert len(out) == SEC_RAW, (len(out), SEC_RAW)
out += body
os.makedirs(os.path.dirname(FILE), exist_ok=True)
open(FILE, "wb").write(out)
print(f"stub written: {FILE} ({len(out)} bytes)")
