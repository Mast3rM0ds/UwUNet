#!/usr/bin/env python3
"""patch-exe.py <src> <dst> — copy PE and set IMAGE_SCN_MEM_EXECUTE (0x20000000)
on the .text section (docs/referee.md: needed for any direct RecRoom.exe run)."""
import sys, struct

src, dst = sys.argv[1], sys.argv[2]
data = bytearray(open(src, 'rb').read())
pe = struct.unpack_from('<I', data, 0x3C)[0]
assert data[pe:pe+4] == b'PE\0\0', 'not PE'
numsec = struct.unpack_from('<H', data, pe+6)[0]
optsize = struct.unpack_from('<H', data, pe+20)[0]
secs = pe + 24 + optsize
for i in range(numsec):
    off = secs + i*40
    name = bytes(data[off:off+8]).rstrip(b'\0').decode(errors='replace')
    chars = struct.unpack_from('<I', data, off+36)[0]
    if name == '.text':
        if not (chars & 0x20000000):
            struct.pack_into('<I', data, off+36, chars | 0x20000000)
            print(f'[patch] .text 0x{chars:08x} -> 0x{chars|0x20000000:08x} (+EXEC)')
        else:
            print(f'[patch] .text already EXEC (0x{chars:08x})')
open(dst, 'wb').write(data)
print(f'[ok] {dst}')
