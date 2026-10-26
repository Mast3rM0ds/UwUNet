#!/usr/bin/env python3
# Slice @@REGION-marked regions out of a wine-referee-dump.bin
# into unpacked-PE* files for offline analysis.
import re, struct, sys

dump = "/tmp/opencode/referee-dump.bin"
data = open(dump, "rb").read()

# find region boundaries: header line, then payload until next header
bounds = [(m.start(), m.end(), m.group(1).decode(), m.group(2).decode(),
           m.group(3).decode(), m.group(4).decode())
          for m in re.finditer(rb"@@REGION ([0-9a-f]+)-([0-9a-f]+) (\S+) (\S*)\n", data)]
regions = []
for i, (hs, he, sa, ea, perm, path) in enumerate(bounds):
    s, e = int(sa, 16), int(ea, 16)
    start = he
    end = bounds[i + 1][0] if i + 1 < len(bounds) else len(data)
    regions.append((s, e, perm, path, data[start:end]))

targets = {
    0x140000000: "hdr.bin",
    0x140001000: "text.bin",
    0x1400b4000: "rdata.bin",
    0x1400e2000: "data.bin",
    0x1400e7000: "rdata2.bin",
    0x1400f1000: "rdata3.bin",
    0x140110000: "data2.bin",
    0x14012f000: "vmthemida.bin",
}
for s, e, perm, path, payload in regions:
    fn = targets.get(s)
    if fn:
        open(f"/tmp/opencode/{fn}", "wb").write(payload)
        print(f"{fn}  {s:#x}-{e:#x} {perm} ({len(payload)/1024:.0f}KB)")
