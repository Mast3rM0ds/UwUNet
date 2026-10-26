#!/usr/bin/env python3
"""dumpmod.py — dump mapped regions of modules matching a regex from live wine processes.

Usage: patterns are joined by '|'; env DUMPTIMEOUT (seconds, default 600).
Output: /tmp/opencode/refdump/<pid>_<start>_<end>_<perms>_<file>.bin + full <pid>.maps
Writes progress to stdout; flush per line. Intended to run detached.
"""
import os, re, sys, time

PATTERNS = sys.argv[1:] or ['Referee']
PAT = re.compile('|'.join(PATTERNS))
OUT = os.environ.get('DUMPDIR', '/home/bloink/UwUNet/re/dumps')
os.makedirs(OUT, exist_ok=True)

MAPRE = re.compile(
    r'([0-9a-f]+)-([0-9a-f]+)\s+(....)\s+[0-9a-f]+\s+\S+\s+\S+\s*(.*)')

def read_maps(pid):
    try:
        with open(f'/proc/{pid}/maps') as f:
            return f.read().splitlines()
    except Exception:
        return []

def dump_process(pid, lines, dumped, maps_saved):
    for line in lines:
        m = MAPRE.match(line)
        if not m:
            continue
        start, end, perms, path = (int(m.group(1), 16), int(m.group(2), 16),
                                   m.group(3), m.group(4).strip())
        if not PAT.search(path):
            continue
        key = (pid, start)
        if key in dumped:
            continue
        dumped.add(key)
        if pid not in maps_saved:
            maps_saved.add(pid)
            try:
                with open(os.path.join(OUT, f'{pid}.maps'), 'w') as f:
                    f.write('\n'.join(lines) + '\n')
                with open(f'/proc/{pid}/cmdline', 'rb') as cf:
                    cmd = cf.read().replace(b'\0', b' ').decode(errors='replace')
                with open(os.path.join(OUT, f'{pid}.cmd'), 'w') as f:
                    f.write(cmd + '\n')
                print(f'[proc] pid={pid} cmd={cmd[:120]}', flush=True)
            except Exception:
                pass
        base = path.split('/')[-1].replace('/', '_')[-64:]
        outp = os.path.join(OUT, f'{pid}_{start:x}_{end:x}_{perms}_{base}.bin')
        try:
            with open(f'/proc/{pid}/mem', 'rb') as mem:
                mem.seek(start)
                data = mem.read(end - start)
            with open(outp, 'wb') as f:
                f.write(data)
            print(f'[dump] pid={pid} {start:x}-{end:x} {perms} {path} -> {outp} '
                  f'({len(data)} bytes)', flush=True)
        except Exception as e:
            print(f'[fail] pid={pid} {start:x} {perms} {path}: {e}', flush=True)

def main():
    dumped, maps_saved = set(), set()
    deadline = time.time() + float(os.environ.get('DUMPTIMEOUT', '600'))
    while time.time() < deadline:
        for pid in os.listdir('/proc'):
            if not pid.isdigit():
                continue
            lines = read_maps(pid)
            if not lines:
                continue
            if any(PAT.search(l.split()[-1] if len(l.split()) >= 6 else '')
                   for l in lines):
                dump_process(pid, lines, dumped, maps_saved)
        time.sleep(0.5)
    print('[done]', flush=True)

main()
