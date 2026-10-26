#!/usr/bin/env python3
"""ref-hash-watch.py — tail the relay log; when ADVAPI32.CryptHashData appears,
freeze the RefereeClientApp process and read the hashed buffer from its memory.

Usage: ref-hash-watch.py <relay_log> [outdir]
Env: WATCH_PATTERNS - comma separated subprocess names to freeze (default
     CryptHashData). Only service processes are frozen (comm ~ RefereeClientAp).
"""
import os, re, sys, time, json, signal, hashlib

LOG = sys.argv[1] if len(sys.argv) > 1 else '/home/bloink/UwUNet/re/logs/chain-relay.log'
OUT = os.path.join(sys.argv[2] if len(sys.argv) > 2 else '.', 'refhash')
os.makedirs(OUT, exist_ok=True)

# CryptHashData(hHash, pbData, dwDataLen, flags) — 64-bit PE, wine relay prints:
#   Call ADVAPI32.CryptHashData(0000abcd,0032abcd,00000126,00000001)
CALLRE = re.compile(r'(?i)Call ADVAPI32\.CryptHashData\(([0-9a-f]+),([0-9a-f]+),([0-9a-f]+),([0-9a-f]+)\)', re.IGNORECASE)

def find_svc_pids():
    out = []
    for d in os.listdir('/proc'):
        if not d.isdigit():
            continue
        try:
            with open(f'/proc/{d}/comm') as f:
                c = f.read().strip()
            if c.startswith('RefereeClientAp'):
                out.append(int(d))
        except Exception:
            pass
    return out

def freeze_and_read(addr, size):
    pids = find_svc_pids()
    seen = {}
    for pid in pids:
        try:
            os.kill(pid, signal.SIGSTOP)
        except Exception:
            continue
        for _ in range(20):
            try:
                with open(f'/proc/{pid}/stat') as f:
                    if f.read().split()[2] == 'T':
                        break
            except Exception:
                pass
            time.sleep(0.01)
        try:
            with open(f'/proc/{pid}/syscall') as f:
                seen['syscall'] = f.read().strip()
        except Exception:
            pass
        try:
            with open(f'/proc/{pid}/mem', 'rb') as mem:
                mem.seek(addr)
                data = mem.read(size)
            sha = hashlib.sha256(data).hexdigest()
            seen[pid] = {'addr': addr, 'size': size, 'data': data.hex(), 'sha256': sha}
            with open(os.path.join(OUT, f'buf_{pid}_{addr}_{size}_{sha[:8]}.bin'), 'wb') as fo:
                fo.write(data)
        except Exception as e:
            seen[pid] = {'err': str(e), 'addr': addr, 'size': size}
        # leave the process frozen — the caller decides when to continue
    return seen

def main():
    deadline = time.time() + float(os.environ.get('HASHWATCH_TIMEOUT', '300'))
    hits = 0
    pos = 0
    buf = ''
    while time.time() < deadline and hits < 12:
        try:
            sz = os.path.getsize(LOG)
            if sz < pos:
                pos = 0
            if sz == pos:
                time.sleep(0.05)
                continue
            with open(LOG, 'r', errors='replace') as f:
                f.seek(pos)
                chunk = f.read()
                pos = f.tell()
            buf += chunk
            lines = buf.split('\n')
            buf = lines.pop()
            for line in lines:
                if 'ryptHashData' not in line:
                    continue
                m = CALLRE.search(line)
                if not m:
                    continue
                tid, hnd, addr, dlen, flags = 'tid', m.group(1), int(m.group(2), 16), int(m.group(3), 16), m.group(4)
                if dlen < 0x40 or dlen > 0x20000:
                    continue
                print(f'hack: tid={tid} h={hnd} addr={addr:x} len={dlen}', flush=True)
                res = freeze_and_read(addr, dlen)
                print(json.dumps(res, indent=1)[:2000], flush=True)
                hits += 1
        except Exception as e:
            print('watch err:', e, flush=True)
            time.sleep(0.3)
    print('done', flush=True)

main()
