import sys, urllib.request, zipfile, io, os, re
shard=sys.argv[1]; zipname=shard+".zip"
url=f"https://archive.org/download/{shard}/{zipname}"
def hook(n,c,url): pass
p=f"/data-rrs/{zipname}"
if not os.path.exists(p):
    print("downloading", p, flush=True)
    urllib.request.urlretrieve(url, p)
print("scanning...", flush=True)
NEEDLES=[b"22555d14", b"22555d14291843f394d4da0c893d96c4", b"MakeItToMidnight", b"597bf45e", bytes.fromhex("22555d14291843f394d4da0c893d96c4")]
z=zipfile.ZipFile(p)
for name in z.namelist():
    try: data=z.read(name)
    except Exception as e: continue
    hits=[n.decode() if isinstance(n,bytes) else n for n in NEEDLES if n in data]
    if hits: print("HIT", name, hits, flush=True)
print("done", shard, flush=True)
os.remove(p)
