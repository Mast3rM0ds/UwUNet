#!/usr/bin/env python3
"""Point every rec.net hostname at 127.0.0.1 inside the Proton prefix hosts file."""
import sys, pathlib

PFX = pathlib.Path.home() / ".local/share/Steam/steamapps/compatdata/471710/pfx"
HOSTS = PFX / "drive_c/windows/system32/drivers/etc/hosts"

NAMES = ["rec.net","www.rec.net","api.rec.net","auth.rec.net","accounts.rec.net",
"rooms.rec.net","match.rec.net","chat.rec.net","lists.rec.net",
"leaderboard.rec.net","clubs.rec.net","econ.rec.net","commerce.rec.net",
"cards.rec.net","discovery.rec.net","playersettings.rec.net","notify.rec.net",
"platformnotifications.rec.net","datacollection.rec.net","ns.rec.net",
"ns-fd.rec.net","ai.rec.net","img.rec.net","cdn.rec.net","strings-cdn.rec.net",
"studiocdn.rec.net","cms.rec.net","forum.rec.net","apim.rec.net"]

MARK = "# uwunet-block"
block = [MARK] + [f"127.0.0.1 {n}" for n in NAMES] + ["# uwunet-end"]

cur = HOSTS.read_text() if HOSTS.exists() else ""
out = []
skipping = False
for line in cur.splitlines():
    if line.strip() == MARK:
        skipping = True
        continue
    if line.strip() == "# uwunet-end":
        skipping = False
        continue
    if not skipping:
        out.append(line)
if out and out[-1].strip():
    out.append("")
HOSTS.write_text("\n".join(out + block) + "\n")
print(f"[uwunet] wrote {len(NAMES)} rec.net redirects to {HOSTS}")
