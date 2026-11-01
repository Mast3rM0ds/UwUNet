# Running the patched 20260323.14 client against UwUNet

Same flow as `client2025/`, with the public
[recflare/patch-2026](https://github.com/recflare/patch-2026) patch (v0.0.3), which supports
client **20260323.14** only.

## 1. Download the 20260323.14 build (needs YOUR Steam login + Steam Guard)

Run this yourself (leading `!` in the Claude Code prompt so the 2FA prompt reaches you):

    ! /home/bloink/Work/UwUNet/tools/depotdownloader/DepotDownloader -app 471710 -depot 471711 -manifest 8867414017562658247 -username YOUR_STEAM_USERNAME -dir /home/bloink/Work/UwUNet/client2026/depot

When done, `client2026/depot/RecRoom.exe` exists.

## 2. Stage the patch

    gh release download v0.0.3 -R recflare/patch-2026 -p '2026Patch-v0.0.3-x64.zip' -D tools/patch2026-dl
    unzip -o tools/patch2026-dl/2026Patch-v0.0.3-x64.zip -d tools/patch2026-dl/extracted
    client2026/stage-patch.sh

## 3. Launch

    client2026/run.sh screen      # or vr

`client2026/depot/2026patch.log` confirms the patch attached. The 2025 client keeps working
from `client2025/` — the edge serves both builds.
