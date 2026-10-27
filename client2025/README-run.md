# Running the patched 20250718 client against UwUNet

Everything is staged except the game files themselves, which must come from your
own Steam account (you own Rec Room). Three steps.

## 1. Download the 20250718.01 build (needs YOUR Steam login + Steam Guard)

Run this yourself in the Claude Code prompt with a leading `!` so the 2FA prompt
reaches you (replace `YOUR_STEAM_USERNAME`):

    ! /home/bloink/UwUNet/tools/depotdownloader/DepotDownloader -app 471710 -depot 471711 -manifest 1151455856673601091 -username YOUR_STEAM_USERNAME -dir /home/bloink/UwUNet/client2025/depot

- Enter your Steam password + Steam Guard code when prompted.
- This downloads several GB; let it finish (it resumes if interrupted).
- When done, `/home/bloink/UwUNet/client2025/depot/Recroom_Release.exe` exists.

## 2. Stage the 2025 client patch into the build

    /home/bloink/UwUNet/client2025/stage-patch.sh            # boot test, no backend
    # or point the game's API at the UwUNet edge:
    /home/bloink/UwUNet/client2025/stage-patch.sh 127.0.0.1  # (edge host)

## 3. Launch

    /home/bloink/UwUNet/client2025/run.sh screen

Confirm success:
- `client2025/depot/2025patch.log` → shows `[Config] ...` = patch attached, Referee bypassed.
- `data/harvest/requests.jsonl` → real API requests from the client (the harvest
  that was blocked by the anti-cheat wall until now).
