@echo off
REM UwUNet - launch the patched Rec Room 20250718.01 client on Windows.
REM
REM Put this file IN the client depot folder (the one that contains
REM Recroom_Release.exe and Injector.exe), e.g.
REM     %USERPROFILE%\UwUNet\client2025\depot
REM then double-click it (or run it from a terminal).
REM
REM Requirements: Steam running and logged in; you have already run
REM uwunet-setup.ps1 (CA trust + hosts redirect); 2025patch.ini has
REM ApiHost= and PhotonHost= empty.

setlocal
cd /d "%~dp0"

if not exist "Recroom_Release.exe" (
  echo [!] Recroom_Release.exe not found here.
  echo     Put this .bat in the client depot folder next to the game exe.
  pause
  exit /b 1
)
if not exist "Injector.exe" (
  echo [!] Injector.exe not found - the 2025 patch is not staged in this folder.
  pause
  exit /b 1
)

REM Steam needs the app id to initialise when the exe is launched directly
REM (not through the Steam library). Write it with no trailing newline.
if not exist "steam_appid.txt" (
  <nul set /p="471710" > steam_appid.txt
  echo [run] wrote steam_appid.txt ^(471710^)
)

echo [run] starting Injector.exe
start "" "Injector.exe"

REM Give the injector a moment to come up and start watching for the game.
timeout /t 2 /nobreak >nul

echo [run] launching Recroom_Release.exe +forcemode:screen
start "" "Recroom_Release.exe" +forcemode:screen

echo.
echo [run] Launched. The injector attaches 2025Patch.dll once the game loads.
echo [run] Logs in this folder: 2025patch.log ^(patch^), Player.log is under
echo       %%USERPROFILE%%\AppData\LocalLow\Against Gravity\Rec Room\Player.log
endlocal
