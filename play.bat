@echo off
rem Launch the recompiled Risk: The Game of Global Domination (builds first if needed).
rem The disc image defaults to the .cue in
rem   %USERPROFILE%\Downloads\Emus\PS1\Risk - The Game of Global Domination (USA)\Risk - The Game of Global Domination (USA)\
rem set RISK_DISC to use another .cue. The memory card is saved to rust\memcard\slot1.mcd.
cd /d "%~dp0rust"
cargo run -p risk-bevy %*
if errorlevel 1 pause
