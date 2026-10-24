@echo off
rem Double-click to start AAVARAN. Add -Local to use Qwen2.5-VL on this laptop.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1" %*
if errorlevel 1 pause
