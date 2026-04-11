@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0discover_remote.ps1" %*
exit /b %ERRORLEVEL%
