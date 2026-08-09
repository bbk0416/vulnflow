@echo off
setlocal
cd /d "%~dp0"
where powershell.exe >nul 2>nul || (
  echo Windows PowerShell is required to launch VulnFlow.
  exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_windows.ps1"
exit /b %ERRORLEVEL%
