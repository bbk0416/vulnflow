$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python을 찾을 수 없습니다. Python 3.11 이상을 설치한 뒤 다시 실행하세요."
}
if (-not (Test-Path ".venv")) {
    python -m venv .venv
}
& .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt

Write-Host "VulnFlow: http://127.0.0.1:8000"
Start-Job -ScriptBlock {
    Start-Sleep -Seconds 2
    Start-Process "http://127.0.0.1:8000"
} | Out-Null
if (-not $env:VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK) {
    $env:VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK = "1"
}
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
