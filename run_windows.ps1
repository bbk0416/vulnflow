[CmdletBinding()]
param(
    [switch]$InstallOnly
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$bootstrap = Get-Command python -ErrorAction SilentlyContinue
if (-not $bootstrap) {
    throw "Python을 찾을 수 없습니다. Python 3.12 또는 3.13을 설치한 뒤 다시 실행하세요."
}
$bootstrapPython = $bootstrap.Source
$pythonVersionOk = & $bootstrapPython -c "import sys; print('1' if sys.version_info[:2] in {(3,12),(3,13)} else '0')"
if ($pythonVersionOk.Trim() -ne "1") {
    throw "VulnFlow는 Python 3.12 또는 3.13만 지원합니다."
}

$lockPath = Join-Path $PSScriptRoot "requirements.lock"
if (-not (Test-Path $lockPath -PathType Leaf)) {
    throw "검증된 런타임 의존성 잠금 파일 requirements.lock을 찾을 수 없습니다."
}

$venvRoot = Join-Path $PSScriptRoot ".venv"
$venvPython = Join-Path $venvRoot "Scripts\python.exe"
if (-not (Test-Path $venvPython -PathType Leaf)) {
    & $bootstrapPython -m venv $venvRoot
    if ($LASTEXITCODE -ne 0) { throw "VulnFlow 가상환경을 만들지 못했습니다." }
}

$installArguments = @(
    "-m", "pip",
    "--disable-pip-version-check",
    "install",
    "--requirement", $lockPath
)
if ($env:VULNFLOW_WHEELHOUSE) {
    $wheelhouse = (Resolve-Path $env:VULNFLOW_WHEELHOUSE -ErrorAction Stop).Path
    $installArguments += @("--no-index", "--find-links", $wheelhouse)
}
& $venvPython @installArguments
if ($LASTEXITCODE -ne 0) { throw "requirements.lock 설치에 실패했습니다." }

if (-not $env:VULNFLOW_RUNTIME_DEPENDENCY_POLICY) { $env:VULNFLOW_RUNTIME_DEPENDENCY_POLICY = "enforce" }
if ($InstallOnly) {
    & $venvPython -c "from app.services.runtime_dependency_policy import enforce_runtime_dependencies; report=enforce_runtime_dependencies(policy='enforce'); print(f'LOCKED_RUNTIME_PACKAGES={report.expected_packages}')"
    if ($LASTEXITCODE -ne 0) { throw "설치된 런타임 의존성이 requirements.lock과 일치하지 않습니다." }
    Write-Host "LOCKED_RUNTIME_INSTALLATION=PASS"
    Write-Host ("LOCKED_RUNTIME_PYTHON=" + $venvPython)
    exit 0
}
if (-not $env:VULNFLOW_DEMO_MODE) { $env:VULNFLOW_DEMO_MODE = "0" }
if (-not $env:VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK) { $env:VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK = "0" }
if (-not $env:VULNFLOW_CONTROL_DB) {
    $env:VULNFLOW_CONTROL_DB = Join-Path $PSScriptRoot "data\control.db"
}
if (-not $env:VULNFLOW_DEFAULT_PROJECT_DB) {
    $env:VULNFLOW_DEFAULT_PROJECT_DB = Join-Path $PSScriptRoot "data\projects\default\vulnflow.db"
}

& $venvPython -m scripts.prepare_storage | Out-Null
if ($LASTEXITCODE -ne 0) { throw "VulnFlow 저장소 분리·마이그레이션에 실패했습니다." }

if ($env:VULNFLOW_DEMO_MODE -ne "1") {
    $activeUsers = & $venvPython -c "from app.core.database_schema import init_db; from app.services.accounts import count_active_users; from pathlib import Path; p=Path(r'$env:VULNFLOW_CONTROL_DB'); init_db(p); print(count_active_users(p))"
    if ([int]$activeUsers -eq 0 -and -not $env:VULNFLOW_API_TOKENS_JSON) {
        Write-Host ""
        Write-Host "최초 관리자 계정을 만듭니다." -ForegroundColor Cyan
        & $venvPython -m scripts.manage_users --db "$env:VULNFLOW_CONTROL_DB" create --username admin --role admin
        if ($LASTEXITCODE -ne 0) { throw "관리자 계정을 만들지 못했습니다." }
    }
}

Write-Host "VulnFlow: http://127.0.0.1:8000/login"
Start-Job -ScriptBlock {
    Start-Sleep -Seconds 2
    Start-Process "http://127.0.0.1:8000/login"
} | Out-Null
& $venvPython -m uvicorn app.main:app --host 127.0.0.1 --port 8000
if ($LASTEXITCODE -ne 0) { throw "VulnFlow 실행이 실패했습니다." }
