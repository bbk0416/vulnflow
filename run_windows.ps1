[CmdletBinding()]
param(
    [switch]$InstallOnly
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Resolve-SupportedPython {
    $candidates = @(
        @{ Command = "py"; Arguments = @("-3.13"); Label = "py -3.13" },
        @{ Command = "py"; Arguments = @("-3.12"); Label = "py -3.12" },
        @{ Command = "python"; Arguments = @(); Label = "python" }
    )

    foreach ($candidate in $candidates) {
        $resolved = Get-Command $candidate.Command -ErrorAction SilentlyContinue
        if (-not $resolved) { continue }

        $executable = $resolved.Source
        $arguments = @($candidate.Arguments)
        try {
            $versionOk = & $executable @arguments -c "import sys; print('1' if sys.version_info[:2] in {(3,12),(3,13)} else '0')" 2>$null
            if ($LASTEXITCODE -eq 0 -and $versionOk.Trim() -eq "1") {
                return [PSCustomObject]@{
                    Executable = $executable
                    Arguments = $arguments
                    Label = $candidate.Label
                }
            }
        } catch {
            continue
        }
    }

    throw @"
VulnFlow를 실행할 Python 3.12 또는 3.13을 찾지 못했습니다.

지원되는 Windows 설치 형태:
  - Python Launcher: py -3.13 또는 py -3.12
  - PATH에 등록된 python.exe

Python 3.12/3.13 설치 후 이 파일을 다시 실행하세요.
"@
}

$bootstrap = Resolve-SupportedPython
$bootstrapPython = $bootstrap.Executable
$bootstrapArguments = @($bootstrap.Arguments)
Write-Host ("PYTHON_BOOTSTRAP=" + $bootstrap.Label)

$lockPath = Join-Path $PSScriptRoot "requirements.lock"
if (-not (Test-Path $lockPath -PathType Leaf)) {
    throw "검증된 런타임 의존성 잠금 파일 requirements.lock을 찾을 수 없습니다."
}
$lockHash = (Get-FileHash -Algorithm SHA256 $lockPath).Hash.ToLowerInvariant()

$venvRoot = Join-Path $PSScriptRoot ".venv"
$venvPython = Join-Path $venvRoot "Scripts\python.exe"
$lockMarkerPath = Join-Path $venvRoot ".vulnflow-requirements-lock.sha256"

if (-not (Test-Path $venvPython -PathType Leaf)) {
    Write-Host "VulnFlow 전용 Python 환경을 처음 구성합니다." -ForegroundColor Cyan
    & $bootstrapPython @bootstrapArguments -m venv $venvRoot
    if ($LASTEXITCODE -ne 0) { throw "VulnFlow 가상환경을 만들지 못했습니다." }
}

function Test-LockedRuntime {
    if (-not (Test-Path $venvPython -PathType Leaf)) { return $false }
    if (-not (Test-Path $lockMarkerPath -PathType Leaf)) { return $false }

    $recordedHash = (Get-Content $lockMarkerPath -Raw -ErrorAction SilentlyContinue).Trim().ToLowerInvariant()
    if ($recordedHash -ne $lockHash) { return $false }

    & $venvPython -c "from app.services.runtime_dependency_policy import enforce_runtime_dependencies; enforce_runtime_dependencies(policy='enforce')" *> $null
    return ($LASTEXITCODE -eq 0)
}

$runtimeReady = Test-LockedRuntime
if (-not $runtimeReady) {
    Write-Host "검증된 VulnFlow 런타임 의존성을 설치·복구합니다." -ForegroundColor Cyan
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

    & $venvPython -c "from app.services.runtime_dependency_policy import enforce_runtime_dependencies; enforce_runtime_dependencies(policy='enforce')"
    if ($LASTEXITCODE -ne 0) { throw "설치된 런타임 의존성이 requirements.lock과 일치하지 않습니다." }

    Set-Content -Path $lockMarkerPath -Value $lockHash -Encoding Ascii -NoNewline
    Write-Host "LOCKED_RUNTIME_INSTALLATION=PASS"
} else {
    Write-Host "LOCKED_RUNTIME_REUSED=PASS"
}

if (-not $env:VULNFLOW_RUNTIME_DEPENDENCY_POLICY) { $env:VULNFLOW_RUNTIME_DEPENDENCY_POLICY = "enforce" }
if ($InstallOnly) {
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

Write-Host ""
Write-Host "VulnFlow Free — Public Beta" -ForegroundColor Cyan
Write-Host "브라우저 주소: http://127.0.0.1:8000/login"
Write-Host "종료하려면 이 창에서 Ctrl+C를 누르세요."
Start-Job -ScriptBlock {
    Start-Sleep -Seconds 2
    Start-Process "http://127.0.0.1:8000/login"
} | Out-Null
& $venvPython -m uvicorn app.main:app --host 127.0.0.1 --port 8000
if ($LASTEXITCODE -ne 0) { throw "VulnFlow 실행이 실패했습니다." }
