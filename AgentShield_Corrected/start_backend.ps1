# AgentShield backend launcher. Safe on a fresh Windows extraction.
$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ProjectRoot

Write-Host '=== AgentShield | FastAPI Zero-Trust Gateway ===' -ForegroundColor Cyan

if (-not (Test-Path (Join-Path $ProjectRoot '.env'))) {
    if (Test-Path (Join-Path $ProjectRoot '.env.example')) {
        Copy-Item (Join-Path $ProjectRoot '.env.example') (Join-Path $ProjectRoot '.env')
        Write-Host 'Created .env from .env.example. Mock mode is ready without an API key.' -ForegroundColor Yellow
    } else {
        throw '.env.example is missing. Restore the project configuration file.'
    }
}

$Python = Get-Command python -ErrorAction SilentlyContinue
if (-not $Python) { throw 'Python 3.10+ was not found in PATH. Install Python and enable Add to PATH.' }
$PythonExe = $Python.Source
$PythonVersion = & $PythonExe -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
$VersionParts = $PythonVersion.Split('.') | ForEach-Object { [int]$_ }
if (($VersionParts[0] -lt 3) -or (($VersionParts[0] -eq 3) -and ($VersionParts[1] -lt 10))) {
    throw "Python 3.10+ is required. Found $PythonVersion."
}

$VenvPython = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path $VenvPython)) {
    Write-Host 'Creating project virtual environment (.venv)...' -ForegroundColor Yellow
    & $PythonExe -m venv (Join-Path $ProjectRoot '.venv')
    if ($LASTEXITCODE -ne 0) { throw 'Failed to create .venv.' }
}
$PythonExe = $VenvPython
Write-Host 'Installing/verifying backend dependencies...' -ForegroundColor Yellow
& $PythonExe -m pip install --disable-pip-version-check -r (Join-Path $ProjectRoot 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'Backend dependency installation failed. Check the output above.' }

$Port = 8000
$PortLine = Get-Content (Join-Path $ProjectRoot '.env') | Where-Object { $_ -match '^AGENTSHIELD_PORT=' } | Select-Object -Last 1
if ($PortLine) { $Port = [int](($PortLine -split '=', 2)[1].Trim()) }
$HostAddress = '127.0.0.1'
$HostLine = Get-Content (Join-Path $ProjectRoot '.env') | Where-Object { $_ -match '^AGENTSHIELD_HOST=' } | Select-Object -Last 1
if ($HostLine) { $HostAddress = (($HostLine -split '=', 2)[1].Trim()) }
if ($HostAddress -notin @('127.0.0.1', 'localhost')) {
    Write-Warning 'Binding beyond localhost exposes the SOC gateway to your network. Review firewall and authentication controls before proceeding.'
}

Write-Host "Starting gateway at http://${HostAddress}:$Port ..." -ForegroundColor Green
Write-Host 'Dashboard: /   |   Swagger: /docs   |   Health: /health' -ForegroundColor Cyan
& $PythonExe -m uvicorn main:app --host $HostAddress --port $Port
if ($LASTEXITCODE -ne 0) { throw "Uvicorn exited with code $LASTEXITCODE." }
