# One-click AgentShield startup. The compiled React dashboard is served by FastAPI.
$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ProjectRoot
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ' AGENTSHIELD | ZERO-TRUST AI SECURITY GATEWAY' -ForegroundColor Green
Write-Host '============================================================' -ForegroundColor Cyan

if (-not (Test-Path '.env')) {
    if (-not (Test-Path '.env.example')) { throw '.env.example is missing.' }
    Copy-Item '.env.example' '.env'
    Write-Host 'Created default .env. Gemini is optional; Mock mode is available offline.' -ForegroundColor Yellow
}
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw 'Python 3.10+ is required but was not found in PATH.' }
$PythonVersion = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
$VersionParts = $PythonVersion.Split('.') | ForEach-Object { [int]$_ }
if (($VersionParts[0] -lt 3) -or (($VersionParts[0] -eq 3) -and ($VersionParts[1] -lt 10))) { throw "Python 3.10+ is required. Found $PythonVersion." }
if (-not (Test-Path '.venv\Scripts\python.exe')) {
    Write-Host 'Creating Python virtual environment...' -ForegroundColor Yellow
    python -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Could not create .venv.' }
}
$PythonExe = (Resolve-Path '.venv\Scripts\python.exe').Path
Write-Host 'Installing/verifying Python dependencies (including document parsers)...' -ForegroundColor Yellow
& $PythonExe -m pip install --disable-pip-version-check -r '.\requirements.txt'
if ($LASTEXITCODE -ne 0) { throw 'Python dependency installation failed.' }

# Build the frontend only when the production bundle is missing. Node is not needed
# to run an existing production bundle served by FastAPI.
if (-not (Test-Path 'frontend\dist\index.html')) {
    $Npm = Get-Command npm -ErrorAction SilentlyContinue
    if (-not $Npm) { throw 'frontend/dist is missing and Node.js/npm is unavailable to build the dashboard.' }
    Push-Location 'frontend'
    if (Test-Path 'package-lock.json') { npm ci } else { npm install }
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw 'npm dependency installation failed.' }
    npm run build
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw 'Vite production build failed.' }
    Pop-Location
}

$Port = 8000
$PortLine = Get-Content '.env' | Where-Object { $_ -match '^AGENTSHIELD_PORT=' } | Select-Object -Last 1
if ($PortLine) { $Port = [int](($PortLine -split '=', 2)[1].Trim()) }
$HealthUrl = "http://127.0.0.1:$Port/health"
try {
    $Existing = Invoke-RestMethod -Uri $HealthUrl -TimeoutSec 2 -ErrorAction Stop
    if ($Existing.status -ne 'healthy') { throw 'Port is occupied by a non-AgentShield service.' }
    Write-Host 'An AgentShield gateway is already running.' -ForegroundColor Yellow
} catch {
    $PortOwner = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($PortOwner) { throw "Port $Port is occupied by PID $($PortOwner.OwningProcess), and it is not a healthy AgentShield instance." }
    Write-Host 'Starting backend in a separate PowerShell window...' -ForegroundColor Yellow
    $BackendScript = Join-Path $ProjectRoot 'start_backend.ps1'
    $Console = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoExit','-ExecutionPolicy','Bypass','-File',"`"$BackendScript`"") -PassThru
    Set-Content -Path '.agentshield_backend_console.pid' -Value $Console.Id
    $Ready = $false
    for ($i = 0; $i -lt 45; $i++) {
        Start-Sleep -Seconds 1
        try {
            $Health = Invoke-RestMethod -Uri $HealthUrl -TimeoutSec 2 -ErrorAction Stop
            if ($Health.status -eq 'healthy') { $Ready = $true; break }
        } catch { Write-Host '.' -NoNewline -ForegroundColor DarkGray }
    }
    Write-Host ''
    if (-not $Ready) { throw "Gateway failed to become healthy at $HealthUrl. Inspect the backend console window." }
}

$Owner = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($Owner) { Set-Content -Path '.agentshield_backend.pid' -Value $Owner.OwningProcess }
Write-Host 'AgentShield is ready:' -ForegroundColor Green
Write-Host " Dashboard: http://127.0.0.1:$Port/" -ForegroundColor Cyan
Write-Host " Swagger:   http://127.0.0.1:$Port/docs" -ForegroundColor Cyan
Write-Host " Health:    $HealthUrl" -ForegroundColor Cyan
Start-Process "http://127.0.0.1:$Port/"
