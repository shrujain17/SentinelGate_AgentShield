# AgentShield React/Vite development launcher.
$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
$FrontendDir = Join-Path $ProjectRoot 'frontend'
if (-not (Test-Path (Join-Path $FrontendDir 'package.json'))) { throw "Frontend package.json missing in $FrontendDir" }

$Node = Get-Command node -ErrorAction SilentlyContinue
$Npm = Get-Command npm -ErrorAction SilentlyContinue
if (-not $Node -or -not $Npm) { throw 'Node.js 18+ and npm are required for frontend development. Install Node.js from https://nodejs.org/.' }
$NodeMajor = [int]((& $Node.Source --version).TrimStart('v').Split('.')[0])
if ($NodeMajor -lt 18) { throw "Node.js 18+ is required. Found $(& $Node.Source --version)." }

Set-Location $FrontendDir
Write-Host 'Installing/verifying React frontend dependencies...' -ForegroundColor Yellow
if (Test-Path (Join-Path $FrontendDir 'package-lock.json')) { npm ci } else { npm install }
if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
Write-Host 'Starting Vite at http://127.0.0.1:5173 ...' -ForegroundColor Green
npm run dev -- --host 127.0.0.1
if ($LASTEXITCODE -ne 0) { throw "Vite exited with code $LASTEXITCODE." }
