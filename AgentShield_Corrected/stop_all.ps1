# Stop only the AgentShield backend process and the launcher console it spawned.
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ProjectRoot
$Stopped = @()
foreach ($PidFile in @('.agentshield_backend.pid', '.agentshield_backend_console.pid')) {
    if (Test-Path $PidFile) {
        $Raw = (Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($Raw -match '^\d+$') {
            $TargetPid = [int]$Raw
            try {
                $Proc = Get-Process -Id $TargetPid -ErrorAction Stop
                Stop-Process -Id $TargetPid -Force -ErrorAction Stop
                $Stopped += "$($Proc.ProcessName) (PID $TargetPid)"
            } catch { Write-Host "Process $TargetPid is already stopped." -ForegroundColor DarkGray }
        }
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    }
}
if ($Stopped.Count) { Write-Host ('Stopped: ' + ($Stopped -join ', ')) -ForegroundColor Green }
else { Write-Host 'No AgentShield process IDs were recorded. Stop the backend console with Ctrl+C if it was started manually.' -ForegroundColor Yellow }
