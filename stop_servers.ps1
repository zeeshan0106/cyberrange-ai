# CyberRange AI - Windows Stop Script
Write-Host "Stopping CyberRange AI Services..." -ForegroundColor Yellow

# Helper to stop processes listening on specific ports
function Stop-PortListener ($port, $name) {
    $connections = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
    if ($connections) {
        $pids = $connections | Select-Object -ExpandProperty OwningProcess -Unique
        foreach ($procId in $pids) {
            if ($procId -gt 0) {
                Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
                Write-Host "Stopped $name (PID: $procId on port $port)." -ForegroundColor Green
            }
        }
    } else {
        Write-Host "$name (port $port) is not running." -ForegroundColor Gray
    }
}

# 1. Stop React (Port 3000)
Stop-PortListener 3000 "Frontend"

# 2. Stop FastAPI (Port 8000)
Stop-PortListener 8000 "Backend"

# 3. Stop MongoDB (Port 27017)
Stop-PortListener 27017 "MongoDB"

# Also clean up any lingering node or mongod processes
Get-Process -Name mongod -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host "All CyberRange AI services stopped." -ForegroundColor Cyan
