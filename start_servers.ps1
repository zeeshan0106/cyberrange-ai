# CyberRange AI - Windows Startup Script
Write-Host "Starting CyberRange AI Services..." -ForegroundColor Cyan

# 1. MongoDB (Port 27017)
$mongoTest = Test-NetConnection -ComputerName 127.0.0.1 -Port 27017 -WarningAction SilentlyContinue -InformationLevel Quiet
if (-not $mongoTest.TcpTestSucceeded) {
    Write-Host "[1/3] Starting MongoDB on port 27017..." -ForegroundColor Yellow
    $dbPath = "$PSScriptRoot\data\db"
    if (-not (Test-Path $dbPath)) {
        New-Item -ItemType Directory -Path $dbPath -Force | Out-Null
    }
    $mongodPath = "C:\Program Files\MongoDB\Server\8.2\bin\mongod.exe"
    if (-not (Test-Path $mongodPath)) {
        $found = Get-Command mongod -ErrorAction SilentlyContinue
        if ($found) { $mongodPath = $found.Source }
    }
    Start-Process -FilePath $mongodPath -ArgumentList "--dbpath `"$dbPath`" --port 27017 --bind_ip 127.0.0.1" -WindowStyle Hidden
    Start-Sleep -Seconds 3
    Write-Host "      MongoDB started successfully." -ForegroundColor Green
} else {
    Write-Host "[1/3] MongoDB is already running on port 27017." -ForegroundColor Green
}

# 2. FastAPI Backend (Port 8000)
# NOTE: uvicorn is run from the backend folder so Python can find the local modules.
$port8000 = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
if ($port8000) {
    Write-Host "[2/3] FastAPI Backend is already running on http://localhost:8000." -ForegroundColor Green
} else {
    Write-Host "[2/3] Starting FastAPI Backend on http://localhost:8000..." -ForegroundColor Yellow
    Start-Process -FilePath "python" -ArgumentList "-m uvicorn server:app --port 8000" -WorkingDirectory "$PSScriptRoot\backend" -WindowStyle Hidden
    Start-Sleep -Seconds 3
    Write-Host "      FastAPI Backend started successfully." -ForegroundColor Green
}

# 3. React Frontend (Port 3000)
$port3000 = Get-NetTCPConnection -LocalPort 3000 -State Listen -ErrorAction SilentlyContinue
if ($port3000) {
    Write-Host "[3/3] Frontend is already running on http://localhost:3000." -ForegroundColor Green
} else {
    Write-Host "[3/3] Starting React Frontend on http://localhost:3000..." -ForegroundColor Yellow
    Write-Host "      (This window will stay open while the frontend is running)" -ForegroundColor DarkGray
    Set-Location -Path "$PSScriptRoot\frontend"
    npm start
}
