# Trust PhishGuard Local Runner
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host " Starting Trust PhishGuard Simulation Platform..." -ForegroundColor Green
Write-Host "===================================================" -ForegroundColor Cyan

$env:PORT = "8899"
$env:ADMIN_USERNAME = "admin"
$env:ADMIN_PASSWORD = "CHANGE_ME"

python server.py
