@echo off
title Trust PhishGuard Simulation Server
echo ===================================================
echo Starting Trust PhishGuard Simulation Platform...
echo ===================================================

set PORT=8899
set ADMIN_USERNAME=admin
set ADMIN_PASSWORD=CHANGE_ME

python server.py
pause
