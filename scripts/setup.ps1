$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

if (-not (Test-Path '.venv\Scripts\python.exe')) { python -m venv .venv }
& '.venv\Scripts\python.exe' -m pip install --upgrade pip
& '.venv\Scripts\python.exe' -m pip install -r 'backend\requirements.txt'
if (-not (Test-Path '.env')) { Copy-Item '.env.example' '.env' }
Set-Location 'frontend'
npm install
Write-Host 'Setup complete. Set APP_SECRET_KEY in this PowerShell session before starting the backend.'
