$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$pythonExe = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path $pythonExe)) { throw 'Python environment missing. Run scripts\setup.ps1 first.' }
Set-Location (Join-Path $projectRoot 'backend')
$env:PYTHONPATH = (Get-Location).Path
& $pythonExe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8009
