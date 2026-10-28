$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location (Join-Path $projectRoot 'frontend')
$env:VITE_API_BASE_URL = 'http://127.0.0.1:8009'
npm run dev
