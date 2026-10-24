# =============================================================================
# AAVARAN - start.ps1   (or double-click start.cmd)
# =============================================================================
# Starts everything the demo needs, each in its own window:
#   model   scripted mock VLM on :8001        (default)
#           or local Qwen2.5-VL via Ollama    (-Local)
#   brain   server/main.py on :8756
#   pages   static server for demo/ and bench/ on :8770
# Anything already listening on its port is left alone, so re-running is safe.
# Close a window to stop that piece.
#
#   .\start.ps1            mock model
#   .\start.ps1 -Local     Qwen2.5-VL 7B on this laptop (pulls ~6 GB once)
# =============================================================================

param(
  [switch]$Local,
  [string]$LocalModel = 'qwen2.5vl:7b'
)

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$Py = Join-Path $Root '.venv\Scripts\python.exe'

function Test-Port($port) {
  [bool](Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
}

function Start-Window($title, $dir, $command) {
  # -NoExit keeps the window open so a crash stays readable.
  Start-Process powershell -WorkingDirectory $dir -ArgumentList @(
    '-NoExit', '-Command', "`$Host.UI.RawUI.WindowTitle = 'AAVARAN $title'; $command")
}

function Wait-Port($port, $what, $seconds = 60) {
  for ($i = 0; $i -lt $seconds; $i++) {
    if (Test-Port $port) { return }
    Start-Sleep -Seconds 1
  }
  throw "$what did not come up on port $port within $seconds s - check its window."
}

# --- preflight ---------------------------------------------------------------
if (-not (Test-Path $Py)) {
  Write-Host 'Creating .venv and installing server deps (one time)...' -ForegroundColor Yellow
  python -m venv (Join-Path $Root '.venv')
  & $Py -m pip install -q -r (Join-Path $Root 'server\requirements-dev.txt')
}
if (-not (Test-Path (Join-Path $Root 'extension\libs\tesseract.min.js'))) {
  Write-Host 'Extension libs missing; fetching them (one time, ~48 MB)...' -ForegroundColor Yellow
  & (Join-Path $Root 'fetch-libs.ps1')
}

# --- model -------------------------------------------------------------------
if ($Local) {
  $vlmBase = 'http://127.0.0.1:11434/v1'
  $vlmModel = $LocalModel
  if (Test-Port 11434) {
    Write-Host 'Ollama already running. If it was started by the tray app, its context window may be too small for screenshots; quit it and re-run this script.' -ForegroundColor DarkYellow
  } else {
    # One screenshot is ~1,500 tokens; the default context would silently truncate.
    Start-Window 'ollama' $Root "`$env:OLLAMA_CONTEXT_LENGTH = '16384'; ollama serve"
    Wait-Port 11434 'Ollama'
  }
  if (-not ((ollama list) -match [regex]::Escape($LocalModel))) {
    Write-Host "Pulling $LocalModel (one time, ~6 GB)..." -ForegroundColor Yellow
    ollama pull $LocalModel
  }
} else {
  $vlmBase = 'http://127.0.0.1:8001/v1'
  $vlmModel = 'Qwen/Qwen2.5-VL-7B-Instruct'
  if (-not (Test-Port 8001)) {
    Start-Window 'mock model' (Join-Path $Root 'server') "& '$Py' -m uvicorn mock_vlm:app --host 127.0.0.1 --port 8001"
  }
}

# --- brain -------------------------------------------------------------------
if (Test-Port 8756) {
  Write-Host 'Server already running on :8756 - leaving it. Close its window and re-run to switch models.' -ForegroundColor DarkYellow
} else {
  # Two screenshots of history keep a local 7B inside 8 GB of VRAM.
  $maxImages = if ($Local) { '2' } else { '3' }
  Start-Window 'server' (Join-Path $Root 'server') (
    "`$env:AAVARAN_VLM_BASE = '$vlmBase'; `$env:AAVARAN_VLM_MODEL = '$vlmModel'; " +
    "`$env:AAVARAN_MAX_IMAGES = '$maxImages'; & '$Py' -m uvicorn main:app --host 127.0.0.1 --port 8756")
}

# --- pages -------------------------------------------------------------------
if (-not (Test-Port 8770)) {
  Start-Window 'pages' $Root "& '$Py' -m http.server 8770 --bind 127.0.0.1"
}

Wait-Port 8756 'Server'
Wait-Port 8770 'Page server' 15
$health = Invoke-RestMethod http://127.0.0.1:8756/healthz
Write-Host "AAVARAN up | model $($health.model) via $vlmBase" -ForegroundColor Green
Start-Process 'http://127.0.0.1:8770/demo/demo-page.html'

Write-Host ''
Write-Host 'Next, in Chrome:' -ForegroundColor Cyan
Write-Host '  1. chrome://extensions -> Developer mode -> Load unpacked -> extension\  (or Reload it)'
Write-Host '  2. On the demo page, open the AAVARAN popup -> Preflight -> Expand'
Write-Host '  3. Try the goals:  pay the bill   |   download the statement'
