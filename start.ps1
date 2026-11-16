# Usage: .\start.ps1 [-Local]  (mock VLM :8001 or Ollama Qwen2.5-VL, server :8756, pages :8770)

param(
  [switch]$Local,
  [string]$BaseModel = 'qwen2.5vl:7b'
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

if (-not (Test-Path $Py)) {
  Write-Host 'Creating .venv and installing server deps (one time)...' -ForegroundColor Yellow
  python -m venv (Join-Path $Root '.venv')
  & $Py -m pip install -q -r (Join-Path $Root 'server\requirements-dev.txt')
}
if (-not (Test-Path (Join-Path $Root 'extension\libs\tesseract.min.js'))) {
  Write-Host 'Extension libs missing; fetching them (one time, ~48 MB)...' -ForegroundColor Yellow
  & (Join-Path $Root 'fetch-libs.ps1')
}

if ($Local) {
  $vlmBase = 'http://127.0.0.1:11434/v1'
  $vlmModel = 'aavaran-qwen'
  if (-not (Test-Port 11434)) {
    # 8k context holds two 1024 px frames plus history; flash attention and a
    # q8 KV cache keep it in VRAM; KEEP_ALIVE -1 stops the idle unload that
    # would otherwise stall the first step after a pause.
    Start-Window 'ollama' $Root ("`$env:OLLAMA_CONTEXT_LENGTH = '8192'; `$env:OLLAMA_FLASH_ATTENTION = '1'; " +
      "`$env:OLLAMA_KV_CACHE_TYPE = 'q8_0'; `$env:OLLAMA_KEEP_ALIVE = '-1'; ollama serve")
    Wait-Port 11434 'Ollama'
  }
  $models = ollama list | Out-String
  if ($models -notmatch [regex]::Escape($BaseModel)) {
    Write-Host "Pulling $BaseModel (one time, ~6 GB)..." -ForegroundColor Yellow
    ollama pull $BaseModel
  }
  if ($models -notmatch 'aavaran-qwen') {
    Write-Host 'Building aavaran-qwen (one time, ~1 min; local copy, no download)...' -ForegroundColor Yellow
    & $Py -m pip install -q gguf
    & $Py (Join-Path $Root 'scripts\make-local-model.py')
  }
  Write-Host 'Loading the model onto the GPU...' -ForegroundColor Yellow
  $null = Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:11434/api/generate' -TimeoutSec 300 `
    -ContentType 'application/json' -Body '{"model":"aavaran-qwen","prompt":"ok","stream":false,"options":{"num_predict":1}}'
  $placement = (ollama ps | Select-String 'aavaran-qwen').Line
  Write-Host "  $placement"
  if ($placement -notmatch 'Forever') {
    Write-Host '  This Ollama was not started by this script: the model may unload when idle (slow next step). Close Ollama and re-run for best results.' -ForegroundColor DarkYellow
  }
  if ($placement -notmatch '100% GPU') {
    Write-Host '  Not fully on the GPU: steps will be slow. Close other GPU apps (browsers with many tabs, games) and re-run.' -ForegroundColor DarkYellow
  }
} else {
  $vlmBase = 'http://127.0.0.1:8001/v1'
  $vlmModel = 'Qwen/Qwen2.5-VL-7B-Instruct'
  if (-not (Test-Port 8001)) {
    Start-Window 'mock model' (Join-Path $Root 'server') "& '$Py' -m uvicorn mock_vlm:app --host 127.0.0.1 --port 8001"
  }
}

if (Test-Port 8756) {
  Write-Host 'Server already running on :8756 - leaving it. Close its window and re-run to switch models.' -ForegroundColor DarkYellow
} else {
  # Two screenshots of history keep a local 7B inside 8 GB of VRAM.
  $maxImages = if ($Local) { '2' } else { '3' }
  Start-Window 'server' (Join-Path $Root 'server') (
    "`$env:AAVARAN_VLM_BASE = '$vlmBase'; `$env:AAVARAN_VLM_MODEL = '$vlmModel'; " +
    "`$env:AAVARAN_MAX_IMAGES = '$maxImages'; & '$Py' -m uvicorn main:app --host 127.0.0.1 --port 8756")
}

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
