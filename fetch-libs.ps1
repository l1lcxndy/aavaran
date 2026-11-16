
param(
  [string]$ExtensionRoot = (Join-Path $PSScriptRoot 'extension'),
  [string]$TesseractVersion = '5.1.1',
  [string]$CoreVersion = '5.1.1',
  [string]$TransformersVersion = '3.8.1',
  [switch]$Clean
)

$ErrorActionPreference = 'Stop'
# Invoke-WebRequest on Windows PowerShell 5.1 is ~50x slower on binaries with
# the progress bar on. This is the difference between 8s and 6 minutes.
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Libs   = Join-Path $ExtensionRoot 'libs'
$Tess   = Join-Path $Libs 'tessdata'
$Models = Join-Path $Libs 'models'
$Tfjs   = Join-Path $Libs 'transformers'
$Ner    = Join-Path $Models 'ner'
$NerRepo = 'https://huggingface.co/onnx-community/NeuroBERT-NER-ONNX/resolve/main'

if ($Clean -and (Test-Path $Libs)) {
  Write-Host "Wiping $Libs" -ForegroundColor Yellow
  Remove-Item -Recurse -Force $Libs
}
New-Item -ItemType Directory -Force -Path $Libs, $Tess, $Models, $Tfjs, (Join-Path $Ner 'onnx') | Out-Null

# name -> @{ url; path; min (bytes) }
$Assets = @(
  @{ n='tesseract.min.js';           min=40000;
     u="https://unpkg.com/tesseract.js@$TesseractVersion/dist/tesseract.min.js";
     p=(Join-Path $Libs 'tesseract.min.js') }

  @{ n='worker.min.js';              min=10000;
     u="https://unpkg.com/tesseract.js@$TesseractVersion/dist/worker.min.js";
     p=(Join-Path $Libs 'worker.min.js') }

  @{ n='tesseract-core.wasm.js';     min=100000;
     u="https://unpkg.com/tesseract.js-core@$CoreVersion/tesseract-core.wasm.js";
     p=(Join-Path $Libs 'tesseract-core.wasm.js') }

  @{ n='tesseract-core.wasm';        min=2000000;
     u="https://unpkg.com/tesseract.js-core@$CoreVersion/tesseract-core.wasm";
     p=(Join-Path $Libs 'tesseract-core.wasm') }

  # SIMD build: ~2.5x faster where available. Optional but cheap.
  @{ n='tesseract-core-simd.wasm.js'; min=100000; optional=$true;
     u="https://unpkg.com/tesseract.js-core@$CoreVersion/tesseract-core-simd.wasm.js";
     p=(Join-Path $Libs 'tesseract-core-simd.wasm.js') }

  @{ n='tesseract-core-simd.wasm';    min=2000000; optional=$true;
     u="https://unpkg.com/tesseract.js-core@$CoreVersion/tesseract-core-simd.wasm";
     p=(Join-Path $Libs 'tesseract-core-simd.wasm') }

  # tessdata_fast, not tessdata. LSTM-only (~4MB) vs legacy+LSTM (~23MB).
  # tesseract.js v5 only uses the LSTM engine, so the 23MB file is 19MB of
  # dead weight and a much slower worker init.
  @{ n='tessdata/eng.traineddata';   min=1000000;
     u='https://github.com/tesseract-ocr/tessdata_fast/raw/main/eng.traineddata';
     p=(Join-Path $Tess 'eng.traineddata') }

  @{ n='face-api.min.js';            min=100000;
     u='https://unpkg.com/face-api.js@0.22.2/dist/face-api.min.js';
     p=(Join-Path $Libs 'face-api.min.js') }

  @{ n='models/tiny_face_detector_model-weights_manifest.json'; min=100;
     u='https://raw.githubusercontent.com/justadudewhohacks/face-api.js/master/weights/tiny_face_detector_model-weights_manifest.json';
     p=(Join-Path $Models 'tiny_face_detector_model-weights_manifest.json') }

  # tinyFaceDetector has exactly ONE shard. shard2 does not exist — asking for
  # it saves a 404 page to disk, which is what broke face-api with
  # "Failed to fetch".
  @{ n='models/tiny_face_detector_model-shard1'; min=100000;
     u='https://raw.githubusercontent.com/justadudewhohacks/face-api.js/master/weights/tiny_face_detector_model-shard1';
     p=(Join-Path $Models 'tiny_face_detector_model-shard1') }

  # --- on-device NER (optional: without it the veil uses label rules only) ---
  # Transformers.js bundles ONNX Runtime Web; the jsep wasm is the WebGPU+WASM build.
  @{ n='transformers/transformers.min.js'; min=500000; optional=$true;
     u="https://unpkg.com/@huggingface/transformers@$TransformersVersion/dist/transformers.min.js";
     p=(Join-Path $Tfjs 'transformers.min.js') }
  @{ n='transformers/ort-wasm-simd-threaded.jsep.mjs'; min=20000; optional=$true;
     u="https://unpkg.com/@huggingface/transformers@$TransformersVersion/dist/ort-wasm-simd-threaded.jsep.mjs";
     p=(Join-Path $Tfjs 'ort-wasm-simd-threaded.jsep.mjs') }
  @{ n='transformers/ort-wasm-simd-threaded.jsep.wasm'; min=10000000; optional=$true;
     u="https://unpkg.com/@huggingface/transformers@$TransformersVersion/dist/ort-wasm-simd-threaded.jsep.wasm";
     p=(Join-Path $Tfjs 'ort-wasm-simd-threaded.jsep.wasm') }
  @{ n='models/ner/config.json'; min=500; optional=$true;
     u="$NerRepo/config.json"; p=(Join-Path $Ner 'config.json') }
  @{ n='models/ner/tokenizer.json'; min=100000; optional=$true;
     u="$NerRepo/tokenizer.json"; p=(Join-Path $Ner 'tokenizer.json') }
  @{ n='models/ner/tokenizer_config.json'; min=100; optional=$true;
     u="$NerRepo/tokenizer_config.json"; p=(Join-Path $Ner 'tokenizer_config.json') }
  @{ n='models/ner/onnx/model_int8.onnx'; min=5000000; optional=$true;
     u="$NerRepo/onnx/model_int8.onnx"; p=(Join-Path $Ner 'onnx\model_int8.onnx') }
)

function Get-Asset($a) {
  $tmp = "$($a.p).part"
  for ($try = 1; $try -le 3; $try++) {
    try {
      Invoke-WebRequest -Uri $a.u -OutFile $tmp -UseBasicParsing -TimeoutSec 180
      $size = (Get-Item $tmp).Length
      if ($size -lt $a.min) { throw "got $size bytes, expected >= $($a.min)" }
      Move-Item -Force $tmp $a.p
      return @{ ok=$true; size=$size }
    } catch {
      if (Test-Path $tmp) { Remove-Item -Force $tmp }
      if ($try -eq 3) { return @{ ok=$false; err=$_.Exception.Message } }
      Start-Sleep -Seconds (2 * $try)
    }
  }
}

$fail = @()
foreach ($a in $Assets) {
  Write-Host ("{0,-52}" -f $a.n) -NoNewline
  $r = Get-Asset $a
  if ($r.ok) {
    Write-Host ("OK  {0,10:N0} bytes" -f $r.size) -ForegroundColor Green
  } elseif ($a.optional) {
    Write-Host ("SKIP (optional) {0}" -f $r.err) -ForegroundColor DarkYellow
  } else {
    Write-Host ("FAIL {0}" -f $r.err) -ForegroundColor Red
    $fail += $a.n
  }
}

Write-Host ''
Write-Host '--- VERIFY ------------------------------------------------------'
Get-ChildItem -Recurse -File $Libs |
  Select-Object @{n='file';e={$_.FullName.Substring($Libs.Length+1)}},
                @{n='bytes';e={$_.Length}} |
  Sort-Object file | Format-Table -AutoSize

if ($fail.Count) {
  Write-Host "STILL MISSING: $($fail -join ', ')" -ForegroundColor Red
  Write-Host 'If unpkg is blocked, swap the host to https://cdn.jsdelivr.net/npm/ (same paths).' -ForegroundColor Yellow
  exit 1
}

Write-Host 'ALL ASSETS PRESENT.' -ForegroundColor Green
Write-Host 'Next: confirm manifest.json has  "content_security_policy": {' -ForegroundColor Cyan
Write-Host '        "extension_pages": "script-src ''self'' ''wasm-unsafe-eval''; object-src ''self''" }' -ForegroundColor Cyan
Write-Host 'Then reload the extension in chrome://extensions and re-run Preflight.' -ForegroundColor Cyan
