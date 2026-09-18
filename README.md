# AAVARAN - On-device visual perception for lightweight browser agents

## Project Goal
Enable browser agents to operate on sensitive pages (banking, healthcare, govt) by performing on-device PII redaction before any data leaves the browser.

## Architecture
- **Extension (Client):** Chrome MV3, OffscreenCanvas, Tesseract.js, face-api.js.
- **Server:** FastAPI, VLM (Qwen2.5-VL).
- **Privacy:** Destructive pixel redaction + Reversible Tokenization.

## Setup
1. Load `extension/` into Chrome as an unpacked extension.
2. Run `docker-compose up` to start the server.
3. Open `extension/panel/index.html` to view the Glass Box.
