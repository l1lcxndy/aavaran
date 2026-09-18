// offscreen.ts - The Redaction Engine
// This is where the "Veil" happens: OCR + Face Det + Redaction

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.target === 'offscreen' && message.type === 'REDACT') {
    processImage(message.payload).then(result => sendResponse(result));
    return true;
  }
});

async function processImage(dataUrl) {
  const canvas = document.getElementById('veilCanvas');
  const ctx = canvas.getContext('2d');
  const img = new Image();
  
  await new Promise(resolve => {
    img.onload = resolve;
    img.src = dataUrl;
  });

  canvas.width = img.width;
  canvas.height = img.height;
  ctx.drawImage(img, 0, 0);

  // TODO: Integrate Tesseract.js and face-api.js here
  // Mock redaction for scaffold:
  ctx.fillStyle = 'black';
  ctx.fillRect(100, 100, 200, 50); // Mock PII box

  return canvas.toDataURL('image/png');
}
