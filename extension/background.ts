// background.ts - Service Worker for AAVARAN
// This handles the top-level orchestration: capture -> veil -> reason -> act

async function captureAndVeil() {
  // 1. Create offscreen document for canvas processing
  await chrome.offscreen.createDocument({
    url: 'offscreen.html',
    reasons: ['CANVAS'],
    justification: 'Process screenshots for PII redaction'
  });

  // 2. Capture current tab
  const dataUrl = await chrome.tabs.captureVisibleTab(null, { format: 'png' });
  
  // 3. Send to offscreen for redaction
  const veiledImage = await chrome.runtime.sendMessage({
    target: 'offscreen',
    type: 'REDACT',
    payload: dataUrl
  });

  return veiledImage;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'START_AGENT') {
    captureAndVeil().then(img => {
      console.log('Veiled image ready for server egress');
      sendResponse({ status: 'success', image: img });
    });
    return true;
  }
});
