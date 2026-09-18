// content.ts - DOM interaction and action execution
// This script runs in the context of the web page

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'EXECUTE_ACTION') {
    const { action, target, value } = message.payload;
    
    if (action === 'CLICK') {
      const el = document.elementFromPoint(target.x, target.y);
      el?.click();
    } else if (action === 'TYPE') {
      const el = document.elementFromPoint(target.x, target.y) as HTMLInputElement;
      if (el) el.value = value;
    }
    
    sendResponse({ status: 'executed' });
  }
});
