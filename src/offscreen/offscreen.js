/* offscreen.js — Relays messages between SW ↔ Worker.
   The worker runs Babel AST taint analysis (heavy CPU, off main thread). */

let worker = null;

function ensureWorker() {
  if (worker) return worker;
  worker = new Worker(chrome.runtime.getURL('worker.bundle.js'));
  worker.onmessage = (e) => {
    // Worker sends findings back → relay to service worker
    chrome.runtime.sendMessage(e.data).catch(() => {});
  };
  worker.onerror = (err) => {
    console.error('[offscreen] Worker error:', err.message);
    worker = null; // will be recreated on next message
  };
  return worker;
}

// Listen for messages from the service worker
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'analyzeScript' || msg.type === 'analyzeHTML' || msg.type === 'resetPage' || msg.type === 'clearFindings') {
    const w = ensureWorker();
    w.postMessage(msg);
  }
  // Don't return true — we don't send async responses from here
});
