/* background.js — MV3 service worker
   Lightweight coordinator: auto-attaches chrome.debugger on tab navigation,
   collects scripts via CDP, relays to offscreen worker, shows notifications.
   Findings are stored in IndexedDB by the worker — this file does NOT use IndexedDB. */

// ── State ──
const attachedTabs = new Map();   // tabId → { origin, scripts: Map<hash,url> }
const tabFindingCounts = new Map(); // tabId → count (for badge, in-memory only)
let offscreenReady = false;
let enabled = true;               // global on/off

// ── Offscreen document lifecycle ──
let offscreenCreating = null;
async function ensureOffscreen() {
  if (offscreenReady) return;
  if (offscreenCreating) return offscreenCreating;
  offscreenCreating = (async () => {
    try {
      const contexts = await chrome.runtime.getContexts({
        contextTypes: ['OFFSCREEN_DOCUMENT'],
      });
      if (contexts.length > 0) { offscreenReady = true; return; }
      await chrome.offscreen.createDocument({
        url: 'offscreen/offscreen.html',
        reasons: ['WORKERS'],
        justification: 'Run Babel AST taint analysis in a web worker',
      });
      offscreenReady = true;
    } finally {
      offscreenCreating = null;
    }
  })();
  return offscreenCreating;
}

// ── Auto-attach: listen for tab navigations ──
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (!enabled) return;
  // Attach when a tab starts loading a real page
  if (changeInfo.status !== 'loading') return;
  if (!tab.url && changeInfo.url === undefined) return;
  const url = tab.url || changeInfo.url || '';
  // Skip only browser-internal pages (not about:blank — it can host injected scripts)
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') ||
      url.startsWith('edge://') || url.startsWith('devtools://') ||
      url.startsWith('about:devtools') || url.startsWith('about:debugging')) return;

  await attachToTab(tabId, url);
});

// Clean up when tab closes
chrome.tabs.onRemoved.addListener((tabId) => {
  detachFromTab(tabId);
});

// ── Message handling (from offscreen / popup) ──
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.origin !== `chrome-extension://${chrome.runtime.id}`) return;
  if (msg.type === 'findings') {
    handleFindings(msg.tabId, msg.findings);
  } else if (msg.type === 'getEnabled') {
    sendResponse(enabled);
  } else if (msg.type === 'setEnabled') {
    enabled = msg.enabled;
    if (!enabled) {
      for (const tabId of [...attachedTabs.keys()]) detachFromTab(tabId);
    }
    persistState();
  } else if (msg.type === 'clearFindings') {
    // IndexedDB is cleared by the side panel and/or offscreen worker.
    // We just reset badge counts here.
    tabFindingCounts.clear();
    for (const tabId of attachedTabs.keys()) updateBadge(tabId);
    sendToOffscreen({ type: 'clearFindings' });
    persistState();
  }
  return true;
});

// ── Attach / Detach debugger ──
async function attachToTab(tabId, url) {
  if (attachedTabs.has(tabId)) {
    // Already attached — tab navigated, reset its state
    const tabState = attachedTabs.get(tabId);
    const newOrigin = safeOrigin(url);
    tabState.origin = newOrigin;
    tabState.pageUrl = url;
    tabState.scripts.clear();
    tabFindingCounts.delete(tabId);
    updateBadge(tabId);
    sendToOffscreen({ type: 'resetPage', tabId, origin: newOrigin });
    return;
  }

  try {
    await chrome.debugger.attach({ tabId }, '1.3');
  } catch (e) {
    // Already attached or can't attach
    return;
  }

  const origin = safeOrigin(url);
  attachedTabs.set(tabId, { origin, pageUrl: url, scripts: new Map() });

  // Enable auto-attach to all frames (iframes, about:blank frames, etc.)
  await chrome.debugger.sendCommand({ tabId }, 'Target.setAutoAttach', {
    autoAttach: true,
    waitForDebuggerOnStart: false,
    flatten: true,
  }).catch(() => {});

  await chrome.debugger.sendCommand({ tabId }, 'Debugger.enable');
  await chrome.debugger.sendCommand({ tabId }, 'Network.enable');
  await chrome.debugger.sendCommand({ tabId }, 'Page.enable');
  await chrome.debugger.sendCommand({ tabId }, 'Runtime.enable').catch(() => {});

  updateBadge(tabId);
  persistState();
}

function detachFromTab(tabId) {
  if (!attachedTabs.has(tabId)) return;
  chrome.debugger.detach({ tabId }).catch(() => {});
  attachedTabs.delete(tabId);
  tabFindingCounts.delete(tabId);
  updateBadge(tabId);
  persistState();
}

function safeOrigin(url) {
  try { return new URL(url).origin; } catch { return ''; }
}

// ── CDP event handler ──
chrome.debugger.onEvent.addListener(async (source, method, params) => {
  const tabId = source.tabId;
  const tabState = attachedTabs.get(tabId);
  if (!tabState) return;

  if (method === 'Debugger.scriptParsed') {
    await handleScriptParsed(tabId, tabState, params);
  } else if (method === 'Network.responseReceived') {
    await handleNetworkResponse(tabId, tabState, params);
  } else if (method === 'Target.attachedToTarget') {
    // New child target (iframe, about:blank frame, worker, etc.)
  }
});

// Debugger detached externally (user closed the banner, etc.)
chrome.debugger.onDetach.addListener((source, reason) => {
  attachedTabs.delete(source.tabId);
});

// ── Script collection ──
async function handleScriptParsed(tabId, tabState, params) {
  const { scriptId, url, isModule, startLine, startColumn } = params;
  // Skip extension scripts only — allow about:blank, data: URIs, blob: URIs, etc.
  if (url && (url.startsWith('chrome-extension://') || url.startsWith('extensions::'))) return;

  let scriptSource;
  try {
    const result = await chrome.debugger.sendCommand(
      { tabId }, 'Debugger.getScriptSource', { scriptId }
    );
    scriptSource = result.scriptSource;
  } catch { return; }

  if (!scriptSource || scriptSource.length < 10) return;

  const hash = await hashString(scriptSource);
  if (tabState.scripts.has(hash)) return;
  tabState.scripts.set(hash, url || `inline-${scriptId}`);

  await ensureOffscreen();
  sendToOffscreen({
    type: 'analyzeScript',
    tabId,
    origin: tabState.origin,
    pageUrl: tabState.pageUrl,
    script: {
      source: scriptSource,
      url: url || `inline:${startLine}:${startColumn}`,
      hash,
      isModule: !!isModule,
    },
  });
}

// ── HTML response handling ──
async function handleNetworkResponse(tabId, tabState, params) {
  const { response } = params;
  if (!response) return;
  const ct = (response.mimeType || response.headers?.['content-type'] || '').toLowerCase();
  if (!ct.includes('html')) return;

  let body;
  try {
    const result = await chrome.debugger.sendCommand(
      { tabId }, 'Network.getResponseBody', { requestId: params.requestId }
    );
    body = result.base64Encoded ? atob(result.body) : result.body;
  } catch { return; }

  if (!body) return;

  const hash = await hashString(body);
  if (tabState.scripts.has('html:' + hash)) return;
  tabState.scripts.set('html:' + hash, response.url);

  await ensureOffscreen();
  sendToOffscreen({
    type: 'analyzeHTML',
    tabId,
    origin: tabState.origin,
    pageUrl: tabState.pageUrl,
    html: { source: body, url: response.url, hash },
  });
}

// ── Findings (from offscreen worker) ──
function handleFindings(tabId, newFindings) {
  if (!newFindings || newFindings.length === 0) return;

  // Update badge count
  const current = tabFindingCounts.get(tabId) || 0;
  tabFindingCounts.set(tabId, current + newFindings.length);
  updateBadge(tabId);
  showNotification(tabId, newFindings.length, newFindings);
  persistState();

  // Signal the side panel to refresh from IndexedDB
  chrome.storage.session.set({ findingsSignal: Date.now() }).catch(() => {});
}

function showNotification(tabId, count, findings) {
  const types = [...new Set(findings.map(f => f.type))].join(', ');
  const notifId = `finding-${tabId}-${Date.now()}`;
  chrome.notifications.create(notifId, {
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: `WebAppSec: ${count} new finding${count > 1 ? 's' : ''}`,
    message: `${types} detected. Click to view details.`,
    priority: 2,
  });
}

function updateBadge(tabId) {
  const count = tabFindingCounts.get(tabId) || 0;
  const text = count > 0 ? String(count) : '';
  const color = count > 0 ? '#e53e3e' : '#4a5568';
  chrome.action.setBadgeText({ text, tabId }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ color, tabId }).catch(() => {});
}

// ── Notification click → open side panel ──
chrome.notifications.onClicked.addListener((notifId) => {
  chrome.notifications.clear(notifId);
  chrome.sidePanel.open({ windowId: chrome.windows.WINDOW_ID_CURRENT });
});

// ── Helpers ──
function sendToOffscreen(msg) {
  chrome.runtime.sendMessage(msg).catch(() => {
    offscreenReady = false;
    ensureOffscreen().then(() => chrome.runtime.sendMessage(msg).catch(() => {}));
  });
}

async function hashString(str) {
  const data = new TextEncoder().encode(str);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function persistState() {
  const counts = {};
  for (const [tabId, count] of tabFindingCounts) counts[tabId] = count;
  await chrome.storage.session.set({ findingCounts: counts, enabled });
}

async function restoreState() {
  const data = await chrome.storage.session.get(['findingCounts', 'enabled']);
  if (data.findingCounts) {
    for (const [tabId, count] of Object.entries(data.findingCounts))
      tabFindingCounts.set(Number(tabId), count);
  }
  if (data.enabled !== undefined) enabled = data.enabled;
}

// ── Side panel: open on action click ──
chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });

// ── Startup ──
restoreState();
