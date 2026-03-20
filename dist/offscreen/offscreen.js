'use strict';
/* offscreen.js — Relays messages between SW ↔ Worker.
   The worker runs Babel AST taint analysis (heavy CPU, off main thread).
   This document writes findings to IndexedDB for persistence
   (shared with the side panel, which reads from the same DB). */

let worker = null;

// ── IndexedDB (same schema as side panel reads) ──
const DB_NAME = 'webappsec-findings';
const DB_VERSION = 1;
const STORE_FINDINGS = 'findings';
let dbPromise = null;

function openDB() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(STORE_FINDINGS)) {
        db.createObjectStore(STORE_FINDINGS);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return dbPromise;
}

function findingKey(f) {
  const srcKey = Array.isArray(f.source)
    ? f.source.map(s => `${s.type}:${s.file}`).join('+')
    : `${f.source?.type}:${f.source?.file}`;
  return `${f.type}|${srcKey}|${f.sink?.expression}:${f.sink?.file}`;
}

async function storeFindingsInDB(findings) {
  if (!findings || findings.length === 0) return;
  try {
    const db = await openDB();

    // Read all existing findings
    const existing = await new Promise((resolve) => {
      const tx = db.transaction(STORE_FINDINGS, 'readonly');
      const store = tx.objectStore(STORE_FINDINGS);
      const req = store.get('all');
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => resolve([]);
    });

    // Dedup against existing
    const existingKeys = new Set(existing.map(findingKey));
    const novel = [];
    for (const f of findings) {
      // Normalise pageUrl → seenOn array
      if (f.pageUrl) {
        f.seenOn = [f.pageUrl];
        delete f.pageUrl;
      }
      const key = findingKey(f);
      if (!existingKeys.has(key)) {
        existingKeys.add(key);
        novel.push(f);
      } else {
        // Merge pageUrl into existing finding's seenOn
        const ef = existing.find(e => findingKey(e) === key);
        if (ef && f.seenOn && f.seenOn[0] && ef.seenOn && !ef.seenOn.includes(f.seenOn[0])) {
          ef.seenOn.push(f.seenOn[0]);
        }
      }
    }

    if (novel.length === 0) return;

    const merged = existing.concat(novel);
    await new Promise((resolve) => {
      const tx = db.transaction(STORE_FINDINGS, 'readwrite');
      const store = tx.objectStore(STORE_FINDINGS);
      store.put(merged, 'all');
      tx.oncomplete = () => resolve();
      tx.onerror = (e) => {
        console.error('[offscreen] IDB write error:', e.target.error);
        resolve();
      };
    });
  } catch (e) {
    console.error('[offscreen] IDB error:', e);
  }
}

async function clearAllFindingsInDB() {
  try {
    const db = await openDB();
    return new Promise((resolve) => {
      const tx = db.transaction(STORE_FINDINGS, 'readwrite');
      tx.objectStore(STORE_FINDINGS).clear();
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    });
  } catch {
    // Non-fatal
  }
}

function ensureWorker() {
  if (worker) return worker;
  worker = new Worker(chrome.runtime.getURL('worker.bundle.js'));
  worker.onmessage = async (e) => {
    const msg = e.data;
    if (msg.type === 'findings' && msg.findings) {
      // Write to IndexedDB for persistence, then relay to service worker
      await storeFindingsInDB(msg.findings);
    }
    chrome.runtime.sendMessage(msg).catch(() => {});
  };
  worker.onerror = (err) => {
    console.error('[offscreen] Worker error:', err.message);
    worker = null;
  };
  return worker;
}

// Listen for messages from the service worker
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!sender.url?.startsWith(`chrome-extension://${chrome.runtime.id}/`)) return;
  if (msg.type === 'analyzeScript' || msg.type === 'analyzeHTML' || msg.type === 'resetPage' || msg.type === 'domCatalog') {
    const w = ensureWorker();
    w.postMessage(msg);
  } else if (msg.type === 'clearFindings') {
    clearAllFindingsInDB();
    const w = ensureWorker();
    w.postMessage(msg);
  }
});
