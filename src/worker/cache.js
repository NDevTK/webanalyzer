/* cache.js — IndexedDB-backed findings store.
   Persists and deduplicates taint analysis findings per tab/origin.
   Always runs analysis (so dynamic scripts participate in cross-file logic),
   but deduplicates findings before storing/reporting.
   IndexedDB is available in Web Workers and persists across sessions. */

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

// Build a dedup key for a single finding — deduplicate by script URL
function findingKey(f) {
  const srcKey = Array.isArray(f.source)
    ? f.source.map(s => `${s.type}:${s.file}`).join('+')
    : `${f.source?.type}:${f.source?.file}`;
  return `${f.type}|${srcKey}|${f.sink?.expression}:${f.sink?.file}`;
}

// Get all stored findings for a tab
export async function getStoredFindings(tabId) {
  try {
    const db = await openDB();
    return new Promise((resolve) => {
      const tx = db.transaction(STORE_FINDINGS, 'readonly');
      const store = tx.objectStore(STORE_FINDINGS);
      const req = store.get(String(tabId));
      req.onsuccess = () => {
        const record = req.result;
        resolve(record ? record.findings : []);
      };
      req.onerror = () => resolve([]);
    });
  } catch {
    return [];
  }
}

// Add new findings for a tab, deduplicating against what's already stored.
// Returns only the genuinely new findings (not previously stored).
export async function addFindings(tabId, newFindings) {
  if (!newFindings || newFindings.length === 0) return [];

  try {
    const db = await openDB();
    const key = String(tabId);

    // Read existing
    const existing = await new Promise((resolve) => {
      const tx = db.transaction(STORE_FINDINGS, 'readonly');
      const store = tx.objectStore(STORE_FINDINGS);
      const req = store.get(key);
      req.onsuccess = () => resolve(req.result ? req.result.findings : []);
      req.onerror = () => resolve([]);
    });

    // Build map of existing keys → finding index for URL merging
    const keyToIdx = new Map();
    for (let i = 0; i < existing.length; i++) {
      keyToIdx.set(findingKey(existing[i]), i);
    }

    // Filter to only genuinely new findings; merge page URLs for duplicates
    const novel = [];
    let urlsUpdated = false;
    for (const f of newFindings) {
      const fk = findingKey(f);
      const existIdx = keyToIdx.get(fk);
      if (existIdx !== undefined) {
        // Duplicate — merge page URL into existing finding's seenOn list
        const ef = existing[existIdx];
        if (f.pageUrl && ef.seenOn && !ef.seenOn.includes(f.pageUrl)) {
          ef.seenOn.push(f.pageUrl);
          urlsUpdated = true;
        }
      } else {
        // Normalise pageUrl → seenOn array
        if (f.pageUrl) {
          f.seenOn = [f.pageUrl];
          delete f.pageUrl;
        }
        keyToIdx.set(fk, existing.length + novel.length);
        novel.push(f);
      }
    }

    if (novel.length === 0 && !urlsUpdated) return [];

    // Write back merged list
    const merged = existing.concat(novel);
    await new Promise((resolve) => {
      const tx = db.transaction(STORE_FINDINGS, 'readwrite');
      const store = tx.objectStore(STORE_FINDINGS);
      store.put({ findings: merged, timestamp: Date.now() }, key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    });

    return novel;
  } catch {
    // IndexedDB failure is non-fatal — return all as new
    return newFindings;
  }
}

// Clear findings for a tab (on navigation / page reset)
export async function clearFindings(tabId) {
  try {
    const db = await openDB();
    return new Promise((resolve) => {
      const tx = db.transaction(STORE_FINDINGS, 'readwrite');
      const store = tx.objectStore(STORE_FINDINGS);
      store.delete(String(tabId));
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    });
  } catch {
    // Non-fatal
  }
}

// Clear all findings (full reset)
export async function clearAllFindings() {
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
