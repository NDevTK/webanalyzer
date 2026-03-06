/* popup.js — Extension popup UI.
   Shows enable/disable toggle and all findings across all tabs.
   Reads findings directly from IndexedDB (shared with the worker).
   Findings persist until the user clicks the clear button. */

const enableToggle = document.getElementById('enableToggle');
const statusEl = document.getElementById('status');
const findingsEl = document.getElementById('findings');
const emptyEl = document.getElementById('empty');
const clearBtn = document.getElementById('clearBtn');

// ── IndexedDB reader (same DB the worker writes to) ──
function openFindingsDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('webappsec-findings', 1);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('findings')) {
        db.createObjectStore('findings');
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function readAllFindingsFromDB() {
  try {
    const db = await openFindingsDB();
    return new Promise((resolve) => {
      const tx = db.transaction('findings', 'readonly');
      const store = tx.objectStore('findings');
      const req = store.getAll();
      req.onsuccess = () => {
        const all = [];
        const seen = new Set();
        for (const record of (req.result || [])) {
          if (!record || !record.findings) continue;
          for (const f of record.findings) {
            // Deduplicate by script URL
            const srcKey = Array.isArray(f.source)
              ? f.source.map(s => `${s.type}:${s.file}`).join('+')
              : `${f.source?.type}:${f.source?.file}`;
            const key = `${f.type}|${srcKey}|${f.sink?.expression}:${f.sink?.file}`;
            if (!seen.has(key)) {
              seen.add(key);
              all.push(f);
            }
          }
        }
        resolve(all);
      };
      req.onerror = () => resolve([]);
    });
  } catch {
    return [];
  }
}

async function clearAllFindingsInDB() {
  try {
    const db = await openFindingsDB();
    return new Promise((resolve) => {
      const tx = db.transaction('findings', 'readwrite');
      tx.objectStore('findings').clear();
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    });
  } catch { /* non-fatal */ }
}

async function init() {
  const enabled = await sendMessage({ type: 'getEnabled' });
  enableToggle.checked = enabled !== false;

  const tabs = await sendMessage({ type: 'getAttachedTabs' });
  const attached = tabs && tabs.length > 0;

  updateStatus(enableToggle.checked, attached);
  loadFindings();
}

enableToggle.addEventListener('change', async () => {
  await sendMessage({ type: 'setEnabled', enabled: enableToggle.checked });
  updateStatus(enableToggle.checked, false);
  if (enableToggle.checked) {
    statusEl.textContent = 'Enabled — will attach on next navigation';
  }
});

clearBtn.addEventListener('click', async () => {
  await clearAllFindingsInDB();
  await sendMessage({ type: 'clearFindings' });
  renderFindings([]);
});

async function loadFindings() {
  const findings = await readAllFindingsFromDB();
  renderFindings(findings || []);
}

function renderFindings(findings) {
  findingsEl.innerHTML = '';

  if (findings.length === 0) {
    emptyEl.classList.remove('hidden');
    clearBtn.classList.add('hidden');
    return;
  }

  emptyEl.classList.add('hidden');
  clearBtn.classList.remove('hidden');

  for (const f of findings) {
    const severity = f.severity === 'critical' ? 'critical' : 'high';
    const el = document.createElement('div');
    el.className = `finding ${severity}`;

    const sources = (f.source || []).map(s =>
      `<span class="finding-source">${esc(s.description || s.type)}</span> ` +
      `<span class="finding-location">${linkUrl(s.file)}:${s.line}</span>`
    ).join('<br>');

    const sinkText = f.sink
      ? `<span class="finding-sink">${esc(f.sink.expression)}</span> ` +
        `<span class="finding-location">${linkUrl(f.sink.file)}:${f.sink.line}</span>`
      : '';

    const pathLines = (f.path || []).map(p => esc(p)).join('\n');

    const seenOn = f.seenOn || (f.pageUrl ? [f.pageUrl] : []);
    const seenOnText = seenOn.length > 0
      ? `<div class="finding-origin">Seen on: ${seenOn.map(u => `<span class="finding-origin-url">${linkUrl(u)}</span>`).join(', ')}</div>`
      : '';

    el.innerHTML = `
      <div class="finding-header">
        <span class="finding-type ${severity}">${esc(f.type)}</span>
        <span class="finding-title">${esc(f.title)}</span>
      </div>
      ${seenOnText}
      <div class="finding-detail">
        <div><strong>Source:</strong><br>${sources}</div>
        <div class="finding-sink-row"><strong>Sink:</strong><br>${sinkText}</div>
      </div>
      ${pathLines ? `<div class="finding-path">${pathLines}</div>` : ''}
    `;
    findingsEl.appendChild(el);
  }
}

function updateStatus(enabled, attached) {
  if (!enabled) {
    statusEl.textContent = 'Disabled';
    statusEl.className = 'status';
  } else if (attached) {
    statusEl.textContent = 'Analyzing scripts...';
    statusEl.className = 'status attached';
  } else {
    statusEl.textContent = 'Enabled — waiting for navigation';
    statusEl.className = 'status';
  }
}

function esc(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = String(str);
  return div.innerHTML;
}

function linkUrl(url) {
  const safe = esc(url);
  if (/^https?:\/\//i.test(url)) {
    return `<a href="${safe}" class="finding-link" target="_blank" rel="noopener">${safe}</a>`;
  }
  return safe;
}

function sendMessage(msg) {
  return new Promise(resolve => {
    chrome.runtime.sendMessage(msg, response => resolve(response));
  });
}

setInterval(loadFindings, 3000);
init();
