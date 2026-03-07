/* popup.js — Extension side panel UI.
   Shows enable/disable toggle and all findings across all tabs.
   Reads findings directly from IndexedDB (shared with offscreen worker).
   Findings persist until the user clicks the clear button. */

const enableToggle = document.getElementById('enableToggle');
const filterBar = document.getElementById('filterBar');
const findingsEl = document.getElementById('findings');
const emptyEl = document.getElementById('empty');
const actionBar = document.getElementById('actionBar');
const clearBtn = document.getElementById('clearBtn');
const exportBtn = document.getElementById('exportBtn');

let activeFilters = new Set(); // empty = show all
let lastFindings = [];

// ── IndexedDB access (same DB as worker/cache.js) ──
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

async function getAllFindingsFromDB() {
  try {
    const db = await openDB();
    return new Promise((resolve) => {
      const tx = db.transaction(STORE_FINDINGS, 'readonly');
      const store = tx.objectStore(STORE_FINDINGS);
      const req = store.get('all');
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => resolve([]);
    });
  } catch {
    return [];
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

// ── Init ──
async function init() {
  const enabled = await sendMessage({ type: 'getEnabled' });
  enableToggle.checked = enabled !== false;

  loadFindings();
}

enableToggle.addEventListener('change', async () => {
  await sendMessage({ type: 'setEnabled', enabled: enableToggle.checked });
});

clearBtn.addEventListener('click', async () => {
  await clearAllFindingsInDB();
  sendMessage({ type: 'clearFindings' });
  activeFilters.clear();
  renderFindings([]);
});

exportBtn.addEventListener('click', async () => {
  const findings = await getAllFindingsFromDB();
  const blob = new Blob([JSON.stringify(findings || [], null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `webappsec-findings-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
});

async function loadFindings() {
  const findings = await getAllFindingsFromDB();
  renderFindings(findings || []);
}

// ── Finding type metadata ──
const TYPE_META = {
  'XSS': {
    cssClass: 'critical',
    groupLabel: 'Cross-Site Scripting (XSS)',
    remediation: 'Sanitize with DOMPurify.sanitize() or use textContent instead of innerHTML. For navigation sinks, validate the URL scheme is http/https to prevent javascript: URI injection.',
  },
  'Open Redirect': {
    cssClass: 'open-redirect',
    groupLabel: 'Open Redirect',
    remediation: 'Restrict redirects to a known allowlist of URLs, or use relative paths only. Validating the scheme blocks javascript: but still allows redirects to attacker-controlled domains.',
  },
  'Prototype Pollution': {
    cssClass: 'proto-pollution',
    groupLabel: 'Prototype Pollution',
    remediation: 'Avoid using attacker-controlled keys for nested property assignment. Use Object.create(null) for lookup objects or validate keys against a known set.',
  },
  'Script Injection': {
    cssClass: 'critical',
    groupLabel: 'Script Injection',
    remediation: 'Do not use attacker-controlled values to create script elements. If dynamic loading is needed, validate against an allowlist of known script URLs.',
  },
};

function getTypeMeta(type) {
  return TYPE_META[type] || { cssClass: 'high', groupLabel: type, remediation: '' };
}

// Detect weak origin check patterns in source descriptions
function getWeakOriginWarning(finding) {
  const sources = finding.source || [];
  for (const s of sources) {
    const desc = s.description || '';
    if (!desc.includes('weak origin check')) continue;
    // Extract the pattern from the taint flow for specific advice
    const path = (finding.path || []).join(' ');
    if (path.includes('.includes(') || desc.includes('.includes('))
      return 'Origin checked with .includes() — bypassable via substring match (e.g. evil-trusted.com matches "trusted.com").';
    if (path.includes('.indexOf(') || desc.includes('.indexOf('))
      return 'Origin checked with .indexOf() — bypassable via substring match.';
    if (path.includes('.endsWith(') || desc.includes('.endsWith('))
      return 'Origin checked with .endsWith() — bypassable (evil-trusted.com ends with "trusted.com").';
    if (path.includes('.startsWith(') || desc.includes('.startsWith('))
      return 'Origin checked with .startsWith() but not a full origin — scheme check alone does not validate the domain.';
    if (desc.includes('null'))
      return 'Origin compared to "null" — sandboxed iframes have a null origin, making this check bypassable.';
    return 'Weak origin validation detected — the check pattern can be bypassed. Use strict === comparison with a full origin (e.g. "https://trusted.com").';
  }
  return null;
}

function renderFindings(findings) {
  lastFindings = findings;
  findingsEl.innerHTML = '';

  if (findings.length === 0) {
    emptyEl.classList.remove('hidden');
    actionBar.classList.add('hidden');
    filterBar.classList.add('hidden');
    return;
  }

  emptyEl.classList.add('hidden');
  actionBar.classList.remove('hidden');

  // Group all findings by type (for filter bar counts)
  const allGroups = new Map();
  for (const f of findings) {
    const type = f.type || 'Unknown';
    if (!allGroups.has(type)) allGroups.set(type, 0);
    allGroups.set(type, allGroups.get(type) + 1);
  }

  // Build filter bar
  const types = [...allGroups.keys()];
  if (types.length > 1) {
    filterBar.classList.remove('hidden');
    filterBar.innerHTML = '';
    for (const type of types) {
      const pill = document.createElement('button');
      pill.className = 'filter-pill' + (activeFilters.has(type) ? ' active' : '');
      pill.dataset.type = type;
      pill.textContent = `${type} (${allGroups.get(type)})`;
      pill.addEventListener('click', () => {
        if (activeFilters.has(type)) activeFilters.delete(type);
        else activeFilters.add(type);
        renderFindings(lastFindings);
      });
      filterBar.appendChild(pill);
    }
  } else {
    filterBar.classList.add('hidden');
  }

  // Apply filters
  const filtered = activeFilters.size > 0
    ? findings.filter(f => activeFilters.has(f.type || 'Unknown'))
    : findings;

  // Group filtered findings by type
  const groups = new Map();
  for (const f of filtered) {
    const type = f.type || 'Unknown';
    if (!groups.has(type)) groups.set(type, []);
    groups.get(type).push(f);
  }

  // Sort groups: critical types first
  const typeOrder = ['XSS', 'Prototype Pollution', 'Script Injection', 'Open Redirect'];
  const sortedTypes = [...groups.keys()].sort((a, b) => {
    const ai = typeOrder.indexOf(a), bi = typeOrder.indexOf(b);
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
  });

  for (const type of sortedTypes) {
    const items = groups.get(type);
    const meta = getTypeMeta(type);

    const groupEl = document.createElement('div');
    groupEl.className = 'finding-group';

    const header = document.createElement('div');
    header.className = 'finding-group-header';
    header.innerHTML = `
      <span class="finding-group-icon">&#9660;</span>
      <span class="finding-group-label ${meta.cssClass}">${esc(meta.groupLabel)}</span>
      <span class="finding-group-count">(${items.length})</span>
    `;
    header.addEventListener('click', () => groupEl.classList.toggle('collapsed'));
    groupEl.appendChild(header);

    const itemsEl = document.createElement('div');
    itemsEl.className = 'finding-group-items';

    for (const f of items) {
      const cardClass = meta.cssClass;
      const el = document.createElement('div');
      el.className = `finding ${cardClass}`;

      const sources = (f.source || []).map(s =>
        `<span class="finding-source">${esc(s.description || s.type)}</span> ` +
        `<span class="finding-location">${linkUrl(s.file)}:${s.line}</span>`
      ).join('<br>');

      const sinkText = f.sink
        ? `<span class="finding-sink">${esc(f.sink.expression)}</span> ` +
          `<span class="finding-location">${linkUrl(f.sink.file)}:${f.sink.line}</span>`
        : '';

      const pathLines = (f.path || []).map(p =>
        `<span class="path-step"><span class="path-arrow">&#8594;</span> ${esc(p)}</span>`
      ).join('');

      const seenOn = f.seenOn || (f.pageUrl ? [f.pageUrl] : []);
      const seenOnText = seenOn.length > 0
        ? `<div class="finding-origin">Seen on: ${seenOn.map(u => `<span class="finding-origin-url">${linkUrl(u)}</span>`).join(', ')}</div>`
        : '';

      // Weak origin check warning
      const weakWarning = getWeakOriginWarning(f);
      const warningHtml = weakWarning
        ? `<div class="finding-warning"><span class="finding-warning-icon">&#9888;</span><span>${esc(weakWarning)}</span></div>`
        : '';

      el.innerHTML = `
        <div class="finding-header">
          <span class="finding-type ${cardClass}">${esc(f.type)}</span>
          <span class="finding-title">${esc(f.title)}</span>
        </div>
        ${seenOnText}
        ${warningHtml}
        <div class="finding-detail">
          <div><strong>Source:</strong><br>${sources}</div>
          <div class="finding-sink-row"><strong>Sink:</strong><br>${sinkText}</div>
        </div>
        ${pathLines ? `<div class="finding-path">${pathLines}</div>` : ''}
        <button class="copy-btn" title="Copy finding">Copy</button>
      `;
      el.querySelector('.copy-btn').addEventListener('click', () => {
        const text = [
          `[${f.type}] ${f.title}`,
          `Source: ${(f.source || []).map(s => `${s.description || s.type} (${s.file}:${s.line})`).join(', ')}`,
          f.sink ? `Sink: ${f.sink.expression} (${f.sink.file}:${f.sink.line})` : '',
          ...(f.path || []).map(p => `  → ${p}`),
        ].filter(Boolean).join('\n');
        navigator.clipboard.writeText(text);
      });

      itemsEl.appendChild(el);
    }

    // Remediation hint (once per group)
    if (meta.remediation) {
      const remEl = document.createElement('div');
      remEl.className = 'finding-remediation';
      remEl.textContent = meta.remediation;
      itemsEl.appendChild(remEl);
    }

    groupEl.appendChild(itemsEl);
    findingsEl.appendChild(groupEl);
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

// Listen for findings signal from background via storage change
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'session' && changes.findingsSignal) loadFindings();
});

init();
