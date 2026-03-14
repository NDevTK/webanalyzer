# WebAppSec Taint Analyzer

A Chrome extension (MV3) that performs real-time, AST-based taint analysis on web applications. It intercepts JavaScript as pages load, parses it with Babel, builds control flow graphs, and traces attacker-controlled data from sources to dangerous sinks — detecting XSS, prototype pollution, open redirects, DOM clobbering, and other client-side vulnerabilities.

<img src="Screenshot.png" />

## How It Works

1. **Script interception** — The background service worker attaches Chrome DevTools Protocol (CDP) via `chrome.debugger` to collect every script loaded by a page, including inline scripts, dynamically injected scripts, and ES modules.

2. **DOM catalog** — On `Page.loadEventFired`, the extension queries `DOM.getFlattenedDocument` to build a catalog of all HTML elements with their IDs and tag names. This enables element-type-aware sink detection (e.g. knowing that `frame.src` targets an `<iframe>`) and DOM clobbering detection. A lightweight HTML regex extraction provides an immediate fallback before the live DOM is available.

3. **AST parsing** — Scripts are sent to a web worker (via an offscreen document) where Babel parses them into ASTs. This works on both formatted and minified code since the parser operates on syntax structure, not formatting.

4. **Control flow graph** — A CFG is built from each AST, with basic blocks connected by edges for branches, loops, try/catch, and short-circuit evaluation.

5. **Taint analysis** — A worklist algorithm iterates over the CFG to a fixpoint, tracking data flow from sources (e.g. `location.hash`, `document.cookie`, `postMessage` data) through assignments, function calls, and object properties to sinks (e.g. `innerHTML`, `eval`, `document.write`). It supports:
   - Interprocedural analysis (function calls, closures, factories, class methods, prototype chains)
   - Cross-file analysis (shared globals, ES module imports/exports)
   - Object property and `this.*` binding propagation
   - Array method callbacks (`forEach`, `map`, `reduce`, etc.)
   - Sanitizer recognition (DOMPurify, encodeURIComponent, etc.)
   - Element-type-aware sinks (script.src vs img.src, a.href vs div.href)
   - DOM attachment tracking (appendChild, append, insertBefore, querySelector results)

6. **Reporting** — Findings appear as badge counts and browser notifications, with full details in the side panel including source/sink locations, taint flow paths, and remediation advice. Findings persist in IndexedDB across browser restarts.

7. **Proof of Concept generation** — Each finding includes an auto-generated PoC derived from the actual data flow. The engine records every transform applied to tainted data (e.g. `slice`, `split`, `JSON.parse`, property access) and reverses them to compute the exact input needed to trigger the vulnerability. PoCs include:
   - The specific source delivery mechanism (URL with the exact query parameter name, `localStorage.setItem` with the actual key, `postMessage` with the exact data shape)
   - The payload appropriate for the sink type (`<img onerror>` for `innerHTML`, `javascript:` for navigation sinks, `alert(1)` for `eval`)
   - Multi-step vectors for stateful patterns (handler→timer→sink chains, conditional branches)
   - Data flow steps showing each transform in the chain

## Architecture

```
Background (Service Worker) → chrome.debugger CDP events
    ↓ chrome.runtime.sendMessage
Offscreen Document (offscreen.js) → message relay + IndexedDB persistence
    ↓ worker.postMessage
Web Worker (worker/index.js) → Babel parse + taint analysis
    ↓ self.postMessage
Offscreen → Background → Badge + Side Panel signal
```

### Message Types
- `analyzeScript` — JS source from `Debugger.scriptParsed`
- `analyzeHTML` — HTML from `Network.getResponseBody`
- `domCatalog` — element type catalog from `DOM.getFlattenedDocument`
- `resetPage` — tab navigation reset
- `clearFindings` — user clear action

## Project Structure

```
src/
  manifest.json          # Chrome MV3 manifest
  background.js          # Service worker — CDP attach, script/DOM collection, notifications
  popup/                 # Side panel UI (findings viewer, toggle, export)
    popup.html
    popup.js
    popup.css
  offscreen/             # Offscreen document (hosts the web worker, persists findings to IndexedDB)
    offscreen.html
    offscreen.js
  worker/                # Taint analysis engine (runs in web worker)
    index.js             # Worker entry — message handler, orchestration, HTML catalog extraction
    taint.js             # Core taint engine — CFG worklist, expression evaluation, sink detection
    cfg.js               # Control flow graph builder
    sources-sinks.js     # Source/sink/sanitizer definitions
    module-graph.js      # Cross-file analysis, import/export resolution, page context
    scope.js             # Scope analysis for variable resolution
  icons/
test/
  test.mjs               # Test suite (~3950 tests)
  harness.mjs            # Test harness wrapping the analysis engine
  libs/                  # Minified production libraries for false-positive baseline
  bundles/               # Large bundled scripts for performance testing
```

## Vulnerability Detection

| Category | Description | Examples |
|---|---|---|
| **XSS** | Tainted data in HTML/script execution contexts | `innerHTML`, `outerHTML`, `document.write`, `eval`, `Function()`, `setTimeout(string)`, `script.src`, `script.textContent` |
| **Open Redirect** | Tainted data in navigation with safe scheme prefix | `location.href = "https://..." + tainted`, `window.open(safePrefix + tainted)` |
| **Prototype Pollution** | Attacker-controlled keys/values on object prototypes | `obj[key][key2] = value`, `Object.defineProperty(obj, taintedKey, ...)`, `obj.__proto__ = tainted` |
| **DOM Clobbering** | Bare identifiers shadowed by named HTML elements | `location.href = configUrl` where `<a id="configUrl">` exists in DOM |
| **CSS Injection** | Tainted data in style properties | `element.style.cssText = tainted` |
| **postMessage** | Missing origin checks on message event handlers | `addEventListener('message', handler)` without `event.origin` validation |

## Taint Sources

- **URL components**: `location.hash`, `location.search`, `location.href`, `location.pathname`, `location.host`
- **Document properties**: `document.URL`, `document.documentURI`, `document.referrer`, `document.cookie`, `document.baseURI`
- **Storage**: `localStorage.getItem()`, `sessionStorage.getItem()`
- **URL APIs**: `new URL()`, `URLSearchParams.get()`, `URLSearchParams.getAll()`
- **Window**: `window.name`
- **Events**: `postMessage` data (`event.data`), `hashchange` events (`event.newURL`)
- **DOM elements**: bare identifiers matching HTML element IDs (DOM clobbering source)

## Element-Type-Aware Sinks

The engine tracks element types through `createElement`, DOM queries, and the DOM catalog to classify property assignments by security impact:

| Element | `.src` | `.href` | `.textContent` |
|---|---|---|---|
| `<script>` | XSS (loads JS) | — | XSS (inline JS) |
| `<iframe>` | XSS / Open Redirect | — | — |
| `<embed>`, `<object>` | XSS / Open Redirect | — | — |
| `<a>`, `<area>` | — | XSS / Open Redirect | — |
| `<img>`, `<video>`, `<audio>` | Safe | — | — |

Navigation sinks (`.src` on iframe/embed, `.href` on anchors) are classified as XSS when `javascript:` URIs are possible, or downgraded to Open Redirect when the value has a safe scheme prefix like `https://`.

## DOM Catalog

Two sources feed element type information to the taint engine:

1. **HTML parsing** — Regex extraction of `<tag id="x">` from raw HTML response bodies. Available immediately when HTML arrives via `Network.getResponseBody`.

2. **Debugger API** — `DOM.getFlattenedDocument` after `Page.loadEventFired`. Provides the accurate live DOM including elements added by JavaScript.

The catalog maps element IDs to tag names, enabling:
- **Type-aware sink detection**: `document.getElementById('frame').src = tainted` only flags if `#frame` is an iframe/embed, not an img
- **DOM clobbering detection**: bare identifiers matching element IDs without JS declarations are treated as attacker-controllable
- **Clobber path tracking**: `<form id="x"><input name="y">` → `x.y` resolves to an input element

## Building

```bash
npm install
npm run build
```

The build (via esbuild) outputs to `dist/`. Load `dist/` as an unpacked extension in Chrome.

## Testing

```bash
node test/test.mjs
```

The test suite (~3950 tests) includes:
- **Positive detections** — vulnerable code patterns that must be flagged
- **Negative/safe patterns** — sanitized or safe code that must not produce false positives
- **Function tracing** — interprocedural analysis: closures, factories, callbacks, aliases, class methods, prototype chains, event emitters
- **PoC accuracy** — verifying that generated PoCs use exact parameter names, storage keys, postMessage data shapes, correct payloads per sink type, and proper transform reversal
- **Multi-step PoCs** — stateful patterns with handler→timer→sink chains and conditional branches
- **Minified code** — taint detection on compressed/minified JavaScript
- **DOM catalog** — element-type-aware sink detection, DOM clobbering vulnerability detection
- **Baseline libraries** — jQuery, Lodash, React, Vue, Angular minified builds scanned for zero false positives

## Dependencies

- **@babel/parser** — JavaScript/TypeScript parsing to AST
- **@babel/traverse** — AST traversal utilities
- **esbuild** — Build/bundling (dev only)
