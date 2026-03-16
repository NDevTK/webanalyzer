/* worker/index.js — Web Worker entry point.
   Receives scripts from the offscreen document, parses with Babel,
   builds CFG, runs taint analysis, reports findings. */

import { parse } from '@babel/parser';
import { buildCFG } from './cfg.js';
import { analyzeCFG, TaintEnv, generatePoC } from './taint.js';
import {
  ModuleGraph, extractImports, extractExports,
  extractGlobalDeclarations, resolveImportTaint, checkPostMessageHandler,
} from './module-graph.js';
import { buildScopeInfo } from './scope.js';
const moduleGraph = new ModuleGraph();

// In-memory dedup set (worker doesn't persist — IndexedDB writes happen in offscreen.js)
const seenFindingKeys = new Set();

// Debounce timers for cross-file analysis per tab
const debounceTimers = new Map();
const DEBOUNCE_MS = 2000;

function findingKey(f) {
  const srcKey = Array.isArray(f.source)
    ? f.source.map(s => `${s.type}:${s.file}`).join('+')
    : `${f.source?.type}:${f.source?.file}`;
  return `${f.type}|${srcKey}|${f.sink?.expression}:${f.sink?.file}`;
}

// ── Message handler ──
self.onmessage = function (e) {
  const msg = e.data;

  switch (msg.type) {
    case 'analyzeScript':
      handleScript(msg.tabId, msg.origin, msg.pageUrl, msg.script);
      break;

    case 'analyzeHTML':
      handleHTML(msg.tabId, msg.origin, msg.pageUrl, msg.html);
      break;

    case 'domCatalog':
      handleDOMCatalog(msg.tabId, msg.origin, msg.pageUrl, msg.catalog);
      break;

    case 'resetPage':
      moduleGraph.resetPage(msg.tabId);
      break;

    case 'clearFindings':
      seenFindingKeys.clear();
      break;
  }
};

// ── Handle a JavaScript file ──
async function handleScript(tabId, origin, pageUrl, script) {
  const page = moduleGraph.getPage(tabId);
  page.origin = origin;
  page.pageUrl = pageUrl;

  // Add to page context (deduplicates by hash)
  if (!page.addScript(script)) return;

  // Parse with Babel
  let ast;
  try {
    ast = parse(script.source, {
      sourceType: script.isModule ? 'module' : 'script',
      plugins: [
        'jsx',
        'typescript',
        'decorators-legacy',
        'exportDefaultFrom',
      ],
      errorRecovery: true,
      allowReturnOutsideFunction: true,
      allowSuperOutsideMethod: true,
    });
  } catch (err) {
    // Parse failed — skip this script
    return;
  }

  // Always run analysis (dynamic scripts need cross-file participation)
  const findings = analyzeAST(ast, script.url, script.isModule, page, script.isWorker);

  // Stamp page URL on each finding so the UI can show where the script was used
  for (const f of findings) f.pageUrl = pageUrl;

  // Deduplicate in memory and report genuinely new findings
  if (findings.length > 0) {
    const novel = findings.filter(f => {
      const key = findingKey(f);
      if (seenFindingKeys.has(key)) return false;
      seenFindingKeys.add(key);
      return true;
    });
    if (novel.length > 0) {
      postFindings(tabId, novel);
    }
  }

  // Schedule cross-file analysis
  scheduleCrossFileAnalysis(tabId);
}

// ── Handle DOM catalog from Debugger API ──
function handleDOMCatalog(tabId, origin, pageUrl, catalog) {
  const page = moduleGraph.getPage(tabId);
  page.origin = origin;
  page.pageUrl = pageUrl;
  // Convert elements array back to Map (serialized as array of [id, tag] pairs)
  if (catalog && catalog.elements) {
    if (Array.isArray(catalog.elements)) {
      catalog.elements = new Map(catalog.elements);
    } else if (!(catalog.elements instanceof Map)) {
      catalog.elements = new Map(Object.entries(catalog.elements));
    }
  }
  page.domCatalog = catalog;
}

// ── Handle HTML (extract event handler attributes) ──
async function handleHTML(tabId, origin, pageUrl, html) {
  const page = moduleGraph.getPage(tabId);
  page.origin = origin;
  page.pageUrl = pageUrl;

  // Build DOM catalog from HTML source (element IDs → tag names)
  // This provides element type resolution before the Debugger API catalog arrives
  if (!page.domCatalog) {
    const catalog = extractDOMCatalogFromHTML(html.source);
    if (catalog) page.domCatalog = catalog;
  }

  // Extract inline event handlers from HTML attributes
  // We parse HTML manually to find on* attributes and javascript: URLs
  const handlers = extractEventHandlers(html.source, html.url);

  const allFindings = [];
  for (const handler of handlers) {
    let ast;
    try {
      ast = parse(handler.code, {
        sourceType: 'script',
        errorRecovery: true,
        allowReturnOutsideFunction: true,
      });
    } catch { continue; }

    const findings = analyzeAST(ast, `${html.url}:${handler.attr}:L${handler.line}`, false, page);
    for (const f of findings) f.pageUrl = pageUrl;
    allFindings.push(...findings);
  }

  if (allFindings.length > 0) {
    const novel = allFindings.filter(f => {
      const key = findingKey(f);
      if (seenFindingKeys.has(key)) return false;
      seenFindingKeys.add(key);
      return true;
    });
    if (novel.length > 0) {
      postFindings(tabId, novel);
    }
  }
}

// ── Core AST analysis for a single file ──
function analyzeAST(ast, file, isModule, pageCtx, isWorker) {
  // 1. Build scope info via @babel/traverse for accurate binding resolution
  let scopeInfo = null;
  try {
    scopeInfo = buildScopeInfo(ast);
  } catch (e) {
    // Scope building may fail on partial/malformed ASTs; proceed without it
  }

  // 2. Extract function declarations for interprocedural analysis
  const funcMap = new Map(pageCtx.globalFuncMap);
  extractGlobalDeclarations(ast, funcMap, file);

  for (const [name, node] of funcMap) {
    pageCtx.globalFuncMap.set(name, node);
  }

  // 3. For modules: extract imports/exports
  let importEnv = new TaintEnv();
  if (isModule) {
    const imports = extractImports(ast);
    const exports = extractExports(ast);
    pageCtx.imports.set(file, imports);
    importEnv = resolveImportTaint(pageCtx, file, imports);
  }

  // 4. Build initial taint environment
  const env = isModule ? importEnv : pageCtx.globalEnv.child();

  // 5. Build CFG for program body
  const cfg = buildCFG(ast.program);

  // 6. Run taint analysis with scope info (isWorker suppresses message handler taint)
  // checkPrototypePollution is called inline during CFG analysis (taint.js:1178)
  const findings = analyzeCFG(cfg, env, file, funcMap, pageCtx.globalEnv, scopeInfo, isWorker, pageCtx.domCatalog);

  // 7. For non-module scripts, propagate final env back to global
  if (!isModule) {
    pageCtx.globalEnv.replaceFrom(env);
  }

  // 9b. Propagate newly discovered functions (e.g. from factory calls) back to globalFuncMap
  for (const [name, node] of funcMap) {
    pageCtx.globalFuncMap.set(name, node);
  }

  // 10. For modules, store export taint
  if (isModule) {
    storeExportTaint(ast, env, file, pageCtx);
  }

  return findings;
}



// ── Store module export taint for cross-file resolution ──
function storeExportTaint(ast, env, file, pageCtx) {
  const exportInfo = extractExports(ast);
  const exportTaints = new Map();

  for (const exp of exportInfo) {
    const taint = env.get(exp.local);
    exportTaints.set(exp.exported, taint.clone());
  }

  pageCtx.exports.set(file, exportTaints);
}

// ── Cross-file analysis ──
function scheduleCrossFileAnalysis(tabId) {
  if (debounceTimers.has(tabId)) {
    clearTimeout(debounceTimers.get(tabId));
  }

  debounceTimers.set(tabId, setTimeout(() => {
    debounceTimers.delete(tabId);
    runCrossFileAnalysis(tabId);
  }, DEBOUNCE_MS));
}

async function runCrossFileAnalysis(tabId) {
  const page = moduleGraph.getPage(tabId);
  const findings = [];

  // Re-analyze modules with now-complete import/export graph
  for (const [url, mod] of page.modules) {
    if (!mod.source) continue;

    let ast;
    try {
      ast = parse(mod.source, {
        sourceType: 'module',
        plugins: ['jsx', 'typescript', 'decorators-legacy', 'exportDefaultFrom'],
        errorRecovery: true,
      });
    } catch { continue; }

    const imports = page.imports.get(url) || extractImports(ast);
    const importEnv = resolveImportTaint(page, url, imports);

    // Only re-analyze if import taint has changed
    let hasNewTaint = false;
    for (const [, t] of importEnv.entries()) { if (t.tainted) { hasNewTaint = true; break; } }
    if (!hasNewTaint) continue;

    const funcMap = new Map(page.globalFuncMap);
    const env = importEnv;

    let scopeInfo = null;
    try { scopeInfo = buildScopeInfo(ast); } catch {}

    const cfg = buildCFG(ast.program);
    const modFindings = analyzeCFG(cfg, env, url, funcMap, page.globalEnv, scopeInfo);
    for (const f of modFindings) f.pageUrl = page.pageUrl;
    findings.push(...modFindings);

    // Update exports with new taint
    storeExportTaint(ast, env, url, page);
  }

  // Re-analyze non-module scripts in order with accumulated global env
  // (This catches cases where script A defines a tainted global, script B uses it)
  const globalEnv = new TaintEnv();
  for (const script of page.scriptOrder) {
    if (!script.source) continue;

    let ast;
    try {
      ast = parse(script.source, {
        sourceType: 'script',
        plugins: ['jsx', 'typescript', 'decorators-legacy', 'exportDefaultFrom'],
        errorRecovery: true,
        allowReturnOutsideFunction: true,
      });
    } catch { continue; }

    const funcMap = new Map(page.globalFuncMap);
    extractGlobalDeclarations(ast, funcMap, script.url);

    const env = globalEnv.child();

    let scopeInfo = null;
    try { scopeInfo = buildScopeInfo(ast); } catch {}

    const cfg = buildCFG(ast.program);
    const scriptFindings = analyzeCFG(cfg, env, script.url, funcMap, globalEnv, scopeInfo);
    for (const f of scriptFindings) f.pageUrl = page.pageUrl;
    findings.push(...scriptFindings);

    globalEnv.replaceFrom(env);
  }

  if (findings.length > 0) {
    const deduped = deduplicateFindings(findings);
    const novel = deduped.filter(f => {
      const key = findingKey(f);
      if (seenFindingKeys.has(key)) return false;
      seenFindingKeys.add(key);
      return true;
    });
    if (novel.length > 0) {
      postFindings(tabId, novel);
    }
  }
}

// ── Extract DOM catalog (element IDs → tag names) from HTML source ──
function extractDOMCatalogFromHTML(html) {
  const elements = new Map();
  // Match opening tags with id attributes: <tagname ... id="value" ...>
  const tagRe = /<([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)>/g;
  let m;
  while ((m = tagRe.exec(html)) !== null) {
    const tag = m[1].toLowerCase();
    const attrs = m[2];
    // Extract id attribute value
    const idMatch = attrs.match(/\bid\s*=\s*(?:"([^"]*)"|'([^']*)'|(\S+))/i);
    if (idMatch) {
      const id = idMatch[1] ?? idMatch[2] ?? idMatch[3];
      if (id) elements.set(id, tag);
    }
  }
  if (elements.size === 0) return null;
  return { elements };
}

// ── Extract inline event handlers from HTML ──
function extractEventHandlers(html, url) {
  const handlers = [];
  const eventAttrs = [
    'onclick', 'onerror', 'onload', 'onmouseover', 'onmouseout',
    'onfocus', 'onblur', 'onsubmit', 'onchange', 'oninput',
    'onkeydown', 'onkeyup', 'onkeypress', 'onscroll', 'onresize',
  ];

  // Simple HTML attribute extraction (not regex-based pattern matching for vulns;
  // this is just DOM structure parsing to extract JS code for AST analysis)
  let lineNum = 1;
  let pos = 0;

  while (pos < html.length) {
    // Find next tag opening
    const tagStart = html.indexOf('<', pos);
    if (tagStart === -1) break;

    // Count newlines up to here
    for (let i = pos; i < tagStart; i++) {
      if (html[i] === '\n') lineNum++;
    }

    const tagEnd = html.indexOf('>', tagStart);
    if (tagEnd === -1) break;

    const tagContent = html.substring(tagStart, tagEnd + 1);

    // Look for event handler attributes in this tag
    for (const attr of eventAttrs) {
      const attrPatterns = [`${attr}="`, `${attr}='`, `${attr}=`];
      for (const pattern of attrPatterns) {
        const idx = tagContent.toLowerCase().indexOf(pattern);
        if (idx === -1) continue;

        const quote = pattern.endsWith('"') ? '"' : pattern.endsWith("'") ? "'" : null;
        const codeStart = idx + pattern.length;
        let codeEnd;

        if (quote) {
          codeEnd = tagContent.indexOf(quote, codeStart);
        } else {
          // Unquoted: ends at space or >
          codeEnd = tagContent.length - 1;
          for (let i = codeStart; i < tagContent.length; i++) {
            if (tagContent[i] === ' ' || tagContent[i] === '>' || tagContent[i] === '/') {
              codeEnd = i;
              break;
            }
          }
        }

        if (codeEnd > codeStart) {
          let code = tagContent.substring(codeStart, codeEnd);
          // Decode HTML entities
          code = decodeHTMLEntities(code);
          handlers.push({ code, attr, line: lineNum, url });
        }
      }
    }

    // Also check for javascript: URLs in href/src/action
    const jsUrlAttrs = ['href', 'src', 'action', 'formaction'];
    for (const attr of jsUrlAttrs) {
      const patterns = [`${attr}="javascript:`, `${attr}='javascript:`];
      for (const pattern of patterns) {
        const idx = tagContent.toLowerCase().indexOf(pattern);
        if (idx === -1) continue;

        const quote = pattern.includes('"') ? '"' : "'";
        const codeStart = idx + pattern.length;
        const codeEnd = tagContent.indexOf(quote, codeStart);
        if (codeEnd > codeStart) {
          let code = tagContent.substring(codeStart, codeEnd);
          code = decodeHTMLEntities(code);
          handlers.push({ code, attr: `${attr}=javascript:`, line: lineNum, url });
        }
      }
    }

    pos = tagEnd + 1;
  }

  return handlers;
}

function decodeHTMLEntities(str) {
  return str
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#x27;/g, "'")
    .replace(/&#x2F;/g, '/')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(parseInt(n, 10)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, n) => String.fromCharCode(parseInt(n, 16)));
}

// ── Utilities ──

function deduplicateFindings(findings) {
  const seen = new Set();
  return findings.filter(f => {
    const key = `${f.type}:${f.sink.file}:${f.sink.line}:${f.source.map(s => `${s.file}:${s.line}`).join(',')}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function postFindings(tabId, findings) {
  for (const f of findings) {
    if (!f.poc) f.poc = generatePoC(f);
  }
  self.postMessage({
    type: 'findings',
    tabId,
    findings,
  });
}
