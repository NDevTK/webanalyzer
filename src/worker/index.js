/* worker/index.js — Web Worker entry point.
   Receives scripts from the offscreen document, parses with Babel,
   builds CFG, runs taint analysis, reports findings. */

import { parse } from '@babel/parser';
import { buildCFG } from './cfg.js';
import { analyzeCFG, TaintEnv, TaintSet, TaintLabel, evaluateExpr, checkPrototypePollution } from './taint.js';
import {
  ModuleGraph, extractImports, extractExports,
  extractGlobalDeclarations, resolveImportTaint, checkPostMessageHandler,
} from './module-graph.js';
import { nodeToString, EVENT_SOURCES } from './sources-sinks.js';
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
        'dynamicImport',
        'optionalChaining',
        'nullishCoalescingOperator',
        'classProperties',
        'classPrivateProperties',
        'classPrivateMethods',
        'decorators-legacy',
        'exportDefaultFrom',
        'exportNamespaceFrom',
        'objectRestSpread',
        'asyncGenerators',
        'optionalCatchBinding',
        'topLevelAwait',
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
  const findings = analyzeAST(ast, script.url, script.isModule, page);

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

// ── Handle HTML (extract event handler attributes) ──
async function handleHTML(tabId, origin, pageUrl, html) {
  const page = moduleGraph.getPage(tabId);
  page.origin = origin;
  page.pageUrl = pageUrl;

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
function analyzeAST(ast, file, isModule, pageCtx) {
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

  // 5. Scan for postMessage handlers and set up taint for event.data
  setupMessageHandlerTaint(ast, env, file);

  // 6. Build CFG for program body
  const cfg = buildCFG(ast.program);

  // 7. Run taint analysis with scope info
  const findings = analyzeCFG(cfg, env, file, funcMap, pageCtx.globalEnv, scopeInfo);

  // 8. Check for prototype pollution patterns
  scanPrototypePollution(ast, env, file, findings, scopeInfo);

  // 9. For non-module scripts, propagate final env back to global
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

// ── Set up taint for message event handlers ──
function setupMessageHandlerTaint(ast, env, file) {
  // Walk AST looking for addEventListener('message', fn) patterns
  walkAST(ast.program, (node) => {
    if (node.type !== 'CallExpression') return;

    const callee = node.callee;
    if (callee.type !== 'MemberExpression') return;
    if (callee.property?.name !== 'addEventListener') return;

    // Skip self.addEventListener('message', ...) — worker receiving from same-origin parent
    const objName = callee.object?.type === 'Identifier' ? callee.object.name : null;
    if (objName === 'self') return;

    const firstArg = node.arguments[0];
    if (!firstArg) return;
    const eventName = firstArg.value;
    if (eventName !== 'message') return;

    const handler = node.arguments[1];
    if (!handler) return;
    if (handler.type !== 'ArrowFunctionExpression' && handler.type !== 'FunctionExpression') return;

    // Check if handler validates origin
    const checksOrigin = containsOriginCheck(handler.body);

    if (!checksOrigin && handler.params[0]) {
      // Mark the event parameter's .data property as tainted
      const paramName = handler.params[0].type === 'Identifier' ? handler.params[0].name : null;
      if (paramName) {
        const loc = handler.loc?.start || {};
        const label = new TaintLabel(
          'postMessage.data', file, loc.line || 0, loc.column || 0,
          `${paramName}.data (no origin check)`
        );
        env.set(`${paramName}.data`, TaintSet.from(label));
        env.set(paramName, TaintSet.from(label));
      }
    }
  });

  // Also handle window.onmessage = function(e) { ... }
  walkAST(ast.program, (node) => {
    if (node.type !== 'AssignmentExpression') return;
    const leftStr = nodeToString(node.left);
    if (leftStr !== 'window.onmessage' && leftStr !== 'onmessage') return;

    const handler = node.right;
    if (handler.type !== 'ArrowFunctionExpression' && handler.type !== 'FunctionExpression') return;

    const checksOrigin = containsOriginCheck(handler.body);

    if (!checksOrigin && handler.params[0]) {
      const paramName = handler.params[0].name;
      if (paramName) {
        const loc = handler.loc?.start || {};
        const label = new TaintLabel(
          'postMessage.data', file, loc.line || 0, loc.column || 0,
          `${paramName}.data (no origin check)`
        );
        env.set(`${paramName}.data`, TaintSet.from(label));
        env.set(paramName, TaintSet.from(label));
      }
    }
  });
}

// ── Scan for prototype pollution ──
function scanPrototypePollution(ast, env, file, findings, scopeInfo) {
  const ctx = { file, funcMap: new Map(), findings, callDepth: 0, maxCallDepth: 0, globalEnv: env, scopeInfo: scopeInfo || null, returnTaint: TaintSet.empty(), analyzedCalls: new Set() };
  walkAST(ast.program, (node) => {
    if (node.type === 'AssignmentExpression') {
      checkPrototypePollution(node, env, ctx);
    }
  });
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
        plugins: ['jsx', 'typescript', 'dynamicImport', 'optionalChaining',
          'nullishCoalescingOperator', 'classProperties', 'decorators-legacy',
          'objectRestSpread', 'topLevelAwait'],
        errorRecovery: true,
      });
    } catch { continue; }

    const imports = page.imports.get(url) || extractImports(ast);
    const importEnv = resolveImportTaint(page, url, imports);

    // Only re-analyze if import taint has changed
    const hasNewTaint = [...importEnv.bindings.values()].some(t => t.tainted);
    if (!hasNewTaint) continue;

    const funcMap = new Map(page.globalFuncMap);
    const env = importEnv;
    setupMessageHandlerTaint(ast, env, url);

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
        plugins: ['jsx', 'typescript', 'dynamicImport', 'optionalChaining',
          'nullishCoalescingOperator', 'classProperties', 'decorators-legacy',
          'objectRestSpread'],
        errorRecovery: true,
        allowReturnOutsideFunction: true,
      });
    } catch { continue; }

    const funcMap = new Map(page.globalFuncMap);
    extractGlobalDeclarations(ast, funcMap, script.url);

    const env = globalEnv.child();
    setupMessageHandlerTaint(ast, env, script.url);

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

function walkAST(node, visitor) {
  if (!node || typeof node !== 'object') return;
  if (node.type) visitor(node);

  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'start' || key === 'end' ||
        key === 'leadingComments' || key === 'trailingComments' ||
        key === 'innerComments' || key === '_closureEnv') continue;

    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (item && typeof item === 'object' && item.type) {
          walkAST(item, visitor);
        }
      }
    } else if (child && typeof child === 'object' && child.type) {
      walkAST(child, visitor);
    }
  }
}

// Check if a node is a MemberExpression accessing .origin by AST structure
function isOriginMemberAccess(node) {
  if (!node) return false;
  if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
    if (!node.computed && node.property?.name === 'origin') return true;
    if (node.computed && node.property?.type === 'StringLiteral' && node.property.value === 'origin') return true;
    if (node.computed && node.property?.type === 'Literal' && node.property.value === 'origin') return true;
  }
  return false;
}

function containsOriginCheck(node) {
  if (!node || typeof node !== 'object') return false;

  if (node.type === 'BinaryExpression' &&
      (node.operator === '===' || node.operator === '==' ||
       node.operator === '!==' || node.operator === '!=')) {
    if (isOriginMemberAccess(node.left) || isOriginMemberAccess(node.right)) {
      return true;
    }
  }

  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'start' || key === 'end') continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (item && typeof item === 'object' && item.type) {
          if (containsOriginCheck(item)) return true;
        }
      }
    } else if (child && typeof child === 'object' && child.type) {
      if (containsOriginCheck(child)) return true;
    }
  }

  return false;
}

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
  self.postMessage({
    type: 'findings',
    tabId,
    findings,
  });
}
