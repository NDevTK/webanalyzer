#!/usr/bin/env node
/**
 * C++ taint analysis for Chromium Blink renderer.
 *
 * Uses clang's typed AST (via -ast-dump=json) to trace data flow from
 * V8 binding entry points (property setters) to security-sensitive terminals
 * (Navigate, ExecuteScript, HTML parsing).
 *
 * Pipeline:
 * 1. For each Blink .cc file, extract method definitions + call graph via clang AST
 * 2. Build cross-file call graph with parameter flow tracking
 * 3. Starting from IDL-identified property setters, trace taint through parameters
 * 4. Output which property setters reach which terminals
 */

import { readFileSync, writeFileSync, existsSync, readdirSync } from 'fs';
import { join, basename } from 'path';
import { execSync } from 'child_process';

const CHROMIUM_DIR = process.argv[2] || 'd:/webappsec/chromium';
const BLINK_CORE = join(CHROMIUM_DIR, 'third_party/blink/renderer/core');
const CLANG = 'C:/Program Files/LLVM/bin/clang++.exe';
const OUTPUT = process.argv[3] || 'd:/webappsec/src/worker/chromium-taint-results.json';

// ═══════════════════════════════════════════
// Phase 1: Extract method definitions + calls from clang AST
// ═══════════════════════════════════════════

/**
 * Parse clang's JSON AST output into method definitions with call info.
 * The output may contain multiple top-level JSON objects (one per matched decl).
 */
function parseClangJSON(jsonText) {
  const objects = [];
  let current = '';
  let depth = 0;

  for (const line of jsonText.split('\n')) {
    current += line + '\n';
    for (const ch of line) {
      if (ch === '{') depth++;
      if (ch === '}') depth--;
    }
    if (depth === 0 && current.trim()) {
      try { objects.push(JSON.parse(current)); } catch {}
      current = '';
    }
  }
  return objects;
}

/**
 * Extract all call expressions from an AST node, tracking which parameters flow into args.
 */
function extractCalls(node, params = new Map(), localVars = new Map(), results = []) {
  if (!node) return results;

  // Track variable declarations and assignments
  if (node.kind === 'VarDecl' && node.name) {
    // Check if initialized from a parameter
    const initTaint = node.inner ? getExprTaint(node.inner[0], params, localVars) : null;
    if (initTaint) {
      localVars.set(node.name, initTaint);
    }
  }

  // Track call expressions
  if (node.kind === 'CXXMemberCallExpr' || node.kind === 'CallExpr') {
    const callInfo = extractCallInfo(node, params, localVars);
    if (callInfo) results.push(callInfo);
  }

  // Recurse into children
  if (node.inner) {
    for (const child of node.inner) {
      extractCalls(child, params, localVars, results);
    }
  }

  return results;
}

/**
 * Determine if an expression references a tainted parameter.
 * Returns the parameter name if tainted, null otherwise.
 */
function getExprTaint(node, params, localVars) {
  if (!node) return null;

  // Direct parameter reference
  if (node.kind === 'DeclRefExpr') {
    const name = node.referencedDecl?.name || '';
    if (params.has(name)) return params.get(name);
    if (localVars.has(name)) return localVars.get(name);
    return null;
  }

  // Member access on a parameter: param.field or param->field
  if (node.kind === 'MemberExpr') {
    const objTaint = node.inner ? getExprTaint(node.inner[0], params, localVars) : null;
    if (objTaint) return objTaint + '.' + (node.name || '');
    return null;
  }

  // Implicit casts, temporary bindings — pass through
  if (node.kind === 'ImplicitCastExpr' || node.kind === 'CXXBindTemporaryExpr' ||
      node.kind === 'MaterializeTemporaryExpr' || node.kind === 'ExprWithCleanups' ||
      node.kind === 'CXXConstructExpr' || node.kind === 'CXXFunctionalCastExpr') {
    if (node.inner) {
      for (const child of node.inner) {
        const t = getExprTaint(child, params, localVars);
        if (t) return t;
      }
    }
  }

  // RecoveryExpr — try to extract taint from sub-expressions
  if (node.kind === 'RecoveryExpr' && node.inner) {
    for (const child of node.inner) {
      const t = getExprTaint(child, params, localVars);
      if (t) return t;
    }
  }

  // CXXDependentScopeMemberExpr — member access that couldn't be resolved
  if (node.kind === 'CXXDependentScopeMemberExpr') {
    const memberName = node.member || '';
    if (node.inner) {
      for (const child of node.inner) {
        const t = getExprTaint(child, params, localVars);
        if (t) return t + '.' + memberName;
      }
    }
  }

  return null;
}

/**
 * Extract call target name and which args are tainted.
 */
function extractCallInfo(callNode, params, localVars) {
  if (!callNode.inner || callNode.inner.length === 0) return null;

  // First child is callee, rest are arguments
  const calleeNode = callNode.inner[0];
  let calleeName = resolveCalleeName(calleeNode);

  // Check which arguments carry taint
  const taintedArgs = [];
  for (let i = 1; i < callNode.inner.length; i++) {
    const argTaint = getExprTaint(callNode.inner[i], params, localVars);
    if (argTaint) {
      taintedArgs.push({ index: i - 1, source: argTaint });
    }
  }

  if (!calleeName) return null;

  return {
    callee: calleeName,
    taintedArgs,
    returnType: callNode.type?.qualType || '',
  };
}

/**
 * Resolve callee name from various AST node types.
 */
function resolveCalleeName(node) {
  if (!node) return null;

  if (node.kind === 'MemberExpr') {
    // obj->Method() or obj.Method()
    const objType = node.inner?.[0]?.type?.qualType || '';
    const method = node.name || '';
    // Try to extract class name from type
    const classMatch = objType.match(/(?:const\s+)?(?:blink::)?(\w+)\s*[*&]/);
    if (classMatch) return classMatch[1] + '::' + method;
    return method;
  }

  if (node.kind === 'DeclRefExpr') {
    return node.referencedDecl?.name || null;
  }

  // Implicit cast around the actual callee
  if (node.kind === 'ImplicitCastExpr' && node.inner) {
    return resolveCalleeName(node.inner[0]);
  }

  // Dependent scope member (unresolved due to template/error)
  if (node.kind === 'CXXDependentScopeMemberExpr') {
    return node.member || null;
  }

  return null;
}

// ═══════════════════════════════════════════
// Phase 2: Parse a single .cc file
// ═══════════════════════════════════════════

function parseFile(ccFile, className) {
  const filter = className || basename(ccFile, '.cc');
  try {
    const result = execSync(
      `"${CLANG}" -Xclang -ast-dump=json -Xclang -ast-dump-filter=${filter} ` +
      `-fsyntax-only -std=c++20 -I${CHROMIUM_DIR} -I${CHROMIUM_DIR}/third_party ` +
      `"${ccFile}"`,
      { maxBuffer: 50 * 1024 * 1024, timeout: 60000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
    );
    return parseClangJSON(result);
  } catch (e) {
    // clang exits non-zero on errors but still produces output
    if (e.stdout) return parseClangJSON(e.stdout);
    return [];
  }
}

/**
 * Extract method definitions from AST objects.
 * Returns Map of qualifiedName → { params, calls, returnType }
 */
function extractMethods(astObjects) {
  const methods = new Map();

  for (const obj of astObjects) {
    if (obj.kind !== 'CXXMethodDecl' || !obj.inner) continue;
    if (!obj.name) continue;

    // Get qualified class name
    const className = obj.parentDeclContextId ?
      findClassName(astObjects, obj.parentDeclContextId) : null;
    const qualName = className ? `${className}::${obj.name}` : obj.name;

    // Extract parameters
    const params = new Map();
    const paramList = [];
    for (const child of obj.inner) {
      if (child.kind === 'ParmVarDecl' && child.name) {
        params.set(child.name, child.name);
        paramList.push({ name: child.name, type: child.type?.qualType || '' });
      }
    }

    // Find the compound statement (function body)
    const body = obj.inner.find(c => c.kind === 'CompoundStmt');
    if (!body) continue;

    // Extract calls with taint tracking
    const calls = extractCalls(body, params, new Map());

    methods.set(qualName, {
      name: obj.name,
      qualName,
      params: paramList,
      calls,
      returnType: obj.type?.qualType || '',
    });
  }

  return methods;
}

function findClassName(objects, contextId) {
  for (const obj of objects) {
    if (obj.id === contextId && obj.kind === 'CXXRecordDecl') {
      return obj.name;
    }
  }
  return null;
}

// ═══════════════════════════════════════════
// Phase 3: Build cross-file call graph + taint propagation
// ═══════════════════════════════════════════

/**
 * Transitive taint propagation through call graph.
 * Starting from entry points (setters), follow tainted parameters through calls.
 */
function propagateTaint(allMethods, entryPoints, terminals) {
  const results = [];

  for (const entry of entryPoints) {
    const method = allMethods.get(entry.qualName);
    if (!method) continue;

    // Mark all parameters as tainted (they come from JS)
    const taintedParams = new Set(method.params.map(p => p.name));

    // BFS through calls
    const visited = new Set();
    const queue = [{ method, taintedParams, path: [entry.qualName] }];

    while (queue.length > 0) {
      const { method: current, taintedParams: curTaint, path } = queue.shift();
      const key = current.qualName + ':' + [...curTaint].sort().join(',');
      if (visited.has(key)) continue;
      visited.add(key);

      for (const call of current.calls) {
        // Check if any tainted arg actually comes from a tainted source
        const taintedFlows = call.taintedArgs.filter(a => {
          const root = a.source.split('.')[0];
          return curTaint.has(root) || curTaint.has(a.source);
        });

        if (taintedFlows.length === 0) continue;

        // Check if this call is a terminal
        const terminalMatch = terminals.find(t =>
          call.callee.includes(t.name) || call.callee === t.name
        );

        if (terminalMatch) {
          results.push({
            entry: entry.qualName,
            property: entry.property,
            terminal: call.callee,
            terminalType: terminalMatch.type,
            path: [...path, call.callee],
          });
          continue;
        }

        // Follow into callee if we have its definition
        const callee = allMethods.get(call.callee);
        if (callee) {
          const nextTaint = new Set();
          for (const ta of call.taintedArgs) {
            if (ta.index < callee.params.length) {
              nextTaint.add(callee.params[ta.index].name);
            }
          }
          if (nextTaint.size > 0) {
            queue.push({
              method: callee,
              taintedParams: nextTaint,
              path: [...path, call.callee],
            });
          }
        }
      }
    }
  }

  return results;
}

// ═══════════════════════════════════════════
// Phase 4: Discover files to analyze + run pipeline
// ═══════════════════════════════════════════

// Terminal sink functions
const TERMINALS = [
  { name: 'Navigate', type: 'navigation' },
  { name: 'LoadOrRedirectSubframe', type: 'navigation' },
  { name: 'CommitNavigation', type: 'navigation' },
  { name: 'ScheduleNavigation', type: 'navigation' },
  { name: 'OpenURL', type: 'navigation' },
  { name: 'SetLocation', type: 'navigation' },
  { name: 'ExecuteScript', type: 'script' },
  { name: 'RunScript', type: 'script' },
  { name: 'PrepareScript', type: 'script' },
  { name: 'setInnerHTML', type: 'html' },
  { name: 'setOuterHTML', type: 'html' },
  { name: 'insertAdjacentHTML', type: 'html' },
  { name: 'ParseHTML', type: 'html' },
];

function findCCFiles(dir) {
  const results = [];
  try {
    for (const entry of readdirSync(dir, { withFileTypes: true, recursive: true })) {
      const full = join(entry.parentPath || dir, entry.name);
      if (entry.name.endsWith('.cc') && !entry.name.includes('_test') && !entry.name.includes('_fuzz')) {
        results.push(full);
      }
    }
  } catch {}
  return results;
}

// Focus on HTML element files + frame/loader for cross-file resolution
const HTML_DIR = join(BLINK_CORE, 'html');
const FRAME_DIR = join(BLINK_CORE, 'frame');
const LOADER_DIR = join(BLINK_CORE, 'loader');
const DOM_DIR = join(BLINK_CORE, 'dom');

console.log('Phase 1: Discovering files...');
const targetDirs = [HTML_DIR, FRAME_DIR, LOADER_DIR, DOM_DIR];
const ccFiles = [];
for (const dir of targetDirs) {
  if (existsSync(dir)) {
    ccFiles.push(...findCCFiles(dir));
  }
}
console.log(`  Found ${ccFiles.length} .cc files`);

// Start with HTML element files that have [URL] attributes (from IDL data)
const urlElements = [
  { file: 'html_frame_element_base', class: 'HTMLFrameElementBase', property: 'src' },
  { file: 'html_iframe_element', class: 'HTMLIFrameElement', property: 'src' },
  { file: 'html_image_element', class: 'HTMLImageElement', property: 'src' },
  { file: 'html_anchor_element', class: 'HTMLAnchorElement', property: 'href' },
  { file: 'html_embed_element', class: 'HTMLEmbedElement', property: 'src' },
  { file: 'html_object_element', class: 'HTMLObjectElement', property: 'data' },
  { file: 'html_link_element', class: 'HTMLLinkElement', property: 'href' },
  { file: 'html_media_element', class: 'HTMLMediaElement', property: 'src' },
  { file: 'html_source_element', class: 'HTMLSourceElement', property: 'src' },
  { file: 'html_script_element', class: 'HTMLScriptElement', property: 'src' },
];

console.log('\nPhase 2: Parsing ASTs...');
const allMethods = new Map();
let parsed = 0;

for (const elem of urlElements) {
  const ccFile = join(HTML_DIR, elem.file + '.cc');
  if (!existsSync(ccFile)) {
    console.log(`  SKIP ${elem.file}.cc (not found)`);
    continue;
  }

  console.log(`  Parsing ${elem.file}.cc...`);
  const ast = parseFile(ccFile, elem.class);
  const methods = extractMethods(ast);

  for (const [name, method] of methods) {
    allMethods.set(name, method);
  }
  parsed++;
}

// Also parse frame/loader files for terminal resolution
const criticalFiles = [
  { dir: FRAME_DIR, file: 'local_frame.cc', class: 'LocalFrame' },
  { dir: FRAME_DIR, file: 'remote_frame.cc', class: 'RemoteFrame' },
  { dir: LOADER_DIR, file: 'frame_loader.cc', class: 'FrameLoader' },
  { dir: LOADER_DIR, file: 'navigation_scheduler.cc', class: 'NavigationScheduler' },
];

for (const { dir, file, class: cls } of criticalFiles) {
  const ccFile = join(dir, file);
  if (!existsSync(ccFile)) {
    console.log(`  SKIP ${file} (not found)`);
    continue;
  }
  console.log(`  Parsing ${file}...`);
  const ast = parseFile(ccFile, cls);
  const methods = extractMethods(ast);
  for (const [name, method] of methods) {
    allMethods.set(name, method);
  }
  parsed++;
}

console.log(`\n  Parsed ${parsed} files, ${allMethods.size} methods extracted`);

// Print method summary
console.log('\n  Method summary:');
for (const [name, method] of allMethods) {
  const callSummary = method.calls
    .filter(c => c.taintedArgs.length > 0)
    .map(c => `${c.callee}(${c.taintedArgs.map(a => a.source).join(', ')})`)
    .join(', ');
  if (callSummary) {
    console.log(`    ${name}: tainted calls → ${callSummary}`);
  }
}

console.log('\nPhase 3: Taint propagation...');

// Entry points: each element's own ParseAttribute + any set* methods
const entryPoints = [];
for (const elem of urlElements) {
  // Only the element's own ParseAttribute — not parent classes
  entryPoints.push(
    { qualName: `${elem.class}::ParseAttribute`, property: `${elem.class}.${elem.property}` },
  );
  // Also check direct setter methods (e.g. setHref, setSrc)
  const setterName = 'set' + elem.property.charAt(0).toUpperCase() + elem.property.slice(1);
  entryPoints.push(
    { qualName: `${elem.class}::${setterName}`, property: `${elem.class}.${elem.property}` },
  );
}
// HTMLFrameElementBase is the base for iframe/frame — add its methods separately
entryPoints.push(
  { qualName: 'HTMLFrameElementBase::ParseAttribute', property: 'HTMLFrameElementBase.src' },
  { qualName: 'HTMLFrameElementBase::OpenURL', property: 'HTMLFrameElementBase.src' },
  { qualName: 'HTMLFrameElementBase::SetLocation', property: 'HTMLFrameElementBase.src' },
  // Anchor click → navigation
  { qualName: 'HTMLAnchorElementBase::NavigateToHyperlink', property: 'HTMLAnchorElement.href' },
  { qualName: 'HTMLAnchorElementBase::HandleClick', property: 'HTMLAnchorElement.href' },
  { qualName: 'HTMLAnchorElementBase::setHref', property: 'HTMLAnchorElement.href' },
);

const taintResults = propagateTaint(allMethods, entryPoints, TERMINALS);

console.log(`\n  Taint paths found: ${taintResults.length}`);
for (const r of taintResults) {
  console.log(`  ${r.property} → ${r.terminalType}: ${r.path.join(' → ')}`);
}

// Write results
writeFileSync(OUTPUT, JSON.stringify({
  taintPaths: taintResults,
  methods: Object.fromEntries([...allMethods].map(([k, v]) => [k, {
    params: v.params,
    calls: v.calls.map(c => ({ callee: c.callee, taintedArgs: c.taintedArgs })),
  }])),
  meta: {
    generated: new Date().toISOString(),
    filesAnalyzed: parsed,
    methodsExtracted: allMethods.size,
  },
}, null, 2));

console.log(`\nWritten to ${OUTPUT}`);
