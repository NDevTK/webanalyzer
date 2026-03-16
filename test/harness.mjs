/* test/harness.mjs — Test harness that runs the taint analysis pipeline
   directly in Node, same code path as the worker. */

import { parse } from '@babel/parser';
import { buildCFG } from '../src/worker/cfg.js';
import { analyzeCFG, TaintEnv, TaintSet, TaintLabel, generatePoC } from '../src/worker/taint.js';
import { buildScopeInfo } from '../src/worker/scope.js';
import { extractGlobalDeclarations } from '../src/worker/module-graph.js';
import { nodeToString } from '../src/worker/sources-sinks.js';

// Babel 8: most syntax plugins are now built-in. Only non-default syntax needs explicit plugins.
const BABEL_PLUGINS = [
  'jsx', 'typescript', 'decorators-legacy', 'exportDefaultFrom',
  ['optionalChainingAssign', { version: '2023-07' }],
];

const WALK_SKIP_KEYS = new Set(['loc', 'start', 'end', 'leadingComments', 'trailingComments', 'innerComments', '_closureEnv']);

// Analyze a single JS source string, return findings
export function analyze(source, { file = 'test.js', isModule = false, globalEnv = null, domCatalog = null } = {}) {
  const ast = parse(source, {
    sourceType: isModule ? 'module' : 'script',
    plugins: BABEL_PLUGINS,
    errorRecovery: true,
    allowReturnOutsideFunction: true,
    allowSuperOutsideMethod: true,
  });

  let scopeInfo = null;
  try { scopeInfo = buildScopeInfo(ast); } catch {}

  const funcMap = new Map();
  extractGlobalDeclarations(ast, funcMap, file);

  const env = globalEnv ? globalEnv.child() : new TaintEnv();

  const cfg = buildCFG(ast.program);
  const findings = analyzeCFG(cfg, env, file, funcMap, globalEnv || new TaintEnv(), scopeInfo, false, domCatalog);

  // Generate PoCs for all findings (same as worker/index.js postFindings)
  for (const f of findings) {
    if (!f.poc) f.poc = generatePoC(f);
  }

  return { findings, env, funcMap, ast };
}

// Analyze multiple scripts in order (shared global scope)
export function analyzeMultiple(scripts, { domCatalog = null } = {}) {
  const globalEnv = new TaintEnv();
  const globalFuncMap = new Map();
  const allFindings = [];

  for (const { source, file, isModule } of scripts) {
    const ast = parse(source, {
      sourceType: isModule ? 'module' : 'script',
      plugins: BABEL_PLUGINS,
      errorRecovery: true,
      allowReturnOutsideFunction: true,
    });

    // Tag all AST nodes with their source file for correct finding attribution
    // when interprocedural analysis crosses file boundaries.
    const srcFile = file || 'test.js';
    (function tagFile(node) {
      if (!node || typeof node !== 'object') return;
      if (node.type) node._sourceFile = srcFile;
      for (const key of Object.keys(node)) {
        if (key === 'leadingComments' || key === 'trailingComments' || key === 'innerComments' || key === '_sourceFile') continue;
        const child = node[key];
        if (Array.isArray(child)) { for (const c of child) { if (c && typeof c === 'object' && c.type) tagFile(c); } }
        else if (child && typeof child === 'object' && child.type) tagFile(child);
      }
    })(ast);

    let scopeInfo = null;
    try { scopeInfo = buildScopeInfo(ast); } catch {}

    const funcMap = new Map(globalFuncMap);
    extractGlobalDeclarations(ast, funcMap, file || 'test.js');
    for (const [k, v] of funcMap) globalFuncMap.set(k, v);

    const env = globalEnv.child();

    const cfg = buildCFG(ast.program);
    const findings = analyzeCFG(cfg, env, file || 'test.js', funcMap, globalEnv, scopeInfo, false, domCatalog);
    allFindings.push(...findings);

    globalEnv.replaceFrom(env);
    // Propagate newly discovered functions (e.g. from factory calls) back to globalFuncMap
    for (const [k, v] of funcMap) globalFuncMap.set(k, v);
  }

  // Generate PoCs for all findings (same as single-file analyze)
  for (const f of allFindings) {
    if (!f.poc) f.poc = generatePoC(f);
  }

  return allFindings;
}

function walkAST(node, visitor) {
  if (!node || typeof node !== 'object') return;
  if (node.type) visitor(node);
  for (const key of Object.keys(node)) {
    if (WALK_SKIP_KEYS.has(key)) continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (item && typeof item === 'object' && item.type) walkAST(item, visitor);
      }
    } else if (child && typeof child === 'object' && child.type) {
      walkAST(child, visitor);
    }
  }
}
