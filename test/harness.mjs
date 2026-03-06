/* test/harness.mjs — Test harness that runs the taint analysis pipeline
   directly in Node, same code path as the worker. */

import { parse } from '@babel/parser';
import { buildCFG } from '../src/worker/cfg.js';
import { analyzeCFG, TaintEnv, TaintSet, TaintLabel, checkPrototypePollution } from '../src/worker/taint.js';
import { buildScopeInfo } from '../src/worker/scope.js';
import { extractGlobalDeclarations } from '../src/worker/module-graph.js';
import { nodeToString } from '../src/worker/sources-sinks.js';

// Analyze a single JS source string, return findings
export function analyze(source, { file = 'test.js', isModule = false, globalEnv = null } = {}) {
  const ast = parse(source, {
    sourceType: isModule ? 'module' : 'script',
    plugins: [
      'jsx', 'typescript', 'dynamicImport', 'optionalChaining',
      'nullishCoalescingOperator', 'classProperties', 'decorators-legacy',
      'objectRestSpread', 'topLevelAwait', 'classPrivateProperties',
      'classPrivateMethods', 'asyncGenerators', 'optionalCatchBinding',
    ],
    errorRecovery: true,
    allowReturnOutsideFunction: true,
    allowSuperOutsideMethod: true,
  });

  let scopeInfo = null;
  try { scopeInfo = buildScopeInfo(ast); } catch {}

  const funcMap = new Map();
  extractGlobalDeclarations(ast, funcMap, file);

  const env = globalEnv ? globalEnv.child() : new TaintEnv();

  // Set up postMessage taint for message handlers
  setupMessageHandlerTaint(ast, env, file);

  const cfg = buildCFG(ast.program);
  const findings = analyzeCFG(cfg, env, file, funcMap, globalEnv || new TaintEnv(), scopeInfo);

  // Also scan for prototype pollution
  const ppCtx = { file, funcMap, findings, globalEnv: env, scopeInfo, returnTaint: TaintSet.empty(), analyzedCalls: new Set() };
  walkAST(ast.program, (node) => {
    if (node.type === 'AssignmentExpression') checkPrototypePollution(node, env, ppCtx);
  });

  return { findings, env, funcMap, ast };
}

// Analyze multiple scripts in order (shared global scope)
export function analyzeMultiple(scripts) {
  const globalEnv = new TaintEnv();
  const globalFuncMap = new Map();
  const allFindings = [];

  for (const { source, file, isModule } of scripts) {
    const ast = parse(source, {
      sourceType: isModule ? 'module' : 'script',
      plugins: [
        'jsx', 'typescript', 'dynamicImport', 'optionalChaining',
        'nullishCoalescingOperator', 'classProperties', 'decorators-legacy',
        'objectRestSpread', 'topLevelAwait', 'asyncGenerators', 'optionalCatchBinding',
      ],
      errorRecovery: true,
      allowReturnOutsideFunction: true,
    });

    let scopeInfo = null;
    try { scopeInfo = buildScopeInfo(ast); } catch {}

    const funcMap = new Map(globalFuncMap);
    extractGlobalDeclarations(ast, funcMap, file || 'test.js');
    for (const [k, v] of funcMap) globalFuncMap.set(k, v);

    const env = globalEnv.child();
    setupMessageHandlerTaint(ast, env, file || 'test.js');

    const cfg = buildCFG(ast.program);
    const findings = analyzeCFG(cfg, env, file || 'test.js', funcMap, globalEnv, scopeInfo);
    allFindings.push(...findings);

    globalEnv.replaceFrom(env);
  }

  return allFindings;
}

function setupMessageHandlerTaint(ast, env, file) {
  walkAST(ast.program, (node) => {
    if (node.type !== 'CallExpression') return;
    if (node.callee?.type !== 'MemberExpression') return;
    if (node.callee.property?.name !== 'addEventListener') return;
    const firstArg = node.arguments[0];
    if (!firstArg || firstArg.value !== 'message') return;
    const handler = node.arguments[1];
    if (!handler || (handler.type !== 'ArrowFunctionExpression' && handler.type !== 'FunctionExpression')) return;

    const checksOrigin = containsOriginCheck(handler.body);
    if (!checksOrigin && handler.params[0]?.type === 'Identifier') {
      const paramName = handler.params[0].name;
      const loc = handler.loc?.start || {};
      const label = new TaintLabel('postMessage.data', file, loc.line || 0, loc.column || 0, `${paramName}.data (no origin check)`);
      env.set(`${paramName}.data`, TaintSet.from(label));
      env.set(paramName, TaintSet.from(label));
    }
  });

  walkAST(ast.program, (node) => {
    if (node.type !== 'AssignmentExpression') return;
    const leftStr = nodeToString(node.left);
    if (leftStr !== 'window.onmessage' && leftStr !== 'onmessage' && leftStr !== 'self.onmessage') return;
    const handler = node.right;
    if (handler.type !== 'ArrowFunctionExpression' && handler.type !== 'FunctionExpression') return;
    if (!containsOriginCheck(handler.body) && handler.params[0]?.name) {
      const paramName = handler.params[0].name;
      const loc = handler.loc?.start || {};
      const label = new TaintLabel('postMessage.data', file, loc.line || 0, loc.column || 0, `${paramName}.data (no origin check)`);
      env.set(`${paramName}.data`, TaintSet.from(label));
      env.set(paramName, TaintSet.from(label));
    }
  });
}

function walkAST(node, visitor) {
  if (!node || typeof node !== 'object') return;
  if (node.type) visitor(node);
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'start' || key === 'end' || key === 'leadingComments' || key === 'trailingComments' || key === 'innerComments' || key === '_closureEnv') continue;
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

function containsOriginCheck(node) {
  if (!node || typeof node !== 'object') return false;
  if (node.type === 'BinaryExpression' && (node.operator === '===' || node.operator === '==' || node.operator === '!==' || node.operator === '!=')) {
    const l = nodeToString(node.left), r = nodeToString(node.right);
    if ((l && l.endsWith('.origin')) || (r && r.endsWith('.origin'))) return true;
  }
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'start' || key === 'end') continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (item && typeof item === 'object' && item.type && containsOriginCheck(item)) return true;
      }
    } else if (child && typeof child === 'object' && child.type && containsOriginCheck(child)) return true;
  }
  return false;
}
