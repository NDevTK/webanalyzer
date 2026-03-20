// Debug script: check what funcMap entries exist after jQuery analysis
import { readFileSync } from 'fs';
import { parse } from '@babel/parser';
import { analyzeCFG, TaintEnv } from '../src/worker/taint.js';
import { buildCFG } from '../src/worker/cfg.js';
import { buildScopeInfo } from '../src/worker/scope.js';
import { extractGlobalDeclarations } from '../src/worker/module-graph.js';

const BABEL_PLUGINS = ['classProperties', 'classStaticBlock', 'objectRestSpread',
  'optionalChaining', 'nullishCoalescingOperator', 'dynamicImport', 'importMeta',
  ['optionalChainingAssign', { version: '2023-07' }], 'classPrivateProperties', 'classPrivateMethods',
  'numericSeparator', 'logicalAssignment', 'exportDefaultFrom'];

// Read jQuery source
const jquerySrc = readFileSync('test/libs/jquery.min.js', 'utf8');

// Parse and analyze jQuery
const ast = parse(jquerySrc, {
  sourceType: 'script',
  plugins: BABEL_PLUGINS,
  errorRecovery: true,
  allowReturnOutsideFunction: true,
});

let scopeInfo = null;
try { scopeInfo = buildScopeInfo(ast); } catch {}

const funcMap = new Map();
extractGlobalDeclarations(ast, funcMap, 'jquery.min.js');

const globalEnv = new TaintEnv();
const env = globalEnv.child();
const cfg = buildCFG(ast.program);
const findings = analyzeCFG(cfg, env, 'jquery.min.js', funcMap, globalEnv, scopeInfo);

console.log('=== jQuery Analysis ===');
console.log('Findings:', findings.length);
console.log('FuncMap size:', funcMap.size);

// Check for jQuery exports
const jqKeys = [];
for (const [k] of funcMap) {
  if (k.includes('jQuery') || k.includes('html') || k.includes('append') || k === '$' || k.includes('$.')) {
    jqKeys.push(k);
  }
}
console.log('jQuery-related funcMap entries:', jqKeys.length);
for (const k of jqKeys.sort().slice(0, 50)) console.log(' ', k);

// Check for $ or jQuery in funcMap
// Check ALL aliases in the env chain
console.log('\nAll aliases:');
let envCur = env;
let depth = 0;
while (envCur && depth < 5) {
  for (const [k, v] of envCur.aliases) {
    if (v === 'window' || k.includes('ie') || k.includes('jQuery') || k.includes('$')) {
      console.log(`  d${depth}:`, k, '→', v);
    }
  }
  envCur = envCur.parent;
  depth++;
}

console.log('\n$ or jQuery base entries:');
for (const [k] of funcMap) {
  if (k === '$' || k === 'jQuery' || k === 'global:$' || k === 'global:jQuery' ||
      k.startsWith('$.') || k.startsWith('jQuery.')) console.log(' ', k);
}

// Check env aliases for window/jQuery/$
console.log('\nAliases with window/jQuery/$:');
for (const [k, v] of env.aliases) {
  if (k.includes('jQuery') || k.includes('$') || v === 'jQuery' || v === '$' ||
      v === 'window' || v === 'self' || v === 'globalThis') {
    console.log('  alias:', k, '→', v);
  }
}

// Check funcMap for global: entries
console.log('\nglobal: funcMap entries:');
for (const [k] of funcMap) {
  if (k.startsWith('global:') && !k.includes('#idx')) console.log('  ', k);
}

// Check global env
for (const [k, v] of globalEnv.entries()) {
  if (k.includes('jQuery') || k === '$' || k === 'global:$') {
    console.log('globalEnv:', k, 'tainted:', v.tainted);
  }
}
