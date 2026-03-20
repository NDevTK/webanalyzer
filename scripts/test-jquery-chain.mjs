// Test each step of the jQuery data flow chain individually
// to find exactly where the analysis breaks down

import { analyzeCFG, TaintEnv } from '../src/worker/taint.js';
import { buildCFG } from '../src/worker/cfg.js';
import { buildScopeInfo } from '../src/worker/scope.js';
import { parse } from '@babel/parser';

const PLUGINS = ['classProperties', 'classStaticBlock', 'objectRestSpread',
  'optionalChaining', 'nullishCoalescingOperator', 'dynamicImport',
  ['optionalChainingAssign', { version: '2023-07' }], 'classPrivateProperties',
  'classPrivateMethods', 'numericSeparator', 'logicalAssignment', 'exportDefaultFrom'];

function test(name, src) {
  const ast = parse(src, { sourceType: 'script', plugins: PLUGINS, errorRecovery: true, allowReturnOutsideFunction: true });
  let scopeInfo = null;
  try { scopeInfo = buildScopeInfo(ast); } catch {}
  const funcMap = new Map();
  const globalEnv = new TaintEnv();
  const env = globalEnv.child();
  const cfg = buildCFG(ast.program);
  const findings = analyzeCFG(cfg, env, 'test.js', funcMap, globalEnv, scopeInfo);
  return { findings, funcMap, env };
}

function hasFM(funcMap, key) { return funcMap.has(key); }
function hasAnyFM(funcMap, substring) {
  for (const [k] of funcMap) if (k.includes(substring)) return k;
  return null;
}

let pass = 0, fail = 0;
function check(name, result, expected) {
  if (result === expected) { console.log(`  PASS  ${name}`); pass++; }
  else { console.log(`  FAIL  ${name} (got ${result}, expected ${expected})`); fail++; }
}

console.log('\n=== Step 1: UMD typeof guard ===');
{
  const { funcMap } = test('UMD', `
    !function(e,t){"object"==typeof module?module.exports=t(e):t(e)}(window,function(w){
      w.myLib = function(){};
    });
  `);
  check('typeof module folds to false', hasFM(funcMap, 'global:myLib'), true);
}

console.log('\n=== Step 2: UMD with ternary window arg ===');
{
  const { funcMap } = test('UMD ternary', `
    !function(e,t){"object"==typeof module?module.exports=t(e):t(e)}(typeof window!=="undefined"?window:this,function(w){
      w.myLib = function(){};
    });
  `);
  check('ternary window resolves', hasFM(funcMap, 'global:myLib'), true);
}

console.log('\n=== Step 3: Chained assignment export ===');
{
  const { funcMap } = test('chained', `
    !function(e,t){t(e)}(window,function(w){
      var S = function(){};
      w.jQuery = w.dollar = S;
    });
  `);
  check('jQuery exported', hasFM(funcMap, 'global:jQuery'), true);
  check('dollar exported', hasFM(funcMap, 'global:dollar'), true);
}

console.log('\n=== Step 4: Prototype method registration ===');
{
  const { funcMap } = test('proto', `
    !function(e,t){t(e)}(window,function(w){
      var S = function(){};
      S.fn = S.prototype = {
        constructor: S,
        html: function(val) { this[0].innerHTML = val; },
        append: function(val) { this[0].appendChild(val); }
      };
      w.jQuery = S;
    });
  `);
  check('jQuery.fn.html registered', hasFM(funcMap, 'jQuery.fn.html'), true);
  check('jQuery.fn.append registered', hasFM(funcMap, 'jQuery.fn.append'), true);
}

console.log('\n=== Step 5: init.prototype = fn (jQuery pattern) ===');
{
  const { funcMap } = test('init.proto', `
    !function(e,t){t(e)}(window,function(w){
      var S = function(sel) { return new S.fn.init(sel); };
      S.fn = S.prototype = {
        html: function(val) { this[0].innerHTML = val; },
        init: function(sel) { this[0] = document.querySelector(sel); return this; }
      };
      S.fn.init.prototype = S.fn;
      w.jQuery = S;
    });
  `);
  check('init#html registered', !!hasAnyFM(funcMap, 'init#html'), true);
}

console.log('\n=== Step 6: $.fn.extend copies methods ===');
{
  const { funcMap } = test('extend', `
    var obj = {};
    obj.extend = function() {
      var target = this, src = arguments[0];
      for (var key in src) { target[key] = src[key]; }
      return target;
    };
    obj.extend({ render: function(d) { document.body.innerHTML = d; } });
  `);
  check('obj.render after extend', hasFM(funcMap, 'obj.render') || !!hasAnyFM(funcMap, 'obj.render'), true);
}

console.log('\n=== Step 7: extend with this alias (target = this) ===');
{
  const { funcMap } = test('extend-this', `
    var obj = {};
    obj.extend = function() {
      var target = arguments[0] || {}, i = 1, length = arguments.length;
      if (i === length) { target = this; i--; }
      for (var key in arguments[i]) { target[key] = arguments[i][key]; }
      return target;
    };
    obj.extend({ render: function(d) { document.body.innerHTML = d; } });
  `);
  const hasRender = hasFM(funcMap, 'obj.render') || !!hasAnyFM(funcMap, 'obj.render');
  check('obj.render after extend(this alias)', hasRender, true);
}

console.log('\n=== Step 8: $() constructor returns object with methods ===');
{
  const { findings } = test('ctor-chain', `
    var S = function(sel) { return new S.fn.init(sel); };
    S.fn = S.prototype = {
      html: function(val) { document.body.innerHTML = val; },
      init: function() { return this; }
    };
    S.fn.init.prototype = S.fn;
    window.dollar = S;
    dollar("div").html(location.hash);
  `);
  check('$().html(tainted) detects XSS', findings.length > 0, true);
}

console.log('\n=== Step 9: Full jQuery-like IIFE ===');
{
  const { findings } = test('full-iife', `
    !function(e,t){t(e)}(window,function(w){
      var S = function(sel) { return new S.fn.init(sel); };
      S.fn = S.prototype = {
        html: function(val) { document.body.innerHTML = val; },
        init: function() { return this; }
      };
      S.fn.init.prototype = S.fn;
      w.jQuery = w.dollar = S;
    });
    dollar("div").html(location.hash);
  `);
  check('IIFE $().html(tainted) XSS', findings.length > 0, true);
}

console.log('\n=== Step 10: extend then sink ===');
{
  const { findings } = test('extend-sink', `
    var S = function(sel) { return new S.fn.init(sel); };
    S.fn = S.prototype = { init: function() { return this; } };
    S.fn.init.prototype = S.fn;
    S.fn.extend = function() {
      var target = this, src = arguments[0];
      for (var key in src) { target[key] = src[key]; }
    };
    S.fn.extend({
      html: function(val) { document.body.innerHTML = val; }
    });
    window.dollar = S;
    dollar("div").html(location.hash);
  `);
  check('extend + $().html(tainted) XSS', findings.length > 0, true);
}

console.log(`\n=== Results: ${pass} passed, ${fail} failed ===\n`);
