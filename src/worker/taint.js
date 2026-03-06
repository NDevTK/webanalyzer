/* taint.js — Forward taint propagation over the CFG using a worklist algorithm.
   Tracks taint from sources through assignments, calls, returns, property access,
   and reports when tainted data reaches a dangerous sink.
   Uses Babel scope info for accurate binding resolution (shadowing, closures). */

import {
  nodeToString, checkMemberSource, checkCallSink, checkAssignmentSink,
  isSanitizer, isPassthrough, CALL_SOURCES, CONSTRUCTOR_SOURCES,
  EVENT_SOURCES, MEMBER_SOURCES,
} from './sources-sinks.js';
import { buildCFG } from './cfg.js';

// ── Taint label: tracks where taint originated ──
export class TaintLabel {
  constructor(sourceType, file, line, col, description) {
    this.sourceType = sourceType;
    this.file = file;
    this.line = line;
    this.col = col;
    this.description = description;
  }

  get id() {
    return `${this.sourceType}@${this.file}:${this.line}:${this.col}`;
  }
}

// ── Taint set: a set of labels attached to a value ──
export class TaintSet {
  constructor(labels) {
    this.labels = labels || new Map();
  }

  get tainted() { return this.labels.size > 0; }
  get size() { return this.labels.size; }

  add(label) { this.labels.set(label.id, label); }

  merge(other) {
    if (!other) return this;
    for (const [id, label] of other.labels) this.labels.set(id, label);
    return this;
  }

  clone() { return new TaintSet(new Map(this.labels)); }
  static empty() { return new TaintSet(); }

  static from(label) {
    const ts = new TaintSet();
    ts.add(label);
    return ts;
  }

  equals(other) {
    if (!other) return this.labels.size === 0;
    if (this.labels.size !== other.labels.size) return false;
    for (const id of this.labels.keys()) {
      if (!other.labels.has(id)) return false;
    }
    return true;
  }

  toArray() { return [...this.labels.values()]; }
}

// ── Taint environment: maps binding keys to taint sets ──
// Keys are scope-resolved (e.g. "3:myVar") for locals, or dot-paths for properties
export class TaintEnv {
  constructor(parent) {
    this.bindings = new Map();
    this.parent = parent || null;
  }

  get(key) {
    if (this.bindings.has(key)) return this.bindings.get(key);
    if (this.parent) return this.parent.get(key);
    return TaintSet.empty();
  }

  set(key, taintSet) { this.bindings.set(key, taintSet); }

  has(key) {
    return this.bindings.has(key) || (this.parent ? this.parent.has(key) : false);
  }

  child() { return new TaintEnv(this); }

  clone() {
    const env = new TaintEnv(this.parent);
    for (const [k, v] of this.bindings) env.bindings.set(k, v.clone());
    return env;
  }

  mergeFrom(other) {
    let changed = false;
    for (const [key, taint] of other.bindings) {
      const existing = this.bindings.get(key);
      if (!existing) {
        this.bindings.set(key, taint.clone());
        changed = true;
      } else {
        const before = existing.size;
        existing.merge(taint);
        if (existing.size !== before) changed = true;
      }
    }
    return changed;
  }

  // Replace bindings from other (overwrites instead of merging).
  // Used for sequential cross-file analysis where later scripts overwrite globals.
  replaceFrom(other) {
    for (const [key, taint] of other.bindings) {
      this.bindings.set(key, taint.clone());
    }
  }

  equals(other) {
    if (!other) return this.bindings.size === 0;
    if (this.bindings.size !== other.bindings.size) return false;
    for (const [key, taint] of this.bindings) {
      const otherTaint = other.bindings.get(key);
      if (!otherTaint || !taint.equals(otherTaint)) return false;
    }
    return true;
  }

  // Collect all tainted bindings matching a prefix (walks parent chain)
  getTaintedWithPrefix(prefix) {
    const results = new Map();
    let env = this;
    while (env) {
      for (const [key, taint] of env.bindings) {
        if (key.startsWith(prefix) && taint.tainted && !results.has(key)) {
          results.set(key, taint);
        }
      }
      env = env.parent;
    }
    return results;
  }
}

// ── Analysis context ──
class AnalysisContext {
  constructor(file, funcMap, findings, globalEnv, scopeInfo, analyzedCalls) {
    this.file = file;
    this.funcMap = funcMap;       // bindingKey|name → AST node
    this.findings = findings;
    this.globalEnv = globalEnv;
    this.scopeInfo = scopeInfo;   // ScopeInfo from @babel/traverse (may be null)
    this.returnTaint = TaintSet.empty();
    // Shared across entire call chain — prevents re-analyzing same function with same taint
    this.analyzedCalls = analyzedCalls || new Set();
    this.returnedFuncNode = null;  // tracks function nodes returned from calls
    this.returnedMethods = null;   // tracks { name → funcNode } for returned objects
  }
}

// ── Resolve an Identifier node to its canonical binding key ──
// Uses Babel scope info when available, falls back to raw name
function resolveId(node, ctx) {
  if (ctx.scopeInfo) {
    const key = ctx.scopeInfo.resolve(node);
    if (key) return key;
  }
  return `global:${node.name}`;
}

// ── Main entry: analyze a CFG with initial taint environment ──
export function analyzeCFG(cfg, env, file, funcMap, globalEnv, scopeInfo) {
  const findings = [];
  const ctx = new AnalysisContext(file, funcMap, findings, globalEnv || new TaintEnv(), scopeInfo);

  const blockEnvs = new Map();
  blockEnvs.set(cfg.entry.id, env.clone());

  const worklist = [cfg.entry];
  const inWorklist = new Set([cfg.entry.id]);

  while (worklist.length > 0) {
    const block = worklist.shift();
    inWorklist.delete(block.id);

    const entryEnv = blockEnvs.get(block.id);
    if (!entryEnv) continue;

    const exitEnv = processBlock(block, entryEnv.clone(), ctx);

    for (const succ of block.successors) {
      const existing = blockEnvs.get(succ.id);
      if (!existing) {
        blockEnvs.set(succ.id, exitEnv.clone());
        if (!inWorklist.has(succ.id)) { worklist.push(succ); inWorklist.add(succ.id); }
      } else {
        const changed = existing.mergeFrom(exitEnv);
        if (changed && !inWorklist.has(succ.id)) { worklist.push(succ); inWorklist.add(succ.id); }
      }
    }
  }

  // Merge final state (at exit block) back into the caller's env
  // so cross-file and interprocedural analysis can see the taint
  const exitState = blockEnvs.get(cfg.exit.id);
  if (exitState) {
    env.mergeFrom(exitState);
  }
  // Also merge from all blocks that reach the exit (in case of multiple paths)
  for (const block of cfg.exit.predecessors) {
    const state = blockEnvs.get(block.id);
    if (state) env.mergeFrom(state);
  }

  return findings;
}

function processBlock(block, env, ctx) {
  for (const node of block.nodes) processNode(node, env, ctx);
  return env;
}

function processNode(node, env, ctx) {
  if (!node) return;

  switch (node.type) {
    case 'VariableDeclarator':
      processVarDeclarator(node, env, ctx);
      break;

    case 'AssignmentExpression':
      processAssignment(node, env, ctx);
      break;

    case 'CallExpression':
    case 'OptionalCallExpression':
    case 'NewExpression':
      evaluateExpr(node, env, ctx);
      break;

    case 'ReturnStatement':
      if (node.argument) {
        const arg = node.argument;
        // Track returned function nodes for factory pattern support
        if (arg.type === 'ArrowFunctionExpression' || arg.type === 'FunctionExpression') {
          arg._closureEnv = env;
          ctx.returnedFuncNode = arg;
        }
        // Track returned objects with function-valued properties (module pattern)
        if (arg.type === 'ObjectExpression') {
          const methods = {};
          for (const prop of arg.properties) {
            if ((prop.type === 'ObjectProperty' || prop.type === 'Property') &&
                prop.key && (prop.key.type === 'Identifier' || prop.key.type === 'StringLiteral')) {
              const name = prop.key.name || prop.key.value;
              const val = prop.value;
              if (val && (val.type === 'FunctionExpression' || val.type === 'ArrowFunctionExpression')) {
                val._closureEnv = env;
                methods[name] = val;
              }
              // Resolve identifier references to functions (e.g., { render: render })
              if (val && val.type === 'Identifier') {
                const refKey = resolveId(val, ctx);
                const refFunc = ctx.funcMap.get(refKey) || ctx.funcMap.get(val.name);
                if (refFunc) {
                  if (!refFunc._closureEnv) refFunc._closureEnv = env;
                  methods[name] = refFunc;
                }
              }
            }
            // Shorthand methods: { render() {} }
            if (prop.type === 'ObjectMethod' && prop.key) {
              const name = prop.key.name || prop.key.value;
              prop._closureEnv = env;
              methods[name] = prop;
            }
          }
          if (Object.keys(methods).length > 0) ctx.returnedMethods = methods;
        }
        ctx.returnTaint.merge(evaluateExpr(arg, env, ctx));
      }
      break;

    case 'FunctionDeclaration':
      if (node.id) {
        const key = resolveId(node.id, ctx);
        ctx.funcMap.set(key, node);
        // Also store by raw name for cross-file resolution
        ctx.funcMap.set(node.id.name, node);
      }
      break;

    case 'ClassDeclaration':
      if (node.id && node.body && node.body.body) {
        const className = node.id.name;
        for (const member of node.body.body) {
          if (member.type !== 'ClassMethod' && member.type !== 'MethodDefinition') continue;
          const mname = member.key?.name || member.key?.value;
          if (!mname) continue;
          if (member.static) {
            ctx.funcMap.set(`${className}.${mname}`, member);
            ctx.funcMap.set(mname, member);
          } else if (mname === 'constructor') {
            ctx.funcMap.set(className, member);
          } else {
            ctx.funcMap.set(mname, member);
          }
        }
      }
      break;

    case '_Test':
      evaluateExpr(node.test, env, ctx);
      break;

    case '_ForInOf':
      processForBinding(node, env, ctx);
      break;

    case '_CatchParam':
      break;

    case 'ExportNamedDeclaration':
      if (node.declaration) processNode(node.declaration, env, ctx);
      break;

    case 'ExportDefaultDeclaration':
      if (node.declaration) processNode(node.declaration, env, ctx);
      break;

    case 'VariableDeclaration':
      for (const decl of node.declarations) processVarDeclarator(decl, env, ctx);
      break;

    default:
      if (node.expression) evaluateExpr(node.expression, env, ctx);
      else evaluateExpr(node, env, ctx);
      break;
  }
}

// ── Variable declaration ──
function processVarDeclarator(node, env, ctx) {
  if (!node.init) return;
  ctx.returnedFuncNode = null;
  ctx.returnedMethods = null;

  // Register function expressions in funcMap so they can be called later
  if (node.id.type === 'Identifier' && node.init &&
      (node.init.type === 'FunctionExpression' || node.init.type === 'ArrowFunctionExpression')) {
    node.init._closureEnv = env;
    const key = resolveId(node.id, ctx);
    ctx.funcMap.set(key, node.init);
    ctx.funcMap.set(node.id.name, node.init);
  }
  // Register function-valued properties from object literals: var obj = { render: function(){} }
  if (node.id.type === 'Identifier' && node.init && node.init.type === 'ObjectExpression') {
    const varName = node.id.name;
    for (const prop of node.init.properties) {
      if ((prop.type === 'ObjectProperty' || prop.type === 'Property') && prop.key) {
        const propName = prop.key.name || prop.key.value;
        const val = prop.value;
        if (propName && val && (val.type === 'FunctionExpression' || val.type === 'ArrowFunctionExpression')) {
          val._closureEnv = env;
          ctx.funcMap.set(`${varName}.${propName}`, val);
          if (!ctx.funcMap.has(propName)) ctx.funcMap.set(propName, val);
        }
      }
      if (prop.type === 'ObjectMethod' && prop.key) {
        const propName = prop.key.name || prop.key.value;
        if (propName) {
          prop._closureEnv = env;
          ctx.funcMap.set(`${varName}.${propName}`, prop);
          if (!ctx.funcMap.has(propName)) ctx.funcMap.set(propName, prop);
        }
      }
    }
  }

  // Alias: var fn = existingFunc — register the alias in funcMap
  if (node.id.type === 'Identifier' && node.init.type === 'Identifier') {
    const refKey = resolveId(node.init, ctx);
    const refFunc = ctx.funcMap.get(refKey) || ctx.funcMap.get(node.init.name);
    if (refFunc) {
      const key = resolveId(node.id, ctx);
      ctx.funcMap.set(key, refFunc);
      ctx.funcMap.set(node.id.name, refFunc);
    }
  }
  // Alias: var r = obj.render — extract method reference from funcMap
  if (node.id.type === 'Identifier' && (node.init.type === 'MemberExpression' || node.init.type === 'OptionalMemberExpression')) {
    const initStr = nodeToString(node.init);
    const methodName = node.init.property?.name;
    const refFunc = (initStr && ctx.funcMap.get(initStr)) || (methodName && ctx.funcMap.get(methodName));
    if (refFunc) {
      const key = resolveId(node.id, ctx);
      ctx.funcMap.set(key, refFunc);
      ctx.funcMap.set(node.id.name, refFunc);
    }
  }

  const taint = evaluateExpr(node.init, env, ctx);
  assignToPattern(node.id, taint, env, ctx);
  registerReturnedFunctions(node.id, ctx);

  // For `new Constructor()` — propagate this.* taint to instance.*
  if (node.init.type === 'NewExpression' && node.id.type === 'Identifier') {
    propagateThisToInstance(node.id.name, env, ctx);
  }
}

// ── Assignment ──
function processAssignment(node, env, ctx) {
  ctx.returnedFuncNode = null;
  ctx.returnedMethods = null;
  const rhsTaint = evaluateExpr(node.right, env, ctx);
  checkSinkAssignment(node.left, rhsTaint, ctx);
  checkPrototypePollution(node, env, ctx);

  let finalTaint = rhsTaint;
  if (node.operator !== '=') {
    finalTaint = evaluateExpr(node.left, env, ctx).clone().merge(rhsTaint);
  }
  assignToPattern(node.left, finalTaint, env, ctx);
  registerReturnedFunctions(node.left, ctx);

  // Register direct function expression assignments in funcMap
  // Handles: Widget.prototype.render = function() { ... }
  //          obj.handler = () => { ... }
  //          handler = function(x) { ... }  (Identifier reassignment)
  if (node.operator === '=' &&
      (node.right.type === 'FunctionExpression' || node.right.type === 'ArrowFunctionExpression')) {
    node.right._closureEnv = env;
    const leftStr = nodeToString(node.left);
    if (leftStr) {
      ctx.funcMap.set(leftStr, node.right);
      // Also register by the last property name for method call resolution
      if (node.left.type === 'MemberExpression' && node.left.property?.name) {
        const propName = node.left.property.name;
        // Don't overwrite existing entries for common names
        if (!ctx.funcMap.has(propName)) ctx.funcMap.set(propName, node.right);
      }
    }
    // For Identifier targets, also register by scope-resolved key
    if (node.left.type === 'Identifier') {
      const key = resolveId(node.left, ctx);
      ctx.funcMap.set(key, node.right);
      ctx.funcMap.set(node.left.name, node.right);
    }
  }

  // Identifier assignment of function ref: handler = existingFunc
  if (node.operator === '=' && node.right.type === 'Identifier' && node.left.type === 'Identifier') {
    const refFunc = ctx.funcMap.get(node.right.name) || ctx.funcMap.get(resolveId(node.right, ctx));
    if (refFunc) {
      const leftKey = resolveId(node.left, ctx);
      ctx.funcMap.set(leftKey, refFunc);
      ctx.funcMap.set(node.left.name, refFunc);
    }
  }

  // window.onmessage / self.onmessage = function(e) { ... }
  // Analyze the handler body with tainted event param, same as addEventListener('message', fn)
  if (node.operator === '=') {
    const leftStr = nodeToString(node.left);
    if (leftStr === 'window.onmessage' || leftStr === 'onmessage' || leftStr === 'self.onmessage') {
      let handler = node.right;
      // Resolve named function reference: window.onmessage = handleMessage
      if (handler.type === 'Identifier') {
        const refKey = resolveId(handler, ctx);
        handler = ctx.funcMap.get(refKey) || ctx.funcMap.get(handler.name) || handler;
      }
      if (handler.type === 'ArrowFunctionExpression' || handler.type === 'FunctionExpression' ||
          handler.type === 'FunctionDeclaration') {
        const checksOrigin = callbackChecksOrigin(handler.body);
        if (!checksOrigin && handler.params[0]) {
          const paramName = handler.params[0].type === 'Identifier' ? handler.params[0].name : null;
          if (paramName) {
            const childEnv = env.child();
            const loc = handler.loc?.start || {};
            const label = new TaintLabel('postMessage.data', ctx.file, loc.line || 0, loc.column || 0, `${paramName}.data (no origin check)`);
            assignToPattern(handler.params[0], TaintSet.from(label), childEnv, ctx);
            childEnv.set(`${paramName}.data`, TaintSet.from(label));
            if (handler.body.type === 'BlockStatement') {
              analyzeInlineFunction(handler, childEnv, ctx);
            } else {
              evaluateExpr(handler.body, childEnv, ctx);
            }
          }
        }
      }
    }
  }
}

// ── Assign taint to a pattern using scope-resolved keys ──
function assignToPattern(pattern, taint, env, ctx) {
  if (!pattern) return;

  switch (pattern.type) {
    case 'Identifier': {
      const key = resolveId(pattern, ctx);
      env.set(key, taint);
      // Also set by raw name for cross-file globals
      env.set(`global:${pattern.name}`, taint);
      break;
    }

    case 'MemberExpression':
    case 'OptionalMemberExpression': {
      const str = nodeToString(pattern);
      if (str) env.set(str, taint);
      if (!pattern.computed && pattern.property?.name) {
        const objStr = nodeToString(pattern.object);
        if (objStr) env.set(`${objStr}.${pattern.property.name}`, taint);
      }
      break;
    }

    case 'ObjectPattern':
      for (const prop of pattern.properties) {
        if (prop.type === 'RestElement') assignToPattern(prop.argument, taint, env, ctx);
        else assignToPattern(prop.value, taint, env, ctx);
      }
      break;

    case 'ArrayPattern':
      for (const elem of pattern.elements) {
        if (elem) {
          if (elem.type === 'RestElement') assignToPattern(elem.argument, taint, env, ctx);
          else assignToPattern(elem, taint, env, ctx);
        }
      }
      break;

    case 'AssignmentPattern': {
      // Default parameter: if no taint was provided (empty), evaluate the default value
      const paramTaint = taint.tainted ? taint : evaluateExpr(pattern.right, env, ctx);
      assignToPattern(pattern.left, paramTaint, env, ctx);
      break;
    }
  }
}

// ── Register returned function nodes in funcMap after a call assignment ──
// Handles: var render = makeRenderer(x)   → stores render → funcNode
//          var obj = factory()             → stores obj.method → funcNode for each method
function registerReturnedFunctions(target, ctx) {
  if (!target) return;

  // Direct function return: var fn = factory()
  if (ctx.returnedFuncNode && target.type === 'Identifier') {
    const key = resolveId(target, ctx);
    ctx.funcMap.set(key, ctx.returnedFuncNode);
    ctx.funcMap.set(target.name, ctx.returnedFuncNode);
    ctx.returnedFuncNode = null;
  }

  // Object with methods: var obj = factory() where factory returns { render: function(){} }
  if (ctx.returnedMethods && target.type === 'Identifier') {
    const varName = target.name;
    for (const [methodName, funcNode] of Object.entries(ctx.returnedMethods)) {
      // Register as "varName.methodName" and raw "methodName" for method call resolution
      ctx.funcMap.set(`${varName}.${methodName}`, funcNode);
      // Also register by just method name for MemberExpression resolution
      ctx.funcMap.set(methodName, funcNode);
    }
    ctx.returnedMethods = null;
  }

  // Also handle: obj.prop = factory()
  if (ctx.returnedFuncNode && (target.type === 'MemberExpression' || target.type === 'OptionalMemberExpression')) {
    const str = nodeToString(target);
    if (str) {
      ctx.funcMap.set(str, ctx.returnedFuncNode);
      const propName = target.property?.name;
      if (propName) ctx.funcMap.set(propName, ctx.returnedFuncNode);
    }
    ctx.returnedFuncNode = null;
  }
}

// ── Propagate this.* taint from constructor to instance.* ──
// After `var w = new Widget(tainted)`, copies this.html → w.html
function propagateThisToInstance(instanceName, env, ctx) {
  const toSet = [];
  for (const [key, taint] of env.bindings) {
    if (key.startsWith('this.') && taint.tainted) {
      const propName = key.slice(5); // "this.html" → "html"
      toSet.push([`${instanceName}.${propName}`, taint]);
    }
  }
  for (const [k, t] of toSet) env.set(k, t);

  // Also register prototype methods for the constructor under instance.methodName
  const constructorFuncs = [];
  for (const [key, funcNode] of ctx.funcMap) {
    // Match "Widget.prototype.render" style entries
    if (key.includes('.prototype.')) {
      const parts = key.split('.prototype.');
      if (parts.length === 2) {
        constructorFuncs.push([`${instanceName}.${parts[1]}`, funcNode]);
        constructorFuncs.push([parts[1], funcNode]);
      }
    }
  }
  for (const [k, f] of constructorFuncs) ctx.funcMap.set(k, f);
}

// ── Evaluate an expression, returning its TaintSet ──
export function evaluateExpr(node, env, ctx) {
  if (!node) return TaintSet.empty();

  switch (node.type) {
    case 'Identifier': {
      // Scope-resolved lookup: try the binding key first, then fall back to global
      const key = resolveId(node, ctx);
      const taint = env.get(key);
      if (taint.tainted) return taint.clone();
      // Fall back: check raw name in case taint was set by another script
      return env.get(`global:${node.name}`).clone();
    }

    case 'MemberExpression':
    case 'OptionalMemberExpression':
      return evaluateMemberExpr(node, env, ctx);

    case 'CallExpression':
    case 'OptionalCallExpression':
      return evaluateCallExpr(node, env, ctx);

    case 'NewExpression':
      return evaluateNewExpr(node, env, ctx);

    case 'AssignmentExpression':
      processAssignment(node, env, ctx);
      return evaluateExpr(node.left, env, ctx);

    case 'BinaryExpression':
      return evaluateExpr(node.left, env, ctx).clone().merge(evaluateExpr(node.right, env, ctx));

    case 'LogicalExpression':
      return evaluateExpr(node.left, env, ctx).clone().merge(evaluateExpr(node.right, env, ctx));

    case 'UnaryExpression':
      if (node.operator === '!' || node.operator === 'typeof' ||
          node.operator === '+' || node.operator === '-' || node.operator === '~' ||
          node.operator === 'void') {
        return TaintSet.empty();
      }
      return evaluateExpr(node.argument, env, ctx);

    case 'UpdateExpression':
      return TaintSet.empty();

    case 'ConditionalExpression':
      evaluateExpr(node.test, env, ctx);
      return evaluateExpr(node.consequent, env, ctx).clone().merge(evaluateExpr(node.alternate, env, ctx));

    case 'TemplateLiteral': {
      const t = TaintSet.empty();
      for (const expr of node.expressions) t.merge(evaluateExpr(expr, env, ctx));
      return t;
    }

    case 'TaggedTemplateExpression': {
      const t = TaintSet.empty();
      for (const expr of node.quasi.expressions) t.merge(evaluateExpr(expr, env, ctx));
      return t;
    }

    case 'SequenceExpression': {
      let r = TaintSet.empty();
      for (const expr of node.expressions) r = evaluateExpr(expr, env, ctx);
      return r;
    }

    case 'ObjectExpression': {
      const t = TaintSet.empty();
      for (const prop of node.properties) {
        if (prop.type === 'SpreadElement') t.merge(evaluateExpr(prop.argument, env, ctx));
        else if (prop.type === 'ObjectProperty' || prop.type === 'Property') t.merge(evaluateExpr(prop.value, env, ctx));
      }
      return t;
    }

    case 'ArrayExpression': {
      const t = TaintSet.empty();
      for (const elem of node.elements) if (elem) t.merge(evaluateExpr(elem, env, ctx));
      return t;
    }

    case 'SpreadElement':
      return evaluateExpr(node.argument, env, ctx);

    case 'ArrowFunctionExpression':
    case 'FunctionExpression':
      node._closureEnv = env;
      return TaintSet.empty();

    case 'AwaitExpression':
      return evaluateExpr(node.argument, env, ctx);

    case 'YieldExpression':
      return node.argument ? evaluateExpr(node.argument, env, ctx) : TaintSet.empty();

    case 'ChainExpression':
    case 'ParenthesizedExpression':
      return evaluateExpr(node.expression, env, ctx);

    case 'StringLiteral':
    case 'NumericLiteral':
    case 'BooleanLiteral':
    case 'NullLiteral':
    case 'BigIntLiteral':
    case 'RegExpLiteral':
      return TaintSet.empty();

    case 'ThisExpression':
      return env.get('this');

    default:
      return TaintSet.empty();
  }
}

// ── Member expression ──
function evaluateMemberExpr(node, env, ctx) {
  const sourceLabel = checkMemberSource(node);
  if (sourceLabel) {
    const loc = node.loc?.start || {};
    return TaintSet.from(new TaintLabel(sourceLabel, ctx.file, loc.line || 0, loc.column || 0, nodeToString(node)));
  }

  const fullPath = nodeToString(node);
  if (fullPath) {
    const propTaint = env.get(fullPath);
    if (propTaint.tainted) return propTaint.clone();
  }

  // Properties that always produce a number or boolean — kill taint
  const propName = !node.computed && node.property ? (node.property.name || node.property.value) : null;
  if (propName && NUMERIC_PROPS.has(propName)) {
    evaluateExpr(node.object, env, ctx); // still evaluate for side effects
    return TaintSet.empty();
  }

  const objTaint = evaluateExpr(node.object, env, ctx);
  if (node.computed) evaluateExpr(node.property, env, ctx);
  return objTaint;
}

// Properties that always return a number or boolean (not attacker-controlled strings)
const NUMERIC_PROPS = new Set([
  'length', 'size', 'byteLength', 'byteOffset',
  'childElementCount', 'clientHeight', 'clientWidth',
  'scrollHeight', 'scrollWidth', 'scrollTop', 'scrollLeft',
  'offsetHeight', 'offsetWidth', 'offsetTop', 'offsetLeft',
  'naturalHeight', 'naturalWidth',
  'status', 'readyState', 'nodeType',
]);

// ── Call expression ──
function evaluateCallExpr(node, env, ctx) {
  const calleeStr = nodeToString(node.callee);
  const methodName = (node.callee.type === 'MemberExpression' || node.callee.type === 'OptionalMemberExpression') ? node.callee.property?.name || '' : '';

  // For factory()() patterns: evaluate the callee CallExpression first
  // so ctx.returnedFuncNode is set before analyzeCalledFunction runs
  if (node.callee.type === 'CallExpression' || node.callee.type === 'OptionalCallExpression') {
    evaluateExpr(node.callee, env, ctx);
  }

  const argTaints = node.arguments.map(arg => evaluateExpr(arg, env, ctx));

  if (isSanitizer(calleeStr, methodName)) return TaintSet.empty();

  const sinkInfo = checkCallSink(calleeStr, methodName);
  if (sinkInfo) checkSinkCall(node, sinkInfo, argTaints, calleeStr || methodName, ctx);

  // setTimeout/setInterval with function callback: analyze body for closure taint reaching sinks
  if ((calleeStr === 'setTimeout' || calleeStr === 'setInterval') && node.arguments[0]) {
    let callback = node.arguments[0];
    if (callback.type === 'Identifier') {
      const refKey = resolveId(callback, ctx);
      callback = ctx.funcMap.get(refKey) || ctx.funcMap.get(callback.name) || callback;
    }
    if (callback.type === 'ArrowFunctionExpression' || callback.type === 'FunctionExpression' ||
        callback.type === 'FunctionDeclaration') {
      const childEnv = (callback._closureEnv || env).child();
      if (callback.body.type === 'BlockStatement') {
        analyzeInlineFunction(callback, childEnv, ctx);
      } else {
        evaluateExpr(callback.body, childEnv, ctx);
      }
    }
  }

  // Object.assign(target, ...sources) — propagate taint from sources to target and return
  if (calleeStr === 'Object.assign' && node.arguments.length >= 2) {
    const merged = argTaints.reduce((acc, t) => acc.merge(t), TaintSet.empty());
    // If target is an identifier or member, update its taint in env
    const targetNode = node.arguments[0];
    if (targetNode) {
      const targetStr = nodeToString(targetNode);
      if (targetStr) {
        env.set(targetStr, env.get(targetStr).clone().merge(merged));
        if (targetNode.type === 'Identifier') {
          const key = resolveId(targetNode, ctx);
          env.set(key, env.get(key).clone().merge(merged));
        }
      }
    }
    return merged;
  }

  if (calleeStr && CALL_SOURCES[calleeStr] && CALL_SOURCES[calleeStr] !== 'passthrough') {
    const loc = node.loc?.start || {};
    return TaintSet.from(new TaintLabel(CALL_SOURCES[calleeStr], ctx.file, loc.line || 0, loc.column || 0, calleeStr + '()'));
  }

  if (calleeStr && isPassthrough(calleeStr)) return argTaints[0]?.clone() || TaintSet.empty();

  const propagated = handleBuiltinMethod(methodName, node, argTaints, env, ctx);
  if (propagated !== null) return propagated;

  return analyzeCalledFunction(node, calleeStr, argTaints, env, ctx);
}

// ── New expression ──
function evaluateNewExpr(node, env, ctx) {
  const constructorName = nodeToString(node.callee);
  const argTaints = node.arguments.map(arg => evaluateExpr(arg, env, ctx));

  if (constructorName && CONSTRUCTOR_SOURCES[constructorName]) {
    const argTaint = argTaints.reduce((acc, t) => acc.merge(t), TaintSet.empty());
    if (argTaint.tainted) return argTaint;
    const loc = node.loc?.start || {};
    return TaintSet.from(new TaintLabel(CONSTRUCTOR_SOURCES[constructorName], ctx.file, loc.line || 0, loc.column || 0, `new ${constructorName}()`));
  }

  if (constructorName === 'Function') {
    checkSinkCall(node, { type: 'XSS', taintedArgs: [0] }, argTaints, 'new Function()', ctx);
  }

  // Analyze constructor body to track this.* assignments
  if (constructorName) {
    const funcNode = ctx.funcMap.get(constructorName);
    if (funcNode && funcNode.body) {
      const callSig = `new:${constructorName}:${argTaints.map(t => t.tainted ? '1' : '0').join('')}`;
      if (!ctx.analyzedCalls.has(callSig)) {
        ctx.analyzedCalls.add(callSig);
        const childEnv = (funcNode._closureEnv || env).child();
        // Set up 'this' as empty so this.* assignments are tracked
        childEnv.set('this', TaintSet.empty());
        for (let i = 0; i < funcNode.params.length; i++) {
          assignToPattern(funcNode.params[i], argTaints[i] || TaintSet.empty(), childEnv, ctx);
        }
        const body = funcNode.body.type === 'BlockStatement' ? funcNode.body
          : { type: 'BlockStatement', body: [{ type: 'ReturnStatement', argument: funcNode.body }] };
        analyzeInlineFunction({ ...funcNode, body }, childEnv, ctx);

        // Propagate this.* taint to the instance variable name
        // The caller will assign this result to a variable, and we propagate this.* taint
        const thisTaint = TaintSet.empty();
        for (const [key, taint] of childEnv.bindings) {
          if (key.startsWith('this.') && taint.tainted) {
            env.set(key, taint);  // Will be resolved via instance later
            thisTaint.merge(taint);
          }
        }
        if (thisTaint.tainted) return thisTaint;
      }
    }
  }

  return argTaints.reduce((acc, t) => acc.merge(t), TaintSet.empty());
}

// ── Built-in method taint propagation ──
function handleBuiltinMethod(methodName, node, argTaints, env, ctx) {
  const objTaint = node.callee?.object ? evaluateExpr(node.callee.object, env, ctx) : TaintSet.empty();

  switch (methodName) {
    case 'slice': case 'substring': case 'substr': case 'trim': case 'trimStart':
    case 'trimEnd': case 'toLowerCase': case 'toUpperCase': case 'normalize':
    case 'repeat': case 'padStart': case 'padEnd': case 'at': case 'charAt':
    case 'charCodeAt': case 'valueOf': case 'toString':
      return objTaint.clone();

    case 'concat':
      return objTaint.clone().merge(argTaints.reduce((a, t) => a.merge(t), TaintSet.empty()));

    case 'replace': case 'replaceAll':
      return objTaint.clone().merge(argTaints[1] || TaintSet.empty());

    case 'split':
      return objTaint.clone();

    case 'join':
      return objTaint.clone().merge(argTaints[0] || TaintSet.empty());

    case 'map': {
      const cbTaint = analyzeArrayCallback(node, argTaints, objTaint, env, ctx);
      return objTaint.clone().merge(cbTaint);
    }

    case 'filter': case 'find': case 'findIndex': case 'some': case 'every':
    case 'flat': case 'flatMap': case 'reverse': case 'sort':
    case 'values': case 'keys': case 'entries':
      return objTaint.clone();

    case 'reduce': case 'reduceRight':
      return objTaint.clone().merge(argTaints[1] || TaintSet.empty());

    case 'forEach':
      analyzeArrayCallback(node, argTaints, objTaint, env, ctx);
      return TaintSet.empty();

    case 'push': case 'unshift':
      if (node.callee?.object) {
        const objStr = nodeToString(node.callee.object);
        if (objStr) {
          const merged = env.get(objStr).clone();
          for (const t of argTaints) merged.merge(t);
          env.set(objStr, merged);
        }
        // Also update scope-resolved key if it's an identifier
        if (node.callee.object.type === 'Identifier') {
          const key = resolveId(node.callee.object, ctx);
          const merged = env.get(key).clone();
          for (const t of argTaints) merged.merge(t);
          env.set(key, merged);
        }
      }
      return TaintSet.empty();

    case 'pop': case 'shift':
      return objTaint.clone();

    case 'get': case 'getAll': {
      if (objTaint.tainted) return objTaint.clone();
      const objStr = nodeToString(node.callee?.object);
      if (objStr === 'localStorage' || objStr === 'sessionStorage') {
        const loc = node.loc?.start || {};
        return TaintSet.from(new TaintLabel(`storage.${objStr === 'localStorage' ? 'local' : 'session'}`, ctx.file, loc.line || 0, loc.column || 0, `${objStr}.getItem()`));
      }
      return TaintSet.empty();
    }

    case 'getItem': {
      const objStr = nodeToString(node.callee?.object);
      if (objStr === 'localStorage' || objStr === 'sessionStorage') {
        const loc = node.loc?.start || {};
        return TaintSet.from(new TaintLabel(`storage.${objStr === 'localStorage' ? 'local' : 'session'}`, ctx.file, loc.line || 0, loc.column || 0, `${objStr}.getItem()`));
      }
      return objTaint.clone();
    }

    case 'getElementById': case 'querySelector': case 'querySelectorAll':
    case 'getElementsByClassName': case 'getElementsByTagName':
    case 'getAttribute':
      return TaintSet.empty();

    case 'json': case 'text': case 'arrayBuffer': case 'blob':
      return objTaint.clone();

    case 'then': case 'catch': case 'finally':
      return analyzePromiseCallback(node, argTaints, objTaint, env, ctx);

    case 'addEventListener':
      return analyzeEventListener(node, argTaints, env, ctx);

    case 'all': case 'race': case 'any': case 'allSettled':
      // Promise.all([...]) — propagate taint from array argument
      return argTaints[0]?.clone() || TaintSet.empty();

    case 'assign':
      // Object.assign handled in evaluateCallExpr; fallback here for chained patterns
      return argTaints.reduce((acc, t) => acc.merge(t), TaintSet.empty());

    default:
      return null;
  }
}

// ── Analyze addEventListener callback (especially 'message') ──
function analyzeEventListener(node, argTaints, env, ctx) {
  const eventType = node.arguments[0];
  let callback = node.arguments[1];
  if (!eventType || !callback) return TaintSet.empty();

  // Resolve named function references: addEventListener('message', handleMessage)
  if (callback.type === 'Identifier') {
    const refKey = resolveId(callback, ctx);
    const refFunc = ctx.funcMap.get(refKey) || ctx.funcMap.get(callback.name);
    if (refFunc) callback = refFunc;
    else return TaintSet.empty();
  }

  if (callback.type !== 'ArrowFunctionExpression' && callback.type !== 'FunctionExpression' &&
      callback.type !== 'FunctionDeclaration') return TaintSet.empty();

  const eventName = eventType.value;
  const childEnv = env.child();

  if (eventName === 'message' && callback.params[0]) {
    // Check if the handler validates event.origin
    const checksOrigin = callbackChecksOrigin(callback.body);
    if (!checksOrigin) {
      const paramName = callback.params[0].type === 'Identifier' ? callback.params[0].name : null;
      if (paramName) {
        const loc = callback.loc?.start || {};
        const label = new TaintLabel('postMessage.data', ctx.file, loc.line || 0, loc.column || 0, `${paramName}.data (no origin check)`);
        assignToPattern(callback.params[0], TaintSet.from(label), childEnv, ctx);
        childEnv.set(`${paramName}.data`, TaintSet.from(label));
      }
    }
  }

  if (callback.body.type === 'BlockStatement') {
    return analyzeInlineFunction(callback, childEnv, ctx);
  }
  return evaluateExpr(callback.body, childEnv, ctx);
}

function callbackChecksOrigin(node) {
  if (!node || typeof node !== 'object') return false;
  if (node.type === 'BinaryExpression' && (node.operator === '===' || node.operator === '==' || node.operator === '!==' || node.operator === '!=')) {
    const l = nodeToString(node.left), r = nodeToString(node.right);
    if ((l && l.endsWith('.origin')) || (r && r.endsWith('.origin'))) return true;
  }
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'start' || key === 'end' || key === '_closureEnv') continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) { if (item && typeof item === 'object' && item.type && callbackChecksOrigin(item)) return true; }
    } else if (child && typeof child === 'object' && child.type && callbackChecksOrigin(child)) return true;
  }
  return false;
}

// ── Analyze callback passed to array methods ──
function analyzeArrayCallback(node, argTaints, objTaint, env, ctx) {
  let callback = node.arguments[0];
  if (!callback) return TaintSet.empty();
  // Resolve named function references: arr.forEach(renderItem)
  if (callback.type === 'Identifier') {
    const refKey = resolveId(callback, ctx);
    const refFunc = ctx.funcMap.get(refKey) || ctx.funcMap.get(callback.name);
    if (refFunc) callback = refFunc;
    else return TaintSet.empty();
  }
  if (callback.type !== 'ArrowFunctionExpression' && callback.type !== 'FunctionExpression' &&
      callback.type !== 'FunctionDeclaration') return TaintSet.empty();

  const childEnv = env.child();
  if (callback.params[0]) assignToPattern(callback.params[0], objTaint, childEnv, ctx);
  if (callback.params[1]) assignToPattern(callback.params[1], TaintSet.empty(), childEnv, ctx);

  if (callback.body.type === 'BlockStatement') {
    return analyzeInlineFunction(callback, childEnv, ctx);
  }
  return evaluateExpr(callback.body, childEnv, ctx);
}

// ── Promise callback ──
function analyzePromiseCallback(node, argTaints, objTaint, env, ctx) {
  const callback = node.arguments[0];
  if (!callback) return objTaint.clone();
  if (callback.type !== 'ArrowFunctionExpression' && callback.type !== 'FunctionExpression') return objTaint.clone();

  const childEnv = env.child();
  if (callback.params[0]) assignToPattern(callback.params[0], objTaint, childEnv, ctx);

  if (callback.body.type === 'BlockStatement') {
    return analyzeInlineFunction(callback, childEnv, ctx);
  }
  return evaluateExpr(callback.body, childEnv, ctx);
}

// ── Analyze inline function body ──
function analyzeInlineFunction(funcNode, env, ctx) {
  const innerCfg = buildCFG(funcNode.body);
  const innerCtx = new AnalysisContext(
    ctx.file, new Map(ctx.funcMap), ctx.findings,
    ctx.globalEnv, ctx.scopeInfo, ctx.analyzedCalls
  );

  const blockEnvs = new Map();
  blockEnvs.set(innerCfg.entry.id, env.clone());
  const worklist = [innerCfg.entry];
  const inWorklist = new Set([innerCfg.entry.id]);

  while (worklist.length > 0) {
    const block = worklist.shift();
    inWorklist.delete(block.id);
    const entryEnv = blockEnvs.get(block.id);
    if (!entryEnv) continue;

    const exitEnv = processBlock(block, entryEnv.clone(), innerCtx);

    for (const succ of block.successors) {
      const existing = blockEnvs.get(succ.id);
      if (!existing) {
        blockEnvs.set(succ.id, exitEnv.clone());
        if (!inWorklist.has(succ.id)) { worklist.push(succ); inWorklist.add(succ.id); }
      } else {
        if (existing.mergeFrom(exitEnv) && !inWorklist.has(succ.id)) {
          worklist.push(succ); inWorklist.add(succ.id);
        }
      }
    }
  }

  // Merge exit state back to the caller's env so side effects are visible
  // (e.g., this.data = x inside a method becomes visible as obj.data)
  const exitState = blockEnvs.get(innerCfg.exit.id);
  if (exitState) env.mergeFrom(exitState);
  for (const pred of innerCfg.exit.predecessors) {
    const state = blockEnvs.get(pred.id);
    if (state) env.mergeFrom(state);
  }

  // Propagate returned function/method info back to the caller
  if (innerCtx.returnedFuncNode) ctx.returnedFuncNode = innerCtx.returnedFuncNode;
  if (innerCtx.returnedMethods) ctx.returnedMethods = innerCtx.returnedMethods;

  return innerCtx.returnTaint;
}

// ── Interprocedural: analyze a called function ──
function analyzeCalledFunction(callNode, calleeStr, argTaints, env, ctx) {
  let funcNode = null;

  // Resolve via scope-aware binding key
  if (callNode.callee?.type === 'Identifier') {
    const key = resolveId(callNode.callee, ctx);
    if (ctx.funcMap.has(key)) funcNode = ctx.funcMap.get(key);
  }

  // Fall back to raw name
  if (!funcNode && calleeStr && ctx.funcMap.has(calleeStr)) {
    funcNode = ctx.funcMap.get(calleeStr);
  }

  // Inline function expression / arrow
  if (!funcNode && callNode.callee) {
    if (callNode.callee.type === 'ArrowFunctionExpression' ||
        callNode.callee.type === 'FunctionExpression') {
      funcNode = callNode.callee;
    }
    // Immediately-invoked return: factory()(arg) — callee is a CallExpression
    if (!funcNode && (callNode.callee.type === 'CallExpression' || callNode.callee.type === 'OptionalCallExpression')) {
      // The callee was already evaluated by evaluateCallExpr (which set ctx.returnedFuncNode)
      // Check if a function node was returned
      if (ctx.returnedFuncNode) {
        funcNode = ctx.returnedFuncNode;
        ctx.returnedFuncNode = null;
      }
    }
  }

  // Method call: try full dot-path first (e.g., "obj.render"), then plain method name
  if (!funcNode && (callNode.callee?.type === 'MemberExpression' || callNode.callee?.type === 'OptionalMemberExpression')) {
    const fullPath = nodeToString(callNode.callee);
    if (fullPath && ctx.funcMap.has(fullPath)) funcNode = ctx.funcMap.get(fullPath);
    if (!funcNode) {
      const methodName = callNode.callee.property?.name;
      if (methodName && ctx.funcMap.has(methodName)) funcNode = ctx.funcMap.get(methodName);
    }
  }

  if (!funcNode || !funcNode.body) return TaintSet.empty();

  const callSig = `${calleeStr || 'anon'}:${argTaints.map(t => t.tainted ? '1' : '0').join('')}`;
  if (ctx.analyzedCalls.has(callSig)) return TaintSet.empty();
  ctx.analyzedCalls.add(callSig);

  const closureEnv = funcNode._closureEnv || env;
  const childEnv = closureEnv.child();

  // For method calls (obj.method()), bind 'this' to the receiver object
  // Propagate obj.* taint as this.* so this.prop lookups resolve correctly
  if (callNode.callee?.type === 'MemberExpression' || callNode.callee?.type === 'OptionalMemberExpression') {
    const objName = nodeToString(callNode.callee.object);
    if (objName) {
      const objTaint = evaluateExpr(callNode.callee.object, env, ctx);
      childEnv.set('this', objTaint);
      // Copy obj.* bindings to this.* (search all env layers)
      const objBindings = env.getTaintedWithPrefix(`${objName}.`);
      for (const [key, taint] of objBindings) {
        const propName = key.slice(objName.length + 1);
        childEnv.set(`this.${propName}`, taint);
      }
    }
  }

  // Store function expression arguments in funcMap so they can be called inside the body
  // Handles: doRender(function(html) { ... }) → fn(x) resolves fn to the passed function
  const innerFuncMap = new Map(ctx.funcMap);
  for (let i = 0; i < funcNode.params.length; i++) {
    const param = funcNode.params[i];
    if (param.type === 'Identifier' && callNode.arguments[i]) {
      const argNode = callNode.arguments[i];
      if (argNode.type === 'FunctionExpression' || argNode.type === 'ArrowFunctionExpression') {
        argNode._closureEnv = env;
        innerFuncMap.set(param.name, argNode);
        const paramKey = resolveId(param, ctx);
        innerFuncMap.set(paramKey, argNode);
      }
      // Also resolve identifier args that reference known functions
      if (argNode.type === 'Identifier') {
        const refKey = resolveId(argNode, ctx);
        const refFunc = ctx.funcMap.get(refKey) || ctx.funcMap.get(argNode.name);
        if (refFunc) {
          innerFuncMap.set(param.name, refFunc);
          const paramKey = resolveId(param, ctx);
          innerFuncMap.set(paramKey, refFunc);
        }
      }
    }
    if (param.type === 'RestElement') {
      const restTaint = TaintSet.empty();
      for (let j = i; j < argTaints.length; j++) restTaint.merge(argTaints[j]);
      assignToPattern(param.argument, restTaint, childEnv, ctx);
    } else {
      assignToPattern(param, argTaints[i] || TaintSet.empty(), childEnv, ctx);
    }
  }

  const savedFuncMap = ctx.funcMap;
  ctx.funcMap = innerFuncMap;

  const body = funcNode.body.type === 'BlockStatement'
    ? funcNode.body
    : { type: 'BlockStatement', body: [{ type: 'ReturnStatement', argument: funcNode.body }] };
  const result = analyzeInlineFunction({ ...funcNode, body }, childEnv, ctx);

  ctx.funcMap = savedFuncMap;

  // Propagate this.* side effects back to the receiver object (setter pattern)
  // After obj.setData(tainted), if setData sets this.data, copy it back as obj.data
  if (callNode.callee?.type === 'MemberExpression' || callNode.callee?.type === 'OptionalMemberExpression') {
    const objName = nodeToString(callNode.callee.object);
    if (objName) {
      for (const [key, taint] of childEnv.bindings) {
        if (key.startsWith('this.') && taint.tainted) {
          const propName = key.slice(5);
          env.set(`${objName}.${propName}`, taint);
        }
      }
    }
  }

  return result;
}

// ── For-in/of binding ──
function processForBinding(node, env, ctx) {
  const iterableTaint = evaluateExpr(node.right, env, ctx);
  if (node.left.type === 'VariableDeclaration') {
    for (const decl of node.left.declarations) assignToPattern(decl.id, iterableTaint, env, ctx);
  } else {
    assignToPattern(node.left, iterableTaint, env, ctx);
  }
}

// ── Sink checks ──
function checkSinkAssignment(leftNode, rhsTaint, ctx) {
  if (!rhsTaint.tainted) return;

  const leftStr = nodeToString(leftNode);
  const propName = leftNode.type === 'MemberExpression' ? leftNode.property?.name : null;
  const sinkInfo = checkAssignmentSink(leftStr, propName);
  if (!sinkInfo) return;

  const loc = leftNode.loc?.start || {};
  ctx.findings.push({
    type: sinkInfo.type,
    severity: sinkInfo.type === 'XSS' ? 'critical' : 'high',
    title: `${sinkInfo.type}: tainted data flows to ${leftStr || propName}`,
    sink: { expression: leftStr || propName, file: ctx.file, line: loc.line || 0, col: loc.column || 0 },
    source: rhsTaint.toArray().map(l => ({ type: l.sourceType, description: l.description, file: l.file, line: l.line })),
    path: buildTaintPath(rhsTaint, leftStr || propName),
  });
}

function checkSinkCall(callNode, sinkInfo, argTaints, calleeStr, ctx) {
  for (const argIdx of sinkInfo.taintedArgs) {
    const argTaint = argTaints[argIdx];
    if (!argTaint || !argTaint.tainted) continue;

    if (sinkInfo.stringOnly && callNode.arguments[argIdx]) {
      const argNode = callNode.arguments[argIdx];
      if (argNode.type === 'ArrowFunctionExpression' || argNode.type === 'FunctionExpression') continue;
    }

    const loc = callNode.loc?.start || {};
    ctx.findings.push({
      type: sinkInfo.type,
      severity: sinkInfo.type === 'XSS' ? 'critical' : 'high',
      title: `${sinkInfo.type}: tainted data flows to ${calleeStr}()`,
      sink: { expression: `${calleeStr}(arg${argIdx})`, file: ctx.file, line: loc.line || 0, col: loc.column || 0 },
      source: argTaint.toArray().map(l => ({ type: l.sourceType, description: l.description, file: l.file, line: l.line })),
      path: buildTaintPath(argTaint, calleeStr),
    });
  }
}

// ── Prototype pollution ──
export function checkPrototypePollution(node, env, ctx) {
  if (node.type !== 'AssignmentExpression') return;
  const left = node.left;
  if (left.type !== 'MemberExpression' || !left.computed) return;

  if (left.object.type === 'MemberExpression' && left.object.computed) {
    const outerKey = evaluateExpr(left.object.property, env, ctx);
    const innerKey = evaluateExpr(left.property, env, ctx);

    if (outerKey.tainted && innerKey.tainted) {
      const loc = node.loc?.start || {};
      ctx.findings.push({
        type: 'Prototype Pollution',
        severity: 'critical',
        title: 'Prototype Pollution: attacker controls nested property keys',
        sink: { expression: nodeToString(left) || 'obj[key1][key2]', file: ctx.file, line: loc.line || 0, col: loc.column || 0 },
        source: outerKey.clone().merge(innerKey).toArray().map(l => ({ type: l.sourceType, description: l.description, file: l.file, line: l.line })),
        path: buildTaintPath(outerKey.clone().merge(innerKey), 'obj[key1][key2]'),
      });
    }
  }
}

function buildTaintPath(taintSet, sinkExpr) {
  return taintSet.toArray().map(label => `${label.description} (${label.file}:${label.line}) → ${sinkExpr}`);
}
