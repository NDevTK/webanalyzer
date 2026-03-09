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
    // Path-sensitive: variables confirmed to have http/https URL scheme on this path
    this.schemeCheckedVars = new Set();
    // Track new URL(x) origins: urlVar → sourceVar (so checking url.protocol also validates sourceVar)
    this.urlConstructorOrigins = new Map();
    // Object aliases: varName → globalName (e.g., loc → location, doc → document)
    this.aliases = new Map();
  }

  get(key) {
    let cur = this;
    while (cur) {
      if (cur.bindings.has(key)) return cur.bindings.get(key);
      cur = cur.parent;
    }
    return TaintSet.empty();
  }

  set(key, taintSet) { this.bindings.set(key, taintSet); }

  has(key) {
    let cur = this;
    while (cur) {
      if (cur.bindings.has(key)) return true;
      cur = cur.parent;
    }
    return false;
  }

  child() { return new TaintEnv(this); }

  clone() {
    const env = new TaintEnv(this.parent);
    for (const [k, v] of this.bindings) env.bindings.set(k, v.clone());
    env.schemeCheckedVars = new Set(this.schemeCheckedVars);
    env.urlConstructorOrigins = new Map(this.urlConstructorOrigins);
    env.aliases = new Map(this.aliases);
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
    // Scheme-checked vars: intersection at join points (conservative —
    // only keep vars checked on ALL incoming paths)
    if (this.schemeCheckedVars.size === 0 && other.schemeCheckedVars.size > 0) {
      // First merge: adopt other's set
      for (const v of other.schemeCheckedVars) this.schemeCheckedVars.add(v);
      changed = true;
    } else if (this.schemeCheckedVars.size > 0 && other.schemeCheckedVars.size > 0) {
      // Subsequent merges: intersect
      for (const v of this.schemeCheckedVars) {
        if (!other.schemeCheckedVars.has(v)) {
          this.schemeCheckedVars.delete(v);
          changed = true;
        }
      }
    }
    for (const [k, v] of other.urlConstructorOrigins) {
      if (!this.urlConstructorOrigins.has(k)) this.urlConstructorOrigins.set(k, v);
    }
    for (const [k, v] of other.aliases) {
      if (!this.aliases.has(k)) this.aliases.set(k, v);
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
    this.returnElementTaints = null; // per-element taints for array returns: [TaintSet, TaintSet, ...]
    this.returnPropertyTaints = null; // per-property taints for object returns: Map<string, TaintSet>
    // Shared across entire call chain — prevents re-analyzing same function with same taint
    this.analyzedCalls = analyzedCalls || new Map();
    this.returnedFuncNode = null;  // tracks function nodes returned from calls
    this.returnedMethods = null;   // tracks { name → funcNode } for returned objects
    this.scriptElements = new Set(); // tracks variables holding createElement('script') results
    this.thrownTaint = TaintSet.empty(); // tracks taint from ThrowStatement for catch param
    this.generatorTaint = new Map(); // maps generator function key → TaintSet from yield expressions
    this.eventListeners = new Map(); // eventName → [{callback, env}] for custom event dispatch tracking
    this.classBodyMap = new Map(); // className → classBody array
    this.superClassMap = new Map(); // className → parentClassName
    this.protoMethodMap = new Map(); // "ClassName" → [{methodName, funcNode}]
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
export function analyzeCFG(cfg, env, file, funcMap, globalEnv, scopeInfo, isWorker) {
  const findings = [];
  const ctx = new AnalysisContext(file, funcMap, findings, globalEnv || new TaintEnv(), scopeInfo);
  ctx.isWorker = !!isWorker;

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
      // Constant-fold: skip unreachable branches (e.g., if(false) consequent)
      if (succ.branchCondition && isConstantBool(succ.branchCondition) !== null) {
        const val = isConstantBool(succ.branchCondition);
        if (val === false && succ.branchPolarity === true) continue;
        if (val === true && succ.branchPolarity === false) continue;
      }
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
  // Path-sensitive: if this block is a branch consequent, check for URL scheme guards
  if (block.branchCondition) {
    applyBranchCondition(block.branchCondition, block.branchPolarity, env);
  }
  for (const node of block.nodes) processNode(node, env, ctx);
  return env;
}

// ── Path-sensitive URL scheme check detection ──
// Examines if-test conditions to determine if a variable's URL scheme has been validated.
// When a navigation sink is reached, scheme-checked vars produce "Open Redirect"
// instead of "XSS" (since javascript: URIs are blocked).

function applyBranchCondition(testNode, polarity, env) {
  const stack = [{ node: testNode, positive: polarity }];
  while (stack.length > 0) {
    let { node, positive } = stack.pop();
    // Unwrap negation: if (!expr) → analyze expr with flipped polarity
    while (node.type === 'UnaryExpression' && node.operator === '!') {
      positive = !positive;
      node = node.argument;
    }

    // Handle logical expressions: if (a && b) → both are true in consequent
    if (node.type === 'LogicalExpression' && node.operator === '&&' && positive) {
      stack.push({ node: node.left, positive: true });
      stack.push({ node: node.right, positive: true });
      continue;
    }
    // if (a || b) in the false branch → both are false
    if (node.type === 'LogicalExpression' && node.operator === '||' && !positive) {
      stack.push({ node: node.left, positive: false });
      stack.push({ node: node.right, positive: false });
      continue;
    }
    // if (a || b) in the true branch → at least one is true
    if (node.type === 'LogicalExpression' && node.operator === '||' && positive) {
      const leftVar = extractSchemeCheck(node.left, true);
      const rightVar = extractSchemeCheck(node.right, true);
      if (leftVar && rightVar && leftVar === rightVar) {
        env.schemeCheckedVars.add(leftVar);
        const origin = env.urlConstructorOrigins.get(leftVar);
        if (origin) env.schemeCheckedVars.add(origin);
        continue;
      }
      stack.push({ node: node.left, positive: true });
      stack.push({ node: node.right, positive: true });
      continue;
    }

    const checkedVar = extractSchemeCheck(node, positive);
    if (checkedVar) {
      env.schemeCheckedVars.add(checkedVar);
      const origin = env.urlConstructorOrigins.get(checkedVar);
      if (origin) env.schemeCheckedVars.add(origin);
    }
  }
}

// Returns the variable name if `node` (with given polarity) represents a URL scheme check.
// Recognizes:
//   url.startsWith('http') / url.startsWith('https') / url.startsWith('/')
//   url.indexOf('http') === 0
//   url.protocol === 'http:' / 'https:'
//   url.protocol !== 'javascript:'
//   /^https?:\/\//.test(url)  /  url.match(/^https?:/)
//   url.slice(0,4) === 'http' / url.substring(0,4) === 'http'
function extractSchemeCheck(node, positive) {
  // Pattern: url.startsWith('http') or url.startsWith('https') or url.startsWith('/')
  if (node.type === 'CallExpression' && positive) {
    const callee = node.callee;
    if (callee.type === 'MemberExpression' && callee.property?.name === 'startsWith') {
      const arg = node.arguments[0];
      if (arg && isStringLiteral(arg)) {
        const val = stringLiteralValue(arg);
        if (isSafeSchemeValue(val)) {
          return nodeToString(callee.object);
        }
      }
    }
    // Pattern: /^https?:\/\//.test(url)  or  regex.test(url)
    if (callee.type === 'MemberExpression' && callee.property?.name === 'test') {
      if (callee.object.type === 'RegExpLiteral' || callee.object.regex) {
        const pattern = callee.object.pattern || callee.object.regex?.pattern || '';
        if (isHttpSchemeRegex(pattern)) {
          const arg = node.arguments[0];
          return arg ? nodeToString(arg) : null;
        }
      }
    }
    // Pattern: url.match(/^https?:/)
    if (callee.type === 'MemberExpression' && callee.property?.name === 'match') {
      const arg = node.arguments[0];
      if (arg && (arg.type === 'RegExpLiteral' || arg.regex)) {
        const pattern = arg.pattern || arg.regex?.pattern || '';
        if (isHttpSchemeRegex(pattern)) {
          return nodeToString(callee.object);
        }
      }
    }
  }

  // Pattern: url.startsWith('javascript:') with negated polarity (false branch)
  if (node.type === 'CallExpression' && !positive) {
    const callee = node.callee;
    if (callee.type === 'MemberExpression' && callee.property?.name === 'startsWith') {
      const arg = node.arguments[0];
      if (arg && isStringLiteral(arg) && isJavaScriptProtocol(stringLiteralValue(arg))) {
        return nodeToString(callee.object);
      }
    }
  }

  // Binary comparisons: === / !== / == / !=
  if (node.type === 'BinaryExpression') {
    const op = node.operator;
    const isEquality = op === '===' || op === '==';
    const isInequality = op === '!==' || op === '!=';

    // Determine effective check: equality+positive or inequality+negative → "equals"
    const isEquals = (isEquality && positive) || (isInequality && !positive);
    const isNotEquals = (isInequality && positive) || (isEquality && !positive);

    // Pattern: url.protocol === 'https:' or url.protocol === 'http:'
    if (isEquals) {
      const varSide = findProtocolMember(node.left) || findProtocolMember(node.right);
      const litSide = getStringLiteral(node.left) || getStringLiteral(node.right);
      if (varSide && litSide && isHttpProtocol(litSide)) {
        return varSide;
      }
    }

    // Pattern: url.protocol !== 'javascript:' (inequality check blocks javascript:)
    if (isNotEquals) {
      const varSide = findProtocolMember(node.left) || findProtocolMember(node.right);
      const litSide = getStringLiteral(node.left) || getStringLiteral(node.right);
      if (varSide && litSide && isJavaScriptProtocol(litSide)) {
        return varSide;
      }
    }

    // Pattern: url.indexOf('http') === 0
    if (isEquals) {
      const zeroSide = isNumericLiteral(node.left, 0) ? 'left' :
                        isNumericLiteral(node.right, 0) ? 'right' : null;
      const callSide = zeroSide === 'left' ? node.right : zeroSide === 'right' ? node.left : null;
      if (callSide && callSide.type === 'CallExpression') {
        const cc = callSide.callee;
        if (cc.type === 'MemberExpression' && cc.property?.name === 'indexOf') {
          const arg = callSide.arguments[0];
          if (arg && isStringLiteral(arg)) {
            const val = stringLiteralValue(arg);
            if (isSafeSchemeValue(val)) {
              return nodeToString(cc.object);
            }
          }
        }
      }
    }

    // Pattern: url.slice(0,4) === 'http' or url.substring(0,5) === 'https'
    if (isEquals) {
      const litVal = getStringLiteral(node.left) || getStringLiteral(node.right);
      const callNode = isStringLiteral(node.left) ? node.right : node.left;
      if (litVal && isSafeSchemeValue(litVal) &&
          callNode?.type === 'CallExpression') {
        const cc = callNode.callee;
        if (cc.type === 'MemberExpression' &&
            (cc.property?.name === 'slice' || cc.property?.name === 'substring' || cc.property?.name === 'substr')) {
          return nodeToString(cc.object);
        }
      }
    }
  }

  return null;
}

// ── Scheme value classification helpers ──
// Checks if a string literal value represents a safe HTTP(S) scheme prefix.
// Case-insensitive to handle 'HTTP', 'Https', etc.
function isSafeSchemeValue(val) {
  if (!val || typeof val !== 'string') return false;
  const lower = val.toLowerCase();
  return lower === 'http' || lower === 'https' ||
         lower === 'http:' || lower === 'https:' ||
         lower === 'http://' || lower === 'https://' ||
         lower === '/';
}

// Checks if a string literal value is a safe HTTP protocol for url.protocol comparison
function isHttpProtocol(val) {
  if (!val || typeof val !== 'string') return false;
  const lower = val.toLowerCase();
  return lower === 'http:' || lower === 'https:';
}

// Checks if a string literal value is the javascript: protocol
function isJavaScriptProtocol(val) {
  if (!val || typeof val !== 'string') return false;
  return val.toLowerCase() === 'javascript:';
}

// Checks if a regex pattern validates HTTP(S) scheme at string start.
// Recognizes anchored patterns: ^https?, ^(https?):, ^(?:https?), etc.
function isHttpSchemeRegex(pattern) {
  if (!pattern) return false;
  // Must be anchored at start
  if (pattern[0] !== '^') return false;
  // Strip the leading ^ and any grouping: (?, (?:, etc.
  let rest = pattern.slice(1);
  while (rest[0] === '(' || rest[0] === '?') {
    if (rest[0] === '(') { rest = rest.slice(1); continue; }
    if (rest[0] === '?' && rest[1] === ':') { rest = rest.slice(2); continue; }
    if (rest[0] === '?') { rest = rest.slice(1); continue; }
    break;
  }
  // Now check if it starts with http/https pattern
  return /^https?\??/.test(rest);
}

// Helpers for scheme check detection
function isStringLiteral(node) {
  return node && (node.type === 'StringLiteral' || (node.type === 'Literal' && typeof node.value === 'string'));
}
function stringLiteralValue(node) {
  return node.value;
}
function getStringLiteral(node) {
  return isStringLiteral(node) ? node.value : null;
}
function isNumericLiteral(node, value) {
  if (!node) return false;
  if (node.type === 'NumericLiteral' && node.value === value) return true;
  if (node.type === 'Literal' && typeof node.value === 'number' && node.value === value) return true;
  return false;
}
// Resolve an identifier to its constant string value if possible
// Uses scope info to find the variable's binding and check if it's a string literal
function resolveToConstant(node, _env, ctx) {
  if (!node) return undefined;
  if (isStringLiteral(node)) return node.value;
  if (node.type === 'NumericLiteral' || (node.type === 'Literal' && typeof node.value === 'number')) return node.value;
  if (node.type === 'Identifier' && ctx?.scopeInfo) {
    // Resolve via scope info to find the declaration node
    const bindingKey = ctx.scopeInfo.resolve(node);
    if (bindingKey) {
      const declNode = ctx.scopeInfo.bindingNodes.get(bindingKey);
      // VariableDeclarator: var key = 'hash' or var key = expr
      if (declNode?.type === 'VariableDeclarator' && declNode.init) {
        return resolveToConstant(declNode.init, _env, ctx);
      }
    }
  }
  // BinaryExpression '+': 'user' + 'Input' → 'userInput'
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = resolveToConstant(node.left, _env, ctx);
    const right = resolveToConstant(node.right, _env, ctx);
    if (left !== undefined && right !== undefined) return String(left) + String(right);
  }
  return undefined;
}

// Resolve the root identifier in a dotted path through env.aliases
// e.g., "w.location.hash" where w→window becomes "window.location.hash"
function resolveAliasedPath(path, env) {
  if (!path || !env.aliases.size) return path;
  const dotIdx = path.indexOf('.');
  const root = dotIdx === -1 ? path : path.slice(0, dotIdx);
  const alias = env.aliases.get(root);
  if (!alias || alias === root) return path;
  return dotIdx === -1 ? alias : `${alias}${path.slice(dotIdx)}`;
}

// Find a function expression/arrow returned from a function body (for IIFE resolution)
function findReturnedFunction(funcNode) {
  if (!funcNode?.body) return null;
  // Arrow with expression body: () => function() {...}
  if (funcNode.body.type === 'FunctionExpression' || funcNode.body.type === 'ArrowFunctionExpression') {
    return funcNode.body;
  }
  // Block body: look for return statements with function expressions
  if (funcNode.body.type === 'BlockStatement') {
    for (const stmt of funcNode.body.body) {
      if (stmt.type === 'ReturnStatement' && stmt.argument) {
        if (stmt.argument.type === 'FunctionExpression' || stmt.argument.type === 'ArrowFunctionExpression') {
          return stmt.argument;
        }
      }
    }
  }
  return null;
}

// Returns true/false if the node is a constant truthy/falsy literal, null if unknown
// When ctx is provided, can resolve Identifier references to their constant values
function isConstantBoolLeaf(node, ctx) {
  if (!node) return null;
  if (node.type === 'BooleanLiteral') return node.value;
  if (node.type === 'Literal' && typeof node.value === 'boolean') return node.value;
  if (node.type === 'NumericLiteral' || (node.type === 'Literal' && typeof node.value === 'number'))
    return node.value !== 0;
  if (node.type === 'StringLiteral' || (node.type === 'Literal' && typeof node.value === 'string'))
    return node.value !== '';
  if (node.type === 'NullLiteral' || (node.type === 'Literal' && node.value === null)) return false;
  if (node.type === 'Identifier' && node.name === 'undefined') return false;
  if (node.type === 'Identifier' && ctx?.scopeInfo) {
    const bindingKey = ctx.scopeInfo.resolve(node);
    if (bindingKey) {
      const declNode = ctx.scopeInfo.bindingNodes.get(bindingKey);
      if (declNode?.type === 'VariableDeclarator' && declNode.init)
        return isConstantBoolLeaf(declNode.init, null); // null ctx prevents further resolution
    }
  }
  return null;
}
function isConstantBool(node, ctx) {
  if (!node) return null;
  if (node.type !== 'LogicalExpression') return isConstantBoolLeaf(node, ctx);
  // Flatten into work stack to avoid recursion on deeply nested chains
  // Stack items: nodes to evaluate, processed right-to-left
  const work = []; // { op, node } — node is a non-LogicalExpression leaf
  let cur = node;
  while (cur.type === 'LogicalExpression') {
    work.push({ op: cur.operator, node: cur.right });
    cur = cur.left;
  }
  // cur is the leftmost non-LogicalExpression node; work is in reverse order
  let result = isConstantBool(cur, ctx);
  for (let i = work.length - 1; i >= 0; i--) {
    const { op, node: rhs } = work[i];
    const rhsVal = () => isConstantBool(rhs, ctx);
    if (op === '||') {
      if (result === true) return true;
      if (result === false) { result = rhsVal(); continue; }
      return null;
    } else if (op === '&&') {
      if (result === false) return false;
      if (result === true) { result = rhsVal(); continue; }
      return null;
    } else if (op === '??') {
      if (result !== null && result !== undefined) continue;
      return null;
    }
  }
  return result;
}
function findProtocolMember(node) {
  // Returns the base object name if node is X.protocol
  if (node?.type === 'MemberExpression' && node.property?.name === 'protocol') {
    return nodeToString(node.object);
  }
  return null;
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
        // Track per-element taints for array returns: return [expr1, expr2, ...]
        if (arg.type === 'ArrayExpression' && arg.elements.length > 0) {
          ctx.returnElementTaints = arg.elements.map(e => e ? evaluateExpr(e, env, ctx) : TaintSet.empty());
        }
        // Track per-property taints for object returns: return { a: tainted, b: safe }
        if (arg.type === 'ObjectExpression' && arg.properties.length > 0) {
          const propTaints = new Map();
          for (const prop of arg.properties) {
            if ((prop.type === 'ObjectProperty' || prop.type === 'Property') && prop.key) {
              const pName = prop.key.name || prop.key.value;
              if (pName) propTaints.set(pName, evaluateExpr(prop.value, env, ctx));
            }
          }
          if (propTaints.size > 0) ctx.returnPropertyTaints = propTaints;
        }
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
        // Store superclass reference for super() resolution
        const superName = node.superClass ? nodeToString(node.superClass) : null;
        let hasConstructor = false;
        for (const member of node.body.body) {
          if (member.type !== 'ClassMethod' && member.type !== 'MethodDefinition') continue;
          const mname = member.key?.name || member.key?.value;
          if (!mname) continue;
          if (member.static) {
            const getterPrefix = member.kind === 'get' ? 'getter:' : '';
            ctx.funcMap.set(`${getterPrefix}${className}.${mname}`, member);
            ctx.funcMap.set(`${getterPrefix}${mname}`, member);
            // Also register without getter prefix for regular method calls
            if (!getterPrefix) {
              ctx.funcMap.set(`${className}.${mname}`, member);
              ctx.funcMap.set(mname, member);
            }
          } else if (mname === 'constructor') {
            hasConstructor = true;
            if (superName) {
              member._superClass = superName;
              ctx.superClassMap.set(className, superName);
            }
            ctx.classBodyMap.set(className, node.body.body);
            ctx.funcMap.set(className, member);
          } else {
            // Register by className#method as canonical, plain name only if no collision
            ctx.funcMap.set(`${className}#${mname}`, member);
            if (!ctx.funcMap.has(mname)) ctx.funcMap.set(mname, member);
          }
        }
        // For classes without explicit constructor, store a synthetic entry
        if (!hasConstructor) {
          const synth = { type: 'ClassMethod', key: { name: 'constructor' }, params: [],
            body: { type: 'BlockStatement', body: [] } };
          if (superName) {
            synth._superClass = superName;
            ctx.superClassMap.set(className, superName);
          }
          ctx.classBodyMap.set(className, node.body.body);
          ctx.funcMap.set(className, synth);
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
      // Assign taint from ThrowStatement to the catch parameter
      // Catch params are block-scoped — don't pollute global:name
      if (node.param && ctx.thrownTaint.tainted) {
        const savedBlockScoped = ctx._blockScopedDecl;
        ctx._blockScopedDecl = true;
        assignToPattern(node.param, ctx.thrownTaint.clone(), env, ctx);
        ctx._blockScopedDecl = savedBlockScoped;
      }
      break;

    case 'ThrowStatement':
      if (node.argument) {
        const throwTaint = evaluateExpr(node.argument, env, ctx);
        if (throwTaint.tainted) {
          ctx.thrownTaint.merge(throwTaint);
        }
      }
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

    case 'ExpressionStatement':
      if (node.expression) evaluateExpr(node.expression, env, ctx);
      break;

    default:
      // Evaluate unknown node types for side effects (e.g., nested expressions)
      evaluateExpr(node, env, ctx);
      break;
  }
}

// ── Assign ObjectPattern destructuring with per-property resolution ──
// For `var { safe, tainted } = obj`, look up `obj.safe` and `obj.tainted` individually
function assignObjectPatternFromSource(pattern, srcStr, fallbackTaint, env, ctx) {
  // Resolve aliases: if srcStr is an alias for a global, use the resolved name for source lookups
  const resolvedSrc = resolveAliasedPath(srcStr, env);
  // Always try per-property lookup first for each property
  for (const prop of pattern.properties) {
    if (prop.type === 'RestElement') {
      assignToPattern(prop.argument, fallbackTaint, env, ctx);
      continue;
    }
    let keyName = null;
    if (prop.computed && prop.key) {
      // Computed key: { [expr]: val } — resolve the key expression's value
      if (prop.key.type === 'StringLiteral' || (prop.key.type === 'Literal' && typeof prop.key.value === 'string')) {
        keyName = prop.key.value;
      } else if (prop.key.type === 'Identifier') {
        // Try to resolve the identifier to a constant string value
        const resolved = resolveToConstant(prop.key, env, ctx);
        if (typeof resolved === 'string') keyName = resolved;
      }
    } else if (prop.key) {
      keyName = prop.key.name || prop.key.value;
    }
    if (keyName) {
      const propKey = `${srcStr}.${keyName}`;
      // Use per-property taint if the binding exists (even if empty/clean)
      if (env.has(propKey)) {
        assignToPattern(prop.value, env.get(propKey), env, ctx);
      } else if (MEMBER_SOURCES[propKey] || (resolvedSrc !== srcStr && MEMBER_SOURCES[`${resolvedSrc}.${keyName}`])) {
        // Destructuring from a known source: var { hash } = location → location.hash is a source
        const label = MEMBER_SOURCES[propKey] || MEMBER_SOURCES[`${resolvedSrc}.${keyName}`];
        const taint = new TaintSet();
        taint.add(new TaintLabel(label, ctx.file, prop.key.loc?.start?.line || 0, `${propKey}`));
        assignToPattern(prop.value, taint, env, ctx);
      } else {
        // No per-property data for this key — use overall object taint
        assignToPattern(prop.value, fallbackTaint, env, ctx);
      }
    } else {
      // Computed key that can't be resolved — use fallback (conservative)
      assignToPattern(prop.value, fallbackTaint, env, ctx);
    }
  }
}

// ── Store per-property taint from an ObjectExpression ──
// For `var obj = { safe: 'hello', tainted: location.hash }`, stores
// obj.safe → empty, obj.tainted → tainted, so destructuring can pick the right taint.
function storeObjectPropertyTaints(varName, objExpr, env, ctx) {
  for (const prop of objExpr.properties) {
    if (prop.type === 'SpreadElement') {
      // Copy per-property taints from spread source, overwriting earlier ones
      const srcStr = nodeToString(prop.argument);
      if (srcStr) {
        // Copy all known per-property taints from the spread source
        const srcTaints = env.getTaintedWithPrefix(`${srcStr}.`);
        for (const [key, taint] of srcTaints) {
          const propName = key.slice(srcStr.length + 1);
          if (propName && !propName.startsWith('#')) {
            env.set(`${varName}.${propName}`, taint);
          }
        }
        // Also check: if source has explicit safe per-property bindings, overwrite tainted ones
        // by scanning all existing varName.* keys and overwriting with source property taint
        for (const [existingKey] of env.getTaintedWithPrefix(`${varName}.`)) {
          const propName = existingKey.slice(varName.length + 1);
          if (propName && !propName.startsWith('#') && env.has(`${srcStr}.${propName}`)) {
            env.set(existingKey, env.get(`${srcStr}.${propName}`));
          }
        }
      }
      continue;
    }
    if ((prop.type === 'ObjectProperty' || prop.type === 'Property') && prop.key) {
      const propName = prop.key.name || prop.key.value;
      if (propName) {
        const propTaint = evaluateExpr(prop.value, env, ctx);
        env.set(`${varName}.${propName}`, propTaint);
      }
    }
  }
}

// ── Check if a node is document.createElement('script') ──
// Uses AST structure walk instead of string comparison to handle aliases
function isCreateScriptElement(node, env) {
  if (node.type !== 'CallExpression') return false;
  const callee = node.callee;
  if (!callee || callee.type !== 'MemberExpression' || callee.computed) return false;
  if (callee.property?.name !== 'createElement') return false;
  // Verify the object is `document` (or an alias to it)
  const obj = callee.object;
  if (obj.type === 'Identifier') {
    if (obj.name !== 'document') {
      const alias = env?.aliases?.get(obj.name);
      if (alias !== 'document') return false;
    }
  } else return false;
  const arg = node.arguments[0];
  return arg && isStringLiteral(arg) && stringLiteralValue(arg).toLowerCase() === 'script';
}

// ── Variable declaration ──
function processVarDeclarator(node, env, ctx) {
  if (!node.init) return;
  ctx.returnedFuncNode = null;
  ctx.returnedMethods = null;
  ctx._blockScopedDecl = !!node._blockScoped;

  // Register function expressions in funcMap so they can be called later
  if (node.id.type === 'Identifier' && node.init &&
      (node.init.type === 'FunctionExpression' || node.init.type === 'ArrowFunctionExpression')) {
    node.init._closureEnv = env;
    const key = resolveId(node.id, ctx);
    ctx.funcMap.set(key, node.init);
    ctx.funcMap.set(node.id.name, node.init);
  }
  // Register function-valued properties from object literals: var obj = { render: function(){} }
  // Also recurses into nested objects: var obj = { inner: { getData: function(){} } }
  if (node.id.type === 'Identifier' && node.init && node.init.type === 'ObjectExpression') {
    const registerObjectMethods = (objExpr, prefix) => {
      for (const prop of objExpr.properties) {
        if ((prop.type === 'ObjectProperty' || prop.type === 'Property') && prop.key) {
          const propName = prop.key.name || prop.key.value;
          const val = prop.value;
          if (propName && val && (val.type === 'FunctionExpression' || val.type === 'ArrowFunctionExpression')) {
            val._closureEnv = env;
            ctx.funcMap.set(`${prefix}.${propName}`, val);
            if (!ctx.funcMap.has(propName)) ctx.funcMap.set(propName, val);
          }
          // Recurse into nested ObjectExpression for deep method registration
          if (propName && val && val.type === 'ObjectExpression') {
            registerObjectMethods(val, `${prefix}.${propName}`);
          }
        }
        if (prop.type === 'ObjectMethod' && prop.key) {
          const propName = prop.key.name || prop.key.value;
          if (propName) {
            prop._closureEnv = env;
            // Register getters with a special prefix so they can be invoked on property access
            const getterPrefix = prop.kind === 'get' ? 'getter:' : '';
            ctx.funcMap.set(`${getterPrefix}${prefix}.${propName}`, prop);
            if (!ctx.funcMap.has(`${getterPrefix}${propName}`)) ctx.funcMap.set(`${getterPrefix}${propName}`, prop);
          }
        }
      }
    };
    registerObjectMethods(node.init, node.id.name);
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

  // Track document.createElement('script') results
  if (node.id.type === 'Identifier' && isCreateScriptElement(node.init, env)) {
    ctx.scriptElements.add(resolveId(node.id, ctx));
    ctx.scriptElements.add(node.id.name);
  }

  const taint = evaluateExpr(node.init, env, ctx);

  // For ObjectPattern destructuring, resolve per-property taint from the source
  if (node.id.type === 'ObjectPattern') {
    const srcStr = nodeToString(node.init);
    if (srcStr) {
      assignObjectPatternFromSource(node.id, srcStr, taint, env, ctx);
    } else if (node.init.type === 'ObjectExpression') {
      // Direct destructuring from object literal: var { x = default } = { x: 'safe' }
      // Build a map of property names → taint values from the RHS literal
      const literalProps = new Map();
      for (const prop of node.init.properties) {
        if ((prop.type === 'ObjectProperty' || prop.type === 'Property') && prop.key) {
          const pName = prop.key.name || prop.key.value;
          if (pName) literalProps.set(pName, evaluateExpr(prop.value, env, ctx));
        }
      }
      for (const prop of node.id.properties) {
        if (prop.type === 'RestElement') {
          assignToPattern(prop.argument, taint, env, ctx);
          continue;
        }
        const keyName = prop.key ? (prop.key.name || prop.key.value) : null;
        if (keyName && literalProps.has(keyName)) {
          // Property exists in RHS literal — use its value, skip default
          const target = prop.value.type === 'AssignmentPattern' ? prop.value.left : prop.value;
          assignToPattern(target, literalProps.get(keyName), env, ctx);
        } else {
          assignToPattern(prop.value, taint, env, ctx);
        }
      }
    } else if (ctx.returnPropertyTaints) {
      // Per-property destructuring from function call: var { a, b } = getData()
      const retProps = ctx.returnPropertyTaints;
      ctx.returnPropertyTaints = null;
      for (const prop of node.id.properties) {
        if (prop.type === 'RestElement') { assignToPattern(prop.argument, taint, env, ctx); continue; }
        const keyName = prop.key ? (prop.key.name || prop.key.value) : null;
        const target = prop.value?.type === 'AssignmentPattern' ? prop.value.left : prop.value;
        if (keyName && retProps.has(keyName)) {
          assignToPattern(target, retProps.get(keyName), env, ctx);
        } else {
          assignToPattern(target || prop, taint, env, ctx);
        }
      }
    } else {
      assignToPattern(node.id, taint, env, ctx);
    }
  } else if (node.id.type === 'ArrayPattern' && node.init.type === 'Identifier') {
    // Array destructuring from variable: var [, b] = arr
    // Check if arr has per-element taint stored
    const srcName = node.init.name;
    const hasPerElem = node.id.elements.some((_, i) => env.has(`${srcName}.#idx_${i}`));
    if (hasPerElem) {
      for (let i = 0; i < node.id.elements.length; i++) {
        const pat = node.id.elements[i];
        if (!pat) continue;
        if (pat.type === 'RestElement') {
          // Collect all per-element taints from index i onward using known stored indices
          const restTaint = TaintSet.empty();
          const allIdxTaints = env.getTaintedWithPrefix(`${srcName}.#idx_`);
          for (const [key, t] of allIdxTaints) {
            const idx = parseInt(key.slice(key.lastIndexOf('_') + 1), 10);
            if (idx >= i) restTaint.merge(t);
          }
          if (!restTaint.tainted) restTaint.merge(taint);
          assignToPattern(pat.argument, restTaint, env, ctx);
          break;
        }
        const elemTaint = env.get(`${srcName}.#idx_${i}`);
        assignToPattern(pat, elemTaint, env, ctx);
      }
    } else {
      assignToPattern(node.id, taint, env, ctx);
    }
  } else if (node.id.type === 'ArrayPattern' && node.init.type === 'ArrayExpression') {
    // Direct destructuring from array literal: var [a, b] = [tainted, safe]
    const elems = node.init.elements;
    const elemTaints = elems.map(e => e ? evaluateExpr(e, env, ctx) : TaintSet.empty());
    for (let i = 0; i < node.id.elements.length; i++) {
      const pat = node.id.elements[i];
      if (!pat) continue;
      if (pat.type === 'RestElement') {
        const restTaint = TaintSet.empty();
        for (let j = i; j < elemTaints.length; j++) restTaint.merge(elemTaints[j]);
        assignToPattern(pat.argument, restTaint, env, ctx);
        break;
      }
      assignToPattern(pat, i < elemTaints.length ? elemTaints[i] : TaintSet.empty(), env, ctx);
    }
  } else if (node.id.type === 'ArrayPattern' && ctx.returnElementTaints) {
    // Per-element destructuring from function call: var [a, b] = getData()
    // where getData() returns [tainted, 'safe'] — use per-element return taints
    const retElems = ctx.returnElementTaints;
    ctx.returnElementTaints = null; // consume once
    for (let i = 0; i < node.id.elements.length; i++) {
      const pat = node.id.elements[i];
      if (!pat) continue;
      if (pat.type === 'RestElement') {
        const restTaint = TaintSet.empty();
        for (let j = i; j < retElems.length; j++) restTaint.merge(retElems[j]);
        assignToPattern(pat.argument, restTaint, env, ctx);
        break;
      }
      assignToPattern(pat, i < retElems.length ? retElems[i] : TaintSet.empty(), env, ctx);
    }
  } else {
    assignToPattern(node.id, taint, env, ctx);
  }
  registerReturnedFunctions(node.id, ctx);

  // Track CustomEvent type: var ev = new CustomEvent('type', ...) → map ev → type
  if (ctx._pendingCustomEventType && node.id.type === 'Identifier') {
    const evName = node.id.name;
    if (!ctx._customEventTypes) ctx._customEventTypes = new Map();
    ctx._customEventTypes.set(evName, ctx._pendingCustomEventType);
    if (ctx._pendingCustomEventDetailTaint) {
      env.set(`${evName}.detail`, ctx._pendingCustomEventDetailTaint);
      ctx._pendingCustomEventDetailTaint = null;
    }
    ctx._pendingCustomEventType = null;
  }

  // Track aliases to known globals: var loc = location; var doc = document; etc.
  if (node.id.type === 'Identifier' && node.init.type === 'Identifier') {
    const ALIASABLE_GLOBALS = new Set(['location', 'document', 'window', 'self', 'globalThis', 'navigator', 'top', 'parent',
      'eval', 'setTimeout', 'setInterval', 'Function', 'fetch', 'atob', 'decodeURIComponent', 'decodeURI',
      'encodeURIComponent', 'encodeURI', 'parseInt', 'parseFloat', 'Number', 'Boolean', 'String', 'JSON', 'Math',
      'DOMPurify', 'structuredClone', 'queueMicrotask', 'requestAnimationFrame']);
    const initName = node.init.name;
    if (ALIASABLE_GLOBALS.has(initName)) {
      env.aliases.set(node.id.name, initName);
    }
    // Transitive: if init is itself an alias, propagate
    const existing = env.aliases.get(initName);
    if (existing) env.aliases.set(node.id.name, existing);
  }
  // Also: var search = location.search (MemberExpression alias)
  if (node.id.type === 'Identifier' && (node.init.type === 'MemberExpression' || node.init.type === 'OptionalMemberExpression')) {
    const prop = node.init.property?.name || node.init.property?.value;
    if (prop) {
      // var loc = window.location → alias loc to 'location'
      // var loc = document.location → alias loc to 'location'
      if (prop === 'location' && node.init.object?.type === 'Identifier') {
        const parentName = node.init.object.name;
        const resolvedParent = env.aliases.get(parentName) || parentName;
        if (resolvedParent === 'window' || resolvedParent === 'document' ||
            resolvedParent === 'self' || resolvedParent === 'globalThis') {
          env.aliases.set(node.id.name, 'location');
        }
      }
      const objStr = nodeToString(node.init.object);
      const resolvedObj = (objStr && env.aliases.get(objStr)) || objStr;
      if (resolvedObj !== objStr) {
        // Store the resolved path so later lookups find it
        const resolvedPath = `${resolvedObj}.${prop}`;
        const sourceTaint = checkMemberSource({ type: 'MemberExpression', object: { type: 'Identifier', name: resolvedObj }, property: node.init.property, computed: false });
        if (sourceTaint) {
          const loc = node.init.loc?.start || {};
          env.set(node.id.name, TaintSet.from(new TaintLabel(sourceTaint, ctx.file, loc.line || 0, loc.column || 0, resolvedPath)));
        }
      }
    }
  }

  // Store per-property taint for ObjectExpression: var obj = { a: tainted, b: safe }
  if (node.id.type === 'Identifier' && node.init.type === 'ObjectExpression') {
    storeObjectPropertyTaints(node.id.name, node.init, env, ctx);
  }
  // Store per-element taint for ArrayExpression: var arr = [tainted, safe]
  if (node.id.type === 'Identifier' && node.init.type === 'ArrayExpression') {
    for (let i = 0; i < node.init.elements.length; i++) {
      const elem = node.init.elements[i];
      if (elem) {
        const elemTaint = evaluateExpr(elem, env, ctx);
        env.set(`${node.id.name}.#idx_${i}`, elemTaint);
      }
    }
  }

  // Store per-property taint from function returning object: var result = getConfig()
  if (node.id.type === 'Identifier' && ctx.returnPropertyTaints) {
    const varName = node.id.name;
    for (const [propName, propTaint] of ctx.returnPropertyTaints) {
      env.set(`${varName}.${propName}`, propTaint);
      const resolvedKey = resolveId(node.id, ctx);
      if (resolvedKey !== varName) env.set(`${resolvedKey}.${propName}`, propTaint);
    }
    ctx.returnPropertyTaints = null;
  }

  // For `new Constructor()` — propagate this.* taint to instance.*
  if (node.init.type === 'NewExpression' && node.id.type === 'Identifier') {
    // Extract constructor name from AST: new Widget() → 'Widget', new ns.Widget() → 'ns.Widget'
    ctx._lastNewCallee = node.init.callee.type === 'Identifier' ? node.init.callee.name : nodeToString(node.init.callee);
    propagateThisToInstance(node.id.name, env, ctx);
    ctx._lastNewCallee = null;
    // Track new URL(x) origins so that url.protocol checks also validate x
    if (isGlobalRef(node.init.callee, 'URL', env) && node.init.arguments[0]) {
      const argStr = nodeToString(node.init.arguments[0]);
      if (argStr) env.urlConstructorOrigins.set(node.id.name, argStr);
    }
  }
}

// ── Assignment ──
function processAssignment(node, env, ctx) {
  ctx.returnedFuncNode = null;
  ctx.returnedMethods = null;

  // Track document.createElement('script') in assignments
  if (node.operator === '=' && node.left.type === 'Identifier' && isCreateScriptElement(node.right, env)) {
    ctx.scriptElements.add(resolveId(node.left, ctx));
    ctx.scriptElements.add(node.left.name);
  }

  const rhsTaint = evaluateExpr(node.right, env, ctx);
  checkSinkAssignment(node.left, rhsTaint, node.right, env, ctx);
  checkScriptElementSink(node.left, rhsTaint, env, ctx);
  checkPrototypePollution(node, env, ctx);

  let finalTaint = rhsTaint;
  if (node.operator === '??=' || node.operator === '||=' || node.operator === '&&=') {
    // Logical assignment: short-circuit based on left side value
    const leftTaint = evaluateExpr(node.left, env, ctx);
    if (node.operator === '??=') {
      // x ??= rhs: only assigns if x is null/undefined
      // If left has existing taint or is a known non-nullish constant, keep left
      if (leftTaint.tainted) { finalTaint = leftTaint.clone().merge(rhsTaint); }
      else {
        // Check if left is a known non-nullish constant
        const leftEnvTaint = node.left.type === 'Identifier' ? env.get(resolveId(node.left, ctx)) : TaintSet.empty();
        if (leftEnvTaint.tainted) { finalTaint = leftEnvTaint.clone().merge(rhsTaint); }
        else {
          // Check if the left variable was initialized to a non-nullish constant
          const leftConst = resolveToConstant(node.left, env, ctx);
          if (leftConst !== undefined) {
            // Left is a known string constant → non-nullish → short-circuits
            finalTaint = leftTaint.clone();
          } else {
            finalTaint = leftTaint.clone().merge(rhsTaint);
          }
        }
      }
    } else if (node.operator === '||=') {
      // x ||= rhs: only assigns if x is falsy
      // If left is a known truthy constant, short-circuit (keep left)
      const leftConst = resolveToConstant(node.left, env, ctx);
      if (leftConst !== undefined && leftConst) {
        finalTaint = leftTaint.clone();
      } else if (leftTaint.tainted) {
        // Left is tainted (truthy in runtime), but conservatively merge both
        finalTaint = leftTaint.clone().merge(rhsTaint);
      } else {
        finalTaint = leftTaint.clone().merge(rhsTaint);
      }
    } else if (node.operator === '&&=') {
      // x &&= rhs: only assigns if x is truthy
      // If left is a known falsy constant, skip assignment
      const leftConst = resolveToConstant(node.left, env, ctx);
      if (leftConst !== undefined && !leftConst) {
        // Left is falsy string ('') → skip assignment
        finalTaint = leftTaint.clone();
      } else {
        finalTaint = leftTaint.clone().merge(rhsTaint);
      }
    }
  } else if (node.operator !== '=') {
    // += preserves taint (string concatenation), but arithmetic/bitwise operators kill taint (return number)
    const NUMERIC_ASSIGN_OPS = new Set(['-=', '*=', '/=', '%=', '**=', '<<=', '>>=', '>>>=', '&=', '|=', '^=']);
    if (NUMERIC_ASSIGN_OPS.has(node.operator)) {
      finalTaint = TaintSet.empty();
    } else {
      finalTaint = evaluateExpr(node.left, env, ctx).clone().merge(rhsTaint);
    }
  }
  // Per-element destructuring from array literal: [a, b] = [expr1, expr2]
  // Evaluate ALL RHS elements first (snapshot), then assign, to handle swaps correctly
  if (node.operator === '=' && node.left.type === 'ArrayPattern' && node.right.type === 'ArrayExpression') {
    const elems = node.right.elements;
    const elemTaints = elems.map(e => e ? evaluateExpr(e, env, ctx) : TaintSet.empty());
    for (let i = 0; i < node.left.elements.length; i++) {
      const pat = node.left.elements[i];
      if (!pat) continue;
      if (pat.type === 'RestElement') {
        const restTaint = TaintSet.empty();
        for (let j = i; j < elemTaints.length; j++) restTaint.merge(elemTaints[j]);
        assignToPattern(pat.argument, restTaint, env, ctx);
        break;
      }
      assignToPattern(pat, i < elemTaints.length ? elemTaints[i] : TaintSet.empty(), env, ctx);
    }
  } else {
    assignToPattern(node.left, finalTaint, env, ctx);
  }
  registerReturnedFunctions(node.left, ctx);

  // Track CustomEvent type: var ev = new CustomEvent('type', ...) → map ev → type
  if (ctx._pendingCustomEventType) {
    const evName = node.left.type === 'Identifier' ? node.left.name : nodeToString(node.left);
    if (evName) {
      if (!ctx._customEventTypes) ctx._customEventTypes = new Map();
      ctx._customEventTypes.set(evName, ctx._pendingCustomEventType);
      // Also store detail taint on the event variable
      if (ctx._pendingCustomEventDetailTaint) {
        env.set(`${evName}.detail`, ctx._pendingCustomEventDetailTaint);
        ctx._pendingCustomEventDetailTaint = null;
      }
    }
    ctx._pendingCustomEventType = null;
  }

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
      // Register prototype methods: Widget.prototype.render = function(){}
      // Store in protoMethodMap so propagateThisToInstance can find them by class name
      if (node.left.type === 'MemberExpression' && !node.left.computed &&
          node.left.object?.type === 'MemberExpression' && !node.left.object.computed &&
          node.left.object.property?.name === 'prototype' &&
          node.left.object.object?.type === 'Identifier') {
        const className = node.left.object.object.name;
        const methodName = node.left.property.name;
        if (ctx.protoMethodMap && !ctx.protoMethodMap.has(className)) ctx.protoMethodMap.set(className, []);
        ctx.protoMethodMap.get(className).push({ methodName, funcNode: node.right });
      }
    }
    // Computed member: obj[key] = function(){} → register as obj[] for dynamic dispatch
    if (!leftStr && node.left.type === 'MemberExpression' && node.left.computed) {
      const objStr = nodeToString(node.left.object);
      if (objStr) {
        ctx.funcMap.set(`${objStr}[]`, node.right);
        if (node.left.object.type === 'Identifier') {
          const key = resolveId(node.left.object, ctx);
          ctx.funcMap.set(`${key}[]`, node.right);
        }
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
    // Update alias on reassignment: fn = parseInt (clear previous eval alias)
    const ALIASABLE_GLOBALS = new Set(['location', 'document', 'window', 'self', 'globalThis', 'navigator', 'top', 'parent',
      'eval', 'setTimeout', 'setInterval', 'Function', 'fetch', 'atob', 'decodeURIComponent', 'decodeURI',
      'encodeURIComponent', 'encodeURI', 'parseInt', 'parseFloat', 'Number', 'Boolean', 'String', 'JSON', 'Math',
      'DOMPurify', 'structuredClone', 'queueMicrotask', 'requestAnimationFrame']);
    const rhsName = node.right.name;
    const rhsAlias = env.aliases.get(rhsName) || rhsName;
    if (ALIASABLE_GLOBALS.has(rhsAlias)) {
      env.aliases.set(node.left.name, rhsAlias);
    } else if (env.aliases.has(node.left.name)) {
      // Reassigned to non-global — clear the alias
      env.aliases.delete(node.left.name);
    }
  }

  // MemberExpression assignment of function ref: window.getConfig = createConfig, obj.handler = existingFunc
  if (node.operator === '=' && node.right.type === 'Identifier' &&
      (node.left.type === 'MemberExpression' || node.left.type === 'OptionalMemberExpression') && !node.left.computed) {
    const refFunc = ctx.funcMap.get(node.right.name) || ctx.funcMap.get(resolveId(node.right, ctx));
    if (refFunc) {
      const leftStr = nodeToString(node.left);
      if (leftStr) {
        ctx.funcMap.set(leftStr, refFunc);
        // Also register by property name for cross-file method resolution
        const propName = node.left.property?.name;
        if (propName && !ctx.funcMap.has(propName)) ctx.funcMap.set(propName, refFunc);
      }
    }
    // Track global function alias: obj.fn = eval → env.aliases.set('obj.fn', 'eval')
    const rhsName = node.right.name;
    const rhsAlias = env.aliases.get(rhsName) || rhsName;
    const SINK_GLOBALS = new Set(['eval', 'setTimeout', 'setInterval', 'Function']);
    if (SINK_GLOBALS.has(rhsAlias)) {
      const leftStr = nodeToString(node.left);
      if (leftStr) env.aliases.set(leftStr, rhsAlias);
    }
  }

  // Computed member assignment of function ref: obj[key] = existingFunc
  if (node.operator === '=' && node.right.type === 'Identifier' &&
      node.left.type === 'MemberExpression' && node.left.computed) {
    const refFunc = ctx.funcMap.get(node.right.name) || ctx.funcMap.get(resolveId(node.right, ctx));
    if (refFunc) {
      const objStr = nodeToString(node.left.object);
      if (objStr) {
        ctx.funcMap.set(`${objStr}[]`, refFunc);
        if (node.left.object.type === 'Identifier') {
          const key = resolveId(node.left.object, ctx);
          ctx.funcMap.set(`${key}[]`, refFunc);
        }
      }
    }
  }

  // Register object literal methods: obj = { render: function(){} } or window.Mod = { get: function(){} }
  if (node.operator === '=' && node.right.type === 'ObjectExpression') {
    const leftStr = nodeToString(node.left);
    if (leftStr) {
      for (const prop of node.right.properties) {
        if ((prop.type === 'ObjectProperty' || prop.type === 'Property') && prop.key) {
          const propName = prop.key.name || prop.key.value;
          const val = prop.value;
          if (propName && val && (val.type === 'FunctionExpression' || val.type === 'ArrowFunctionExpression')) {
            val._closureEnv = env;
            ctx.funcMap.set(`${leftStr}.${propName}`, val);
            if (!ctx.funcMap.has(propName)) ctx.funcMap.set(propName, val);
          }
        }
        if (prop.type === 'ObjectMethod' && prop.key) {
          const propName = prop.key.name || prop.key.value;
          if (propName) {
            prop._closureEnv = env;
            ctx.funcMap.set(`${leftStr}.${propName}`, prop);
            if (!ctx.funcMap.has(propName)) ctx.funcMap.set(propName, prop);
          }
        }
      }
    }
  }

  // DOM event handler property assignment: el.onclick = function() { ... }
  // Analyze the handler body immediately since the browser will invoke it
  if (node.operator === '=' && node.left.type === 'MemberExpression' && !node.left.computed &&
      node.left.property?.name?.startsWith('on') && node.left.property.name !== 'onmessage') {
    let handler = node.right;
    if (handler.type === 'Identifier') {
      handler = ctx.funcMap.get(resolveId(handler, ctx)) || ctx.funcMap.get(handler.name) || handler;
    }
    if (handler.type === 'ArrowFunctionExpression' || handler.type === 'FunctionExpression' ||
        handler.type === 'FunctionDeclaration') {
      const childEnv = env.child();
      if (handler.body.type === 'BlockStatement') {
        analyzeInlineFunction(handler, childEnv, ctx);
      } else {
        evaluateExpr(handler.body, childEnv, ctx);
      }
    }
  }

  // window.onmessage / self.onmessage = function(e) { ... }
  // Analyze the handler body with tainted event param, same as addEventListener('message', fn)
  if (node.operator === '=') {
    const isOnmessage = (node.left.type === 'Identifier' && node.left.name === 'onmessage') ||
      (node.left.type === 'MemberExpression' && !node.left.computed &&
       node.left.property?.name === 'onmessage' &&
       node.left.object?.type === 'Identifier' &&
       (node.left.object.name === 'window' || node.left.object.name === 'self' || node.left.object.name === 'globalThis'));
    if (isOnmessage && !ctx.isWorker) {
      let handler = node.right;
      // Resolve named function reference: window.onmessage = handleMessage
      if (handler.type === 'Identifier') {
        const refKey = resolveId(handler, ctx);
        handler = ctx.funcMap.get(refKey) || ctx.funcMap.get(handler.name) || handler;
      }
      if (handler.type === 'ArrowFunctionExpression' || handler.type === 'FunctionExpression' ||
          handler.type === 'FunctionDeclaration') {
        const originCheck = callbackChecksOrigin(handler.body, ctx);
        if (originCheck !== 'strong' && handler.params[0]) {
          const paramName = handler.params[0].type === 'Identifier' ? handler.params[0].name : null;
          if (paramName) {
            const childEnv = env.child();
            const loc = handler.loc?.start || {};
            const desc = originCheck === 'weak'
              ? `${paramName}.data (weak origin check)`
              : `${paramName}.data (no origin check)`;
            const label = new TaintLabel('postMessage.data', ctx.file, loc.line || 0, loc.column || 0, desc);
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
function assignToPattern(rootPattern, rootTaint, env, ctx) {
  if (!rootPattern) return;
  const stack = [{ pattern: rootPattern, taint: rootTaint }];
  while (stack.length > 0) {
    const { pattern, taint } = stack.pop();
    if (!pattern) continue;

    switch (pattern.type) {
      case 'Identifier': {
        const key = resolveId(pattern, ctx);
        env.set(key, taint);
        const skipGlobal = ctx._blockScopedDecl && ctx.scopeInfo &&
          key !== `global:${pattern.name}` && key !== pattern.name &&
          !key.startsWith('0:');
        if (!skipGlobal) {
          env.set(`global:${pattern.name}`, taint);
        }
        break;
      }

      case 'MemberExpression':
      case 'OptionalMemberExpression': {
        const str = nodeToString(pattern);
        if (str) env.set(str, taint);
        if (!pattern.computed && pattern.property?.name) {
          const objStr = nodeToString(pattern.object);
          if (objStr) env.set(`${objStr}.${pattern.property.name}`, taint);
          const GLOBAL_PREFIXES = new Set(['window', 'self', 'globalThis']);
          if (pattern.object.type === 'Identifier' && GLOBAL_PREFIXES.has(pattern.object.name)) {
            const propName = pattern.property.name;
            env.set(propName, taint);
            env.set(`global:${propName}`, taint);
          }
        }
        if (pattern.computed) {
          const objStr = nodeToString(pattern.object);
          if (objStr) {
            const resolved = resolveToConstant(pattern.property, null, ctx);
            if (resolved !== undefined) {
              env.set(`${objStr}.${resolved}`, taint);
              if (/^\d+$/.test(String(resolved))) {
                env.set(`${objStr}.#idx_${resolved}`, taint);
              }
            } else {
              if (taint.tainted) env.set(objStr, env.get(objStr).clone().merge(taint));
            }
          }
        }
        break;
      }

      case 'ObjectPattern':
        for (const prop of pattern.properties) {
          if (prop.type === 'RestElement') stack.push({ pattern: prop.argument, taint });
          else stack.push({ pattern: prop.value, taint });
        }
        break;

      case 'ArrayPattern':
        for (const elem of pattern.elements) {
          if (elem) {
            if (elem.type === 'RestElement') stack.push({ pattern: elem.argument, taint });
            else stack.push({ pattern: elem, taint });
          }
        }
        break;

      case 'AssignmentPattern': {
        const paramTaint = taint.tainted ? taint : evaluateExpr(pattern.right, env, ctx);
        stack.push({ pattern: pattern.left, taint: paramTaint });
        break;
      }
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
    if (key.startsWith('this.')) {
      const propName = key.slice(5); // "this.html" → "html"
      if (propName) toSet.push([`${instanceName}.${propName}`, taint]);
    }
  }
  for (const [k, t] of toSet) env.set(k, t);

  // Also register prototype methods for the constructor under instance.methodName
  const constructorFuncs = [];
  // Look up prototype methods from protoMethodMap by class name
  const ctorCalleeForProto = ctx._lastNewCallee;
  if (ctorCalleeForProto && ctx.protoMethodMap.has(ctorCalleeForProto)) {
    for (const { methodName, funcNode } of ctx.protoMethodMap.get(ctorCalleeForProto)) {
      constructorFuncs.push([`${instanceName}.${methodName}`, funcNode]);
      constructorFuncs.push([methodName, funcNode]);
    }
  }
  // For class methods: if the constructor was registered as className (from ClassDeclaration),
  // find all class methods and register them under instance.methodName
  // Class methods are registered by plain name in funcMap during ClassDeclaration processing
  const ctorCallee = ctx._lastNewCallee;
  if (ctorCallee) {
    const classBody = ctx.classBodyMap.get(ctorCallee);
    if (classBody) {
      for (const member of classBody) {
        if (member.type !== 'ClassMethod' && member.type !== 'MethodDefinition') continue;
        const mname = member.key?.name || member.key?.value;
        if (mname && mname !== 'constructor' && !member.static) {
          constructorFuncs.push([`${instanceName}.${mname}`, member]);
        }
      }
    }
  }
  for (const [k, f] of constructorFuncs) ctx.funcMap.set(k, f);
}

// ── Evaluate an expression, returning its TaintSet ──
// ── Work item kinds for the iterative engine ──
const W_EVAL_EXPR = 0;       // Evaluate an expression node → push TaintSet to V
const W_CONTINUATION = 1;    // Run a continuation that pops from V, pushes result

// ── Continuation labels ──
const C_PASSTHROUGH = 0;      // Pop 1 value, push it back unchanged
const C_KILL_TAINT = 1;       // Pop 1 value (side effects done), push empty
const C_IMPORT_EXPR = 2;      // Pop specifier taint, check for XSS, push empty
const C_YIELD_EXPR = 3;       // Pop yield taint, merge into returnTaint, push it
const C_MERGE_N = 4;          // Pop N values, merge all, push result
const C_TAKE_LAST = 5;        // Pop N values, push only the last one
const C_BINARY_INIT = 6;     // Pop leftmost result, begin binary chain iteration
const C_BINARY_NEXT = 7;     // Pop right operand result, combine with accum, continue
const C_LOGICAL_INIT = 8;    // Pop leftmost result, begin logical chain iteration
const C_LOGICAL_NEXT = 9;    // Pop right operand result, merge with accum, continue
const C_COND_TEST = 10;      // Pop test taint (discarded), dispatch on constness
const C_COND_BRANCH = 11;    // Pop branch taint, merge with accum, continue to alternate
const C_COND_FINAL = 12;     // Pop final alternate taint, merge with accum, push result

// ── Stepper helpers for compound expressions (push work items, no JS recursion) ──

const COMPARISON_OPS = new Set(['===', '==', '!==', '!=', '>', '<', '>=', '<=', 'instanceof', 'in']);
const ARITHMETIC_OPS = new Set(['-', '*', '/', '%', '**', '|', '&', '^', '<<', '>>', '>>>']);

/** Push work for the next step of a BinaryExpression chain, or finalize. */
function binaryStep(accum, parts, index, bn, env, ctx, W, V) {
  if (index < 0) { V.push(accum); return; }
  const { op, right } = parts[index];
  if (COMPARISON_OPS.has(op) || ARITHMETIC_OPS.has(op)) {
    // Evaluate right for side effects, then push empty as final result
    W.push({ kind: W_CONTINUATION, label: C_KILL_TAINT });
    W.push({ kind: W_EVAL_EXPR, node: right, env, ctx });
    return;
  }
  // Evaluate right, then combine in C_BINARY_NEXT
  W.push({ kind: W_CONTINUATION, label: C_BINARY_NEXT, accum, parts, index, bn, env, ctx });
  W.push({ kind: W_EVAL_EXPR, node: right, env, ctx });
}

/** Push work for the next step of a LogicalExpression chain, or finalize. */
function logicalStep(accum, parts, index, ln, env, ctx, W, V) {
  // While loop to handle short-circuit skips without recursion
  while (index >= 0) {
    const { op, right } = parts[index];
    if (op === '&&') {
      const constLeft = isConstantBool(ln, ctx);
      if (constLeft === false) { V.push(TaintSet.empty()); return; }
      W.push({ kind: W_CONTINUATION, label: C_LOGICAL_NEXT, accum, parts, index, ln: right, env, ctx });
      W.push({ kind: W_EVAL_EXPR, node: right, env, ctx });
      return;
    } else if (op === '||') {
      const constLeft = isConstantBool(ln, ctx);
      if (constLeft === true) {
        // short-circuit: left is truthy → entire chain result is the left value
        V.push(accum);
        return;
      }
      W.push({ kind: W_CONTINUATION, label: C_LOGICAL_NEXT, accum, parts, index, ln: right, env, ctx });
      W.push({ kind: W_EVAL_EXPR, node: right, env, ctx });
      return;
    } else if (op === '??') {
      const isNullish = (ln.type === 'NullLiteral') ||
        (ln.type === 'Literal' && ln.value === null) ||
        (ln.type === 'Identifier' && ln.name === 'undefined');
      if (isNullish) {
        W.push({ kind: W_CONTINUATION, label: C_LOGICAL_NEXT, accum: TaintSet.empty(), parts, index, ln: right, env, ctx });
        W.push({ kind: W_EVAL_EXPR, node: right, env, ctx });
        return;
      }
      const isNonNullishConst = (ln.type === 'StringLiteral') ||
        (ln.type === 'NumericLiteral') || (ln.type === 'BooleanLiteral') ||
        (ln.type === 'Literal' && ln.value !== null && ln.value !== undefined) ||
        (ln.type === 'ObjectExpression') || (ln.type === 'ArrayExpression');
      if (isNonNullishConst) {
        // Definitely non-nullish: entire chain result is the left value
        V.push(accum);
        return;
      }
      W.push({ kind: W_CONTINUATION, label: C_LOGICAL_NEXT, accum, parts, index, ln: right, env, ctx });
      W.push({ kind: W_EVAL_EXPR, node: right, env, ctx });
      return;
    }
    break; // unknown op, shouldn't happen
  }
  V.push(accum);
}

/** Push work for the next step of a ConditionalExpression chain, or finalize. */
function conditionalStep(accum, cn, env, ctx, W, V) {
  if (cn.type !== 'ConditionalExpression') {
    // Final alternate — evaluate and merge with accum
    W.push({ kind: W_CONTINUATION, label: C_COND_FINAL, accum, ctx, node: cn });
    W.push({ kind: W_EVAL_EXPR, node: cn, env, ctx });
    return;
  }
  // Evaluate test, then dispatch in C_COND_TEST
  W.push({ kind: W_CONTINUATION, label: C_COND_TEST, accum, cn, env, ctx });
  W.push({ kind: W_EVAL_EXPR, node: cn.test, env, ctx });
}

/** Iterative expression evaluator — single work loop with explicit W and V stacks. */
export function evaluateExpr(node, env, ctx) {
  if (!node) return TaintSet.empty();

  const W = []; // work stack
  const V = []; // value stack (TaintSet results)

  W.push({ kind: W_EVAL_EXPR, node, env, ctx });

  while (W.length > 0) {
    const item = W.pop();

    switch (item.kind) {
      case W_EVAL_EXPR: {
        if (!item.node) { V.push(TaintSet.empty()); break; }
        const _n = item.node, _e = item.env, _c = item.ctx;
        switch (_n.type) {
          // ── Stage 1: Leaf nodes (no sub-expression evaluation) ──
          case 'Identifier': {
            const key = resolveId(_n, _c);
            const taint = _e.get(key);
            if (taint.tainted) { V.push(taint.clone()); break; }
            if (key !== _n.name && _e.has(key)) { V.push(TaintSet.empty()); break; }
            const globalTaint = _e.get(`global:${_n.name}`);
            if (globalTaint.tainted) { V.push(globalTaint.clone()); break; }
            V.push(TaintSet.empty());
            break;
          }
          case 'ThisExpression':
            V.push(_e.get('this'));
            break;
          case 'StringLiteral':
          case 'NumericLiteral':
          case 'BooleanLiteral':
          case 'NullLiteral':
          case 'BigIntLiteral':
          case 'RegExpLiteral':
          case 'Literal':
          case 'UpdateExpression':
            V.push(TaintSet.empty());
            break;
          case 'ArrowFunctionExpression':
          case 'FunctionExpression':
            _n._closureEnv = _e;
            V.push(TaintSet.empty());
            break;
          // ── Stage 6: MemberExpression ──
          case 'MemberExpression':
          case 'OptionalMemberExpression':
            V.push(evaluateMemberExpr(_n, _e, _c));
            break;
          // ── Stage 7: CallExpression / NewExpression ──
          case 'CallExpression':
          case 'OptionalCallExpression':
            V.push(evaluateCallExpr(_n, _e, _c));
            break;
          case 'NewExpression':
            V.push(evaluateNewExpr(_n, _e, _c));
            break;
          case 'TaggedTemplateExpression':
            V.push(evaluateTaggedTemplate(_n, _e, _c));
            break;
          // ── Stage 5: AssignmentExpression ──
          case 'AssignmentExpression':
            processAssignment(_n, _e, _c);
            // Return value is the LHS after assignment
            W.push({ kind: W_EVAL_EXPR, node: _n.left, env: _e, ctx: _c });
            break;
          // ── Stage 4: Compound expressions with control flow ──
          case 'BinaryExpression': {
            const parts = [];
            let bn = _n;
            const topOp = _n.operator;
            while (bn.type === 'BinaryExpression' && bn.operator === topOp) {
              parts.push({ op: bn.operator, right: bn.right });
              bn = bn.left;
            }
            // Push C_BINARY_INIT to receive leftmost result, then evaluate leftmost
            W.push({ kind: W_CONTINUATION, label: C_BINARY_INIT, parts, bn, env: _e, ctx: _c });
            W.push({ kind: W_EVAL_EXPR, node: bn, env: _e, ctx: _c });
            break;
          }
          case 'LogicalExpression': {
            const parts = [];
            let ln = _n;
            while (ln.type === 'LogicalExpression') {
              parts.push({ op: ln.operator, right: ln.right });
              ln = ln.left;
            }
            W.push({ kind: W_CONTINUATION, label: C_LOGICAL_INIT, parts, ln, env: _e, ctx: _c });
            W.push({ kind: W_EVAL_EXPR, node: ln, env: _e, ctx: _c });
            break;
          }
          case 'ConditionalExpression':
            // Push C_COND_TEST to evaluate test and dispatch
            W.push({ kind: W_CONTINUATION, label: C_COND_TEST, accum: TaintSet.empty(), cn: _n, env: _e, ctx: _c });
            W.push({ kind: W_EVAL_EXPR, node: _n.test, env: _e, ctx: _c });
            break;
          // ── Stage 2: Simple wrappers (1 sub-expression) ──
          case 'UnaryExpression':
            if (_n.operator === '!' || _n.operator === 'typeof' ||
                _n.operator === '+' || _n.operator === '-' || _n.operator === '~' ||
                _n.operator === 'void' || _n.operator === 'delete') {
              W.push({ kind: W_CONTINUATION, label: C_KILL_TAINT });
            } else {
              W.push({ kind: W_CONTINUATION, label: C_PASSTHROUGH });
            }
            W.push({ kind: W_EVAL_EXPR, node: _n.argument, env: _e, ctx: _c });
            break;
          case 'AwaitExpression':
            W.push({ kind: W_CONTINUATION, label: C_PASSTHROUGH });
            W.push({ kind: W_EVAL_EXPR, node: _n.argument, env: _e, ctx: _c });
            break;
          case 'SpreadElement':
            W.push({ kind: W_CONTINUATION, label: C_PASSTHROUGH });
            W.push({ kind: W_EVAL_EXPR, node: _n.argument, env: _e, ctx: _c });
            break;
          case 'ChainExpression':
          case 'ParenthesizedExpression':
            W.push({ kind: W_CONTINUATION, label: C_PASSTHROUGH });
            W.push({ kind: W_EVAL_EXPR, node: _n.expression, env: _e, ctx: _c });
            break;
          // ── Stage 3: Aggregating nodes (N sub-expressions) ──
          case 'TemplateLiteral': {
            const exprs = _n.expressions;
            if (exprs.length === 0) { V.push(TaintSet.empty()); break; }
            W.push({ kind: W_CONTINUATION, label: C_MERGE_N, count: exprs.length });
            for (let i = exprs.length - 1; i >= 0; i--)
              W.push({ kind: W_EVAL_EXPR, node: exprs[i], env: _e, ctx: _c });
            break;
          }
          case 'ObjectExpression': {
            const props = _n.properties;
            if (props.length === 0) { V.push(TaintSet.empty()); break; }
            // Each property contributes one value: spread → argument, property → value
            W.push({ kind: W_CONTINUATION, label: C_MERGE_N, count: props.length });
            for (let i = props.length - 1; i >= 0; i--) {
              const prop = props[i];
              if (prop.type === 'SpreadElement')
                W.push({ kind: W_EVAL_EXPR, node: prop.argument, env: _e, ctx: _c });
              else if (prop.type === 'ObjectProperty' || prop.type === 'Property')
                W.push({ kind: W_EVAL_EXPR, node: prop.value, env: _e, ctx: _c });
              else
                W.push({ kind: W_EVAL_EXPR, node: null, env: _e, ctx: _c }); // safety
            }
            break;
          }
          case 'ArrayExpression': {
            const elems = _n.elements;
            const valid = elems.filter(e => e);
            if (valid.length === 0) { V.push(TaintSet.empty()); break; }
            W.push({ kind: W_CONTINUATION, label: C_MERGE_N, count: valid.length });
            for (let i = valid.length - 1; i >= 0; i--)
              W.push({ kind: W_EVAL_EXPR, node: valid[i], env: _e, ctx: _c });
            break;
          }
          case 'SequenceExpression': {
            const exprs = _n.expressions;
            if (exprs.length === 0) { V.push(TaintSet.empty()); break; }
            W.push({ kind: W_CONTINUATION, label: C_TAKE_LAST, count: exprs.length });
            for (let i = exprs.length - 1; i >= 0; i--)
              W.push({ kind: W_EVAL_EXPR, node: exprs[i], env: _e, ctx: _c });
            break;
          }
          case 'ImportExpression':
            W.push({ kind: W_CONTINUATION, label: C_IMPORT_EXPR, node: _n, ctx: _c });
            W.push({ kind: W_EVAL_EXPR, node: _n.source, env: _e, ctx: _c });
            break;
          case 'YieldExpression':
            W.push({ kind: W_CONTINUATION, label: C_YIELD_EXPR, ctx: _c });
            W.push({ kind: W_EVAL_EXPR, node: _n.argument, env: _e, ctx: _c });
            break;
          // ── Everything else: unknown node type → safe ──
          default:
            V.push(TaintSet.empty());
            break;
        }
        break;
      }

      case W_CONTINUATION: {
        switch (item.label) {
          case C_PASSTHROUGH:
            // Value already on V — nothing to do
            break;
          case C_KILL_TAINT:
            V.pop(); // discard (evaluated for side effects)
            V.push(TaintSet.empty());
            break;
          case C_IMPORT_EXPR: {
            const specifierTaint = V.pop();
            if (specifierTaint.tainted) {
              for (const label of specifierTaint.labels) {
                item.ctx.findings.push({
                  type: 'XSS',
                  description: `XSS: tainted data flows to dynamic import()`,
                  location: { file: item.ctx.file, line: item.node.loc?.start?.line || 0, column: item.node.loc?.start?.column || 0 },
                  source: label,
                });
              }
            }
            V.push(TaintSet.empty());
            break;
          }
          case C_YIELD_EXPR: {
            const yieldTaint = V.pop();
            if (yieldTaint.tainted) item.ctx.returnTaint.merge(yieldTaint);
            V.push(yieldTaint);
            break;
          }
          case C_MERGE_N: {
            const t = TaintSet.empty();
            for (let i = 0; i < item.count; i++) t.merge(V.pop());
            V.push(t);
            break;
          }
          case C_TAKE_LAST: {
            // All N values are on V; the last expression's result is on top
            const last = V.pop();
            for (let i = 1; i < item.count; i++) V.pop(); // discard earlier
            V.push(last);
            break;
          }
          // ── Stage 4: Binary/Logical/Conditional steppers ──
          case C_BINARY_INIT: {
            const leftResult = V.pop();
            binaryStep(leftResult, item.parts, item.parts.length - 1, item.bn, item.env, item.ctx, W, V);
            break;
          }
          case C_BINARY_NEXT: {
            const rightT = V.pop();
            let result = item.accum;
            const { op, right } = item.parts[item.index];
            if (op === '+') {
              result = result.clone().merge(rightT);
              // Check toString/valueOf coercion on both operands
              const leftNode = item.index === item.parts.length - 1 ? item.bn : item.parts[item.index + 1].right;
              for (const operand of [leftNode, right]) {
                if (operand.type === 'Identifier' && !result.tainted) {
                  const objName = operand.name;
                  for (const methodName of ['toString', 'valueOf']) {
                    const coercionFunc = item.ctx.funcMap.get(`${objName}.${methodName}`);
                    if (coercionFunc && coercionFunc.body) {
                      const synthCall = { type: 'CallExpression', callee: operand, arguments: [], loc: operand.loc };
                      const coercionTaint = analyzeCalledFunction(synthCall, `${objName}.${methodName}`, [], item.env, item.ctx);
                      result = result.merge(coercionTaint);
                    }
                  }
                }
              }
            } else {
              result = result.clone().merge(rightT);
            }
            binaryStep(result, item.parts, item.index - 1, item.bn, item.env, item.ctx, W, V);
            break;
          }
          case C_LOGICAL_INIT: {
            const leftResult = V.pop();
            logicalStep(leftResult, item.parts, item.parts.length - 1, item.ln, item.env, item.ctx, W, V);
            break;
          }
          case C_LOGICAL_NEXT: {
            const rightT = V.pop();
            const result = item.accum.clone().merge(rightT);
            logicalStep(result, item.parts, item.index - 1, item.ln, item.env, item.ctx, W, V);
            break;
          }
          case C_COND_TEST: {
            V.pop(); // discard test taint (evaluated for side effects)
            const cn = item.cn;
            const constCond = isConstantBool(cn.test);
            if (constCond === true) {
              // Definite true: evaluate consequent as final result
              W.push({ kind: W_CONTINUATION, label: C_COND_FINAL, accum: TaintSet.empty(), ctx: item.ctx, node: cn.consequent });
              W.push({ kind: W_EVAL_EXPR, node: cn.consequent, env: item.env, ctx: item.ctx });
            } else if (constCond === false) {
              // Definite false: skip to alternate
              conditionalStep(item.accum, cn.alternate, item.env, item.ctx, W, V);
            } else {
              // Unknown: evaluate consequent, then continue to alternate
              const checkedVar = extractSchemeCheck(cn.test, true);
              W.push({ kind: W_CONTINUATION, label: C_COND_BRANCH, accum: item.accum, cn, env: item.env, ctx: item.ctx, checkedVar, hadCheck: checkedVar && item.env.schemeCheckedVars.has(checkedVar) });
              if (checkedVar && !item.env.schemeCheckedVars.has(checkedVar)) item.env.schemeCheckedVars.add(checkedVar);
              W.push({ kind: W_EVAL_EXPR, node: cn.consequent, env: item.env, ctx: item.ctx });
            }
            break;
          }
          case C_COND_BRANCH: {
            const consequentTaint = V.pop();
            const cn = item.cn;
            if (item.checkedVar && !item.hadCheck) item.env.schemeCheckedVars.delete(item.checkedVar);
            let accum = item.accum.merge(consequentTaint);
            if (!item.ctx.returnedFuncNode && cn.consequent.type === 'Identifier') {
              const refKey = resolveId(cn.consequent, item.ctx);
              const funcRef = item.ctx.funcMap.get(refKey) || item.ctx.funcMap.get(cn.consequent.name);
              if (funcRef) item.ctx.returnedFuncNode = funcRef;
            }
            conditionalStep(accum, cn.alternate, item.env, item.ctx, W, V);
            break;
          }
          case C_COND_FINAL: {
            const taint = V.pop();
            const result = item.accum.merge(taint);
            // Check for returnedFuncNode on the final node (passed via item.node if set)
            if (item.node && !item.ctx.returnedFuncNode && item.node.type === 'Identifier') {
              const refKey = resolveId(item.node, item.ctx);
              const funcRef = item.ctx.funcMap.get(refKey) || item.ctx.funcMap.get(item.node.name);
              if (funcRef) item.ctx.returnedFuncNode = funcRef;
            }
            V.push(result);
            break;
          }
        }
        break;
      }
    }
  }

  return V.pop() || TaintSet.empty();
}

// ── Member expression ──
function evaluateTaggedTemplate(node, env, ctx) {
  const exprTaints = node.quasi.expressions.map(e => evaluateExpr(e, env, ctx));
  const stringsArg = TaintSet.empty();
  const allArgTaints = [stringsArg, ...exprTaints];
  const tagCallee = node.tag;
  let funcNode = null;
  if (tagCallee.type === 'Identifier') {
    funcNode = ctx.funcMap.get(resolveId(tagCallee, ctx)) || ctx.funcMap.get(tagCallee.name);
  } else if (tagCallee.type === 'MemberExpression') {
    const tagStr = nodeToString(tagCallee);
    if (tagStr) funcNode = ctx.funcMap.get(tagStr);
  }
  if (funcNode && funcNode.body) {
    const synthCall = { type: 'CallExpression', callee: tagCallee, arguments: [{ type: 'ArrayExpression', elements: [] }, ...node.quasi.expressions] };
    const tagCalleeStr = nodeToString(tagCallee);
    if (isSanitizer(tagCalleeStr, '')) return TaintSet.empty();
    return analyzeCalledFunction(synthCall, tagCalleeStr, allArgTaints, env, ctx);
  }
  const t = TaintSet.empty();
  for (const et of exprTaints) t.merge(et);
  return t;
}

function evaluateMemberExpr(node, env, ctx) {
  // Iterative evaluation for MemberExpression chains to avoid stack overflow on minified code.
  // Walk the chain, checking sources/env/getters at each level. Only recurse for computed access.
  let cur = node;
  while (cur.type === 'MemberExpression' || cur.type === 'OptionalMemberExpression') {
    const sourceLabel = checkMemberSource(cur);
    if (sourceLabel) {
      const loc = cur.loc?.start || {};
      return TaintSet.from(new TaintLabel(sourceLabel, ctx.file, loc.line || 0, loc.column || 0, nodeToString(cur)));
    }

    // Resolve aliases: replace root identifier with its alias and re-check as source
    const fullStr = nodeToString(cur);
    if (fullStr) {
      const resolvedStr = resolveAliasedPath(fullStr, env);
      if (resolvedStr !== fullStr && MEMBER_SOURCES[resolvedStr]) {
        const loc = cur.loc?.start || {};
        return TaintSet.from(new TaintLabel(MEMBER_SOURCES[resolvedStr], ctx.file, loc.line || 0, loc.column || 0, resolvedStr));
      }
    }
    if (!cur.computed && cur.object?.type === 'Identifier') {
      const alias = env.aliases.get(cur.object.name);
      if (alias && cur.property) {
        const deepPath = `${alias}.${cur.property.name || cur.property.value}`;
        if (MEMBER_SOURCES[deepPath]) {
          const loc = cur.loc?.start || {};
          return TaintSet.from(new TaintLabel(MEMBER_SOURCES[deepPath], ctx.file, loc.line || 0, loc.column || 0, deepPath));
        }
      }
    }

    const fullPath = fullStr;
    if (fullPath) {
      if (env.has(fullPath)) return env.get(fullPath).clone();
    }
    // Scope-resolved lookup
    if (!cur.computed && cur.object?.type === 'Identifier' && cur.property) {
      const resolvedObjKey = resolveId(cur.object, ctx);
      const memberProp = cur.property.name || cur.property.value;
      if (memberProp) {
        const scopedPath = `${resolvedObjKey}.${memberProp}`;
        if (env.has(scopedPath)) return env.get(scopedPath).clone();
      }
    }
    if (fullPath) {
      const getterFunc = ctx.funcMap.get(`getter:${fullPath}`);
      if (getterFunc && getterFunc.body) {
        const childEnv = (getterFunc._closureEnv || env).child();
        const getterTaint = analyzeInlineFunction(getterFunc, childEnv, ctx);
        if (getterTaint.tainted) return getterTaint;
      }
    }

    const propName = !cur.computed && cur.property ? (cur.property.name || cur.property.value) : null;
    if (propName && (NUMERIC_PROPS.has(propName) || propName === 'constructor' || propName === 'prototype')) {
      return TaintSet.empty();
    }

    // Computed access: evaluate object + key, handle property lookups, then return
    if (cur.computed) {
      const objTaint = evaluateExpr(cur.object, env, ctx);
      return evaluateComputedMember(cur, objTaint, env, ctx);
    }

    // Non-computed: continue walking up the chain
    cur = cur.object;
  }
  // Reached the root (non-MemberExpression node)
  return evaluateExpr(cur, env, ctx);
}

function evaluateComputedMember(node, objTaint, env, ctx) {
    const keyTaint = evaluateExpr(node.property, env, ctx);
    // For computed access with a constant key (obj['key'], arr[0], obj[constVar]),
    // do per-property lookup — precise, not overapproximated
    let litKey = null;
    if (isStringLiteral(node.property)) {
      litKey = stringLiteralValue(node.property);
    } else if (node.property.type === 'NumericLiteral' || (node.property.type === 'Literal' && typeof node.property.value === 'number')) {
      litKey = String(node.property.value);
    } else {
      // Try to resolve identifier to constant: obj[key] where key = 'prop'
      const resolved = resolveToConstant(node.property, env, ctx);
      if (resolved !== undefined) litKey = String(resolved);
    }
    // Only trust resolved key when it came directly from a literal (not a variable that might change)
    const isDirectLiteral = isStringLiteral(node.property) ||
      node.property.type === 'NumericLiteral' ||
      (node.property.type === 'Literal' && (typeof node.property.value === 'string' || typeof node.property.value === 'number'));
    if (litKey !== null && isDirectLiteral) {
      const objStr = nodeToString(node.object);
      if (objStr) {
        if (env.has(`${objStr}.${litKey}`)) return env.get(`${objStr}.${litKey}`).clone();
        if (/^\d+$/.test(litKey) && env.has(`${objStr}.#idx_${litKey}`)) return env.get(`${objStr}.#idx_${litKey}`).clone();
      }
      if (node.object?.type === 'Identifier') {
        const resolvedKey = resolveId(node.object, ctx);
        if (env.has(`${resolvedKey}.${litKey}`)) return env.get(`${resolvedKey}.${litKey}`).clone();
        if (/^\d+$/.test(litKey) && env.has(`${resolvedKey}.#idx_${litKey}`)) return env.get(`${resolvedKey}.#idx_${litKey}`).clone();
      }
    }
    // For variable-resolved keys (obj[key] where key='prop'), do per-property lookup
    // but also fall through to prefix check to handle mutable variables (loop counters)
    if (litKey !== null && !isDirectLiteral) {
      const objStr = nodeToString(node.object);
      if (objStr) {
        if (env.has(`${objStr}.${litKey}`)) {
          const specific = env.get(`${objStr}.${litKey}`);
          if (specific.tainted) return specific.clone();
        }
      }
      if (node.object?.type === 'Identifier') {
        const resolvedKey = resolveId(node.object, ctx);
        if (env.has(`${resolvedKey}.${litKey}`)) {
          const specific = env.get(`${resolvedKey}.${litKey}`);
          if (specific.tainted) return specific.clone();
        }
      }
      // Fall through to prefix check for overapproximation (variable might hold different values)
    }
    // For dynamic computed access obj[key], check if any obj.* properties are tainted
    // When the key is tainted, the attacker controls which property is selected,
    // but the VALUE read carries its own taint — don't propagate key taint as value taint.
    const objStr = nodeToString(node.object);
    if (objStr) {
      const taintedProps = env.getTaintedWithPrefix(`${objStr}.`);
      if (taintedProps.size > 0) {
        const merged = TaintSet.empty();
        for (const [, taint] of taintedProps) merged.merge(taint);
        return merged;
      }
    }
    // Also check scope-resolved key for computed access
    if (node.object?.type === 'Identifier') {
      const resolvedKey = resolveId(node.object, ctx);
      if (resolvedKey !== objStr) {
        const resolvedProps = env.getTaintedWithPrefix(`${resolvedKey}.`);
        if (resolvedProps.size > 0) {
          const merged = TaintSet.empty();
          for (const [, taint] of resolvedProps) merged.merge(taint);
          return merged;
        }
      }
    }
    // If the object itself is tainted (e.g. from JSON.parse), reading any property is tainted
    if (objTaint.tainted) return objTaint.clone();
    // If key is tainted but object has no tainted values, the read value is safe
  return objTaint;
}

// ── AST-based callee matching ──
// Verifies a CallExpression callee matches a specific Object.method pattern
// by walking the AST structure directly, not converting to string.
// Handles aliasing: if `Array` is shadowed, `isCalleeMatch` returns false.
function isCalleeMatch(node, objectName, methodName, env) {
  const callee = node.callee;
  if (!callee) return false;
  // For Object.method patterns (e.g., Array.from, Object.assign)
  if (callee.type === 'MemberExpression' && !callee.computed) {
    const prop = callee.property?.name;
    if (prop !== methodName) return false;
    if (callee.object.type === 'Identifier') {
      const objName = callee.object.name;
      // Direct match or alias match
      if (objName === objectName) return true;
      const alias = env?.aliases?.get(objName);
      if (alias === objectName) return true;
    }
  }
  return false;
}
// Match bare function name (e.g., eval, setTimeout) by AST Identifier type
function isCalleeIdentifier(node, name, env) {
  const callee = node.callee;
  if (!callee || callee.type !== 'Identifier') return false;
  if (callee.name === name) return true;
  const alias = env?.aliases?.get(callee.name);
  return alias === name;
}

// Check if a node refers to a well-known global by AST structure.
// Matches: bare Identifier (e.g., localStorage), or window.localStorage, self.localStorage, globalThis.localStorage
// Also resolves aliases via env.
function isGlobalRef(node, globalName, env) {
  if (!node) return false;
  if (node.type === 'Identifier') {
    if (node.name === globalName) return true;
    const alias = env?.aliases?.get(node.name);
    if (alias === globalName) return true;
    return false;
  }
  if (node.type === 'MemberExpression' && !node.computed) {
    if (node.property?.name !== globalName) return false;
    if (node.object?.type === 'Identifier') {
      const objName = node.object.name;
      if (objName === 'window' || objName === 'self' || objName === 'globalThis') return true;
      const alias = env?.aliases?.get(objName);
      if (alias === 'window' || alias === 'self' || alias === 'globalThis') return true;
    }
    return false;
  }
  return false;
}

// Known event handler attribute names (per HTML spec)
const EVENT_HANDLER_ATTRS = new Set([
  'onabort', 'onblur', 'oncancel', 'oncanplay', 'oncanplaythrough', 'onchange',
  'onclick', 'onclose', 'oncontextmenu', 'oncopy', 'oncuechange', 'oncut',
  'ondblclick', 'ondrag', 'ondragend', 'ondragenter', 'ondragleave', 'ondragover',
  'ondragstart', 'ondrop', 'ondurationchange', 'onemptied', 'onended', 'onerror',
  'onfocus', 'onfocusin', 'onfocusout', 'onformdata', 'ongotpointercapture',
  'oninput', 'oninvalid', 'onkeydown', 'onkeypress', 'onkeyup', 'onload',
  'onloadeddata', 'onloadedmetadata', 'onloadstart', 'onlostpointercapture',
  'onmousedown', 'onmouseenter', 'onmouseleave', 'onmousemove', 'onmouseout',
  'onmouseover', 'onmouseup', 'onpaste', 'onpause', 'onplay', 'onplaying',
  'onpointercancel', 'onpointerdown', 'onpointerenter', 'onpointerleave',
  'onpointermove', 'onpointerout', 'onpointerover', 'onpointerup', 'onprogress',
  'onratechange', 'onreset', 'onresize', 'onscroll', 'onsecuritypolicyviolation',
  'onseeked', 'onseeking', 'onselect', 'onselectionchange', 'onselectstart',
  'onslotchange', 'onstalled', 'onsubmit', 'onsuspend', 'ontimeupdate',
  'ontoggle', 'ontouchcancel', 'ontouchend', 'ontouchmove', 'ontouchstart',
  'ontransitioncancel', 'ontransitionend', 'ontransitionrun', 'ontransitionstart',
  'onvolumechange', 'onwaiting', 'onwheel',
]);

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
  let calleeStr = nodeToString(node.callee);
  let methodName = '';
  if (node.callee.type === 'MemberExpression' || node.callee.type === 'OptionalMemberExpression') {
    if (node.callee.computed) {
      // Computed property: obj[method]() — resolve the property to a constant string
      const resolved = resolveToConstant(node.callee.property, env, ctx);
      if (resolved) methodName = resolved;
    } else {
      methodName = node.callee.property?.name || '';
    }
  }

  // Resolve aliases for identifier callees: var e = eval; e(x) → eval(x)
  if (calleeStr && node.callee.type === 'Identifier') {
    const alias = env.aliases.get(calleeStr);
    if (alias) calleeStr = alias;
  }
  // Resolve MemberExpression callee aliases: obj.fn = eval; obj.fn(x) → eval(x)
  if (calleeStr && (node.callee.type === 'MemberExpression' || node.callee.type === 'OptionalMemberExpression')) {
    const memberAlias = env.aliases.get(calleeStr);
    if (memberAlias) calleeStr = memberAlias;
  }

  // Indirect eval: (0, eval)(x) — the callee is a SequenceExpression whose last element is eval
  if (!calleeStr && node.callee.type === 'SequenceExpression') {
    const last = node.callee.expressions[node.callee.expressions.length - 1];
    if (last) {
      const lastStr = nodeToString(last);
      if (lastStr) calleeStr = lastStr;
    }
  }

  // Babel parses import(x) as CallExpression with callee.type === 'Import'
  if (node.callee.type === 'Import' && node.arguments.length > 0) {
    const specifierTaint = evaluateExpr(node.arguments[0], env, ctx);
    if (specifierTaint.tainted) {
      for (const label of specifierTaint.labels) {
        ctx.findings.push({
          type: 'XSS',
          description: `XSS: tainted data flows to dynamic import()`,
          location: { file: ctx.file, line: node.loc?.start?.line || 0, column: node.loc?.start?.column || 0 },
          source: label,
        });
      }
    }
    return TaintSet.empty();
  }

  // For factory()() patterns: evaluate the callee CallExpression first
  // so ctx.returnedFuncNode is set before analyzeCalledFunction runs
  if (node.callee.type === 'CallExpression' || node.callee.type === 'OptionalCallExpression') {
    evaluateExpr(node.callee, env, ctx);
  }
  // For new Function(code)() patterns: evaluate the NewExpression callee
  // so the sink check inside evaluateNewExpr fires
  if (node.callee.type === 'NewExpression') {
    evaluateExpr(node.callee, env, ctx);
  }

  const argTaints = node.arguments.map(arg => evaluateExpr(arg, env, ctx));

  if (isSanitizer(calleeStr, methodName)) return TaintSet.empty();

  const sinkInfo = checkCallSink(calleeStr, methodName);
  if (sinkInfo) checkSinkCall(node, sinkInfo, argTaints, calleeStr || methodName, env, ctx);

  // Script element: el.setAttribute('src', tainted)
  if (methodName === 'setAttribute' && node.arguments.length >= 2) {
    const attrArg = node.arguments[0];
    if (attrArg && isStringLiteral(attrArg)) {
      const attrName = stringLiteralValue(attrArg).toLowerCase();
      const srcTaint = argTaints[1];
      if (srcTaint && srcTaint.tainted && node.callee?.object) {
        const objName = nodeToString(node.callee.object);
        const objKey = node.callee.object.type === 'Identifier' ? resolveId(node.callee.object, ctx) : objName;
        // Script element src
        if (attrName === 'src' && objName && (ctx.scriptElements.has(objKey) || ctx.scriptElements.has(objName))) {
          const loc = node.loc?.start || {};
          ctx.findings.push({
            type: 'Script Injection',
            severity: 'critical',
            title: 'Script Injection: tainted data flows to script element src',
            sink: { expression: `${objName}.setAttribute('src')`, file: ctx.file, line: loc.line || 0, col: loc.column || 0 },
            source: srcTaint.toArray().map(l => ({ type: l.sourceType, description: l.description, file: l.file, line: l.line })),
            path: buildTaintPath(srcTaint, `${objName}.setAttribute('src')`),
          });
        }
        // Dangerous attributes: event handlers, href, action, srcdoc, formaction
        const DANGEROUS_ATTRS = new Set(['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onblur',
          'onchange', 'oninput', 'onsubmit', 'onkeydown', 'onkeyup', 'onkeypress',
          'href', 'action', 'formaction', 'srcdoc', 'src', 'data', 'style']);
        if (DANGEROUS_ATTRS.has(attrName)) {
          const isEventHandler = EVENT_HANDLER_ATTRS.has(attrName);
          const isCss = attrName === 'style';
          const type = isCss ? 'CSS Injection' : 'XSS';
          const loc = node.loc?.start || {};
          ctx.findings.push({
            type,
            severity: isCss ? 'high' : (isEventHandler ? 'critical' : 'high'),
            title: `${type}: tainted data flows to setAttribute('${attrName}')`,
            sink: { expression: `${objName || 'element'}.setAttribute('${attrName}')`, file: ctx.file, line: loc.line || 0, col: loc.column || 0 },
            source: srcTaint.toArray().map(l => ({ type: l.sourceType, description: l.description, file: l.file, line: l.line })),
            path: buildTaintPath(srcTaint, `${objName || 'element'}.setAttribute('${attrName}')`),
          });
        }
      }
    }
  }

  // setTimeout/setInterval/queueMicrotask/requestAnimationFrame with function callback:
  // analyze body for closure taint reaching sinks
  if ((isCalleeIdentifier(node, 'setTimeout', env) || isCalleeIdentifier(node, 'setInterval', env) ||
       isCalleeIdentifier(node, 'queueMicrotask', env) || isCalleeIdentifier(node, 'requestAnimationFrame', env)) && node.arguments[0]) {
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

  // Array.from(iterable) / Array.of(...items) — propagate taint from args
  if (isCalleeMatch(node, 'Array', 'from', env) || isCalleeMatch(node, 'Array', 'of', env)) {
    const merged = TaintSet.empty();
    for (const t of argTaints) merged.merge(t);
    return merged;
  }

  // Object.fromEntries — propagate taint from entries (array of [key, value] pairs)
  if (isCalleeMatch(node, 'Object', 'fromEntries', env)) {
    return argTaints[0]?.clone() || TaintSet.empty();
  }

  // Reflect.get(obj, prop) → equivalent to obj[prop]
  if (isCalleeMatch(node, 'Reflect', 'get', env) && node.arguments.length >= 2) {
    const objNode = node.arguments[0];
    const propNode = node.arguments[1];
    const objStr = nodeToString(objNode);
    if (objStr && isStringLiteral(propNode)) {
      const propName = stringLiteralValue(propNode);
      // Per-property lookup: if the specific property binding exists, use it (even if empty)
      if (env.has(`${objStr}.${propName}`)) return env.get(`${objStr}.${propName}`).clone();
      if (objNode.type === 'Identifier') {
        const key = resolveId(objNode, ctx);
        if (env.has(`${key}.${propName}`)) return env.get(`${key}.${propName}`).clone();
      }
    }
    // Fall back: if object itself is tainted, reading any property is tainted
    return argTaints[0]?.clone() || TaintSet.empty();
  }

  // Object.defineProperty(obj, prop, descriptor) — propagate taint from descriptor.value or getter
  if (isCalleeMatch(node, 'Object', 'defineProperty', env) && node.arguments.length >= 3) {
    const objNode = node.arguments[0];
    const propNode = node.arguments[1];
    const descNode = node.arguments[2];
    if (objNode && propNode && descNode && descNode.type === 'ObjectExpression') {
      const objStr = nodeToString(objNode);
      const propName = isStringLiteral(propNode) ? stringLiteralValue(propNode) : null;
      for (const prop of descNode.properties) {
        if ((prop.type === 'ObjectProperty' || prop.type === 'Property') && prop.key) {
          const descPropName = prop.key.name || prop.key.value;
          if (descPropName === 'value') {
            const valTaint = evaluateExpr(prop.value, env, ctx);
            if (valTaint.tainted && objStr && propName) {
              env.set(`${objStr}.${propName}`, valTaint);
              if (objNode.type === 'Identifier') {
                const key = resolveId(objNode, ctx);
                env.set(`${key}.${propName}`, valTaint);
              }
            }
          }
          // Register getter function: Object.defineProperty(obj, 'prop', {get: function(){...}})
          if (descPropName === 'get' && objStr && propName) {
            const getterFunc = prop.value;
            if (getterFunc && (getterFunc.type === 'FunctionExpression' || getterFunc.type === 'ArrowFunctionExpression')) {
              getterFunc._closureEnv = env;
              ctx.funcMap.set(`getter:${objStr}.${propName}`, getterFunc);
              if (objNode.type === 'Identifier') {
                const key = resolveId(objNode, ctx);
                ctx.funcMap.set(`getter:${key}.${propName}`, getterFunc);
              }
            }
          }
        }
      }
    }
    return TaintSet.empty();
  }

  // Object.create(proto, propertyDescriptors) — extract taint from descriptor values
  if (isCalleeMatch(node, 'Object', 'create', env) && node.arguments.length >= 2) {
    const descMapNode = node.arguments[1];
    if (descMapNode && descMapNode.type === 'ObjectExpression') {
      const resultTaint = TaintSet.empty();
      for (const prop of descMapNode.properties) {
        if ((prop.type === 'ObjectProperty' || prop.type === 'Property') && prop.key && prop.value) {
          const propName = prop.key.name || prop.key.value;
          if (propName && prop.value.type === 'ObjectExpression') {
            // Extract value from property descriptor: {value: ..., writable: ...}
            for (const descProp of prop.value.properties) {
              if ((descProp.type === 'ObjectProperty' || descProp.type === 'Property') &&
                  descProp.key && (descProp.key.name === 'value' || descProp.key.value === 'value')) {
                const valTaint = evaluateExpr(descProp.value, env, ctx);
                if (valTaint.tainted) resultTaint.merge(valTaint);
              }
            }
          }
        }
      }
      return resultTaint;
    }
  }

  // Reflect.apply(fn, thisArg, argsArray) — interprocedural call
  if (isCalleeMatch(node, 'Reflect', 'apply', env) && node.arguments.length >= 3) {
    const fnNode = node.arguments[0];
    const argsArrayTaint = argTaints[2] || TaintSet.empty();
    const funcName = nodeToString(fnNode);
    const funcRef = fnNode.type === 'Identifier'
      ? (ctx.funcMap.get(resolveId(fnNode, ctx)) || ctx.funcMap.get(fnNode.name))
      : (funcName && ctx.funcMap.get(funcName));
    if (funcRef && funcRef.body) {
      const synthCall = { ...node, callee: fnNode, arguments: node.arguments.slice(2) };
      return analyzeCalledFunction(synthCall, funcName, [argsArrayTaint], env, ctx);
    }
    return argsArrayTaint.clone();
  }

  // Object.freeze/seal/preventExtensions — return the same object, propagate taint
  if (isCalleeMatch(node, 'Object', 'freeze', env) || isCalleeMatch(node, 'Object', 'seal', env) || isCalleeMatch(node, 'Object', 'preventExtensions', env)) {
    return argTaints[0]?.clone() || TaintSet.empty();
  }

  // Object.values/keys/entries — propagate taint from object properties
  // Object.keys returns property names (strings) — not tainted by values
  if (isCalleeMatch(node, 'Object', 'keys', env)) return TaintSet.empty();

  if (isCalleeMatch(node, 'Object', 'values', env) || isCalleeMatch(node, 'Object', 'entries', env)) {
    const argTaint = argTaints[0] || TaintSet.empty();
    if (argTaint.tainted) return argTaint.clone();
    // Also check if any properties of the argument are tainted
    const argNode = node.arguments[0];
    if (argNode) {
      const argStr = nodeToString(argNode);
      if (argStr) {
        const propTaints = env.getTaintedWithPrefix(`${argStr}.`);
        if (propTaints.size > 0) {
          const merged = TaintSet.empty();
          for (const [, taint] of propTaints) merged.merge(taint);
          return merged;
        }
      }
    }
    return TaintSet.empty();
  }

  // Object.assign(target, ...sources) — propagate taint from sources to target and return
  if (isCalleeMatch(node, 'Object', 'assign', env) && node.arguments.length >= 2) {
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
        // Propagate per-property taints from source objects to target
        // Handles: Object.assign(target, { html: tainted }) → target.html = tainted
        for (let si = 1; si < node.arguments.length; si++) {
          const srcNode = node.arguments[si];
          if (srcNode.type === 'ObjectExpression') {
            for (const prop of srcNode.properties) {
              if (prop.type === 'SpreadElement') continue;
              if ((prop.type === 'ObjectProperty' || prop.type === 'Property') && prop.key) {
                const propName = prop.key.name || prop.key.value;
                if (propName) {
                  const propTaint = evaluateExpr(prop.value, env, ctx);
                  env.set(`${targetStr}.${propName}`, propTaint);
                }
              }
            }
          } else {
            const srcStr = nodeToString(srcNode);
            if (srcStr) {
              // Copy per-property taints from source identifier
              for (const [key, taint] of env.getTaintedWithPrefix(`${srcStr}.`)) {
                const propName = key.slice(srcStr.length + 1);
                if (propName && !propName.startsWith('#')) {
                  env.set(`${targetStr}.${propName}`, taint);
                }
              }
            }
          }
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

  // Check if there's a user-defined function for this exact callee path before deferring to builtins.
  // Only match full dot-path (e.g., "s.get") — prevents Map.get from intercepting class method s.get().
  if (methodName && (node.callee?.type === 'MemberExpression' || node.callee?.type === 'OptionalMemberExpression')) {
    const fullPath = nodeToString(node.callee);
    if (fullPath && ctx.funcMap.has(fullPath)) {
      return analyzeCalledFunction(node, calleeStr, argTaints, env, ctx);
    }
  }

  const propagated = handleBuiltinMethod(methodName, node, argTaints, env, ctx);
  if (propagated !== null) return propagated;

  // Chained method on returned object: factory().method()
  // After evaluating the callee object (a CallExpression), ctx.returnedMethods may have the method
  if (methodName && ctx.returnedMethods && ctx.returnedMethods[methodName] &&
      (node.callee?.type === 'MemberExpression' || node.callee?.type === 'OptionalMemberExpression') &&
      (node.callee.object?.type === 'CallExpression' || node.callee.object?.type === 'OptionalCallExpression')) {
    const funcNode = ctx.returnedMethods[methodName];
    ctx.returnedMethods = null;
    ctx.funcMap.set(methodName, funcNode);
  }

  return analyzeCalledFunction(node, calleeStr, argTaints, env, ctx);
}

// Walk AST to find calls to a named function (e.g., resolve(x) inside Promise constructor)
// Scope-aware: skips nested function scopes that shadow the resolve parameter
function walkCallsToResolve(root, resolveName, env, ctx, taintOut) {
  if (!root || typeof root !== 'object') return;
  const stack = [root];
  while (stack.length > 0) {
    const node = stack.pop();
    if (!node || typeof node !== 'object') continue;
    if (node.type === 'CallExpression' || node.type === 'OptionalCallExpression') {
      if (node.callee?.type === 'Identifier' && node.callee.name === resolveName && node.arguments[0]) {
        const argTaint = evaluateExpr(node.arguments[0], env, ctx);
        taintOut.merge(argTaint);
      }
    }
    // Skip nested function scopes that shadow the resolve name
    if (node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression' ||
        node.type === 'FunctionDeclaration') {
      const shadowsResolve = node.params?.some(p =>
        p.type === 'Identifier' && p.name === resolveName);
      if (shadowsResolve) continue;
    }
    for (const key of Object.keys(node)) {
      if (key === 'loc' || key === 'start' || key === 'end' || key === '_closureEnv') continue;
      const child = node[key];
      if (Array.isArray(child)) {
        for (const item of child) {
          if (item && typeof item === 'object' && item.type) stack.push(item);
        }
      } else if (child && typeof child === 'object' && child.type) {
        stack.push(child);
      }
    }
  }
}

// ── New expression ──
function evaluateNewExpr(node, env, ctx) {
  let constructorName = nodeToString(node.callee);
  // Resolve aliases: var F = Function; new F(code) → new Function(code)
  if (constructorName && node.callee.type === 'Identifier') {
    const alias = env.aliases.get(constructorName);
    if (alias) constructorName = alias;
  }
  const argTaints = node.arguments.map(arg => evaluateExpr(arg, env, ctx));

  if (constructorName && CONSTRUCTOR_SOURCES[constructorName]) {
    const argTaint = argTaints.reduce((acc, t) => acc.merge(t), TaintSet.empty());
    if (argTaint.tainted) return argTaint;
    const loc = node.loc?.start || {};
    return TaintSet.from(new TaintLabel(CONSTRUCTOR_SOURCES[constructorName], ctx.file, loc.line || 0, loc.column || 0, `new ${constructorName}()`));
  }

  if (isGlobalRef(node.callee, 'Function', env)) {
    // new Function(body) or new Function(arg1, ..., body) — any tainted arg is code injection
    const allArgIndices = argTaints.map((_, i) => i);
    checkSinkCall(node, { type: 'XSS', taintedArgs: allArgIndices }, argTaints, 'new Function()', env, ctx);
  }

  // new Promise(function(resolve, reject) { resolve(tainted) }) → taint propagates to .then()
  if (isGlobalRef(node.callee, 'Promise', env) && node.arguments[0]) {
    let callback = node.arguments[0];
    if (callback.type === 'ArrowFunctionExpression' || callback.type === 'FunctionExpression') {
      const childEnv = env.child();
      // The first param is `resolve` — calls to resolve(x) should capture x's taint as the promise's value
      // We analyze the callback body and track what resolve() is called with
      const resolveName = callback.params[0]?.type === 'Identifier' ? callback.params[0].name : null;
      if (resolveName) {
        // Create a synthetic "resolve" function that captures its argument taint
        // by analyzing the callback body and looking for resolve(x) calls
        if (callback.body.type === 'BlockStatement') {
          const result = analyzeInlineFunction(callback, childEnv, ctx);
          // The return taint of the inline function captures resolve(x) calls
          // But we need to specifically find what resolve() was called with.
          // Walk the callback body for CallExpression where callee is resolve
          const resolveTaint = TaintSet.empty();
          walkCallsToResolve(callback.body, resolveName, env, ctx, resolveTaint);
          if (resolveTaint.tainted) return resolveTaint;
          return result;
        }
      }
    }
  }

  // new CustomEvent('type', {detail: tainted}) — track event type and detail taint
  if (isGlobalRef(node.callee, 'CustomEvent', env) && node.arguments.length >= 2) {
    const eventTypeNode = node.arguments[0];
    const optionsNode = node.arguments[1];
    if (eventTypeNode && (eventTypeNode.type === 'StringLiteral' || (eventTypeNode.type === 'Literal' && typeof eventTypeNode.value === 'string'))) {
      const eventTypeName = eventTypeNode.value;
      // Initialize custom event type tracker if needed
      if (!ctx._customEventTypes) ctx._customEventTypes = new Map();
      // The assignment target will be set by the caller (processAssignment)
      // Store the event type for later resolution; we use _pendingCustomEventType
      ctx._pendingCustomEventType = eventTypeName;
    }
    // Extract detail taint from options object
    if (optionsNode && optionsNode.type === 'ObjectExpression') {
      for (const prop of optionsNode.properties) {
        if ((prop.type === 'ObjectProperty' || prop.type === 'Property') && prop.key) {
          const pname = prop.key.name || prop.key.value;
          if (pname === 'detail') {
            const detailTaint = evaluateExpr(prop.value, env, ctx);
            if (detailTaint.tainted) {
              ctx._pendingCustomEventDetailTaint = detailTaint;
              return detailTaint;
            }
          }
        }
      }
    }
  }

  // Proxy: new Proxy(target, handler) — analyze handler.get return taint
  if (constructorName === 'Proxy' && node.arguments.length >= 2) {
    const handlerNode = node.arguments[1];
    if (handlerNode.type === 'ObjectExpression') {
      for (const prop of handlerNode.properties) {
        if ((prop.type === 'ObjectProperty' || prop.type === 'Property' || prop.type === 'ObjectMethod') && prop.key) {
          const pname = prop.key.name || prop.key.value;
          if (pname === 'get') {
            const getFunc = prop.type === 'ObjectMethod' ? prop : prop.value;
            if (getFunc && (getFunc.type === 'FunctionExpression' || getFunc.type === 'ArrowFunctionExpression' || getFunc.type === 'ObjectMethod')) {
              const childEnv = env.child();
              let getTaint;
              if (getFunc.body?.type === 'BlockStatement') {
                getTaint = analyzeInlineFunction(getFunc, childEnv, ctx);
              } else if (getFunc.body) {
                getTaint = evaluateExpr(getFunc.body, childEnv, ctx);
              }
              if (getTaint?.tainted) return getTaint;
            }
          }
        }
      }
    }
    // If handler is an identifier, try to resolve its get method via funcMap
    if (handlerNode.type === 'Identifier') {
      const handlerName = handlerNode.name;
      const resolvedName = resolveId(handlerNode, ctx);
      const getFunc = ctx.funcMap.get(`${handlerName}.get`) || ctx.funcMap.get(`${resolvedName}.get`);
      if (getFunc && (getFunc.type === 'FunctionExpression' || getFunc.type === 'ArrowFunctionExpression' || getFunc.type === 'FunctionDeclaration')) {
        const childEnv = env.child();
        let getTaint;
        if (getFunc.body?.type === 'BlockStatement') {
          getTaint = analyzeInlineFunction(getFunc, childEnv, ctx);
        } else if (getFunc.body) {
          getTaint = evaluateExpr(getFunc.body, childEnv, ctx);
        }
        if (getTaint?.tainted) return getTaint;
      }
    }
  }

  // Analyze constructor body to track this.* assignments
  if (constructorName) {
    const funcNode = ctx.funcMap.get(constructorName);
    if (funcNode && funcNode.body) {
      const callSig = `new:${constructorName}:${argTaints.map(t => t.tainted ? '1' : '0').join('')}`;
      if (!ctx.analyzedCalls.has(callSig)) {
        ctx.analyzedCalls.set(callSig, TaintSet.empty());
        const childEnv = (funcNode._closureEnv || env).child();
        // Set up 'this' as empty so this.* assignments are tracked
        childEnv.set('this', TaintSet.empty());
        for (let i = 0; i < funcNode.params.length; i++) {
          assignToPattern(funcNode.params[i], argTaints[i] || TaintSet.empty(), childEnv, ctx);
        }
        const body = funcNode.body.type === 'BlockStatement' ? funcNode.body
          : { type: 'BlockStatement', body: [{ type: 'ReturnStatement', argument: funcNode.body }] };
        analyzeInlineFunction({ ...funcNode, body }, childEnv, ctx);

        // Propagate this.* bindings to the parent env for instance resolution
        // Includes clean bindings so sanitized properties are tracked accurately
        const thisTaint = TaintSet.empty();
        for (const [key, taint] of childEnv.bindings) {
          if (key.startsWith('this.') && key.length > 5) {
            env.set(key, taint);
            if (taint.tainted) thisTaint.merge(taint);
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
    case 'repeat': case 'at': case 'charAt':
    case 'valueOf': case 'toString':
      return objTaint.clone();

    case 'padStart': case 'padEnd':
      // padStart/padEnd(targetLength, padString) — result includes both obj and pad string
      return objTaint.clone().merge(argTaints[1] || TaintSet.empty());

    case 'match': case 'matchAll':
      // Returns array of matches — preserve taint from the source string
      return objTaint.clone();

    case 'exec':
      // RegExp.exec(string) — taint comes from the argument string, not the regex
      return argTaints[0]?.clone() || TaintSet.empty();

    case 'search': case 'localeCompare':
      // Returns number — kill taint
      return TaintSet.empty();

    case 'charCodeAt': case 'codePointAt':
      // These return numbers — kill taint
      return TaintSet.empty();

    case 'splice':
      // Returns removed elements — they carry the array's taint
      return objTaint.clone();

    case 'bind': {
      // fn.bind(thisArg, ...prefilled) returns a bound function — register it in funcMap
      // so when the result is called, it resolves to the original function
      const callee = node.callee?.object;
      if (callee) {
        const funcRef = callee.type === 'Identifier'
          ? (ctx.funcMap.get(resolveId(callee, ctx)) || ctx.funcMap.get(callee.name))
          : null;
        if (funcRef) {
          // Store the thisArg node so analyzeCalledFunction can bind this.* properties
          const thisArgNode = node.arguments?.[0];
          if (thisArgNode) funcRef._boundThisArg = nodeToString(thisArgNode);
          // Store pre-filled argument nodes for partial application: fn.bind(null, arg1, arg2)
          if (node.arguments && node.arguments.length > 1) {
            funcRef._boundArgs = node.arguments.slice(1);
          }
          ctx.returnedFuncNode = funcRef;
        }
      }
      return objTaint.clone();
    }

    case 'fill':
      // Array.fill(value) — returns array filled with the value's taint
      return argTaints[0]?.clone() || TaintSet.empty();

    case 'concat':
      return objTaint.clone().merge(argTaints.reduce((a, t) => a.merge(t), TaintSet.empty()));

    case 'replace': case 'replaceAll':
      return objTaint.clone().merge(argTaints[1] || TaintSet.empty());

    case 'split':
      return objTaint.clone();

    case 'join':
      return objTaint.clone().merge(argTaints[0] || TaintSet.empty());

    case 'map': {
      // map creates a new array from callback returns — taint is ONLY from callback result
      const cbTaint = analyzeArrayCallback(node, argTaints, objTaint, env, ctx);
      return cbTaint;
    }

    case 'filter': case 'find':
    case 'flat': case 'reverse': case 'sort':
      return objTaint.clone();

    case 'values': case 'keys': case 'entries': {
      // For Map/Set, also merge per-key taints stored as obj.#key_*
      const result = objTaint.clone();
      if (node.callee?.object) {
        const iterObjStr = nodeToString(node.callee.object);
        if (iterObjStr) {
          const perKeyTaints = env.getTaintedWithPrefix(`${iterObjStr}.#key_`);
          for (const [, t] of perKeyTaints) result.merge(t);
        }
      }
      return result;
    }

    case 'flatMap': {
      // flatMap creates a new array from callback returns — taint is ONLY from callback result
      const cbTaint = analyzeArrayCallback(node, argTaints, objTaint, env, ctx);
      return cbTaint;
    }

    case 'findIndex': case 'indexOf': case 'lastIndexOf':
      // These return a number — kill taint
      analyzeArrayCallback(node, argTaints, objTaint, env, ctx);
      return TaintSet.empty();

    case 'some': case 'every': case 'includes':
      // These return a boolean — kill taint, but analyze callback for sinks
      analyzeArrayCallback(node, argTaints, objTaint, env, ctx);
      return TaintSet.empty();

    case 'reduce': case 'reduceRight': {
      // Analyze the callback: (accumulator, element, index, array) => ...
      // The accumulator starts with initial value (argTaints[1]) and merges with array elements
      const cbReduce = node.arguments[0];
      if (cbReduce && (cbReduce.type === 'ArrowFunctionExpression' || cbReduce.type === 'FunctionExpression')) {
        const childEnv = env.child();
        // accumulator param gets initial value taint + array element taint (conservative: any iteration can feed back)
        const accTaint = objTaint.clone().merge(argTaints[1] || TaintSet.empty());
        if (cbReduce.params[0]) assignToPattern(cbReduce.params[0], accTaint, childEnv, ctx);
        // element param gets array element taint
        if (cbReduce.params[1]) assignToPattern(cbReduce.params[1], objTaint.clone(), childEnv, ctx);
        // index param is safe
        if (cbReduce.params[2]) assignToPattern(cbReduce.params[2], TaintSet.empty(), childEnv, ctx);
        // Evaluate callback body for return taint
        let retTaint;
        if (cbReduce.body.type === 'BlockStatement') {
          retTaint = analyzeInlineFunction(cbReduce, childEnv, ctx);
        } else {
          retTaint = evaluateExpr(cbReduce.body, childEnv, ctx);
        }
        return retTaint;
      }
      return objTaint.clone().merge(argTaints[1] || TaintSet.empty());
    }

    case 'forEach': {
      // For Map/Set forEach, also include per-key taint stored as obj.#key_*
      let effectiveTaint = objTaint.clone();
      if (node.callee?.object) {
        const objStr = nodeToString(node.callee.object);
        if (objStr) {
          const perKeyTaints = env.getTaintedWithPrefix(`${objStr}.#key_`);
          for (const [, t] of perKeyTaints) effectiveTaint.merge(t);
        }
      }
      analyzeArrayCallback(node, argTaints, effectiveTaint, env, ctx);
      return TaintSet.empty();
    }

    case 'set': {
      // Map.set(key, value) — store taint per-key for precise tracking
      const valueTaint = argTaints[1] || TaintSet.empty();
      if (node.callee?.object) {
        const objStr = nodeToString(node.callee.object);
        const mapKey = node.arguments[0];
        const keyStr = mapKey && (mapKey.type === 'StringLiteral' || mapKey.type === 'Literal')
          ? (mapKey.value ?? mapKey.raw) : null;
        if (objStr && keyStr != null) {
          // Per-key taint: store as "map.#key_<keyStr>"
          const perKeyPath = `${objStr}.#key_${keyStr}`;
          env.set(perKeyPath, valueTaint.clone());
          if (node.callee.object.type === 'Identifier') {
            const scopedKey = resolveId(node.callee.object, ctx);
            env.set(`${scopedKey}.#key_${keyStr}`, valueTaint.clone());
          }
          // Track nested Map aliases: map.set('key', otherMap) → alias for per-key chaining
          const valueArg = node.arguments[1];
          if (valueArg?.type === 'Identifier') {
            const valueId = resolveId(valueArg, ctx);
            env.aliases.set(perKeyPath, valueId);
            if (node.callee.object.type === 'Identifier') {
              const scopedKey = resolveId(node.callee.object, ctx);
              env.aliases.set(`${scopedKey}.#key_${keyStr}`, valueId);
            }
          }
        } else if (objStr && valueTaint.tainted) {
          // Dynamic key: fall back to tainting the whole Map
          env.set(objStr, env.get(objStr).clone().merge(valueTaint));
          if (node.callee.object.type === 'Identifier') {
            const key = resolveId(node.callee.object, ctx);
            env.set(key, env.get(key).clone().merge(valueTaint));
          }
        }
      }
      // If the callee resolves to a user-defined function, let analyzeCalledFunction handle it
      const setCalleeStr = nodeToString(node.callee);
      if (setCalleeStr && ctx.funcMap.has(setCalleeStr)) return null;
      if (ctx.funcMap.has('set')) {
        const setFunc = ctx.funcMap.get('set');
        if (setFunc && setFunc.body) return null;
      }
      return objTaint.clone(); // Map.set returns the Map itself
    }

    case 'add': {
      // Set.add(value) — taint the Set if value is tainted
      const valueTaint = argTaints[0] || TaintSet.empty();
      if (valueTaint.tainted && node.callee?.object) {
        if (node.callee.object.type === 'Identifier') {
          const key = resolveId(node.callee.object, ctx);
          env.set(key, env.get(key).clone().merge(valueTaint));
          env.set(`global:${node.callee.object.name}`, env.get(key).clone());
        } else {
          const objStr = nodeToString(node.callee.object);
          if (objStr) env.set(objStr, env.get(objStr).clone().merge(valueTaint));
        }
      }
      return objTaint.clone();
    }

    case 'push': case 'unshift':
      if (node.callee?.object) {
        const objStr = nodeToString(node.callee.object);
        // Update scope-resolved key and global: prefix for bare identifiers
        if (node.callee.object.type === 'Identifier') {
          const key = resolveId(node.callee.object, ctx);
          const merged = env.get(key).clone();
          for (const t of argTaints) merged.merge(t);
          env.set(key, merged);
          env.set(`global:${node.callee.object.name}`, merged);
        } else if (objStr) {
          const merged = env.get(objStr).clone();
          for (const t of argTaints) merged.merge(t);
          env.set(objStr, merged);
        }
        // Register function arguments pushed to arrays so computed calls (arr[0]()) can resolve them
        for (const arg of node.arguments) {
          if (arg.type === 'FunctionExpression' || arg.type === 'ArrowFunctionExpression') {
            arg._closureEnv = env;
            if (objStr) ctx.funcMap.set(`${objStr}[]`, arg);
            if (node.callee.object.type === 'Identifier') {
              const key = resolveId(node.callee.object, ctx);
              ctx.funcMap.set(`${key}[]`, arg);
            }
          }
          // Resolve identifier references to known functions
          if (arg.type === 'Identifier') {
            const refKey = resolveId(arg, ctx);
            const refFunc = ctx.funcMap.get(refKey) || ctx.funcMap.get(arg.name);
            if (refFunc) {
              if (objStr) ctx.funcMap.set(`${objStr}[]`, refFunc);
              if (node.callee.object.type === 'Identifier') {
                const key = resolveId(node.callee.object, ctx);
                ctx.funcMap.set(`${key}[]`, refFunc);
              }
            }
          }
          // IIFE pattern: handlers.push((function(x){return function(){...}})(args))
          // Resolve the IIFE to find the returned function node
          if (arg.type === 'CallExpression') {
            const iifeCallee = arg.callee;
            const iifeFn = (iifeCallee.type === 'FunctionExpression' || iifeCallee.type === 'ArrowFunctionExpression')
              ? iifeCallee : null;
            if (iifeFn) {
              const retFunc = findReturnedFunction(iifeFn);
              if (retFunc) {
                retFunc._closureEnv = env;
                if (objStr) ctx.funcMap.set(`${objStr}[]`, retFunc);
                if (node.callee.object.type === 'Identifier') {
                  const key = resolveId(node.callee.object, ctx);
                  ctx.funcMap.set(`${key}[]`, retFunc);
                }
              }
            }
          }
        }
      }
      return TaintSet.empty();

    case 'pop': case 'shift':
      return objTaint.clone();

    case 'next':
      // Generator iterator .next() — propagate taint from the iterator (which holds yield taint)
      return objTaint.clone();

    case 'call': {
      // Function.prototype.call(thisArg, ...args) — invoke with shifted args
      // e.g. Array.prototype.join.call(arr, sep) → join taint from first arg (the array)
      const thisArgTaint = argTaints[0] || TaintSet.empty();
      const restArgTaints = argTaints.slice(1);
      const calleeObj = node.callee?.object;
      const protoMethod = calleeObj ? nodeToString(calleeObj) : null;
      if (protoMethod) {
        // Extract the terminal method name by walking the AST MemberExpression chain
        // instead of string-splitting: Array.prototype.join → property 'join'
        let method;
        if (calleeObj.type === 'MemberExpression' || calleeObj.type === 'OptionalMemberExpression') {
          method = calleeObj.property?.name || calleeObj.property?.value;
        } else if (calleeObj.type === 'Identifier') {
          method = calleeObj.name;
        } else {
          method = null;
        }
        // Try builtin method first
        const result = handleBuiltinMethod(method, {
          ...node,
          callee: { ...node.callee, object: node.arguments?.[0] || node.callee.object },
        }, restArgTaints, env, ctx);
        if (result !== null) return thisArgTaint.clone().merge(result);
        // Try interprocedural: fn.call(thisArg, arg1, ...) → analyze fn with args
        const funcRef = calleeObj.type === 'Identifier'
          ? (ctx.funcMap.get(resolveId(calleeObj, ctx)) || ctx.funcMap.get(calleeObj.name))
          : (protoMethod && ctx.funcMap.get(protoMethod));
        if (funcRef && funcRef.body) {
          const thisArgNode = node.arguments?.[0];
          const thisArgName = thisArgNode ? nodeToString(thisArgNode) : null;
          if (thisArgName) {
            funcRef._boundThisArg = thisArgName;
          } else if (thisArgNode && thisArgNode.type === 'ObjectExpression') {
            // Inline object literal: evaluate properties into this.* bindings
            funcRef._boundThisNode = thisArgNode;
          }
          const synthCall = { ...node, callee: calleeObj, arguments: node.arguments.slice(1) };
          return analyzeCalledFunction(synthCall, protoMethod, restArgTaints, env, ctx);
        }
      }
      return thisArgTaint.clone().merge(restArgTaints.reduce((a, t) => a.merge(t), TaintSet.empty()));
    }

    case 'apply': {
      // Function.prototype.apply(thisArg, argsArray) — similar to call but args in array
      const thisArgTaint = argTaints[0] || TaintSet.empty();
      const argsArrayTaint = argTaints[1] || TaintSet.empty();
      // Try interprocedural: fn.apply(thisArg, [args]) → analyze fn
      const applyObj = node.callee?.object;
      if (applyObj) {
        const funcName = nodeToString(applyObj);
        const funcRef = applyObj.type === 'Identifier'
          ? (ctx.funcMap.get(resolveId(applyObj, ctx)) || ctx.funcMap.get(applyObj.name))
          : (funcName && ctx.funcMap.get(funcName));
        if (funcRef && funcRef.body) {
          // For apply, args are in an array — pass the array taint as each arg
          const synthCall = { ...node, callee: applyObj, arguments: node.arguments?.slice(1) || [] };
          return analyzeCalledFunction(synthCall, funcName, [argsArrayTaint], env, ctx);
        }
      }
      return thisArgTaint.clone().merge(argsArrayTaint);
    }

    case 'get': case 'getAll': {
      // Check per-key Map taint first
      const getObjStr = nodeToString(node.callee?.object);
      const getKeyArg = node.arguments?.[0];
      const getKeyStr = getKeyArg && (getKeyArg.type === 'StringLiteral' || getKeyArg.type === 'Literal')
        ? (getKeyArg.value ?? getKeyArg.raw) : null;
      if (getObjStr && getKeyStr != null) {
        const perKeyPath = `${getObjStr}.#key_${getKeyStr}`;
        const perKeyTaint = env.get(perKeyPath);
        if (perKeyTaint.tainted) return perKeyTaint.clone();
        // Also check scope-resolved key
        if (node.callee?.object?.type === 'Identifier') {
          const scopedKey = resolveId(node.callee.object, ctx);
          const scopedPerKey = env.get(`${scopedKey}.#key_${getKeyStr}`);
          if (scopedPerKey.tainted) return scopedPerKey.clone();
        }
      }
      // Chained .get().get(): resolve intermediate Map alias for nested Map lookups
      // e.g., outer.get('inner').get('key') where outer.set('inner', innerMap)
      if (!getObjStr && getKeyStr != null && node.callee?.object?.type === 'CallExpression') {
        const innerCall = node.callee.object;
        const innerCallee = innerCall.callee;
        if ((innerCallee?.type === 'MemberExpression' || innerCallee?.type === 'OptionalMemberExpression') &&
            (innerCallee.property?.name === 'get')) {
          const innerObjStr = nodeToString(innerCallee.object);
          const innerKeyArg = innerCall.arguments?.[0];
          const innerKeyStr = innerKeyArg && (innerKeyArg.type === 'StringLiteral' || innerKeyArg.type === 'Literal')
            ? (innerKeyArg.value ?? innerKeyArg.raw) : null;
          if (innerObjStr && innerKeyStr != null) {
            // Look up alias: outer.#key_inner → inner variable
            const innerPerKeyPath = `${innerObjStr}.#key_${innerKeyStr}`;
            const aliasTarget = env.aliases.get(innerPerKeyPath);
            if (aliasTarget) {
              const nestedPerKey = env.get(`${aliasTarget}.#key_${getKeyStr}`);
              if (nestedPerKey.tainted) return nestedPerKey.clone();
            }
            // Also try scope-resolved
            if (innerCallee.object?.type === 'Identifier') {
              const scopedInner = resolveId(innerCallee.object, ctx);
              const scopedInnerPerKey = `${scopedInner}.#key_${innerKeyStr}`;
              const aliasTarget2 = env.aliases.get(scopedInnerPerKey);
              if (aliasTarget2) {
                const nestedPerKey2 = env.get(`${aliasTarget2}.#key_${getKeyStr}`);
                if (nestedPerKey2.tainted) return nestedPerKey2.clone();
              }
            }
          }
        }
      }
      if (objTaint.tainted) return objTaint.clone();
      // Storage API: localStorage.get() / sessionStorage.get()
      if (node.callee?.object) {
        const storageObj = node.callee.object;
        if (isGlobalRef(storageObj, 'localStorage', env)) {
          const loc = node.loc?.start || {};
          return TaintSet.from(new TaintLabel('storage.local', ctx.file, loc.line || 0, loc.column || 0, 'localStorage.getItem()'));
        }
        if (isGlobalRef(storageObj, 'sessionStorage', env)) {
          const loc = node.loc?.start || {};
          return TaintSet.from(new TaintLabel('storage.session', ctx.file, loc.line || 0, loc.column || 0, 'sessionStorage.getItem()'));
        }
      }
      // If the callee resolves to a user-defined function, let analyzeCalledFunction handle it
      const getCalleeStr = nodeToString(node.callee);
      if (getCalleeStr && ctx.funcMap.has(getCalleeStr)) return null;
      return TaintSet.empty();
    }

    case 'getItem': {
      // Storage API: localStorage.getItem() / sessionStorage.getItem()
      if (node.callee?.object) {
        const storageObj = node.callee.object;
        if (isGlobalRef(storageObj, 'localStorage', env)) {
          const loc = node.loc?.start || {};
          return TaintSet.from(new TaintLabel('storage.local', ctx.file, loc.line || 0, loc.column || 0, 'localStorage.getItem()'));
        }
        if (isGlobalRef(storageObj, 'sessionStorage', env)) {
          const loc = node.loc?.start || {};
          return TaintSet.from(new TaintLabel('storage.session', ctx.file, loc.line || 0, loc.column || 0, 'sessionStorage.getItem()'));
        }
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

    case 'dispatchEvent': {
      // dispatchEvent(eventObj) — find matching custom event listeners and re-analyze
      // with tainted event param from the dispatched event
      const eventArg = node.arguments?.[0];
      if (eventArg) {
        const eventTaint = argTaints[0] || TaintSet.empty();
        // Look up event type by variable name (try raw name first, then scope-resolved)
        const eventStr = eventArg.type === 'Identifier' ? eventArg.name : nodeToString(eventArg);
        let eventType = eventStr && ctx._customEventTypes?.get(eventStr);
        if (!eventType && eventArg.type === 'Identifier') {
          const resolvedKey = resolveId(eventArg, ctx);
          eventType = ctx._customEventTypes?.get(resolvedKey);
        }
        if (eventType && ctx.eventListeners.has(eventType)) {
          for (const { callback, env: listenerEnv } of ctx.eventListeners.get(eventType)) {
            if (callback.params[0]) {
              const childEnv = listenerEnv.child();
              const paramName = callback.params[0].type === 'Identifier' ? callback.params[0].name : null;
              if (paramName) {
                // Taint the event parameter and its .detail property
                assignToPattern(callback.params[0], eventTaint, childEnv, ctx);
                // Get detail taint from the event object
                const detailKey = eventStr ? `${eventStr}.detail` : '';
                const detailTaint = env.get(detailKey);
                if (detailTaint.tainted) {
                  childEnv.set(`${paramName}.detail`, detailTaint);
                }
              }
              if (callback.body.type === 'BlockStatement') {
                analyzeInlineFunction(callback, childEnv, ctx);
              }
            }
          }
        }
      }
      return TaintSet.empty();
    }

    case 'resolve': case 'reject':
      // Promise.resolve(val) / Promise.reject(val) — propagate taint
      return argTaints[0]?.clone() || TaintSet.empty();

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

  // Handle hashchange and other EVENT_SOURCES events
  if (eventName && eventName !== 'message' && EVENT_SOURCES[eventName] && callback.params[0]) {
    const paramName = callback.params[0].type === 'Identifier' ? callback.params[0].name : null;
    if (paramName) {
      const evtSource = EVENT_SOURCES[eventName];
      const loc = callback.loc?.start || {};
      const label = new TaintLabel(evtSource.label, ctx.file, loc.line || 0, loc.column || 0, `${paramName}.${evtSource.property}`);
      childEnv.set(`${paramName}.${evtSource.property}`, TaintSet.from(label));
      // Also taint the param itself so member access chains work
      assignToPattern(callback.params[0], TaintSet.from(label), childEnv, ctx);
    }
  }

  if (eventName === 'message' && callback.params[0] && !ctx.isWorker) {
    // Check if the handler validates event.origin — returns 'strong', 'weak', or false
    const originCheck = callbackChecksOrigin(callback.body, ctx);
    if (originCheck !== 'strong') {
      const paramName = callback.params[0].type === 'Identifier' ? callback.params[0].name : null;
      if (paramName) {
        const loc = callback.loc?.start || {};
        const desc = originCheck === 'weak'
          ? `${paramName}.data (weak origin check)`
          : `${paramName}.data (no origin check)`;
        const label = new TaintLabel('postMessage.data', ctx.file, loc.line || 0, loc.column || 0, desc);
        assignToPattern(callback.params[0], TaintSet.from(label), childEnv, ctx);
        childEnv.set(`${paramName}.data`, TaintSet.from(label));
      }
    }
  }

  // Store custom event listeners for dispatchEvent resolution
  if (eventName && eventName !== 'message' && !EVENT_SOURCES[eventName]) {
    if (!ctx.eventListeners.has(eventName)) ctx.eventListeners.set(eventName, []);
    ctx.eventListeners.get(eventName).push({ callback, env });
  }

  if (callback.body.type === 'BlockStatement') {
    return analyzeInlineFunction(callback, childEnv, ctx);
  }
  return evaluateExpr(callback.body, childEnv, ctx);
}

// Check if an AST node accesses .origin via MemberExpression (not string-based)
function isOriginAccess(node) {
  if (!node) return false;
  // e.origin or e['origin']
  if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
    if (!node.computed && node.property?.name === 'origin') return true;
    if (node.computed && isStringLiteral(node.property) && stringLiteralValue(node.property) === 'origin') return true;
  }
  return false;
}

// Classify origin validation quality in a postMessage handler.
// Returns: 'strong' — properly validated (suppress finding)
//          'weak'   — bypassable check (still flag, but note the weak check)
//          false    — no origin check at all
function callbackChecksOrigin(node, ctx) {
  if (!node || typeof node !== 'object') return false;
  const checks = [];
  collectOriginChecks(node, checks, ctx);
  if (checks.length === 0) return false;
  // If any check is strong, the handler is safe
  if (checks.some(c => c === 'strong')) return 'strong';
  return 'weak';
}

function collectOriginChecks(root, checks, ctx) {
  if (!root || typeof root !== 'object') return;
  const stack = [root];
  while (stack.length > 0) {
    const node = stack.pop();
    if (!node || typeof node !== 'object') continue;
    let handled = false;

    // Binary comparison: e.origin === / !== / == / != something
    if (node.type === 'BinaryExpression' &&
        (node.operator === '===' || node.operator === '==' ||
         node.operator === '!==' || node.operator === '!=')) {
      const originSide = isOriginAccess(node.left) ? 'left' : isOriginAccess(node.right) ? 'right' : null;
      if (originSide) {
        const otherNode = originSide === 'left' ? node.right : node.left;
        const otherStr = isStringLiteral(otherNode) ? stringLiteralValue(otherNode) : null;
        if (otherStr !== null) {
          checks.push(classifyOriginLiteral(otherStr));
        } else {
          const otherIsTainted = ctx && ctx.globalEnv &&
            (otherNode.type === 'Identifier' && ctx.globalEnv.get(otherNode.name).tainted);
          checks.push(otherIsTainted ? 'weak' : 'strong');
        }
        handled = true;
      }
    }

    // Method call on .origin: e.origin.includes(), e.origin.startsWith(), etc.
    if (!handled && node.type === 'CallExpression' && node.callee?.type === 'MemberExpression') {
      const method = node.callee.property?.name;
      if (isOriginAccess(node.callee.object) && method) {
        checks.push(classifyOriginMethod(method, node));
        handled = true;
      }
      if (!handled && (method === 'includes' || method === 'has')) {
        const arg = node.arguments[0];
        if (arg && isOriginAccess(arg)) {
          checks.push('strong');
          handled = true;
        }
      }
      if (!handled && method === 'test') {
        const arg = node.arguments[0];
        if (arg && isOriginAccess(arg)) {
          const pattern = node.callee.object?.regex?.pattern ||
                          node.callee.object?.pattern || '';
          checks.push(classifyOriginRegex(pattern));
          handled = true;
        }
      }
    }

    // Custom validator function call with origin as argument
    if (!handled && node.type === 'CallExpression') {
      const hasOriginArg = node.arguments?.some(arg => isOriginAccess(arg));
      if (hasOriginArg) {
        if (ctx) {
          let funcNode = null;
          if (node.callee.type === 'Identifier') {
            const key = resolveId(node.callee, ctx);
            funcNode = ctx.funcMap.get(key) || ctx.funcMap.get(node.callee.name);
          } else {
            const calleeName = nodeToString(node.callee);
            if (calleeName) funcNode = ctx.funcMap.get(calleeName);
          }
          if (funcNode) {
            const quality = analyzeOriginValidator(funcNode, ctx);
            checks.push(quality);
            handled = true;
          }
        }
        if (!handled) {
          checks.push('weak');
          handled = true;
        }
      }
    }

    if (handled) continue;

    // Push child nodes onto stack
    for (const key of Object.keys(node)) {
      if (key === 'loc' || key === 'start' || key === 'end' || key === '_closureEnv') continue;
      const child = node[key];
      if (Array.isArray(child)) {
        for (const item of child) {
          if (item && typeof item === 'object' && item.type) stack.push(item);
        }
      } else if (child && typeof child === 'object' && child.type) {
        stack.push(child);
      }
    }
  }
}

// Classify a string literal compared against .origin
function classifyOriginLiteral(value) {
  if (!value || typeof value !== 'string') return 'weak';
  // 'null' origin — sandboxed iframes have null origin, this is insecure
  if (value === 'null') return 'weak';
  // Empty string check is useless
  if (value === '') return 'weak';
  // Wildcard '*' is not a real check
  if (value === '*') return 'weak';
  // Must look like a proper origin: scheme + :// + host (no path)
  // e.g., 'https://trusted.com', 'http://localhost:3000'
  if (/^https?:\/\/[^/]+$/.test(value)) return 'strong';
  // Partial values (just a domain, just a scheme) are weak
  return 'weak';
}

// Classify a method call on .origin (e.g., e.origin.includes('x'))
function classifyOriginMethod(method, callNode) {
  const arg = callNode.arguments?.[0];
  const argVal = (arg && isStringLiteral(arg)) ? stringLiteralValue(arg) : null;

  switch (method) {
    case 'includes':
    case 'indexOf':
      // Substring matching is always bypassable: evil-trusted.com matches 'trusted.com'
      return 'weak';
    case 'endsWith':
      // e.origin.endsWith('.example.com') — bypassable: evil.example.com matches
      // e.origin.endsWith('trusted.com') — bypassable: evil-trusted.com matches
      return 'weak';
    case 'startsWith':
      // e.origin.startsWith('https://trusted.com') with full origin is strong
      // Use the same origin literal classifier for consistency
      if (argVal) return classifyOriginLiteral(argVal);
      return 'weak';
    case 'match':
      // Regex match on origin
      if (arg && (arg.type === 'RegExpLiteral' || arg.regex)) {
        return classifyOriginRegex(arg.pattern || arg.regex?.pattern || '');
      }
      return 'weak';
    default:
      return 'weak';
  }
}

// Classify a regex used to validate .origin
// Analyzes regex pattern anchors: ^ at start, $ at end (unescaped)
function classifyOriginRegex(pattern) {
  if (!pattern) return 'weak';
  // Check for unescaped ^ anchor at start of pattern (or after leading group)
  const hasStart = pattern[0] === '^' || /^\(\?[^)]*\)\^/.test(pattern);
  // Check for unescaped $ anchor at end (not preceded by unescaped backslash)
  const hasEnd = pattern.length > 0 && pattern[pattern.length - 1] === '$' &&
    (pattern.length < 2 || pattern[pattern.length - 2] !== '\\');
  if (hasStart && hasEnd) return 'strong';
  // Anchored at start with a full origin scheme pattern is acceptable
  // (e.g., /^https?:\/\/trusted\.com/ — the path structure prevents bypass)
  if (hasStart && /^\^https?:/.test(pattern)) return 'strong';
  // Unanchored regex is bypassable
  return 'weak';
}

// Analyze a custom origin validator function to determine check quality.
// Looks inside the function body for origin comparison patterns.
function analyzeOriginValidator(funcNode, ctx) {
  if (!funcNode) return 'weak';
  const body = funcNode.body || funcNode;
  const checks = [];
  collectOriginValidatorChecks(body, funcNode.params, checks);
  if (checks.length === 0) return 'weak';
  if (checks.some(c => c === 'strong')) return 'strong';
  return 'weak';
}

// Scan a validator function body for comparison patterns on its parameter
function collectOriginValidatorChecks(root, params, checks) {
  if (!root || typeof root !== 'object') return;
  const paramNames = (params || []).map(p => p.type === 'Identifier' ? p.name : null).filter(Boolean);
  const isParamRef = (n) => n.type === 'Identifier' && paramNames.includes(n.name);
  const stack = [root];
  while (stack.length > 0) {
    const node = stack.pop();
    if (!node || typeof node !== 'object') continue;
    let handled = false;

    // Binary comparison: param === 'https://...' or allowList.includes(param)
    if (node.type === 'BinaryExpression' &&
        (node.operator === '===' || node.operator === '==' ||
         node.operator === '!==' || node.operator === '!=')) {
      const paramSide = isParamRef(node.left) ? 'left' : isParamRef(node.right) ? 'right' : null;
      if (paramSide) {
        const otherNode = paramSide === 'left' ? node.right : node.left;
        const otherStr = isStringLiteral(otherNode) ? stringLiteralValue(otherNode) : null;
        if (otherStr !== null) {
          checks.push(classifyOriginLiteral(otherStr));
        } else {
          checks.push('strong');
        }
        handled = true;
      }
    }

    // Method call: param.includes(), allowList.includes(param), etc.
    if (!handled && node.type === 'CallExpression' && node.callee?.type === 'MemberExpression') {
      const method = node.callee.property?.name;
      if (node.callee.object?.type === 'Identifier' && paramNames.includes(node.callee.object.name) && method) {
        checks.push(classifyOriginMethod(method, node));
        handled = true;
      }
      if (!handled && (method === 'includes' || method === 'has') && node.arguments?.[0]) {
        const argNode = node.arguments[0];
        if (argNode.type === 'Identifier' && paramNames.includes(argNode.name)) {
          checks.push('strong');
          handled = true;
        }
      }
    }

    if (handled) continue;

    for (const key of Object.keys(node)) {
      if (key === 'loc' || key === 'start' || key === 'end' || key === '_closureEnv') continue;
      const child = node[key];
      if (Array.isArray(child)) {
        for (const item of child) {
          if (item && typeof item === 'object' && item.type) stack.push(item);
        }
      } else if (child && typeof child === 'object' && child.type) {
        stack.push(child);
      }
    }
  }
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
  const methodName = node.callee?.property?.name || '';
  const callback = node.arguments[0];

  // .finally() does not receive the resolved value; it passes through the original taint
  if (methodName === 'finally') {
    if (callback && (callback.type === 'ArrowFunctionExpression' || callback.type === 'FunctionExpression')) {
      const childEnv = env.child();
      // finally callback gets no arguments — analyze for side effects only
      if (callback.body.type === 'BlockStatement') analyzeInlineFunction(callback, childEnv, ctx);
      else evaluateExpr(callback.body, childEnv, ctx);
    }
    return objTaint.clone(); // pass through original promise taint
  }

  if (!callback) return objTaint.clone();
  if (callback.type !== 'ArrowFunctionExpression' && callback.type !== 'FunctionExpression') return objTaint.clone();

  const childEnv = env.child();
  if (callback.params[0]) assignToPattern(callback.params[0], objTaint, childEnv, ctx);

  // If a previous promise callback returned a function node, register it under the
  // current callback's parameter name so fn() calls inside this callback resolve correctly
  if (ctx.returnedFuncNode && callback.params[0]?.type === 'Identifier') {
    ctx.funcMap.set(callback.params[0].name, ctx.returnedFuncNode);
    ctx.returnedFuncNode = null;
  }

  let cbResult;
  if (callback.body.type === 'BlockStatement') {
    cbResult = analyzeInlineFunction(callback, childEnv, ctx);
  } else {
    cbResult = evaluateExpr(callback.body, childEnv, ctx);
  }

  // .catch() only runs on rejection — on the success path, the resolved value passes through.
  // Merge original taint so the next .then() in the chain sees it.
  if (methodName === 'catch') {
    return objTaint.clone().merge(cbResult);
  }
  return cbResult;
}

// ── Analyze inline function body ──
function analyzeInlineFunction(funcNode, env, ctx) {
  const innerCfg = buildCFG(funcNode.body);
  const innerCtx = new AnalysisContext(
    ctx.file, new Map(ctx.funcMap), ctx.findings,
    ctx.globalEnv, ctx.scopeInfo, ctx.analyzedCalls
  );
  innerCtx.classBodyMap = ctx.classBodyMap;
  innerCtx.superClassMap = ctx.superClassMap;
  innerCtx.protoMethodMap = ctx.protoMethodMap;
  // Track which super class to resolve for super() calls inside this constructor
  if (funcNode._superClass) innerCtx._currentSuperClass = funcNode._superClass;

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
      // Constant-fold: skip unreachable branches
      if (succ.branchCondition && isConstantBool(succ.branchCondition) !== null) {
        const val = isConstantBool(succ.branchCondition);
        if (val === false && succ.branchPolarity === true) continue;
        if (val === true && succ.branchPolarity === false) continue;
      }
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
  if (innerCtx.returnElementTaints) ctx.returnElementTaints = innerCtx.returnElementTaints;
  if (innerCtx.returnPropertyTaints) ctx.returnPropertyTaints = innerCtx.returnPropertyTaints;

  // Propagate function entries discovered during inline analysis back to the caller:
  // - Array-stored callbacks (key ends with [])
  // - Global assignments via window.X (strip prefix for cross-file resolution)
  // Propagate function entries discovered during inline analysis back to the caller:
  // Array-stored callbacks (key ends with []) and global assignments (window.X, self.X, globalThis.X)
  const GLOBAL_OBJ_PREFIXES = ['window.', 'self.', 'globalThis.'];
  for (const [key, val] of innerCtx.funcMap) {
    if (key.length > 2 && key[key.length - 1] === ']' && key[key.length - 2] === '[' && !ctx.funcMap.has(key)) {
      ctx.funcMap.set(key, val);
    }
    for (const prefix of GLOBAL_OBJ_PREFIXES) {
      if (key.length > prefix.length && key.slice(0, prefix.length) === prefix && !ctx.funcMap.has(key)) {
        ctx.funcMap.set(key, val);
        const stripped = key.slice(prefix.length);
        if (stripped && !ctx.funcMap.has(stripped)) ctx.funcMap.set(stripped, val);
        break;
      }
    }
  }

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

  // super() call — resolve to parent class constructor via _superClass or superClassMap
  if (!funcNode && callNode.callee?.type === 'Super') {
    // First try: use the _superClass from the currently analyzed function
    const currentSuper = ctx._currentSuperClass;
    if (currentSuper) {
      const parentCtor = ctx.funcMap.get(currentSuper);
      if (parentCtor) funcNode = parentCtor;
    }
    // Fallback: iterate superClassMap
    if (!funcNode) {
      for (const [, parentClass] of ctx.superClassMap) {
        const parentCtor = ctx.funcMap.get(parentClass);
        if (parentCtor) { funcNode = parentCtor; break; }
      }
    }
  }

  // Inline function expression / arrow
  if (!funcNode && callNode.callee) {
    if (callNode.callee.type === 'ArrowFunctionExpression' ||
        callNode.callee.type === 'FunctionExpression') {
      funcNode = callNode.callee;
    }
    // Immediately-invoked return: factory()(arg) — callee is a CallExpression
    if (!funcNode && (callNode.callee.type === 'CallExpression' || callNode.callee.type === 'OptionalCallExpression')) {
      if (ctx.returnedFuncNode) {
        funcNode = ctx.returnedFuncNode;
        ctx.returnedFuncNode = null;
      }
    }
    // Ternary callee: (cond ? fnA : fnB)(args) — resolve either branch
    if (!funcNode && callNode.callee.type === 'ConditionalExpression') {
      for (const branch of [callNode.callee.consequent, callNode.callee.alternate]) {
        if (branch.type === 'Identifier') {
          const ref = ctx.funcMap.get(resolveId(branch, ctx)) || ctx.funcMap.get(branch.name);
          if (ref) { funcNode = ref; break; }
        }
        if (branch.type === 'ArrowFunctionExpression' || branch.type === 'FunctionExpression') {
          funcNode = branch; break;
        }
      }
    }
  }

  // Inline object method call: ({fn: function(){...}}).fn()
  if (!funcNode && (callNode.callee?.type === 'MemberExpression' || callNode.callee?.type === 'OptionalMemberExpression') &&
      callNode.callee.object?.type === 'ObjectExpression' && !callNode.callee.computed) {
    const methodName = callNode.callee.property?.name;
    if (methodName) {
      for (const prop of callNode.callee.object.properties) {
        if ((prop.type === 'ObjectProperty' || prop.type === 'Property' || prop.type === 'ObjectMethod') && prop.key) {
          const pName = prop.key.name || prop.key.value;
          if (pName === methodName) {
            funcNode = prop.type === 'ObjectMethod' ? prop : prop.value;
            break;
          }
        }
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
    // Computed member call: obj[method](args) — resolve method name to dot-path
    if (!funcNode && callNode.callee.computed) {
      const objStr = nodeToString(callNode.callee.object);
      if (objStr) {
        // Try resolving the computed property to a constant string: obj["render"]() or obj[varHoldingName]()
        const resolvedMethod = resolveToConstant(callNode.callee.property, env, ctx);
        if (resolvedMethod) {
          const dotPath = `${objStr}.${resolvedMethod}`;
          if (ctx.funcMap.has(dotPath)) funcNode = ctx.funcMap.get(dotPath);
        }
        // Fallback: arr[0](args) — resolve function pushed to array via arr[]
        if (!funcNode) {
          const arrFunc = ctx.funcMap.get(`${objStr}[]`);
          if (arrFunc) funcNode = arrFunc;
        }
        if (!funcNode && callNode.callee.object.type === 'Identifier') {
          const arrKey = resolveId(callNode.callee.object, ctx);
          const arrFunc2 = ctx.funcMap.get(`${arrKey}[]`);
          if (arrFunc2) funcNode = arrFunc2;
        }
      }
    }
  }

  if (!funcNode || !funcNode.body) return TaintSet.empty();

  // Include the resolved super class in the signature so different super() calls in an inheritance chain aren't deduplicated
  const superSuffix = callNode.callee?.type === 'Super' && ctx._currentSuperClass ? `:super=${ctx._currentSuperClass}` : '';
  // For inline function expressions (IIFEs), use source location to disambiguate since they all resolve to 'anon'
  const locSuffix = (!calleeStr && funcNode.loc) ? `:${funcNode.loc.start.line}:${funcNode.loc.start.column}` : '';
  const callSig = `${calleeStr || 'anon'}:${argTaints.map(t => t.tainted ? '1' : '0').join('')}${superSuffix}${locSuffix}`;
  if (ctx.analyzedCalls.has(callSig)) return ctx.analyzedCalls.get(callSig)?.clone() || TaintSet.empty();
  ctx.analyzedCalls.set(callSig, TaintSet.empty());

  const closureEnv = funcNode._closureEnv || env;
  const childEnv = closureEnv.child();

  // For method calls (obj.method()), bind 'this' to the receiver object
  // Propagate obj.* taint as this.* so this.prop lookups resolve correctly
  if (callNode.callee?.type === 'MemberExpression' || callNode.callee?.type === 'OptionalMemberExpression') {
    let objName = nodeToString(callNode.callee.object);
    // For chained method calls like a.setData(x).render(), the receiver is a CallExpression.
    // Trace back to the original object: a.setData(x) → callee a.setData → object a
    if (!objName && callNode.callee.object) {
      let receiver = callNode.callee.object;
      while (receiver && (receiver.type === 'CallExpression' || receiver.type === 'OptionalCallExpression')) {
        if (receiver.callee?.type === 'MemberExpression' || receiver.callee?.type === 'OptionalMemberExpression') {
          receiver = receiver.callee.object;
        } else break;
      }
      if (receiver) objName = nodeToString(receiver);
    }
    if (objName) {
      const objTaint = evaluateExpr(callNode.callee.object, env, ctx);
      childEnv.set('this', objTaint);
      // Copy obj.* bindings to this.* (search all env layers)
      const objBindings = env.getTaintedWithPrefix(`${objName}.`);
      for (const [key, taint] of objBindings) {
        const propName = key.slice(objName.length + 1);
        childEnv.set(`this.${propName}`, taint);
      }
    } else {
      // Anonymous receiver (chained calls on new X() or other expressions):
      // Inherit this.* bindings from env set by a previous call in the chain
      const thisBindings = env.getTaintedWithPrefix('this.');
      for (const [key, taint] of thisBindings) {
        childEnv.set(key, taint);
      }
    }
  }

  // Handle bound this context from fn.bind(thisArg) or fn.call(thisArg)
  if (funcNode._boundThisArg) {
    const boundName = funcNode._boundThisArg;
    const boundTaint = env.get(boundName);
    if (boundTaint.tainted) childEnv.set('this', boundTaint);
    const boundBindings = env.getTaintedWithPrefix(`${boundName}.`);
    for (const [key, taint] of boundBindings) {
      const propName = key.slice(boundName.length + 1);
      childEnv.set(`this.${propName}`, taint);
    }
  }
  // Handle inline object literal as thisArg: fn.call({html: tainted})
  if (funcNode._boundThisNode) {
    const objNode = funcNode._boundThisNode;
    for (const prop of objNode.properties || []) {
      if ((prop.type === 'ObjectProperty' || prop.type === 'Property') && prop.key) {
        const propName = prop.key.name || prop.key.value;
        if (propName && prop.value) {
          const propTaint = evaluateExpr(prop.value, env, ctx);
          childEnv.set(`this.${propName}`, propTaint);
        }
      }
    }
    funcNode._boundThisNode = null; // consume
  }

  // Handle pre-filled arguments from fn.bind(thisArg, arg1, arg2)
  if (funcNode._boundArgs) {
    const boundArgNodes = funcNode._boundArgs;
    const boundArgTaints = boundArgNodes.map(a => evaluateExpr(a, env, ctx));
    // Prepend bound args to call args
    argTaints = [...boundArgTaints, ...argTaints];
    callNode = { ...callNode, arguments: [...boundArgNodes, ...(callNode.arguments || [])] };
    funcNode._boundArgs = null; // consume
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
      // If an actual non-undefined argument was provided, assign directly to the param's
      // left side (skip default evaluation even if the arg taint is empty).
      // Passing undefined explicitly still triggers the default parameter.
      if (param.type === 'AssignmentPattern' && i < callNode.arguments.length) {
        const argNode = callNode.arguments[i];
        const isUndefined = argNode && argNode.type === 'Identifier' && argNode.name === 'undefined';
        if (isUndefined) {
          // Treat as missing — let AssignmentPattern evaluate the default
          assignToPattern(param, argTaints[i] || TaintSet.empty(), childEnv, ctx);
        } else {
          assignToPattern(param.left, argTaints[i] || TaintSet.empty(), childEnv, ctx);
        }
      } else {
        // For ObjectPattern params, use assignObjectPatternFromSource if the argument
        // is a source object (e.g., render({ hash }) called with render(location))
        if (param.type === 'ObjectPattern' && callNode.arguments[i]) {
          const argNode = callNode.arguments[i];
          const argStr = nodeToString(argNode);
          if (argStr) {
            assignObjectPatternFromSource(param, argStr, argTaints[i] || TaintSet.empty(), childEnv, ctx);
          } else {
            assignToPattern(param, argTaints[i] || TaintSet.empty(), childEnv, ctx);
          }
        } else {
          assignToPattern(param, argTaints[i] || TaintSet.empty(), childEnv, ctx);
        }
      }
    }
  }

  // Bind `arguments` object — merge all arg taints so arguments[n] resolves
  const argsMerged = TaintSet.empty();
  for (const t of argTaints) argsMerged.merge(t);
  if (argsMerged.tainted) {
    childEnv.set('arguments', argsMerged);
    childEnv.set('global:arguments', argsMerged);
  }

  const savedFuncMap = ctx.funcMap;
  ctx.funcMap = innerFuncMap;

  // Collect parameter names to distinguish locals from closure vars
  const paramNames = new Set();
  for (const param of funcNode.params) {
    if (param.type === 'Identifier') paramNames.add(param.name);
    else if (param.type === 'RestElement' && param.argument?.type === 'Identifier') paramNames.add(param.argument.name);
  }

  const body = funcNode.body.type === 'BlockStatement'
    ? funcNode.body
    : { type: 'BlockStatement', body: [{ type: 'ReturnStatement', argument: funcNode.body }] };
  const result = analyzeInlineFunction({ ...funcNode, body }, childEnv, ctx);

  ctx.funcMap = savedFuncMap;

  // Propagate new funcMap entries discovered during the call back to the caller's funcMap
  // Handles: function on(fn) { handlers.push(fn); } — the handlers[] entry must survive
  for (const [key, val] of innerFuncMap) {
    if (!savedFuncMap.has(key)) savedFuncMap.set(key, val);
  }

  // super() call: propagate this.* from parent constructor back to the current scope
  if (callNode.callee?.type === 'Super') {
    for (const [key, taint] of childEnv.bindings) {
      if (key.startsWith('this.') && taint.tainted) {
        env.set(key, taint);
      }
    }
  }

  // Propagate this.* side effects back to the receiver object (setter pattern)
  // After obj.setData(tainted), if setData sets this.data, copy it back as obj.data
  if (callNode.callee?.type === 'MemberExpression' || callNode.callee?.type === 'OptionalMemberExpression') {
    const objName = nodeToString(callNode.callee.object);
    for (const [key, taint] of childEnv.bindings) {
      if (key.startsWith('this.') && taint.tainted) {
        const propName = key.slice(5);
        if (objName) env.set(`${objName}.${propName}`, taint);
        // Also keep this.* in env for chained calls on anonymous receivers
        // e.g., new Builder().set(x).build() — this.data persists across the chain
        env.set(key, taint);
      }
    }
  }

  // Propagate closure variable mutations back to the closure env
  // When a method mutates a closure variable (e.g., data = d inside setData),
  // sibling methods sharing the same closure need to see the mutation.
  if (funcNode._closureEnv) {
    for (const [key, taint] of childEnv.bindings) {
      if (taint.tainted && !key.startsWith('this.') && !paramNames.has(key) && key !== 'this') {
        // This is a non-local, non-param binding — likely a closure variable
        funcNode._closureEnv.set(key, taint);
      }
    }
  }

  // Propagate closure variable mutations back to the caller's env
  // Handles: var x = "safe"; function f() { x = tainted; } f(); sink(x);
  // Also handles inverse: var x = tainted; function f() { x = "safe"; } f(); sink(x);
  for (const [key, taint] of childEnv.bindings) {
    if (key.startsWith('this.') || key === 'this' || key.startsWith('global:') ||
        paramNames.has(key) || key.indexOf('.') !== -1) continue;
    // Only propagate if the key is a closure variable (exists in caller's env)
    if (env.has(key)) {
      env.set(key, taint);
    }
  }

  // Propagate global-scoped side effects back to the caller's env
  // Handles: Config.init(val) sets Config.data = val → caller sees Config.data as tainted
  // A dot-path binding (e.g., "Config.data") is a property path — propagate it back.
  // Exclude internal namespaces: 'this.', 'global:', and scope-resolved keys (digit + ':').
  for (const [key, taint] of childEnv.bindings) {
    if (taint.tainted && key.indexOf('.') !== -1 &&
        key.slice(0, 5) !== 'this.' && key.slice(0, 7) !== 'global:' &&
        !(key[0] >= '0' && key[0] <= '9')) {
      env.set(key, taint);
    }
  }

  // Cache the result so repeated calls with the same signature return the correct taint
  if (result.tainted) ctx.analyzedCalls.set(callSig, result);

  return result;
}

// ── For-in/of binding ──
function processForBinding(node, env, ctx) {
  let iterableTaint = evaluateExpr(node.right, env, ctx);
  // For Maps/objects with per-key taint, merge per-key entries into iterable taint
  const iterStr = nodeToString(node.right);
  if (iterStr) {
    const perKeyTaints = env.getTaintedWithPrefix(`${iterStr}.#key_`);
    if (perKeyTaints.size > 0) {
      iterableTaint = iterableTaint.clone();
      for (const [, taint] of perKeyTaints) iterableTaint.merge(taint);
    }
    // Also merge per-element array taint (arr.#idx_N)
    const perIdxTaints = env.getTaintedWithPrefix(`${iterStr}.#idx_`);
    if (perIdxTaints.size > 0) {
      iterableTaint = iterableTaint.clone();
      for (const [, taint] of perIdxTaints) iterableTaint.merge(taint);
    }
  }

  // Custom iterable: if the object has a function assigned via computed property (Symbol.iterator)
  // that captures tainted variables, propagate that taint to the iteration binding.
  if (!iterableTaint.tainted && iterStr) {
    const iterFunc = ctx.funcMap.get(`${iterStr}[]`);
    if (iterFunc && (iterFunc.type === 'FunctionExpression' || iterFunc.type === 'ArrowFunctionExpression')) {
      // Scan the function body for Identifier references to tainted env bindings
      const closureTaint = TaintSet.empty();
      collectClosureTaint(iterFunc.body, env, ctx, closureTaint, new Set());
      if (closureTaint.tainted) iterableTaint = closureTaint;
    }
  }

  if (node.left.type === 'VariableDeclaration') {
    for (const decl of node.left.declarations) assignToPattern(decl.id, iterableTaint, env, ctx);
  } else {
    assignToPattern(node.left, iterableTaint, env, ctx);
  }
}

// Recursively scan AST for Identifier nodes that reference tainted env bindings
function collectClosureTaint(root, env, ctx, taintOut, visited) {
  if (!root || typeof root !== 'object') return;
  const stack = [root];
  while (stack.length > 0) {
    const node = stack.pop();
    if (!node || typeof node !== 'object' || visited.has(node)) continue;
    visited.add(node);
    if (node.type === 'Identifier') {
      const t = env.get(node.name);
      if (t.tainted) taintOut.merge(t);
      const perIdx = env.getTaintedWithPrefix(`${node.name}.#idx_`);
      for (const [, pt] of perIdx) taintOut.merge(pt);
      const perKey = env.getTaintedWithPrefix(`${node.name}.#key_`);
      for (const [, pt] of perKey) taintOut.merge(pt);
      continue;
    }
    if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
      const str = nodeToString(node);
      if (str) {
        const t = env.get(str);
        if (t.tainted) { taintOut.merge(t); continue; }
      }
    }
    for (const key of Object.keys(node)) {
      if (key === 'loc' || key === 'start' || key === 'end' || key === '_closureEnv') continue;
      const child = node[key];
      if (Array.isArray(child)) {
        for (const item of child) {
          if (item && typeof item === 'object' && item.type) stack.push(item);
        }
      } else if (child && typeof child === 'object' && child.type) {
        stack.push(child);
      }
    }
  }
}

// ── Sink checks ──
function classifyNavigationType(sinkInfo, env, rhsNode, ctx) {
  // For navigation sinks, check if the value has been URL-scheme-validated on this path.
  // If scheme is confirmed http/https, it's Open Redirect (javascript: blocked).
  // Otherwise it's XSS (javascript: URI injection possible).
  if (!sinkInfo.navigation) return sinkInfo.type;

  // Check the RHS expression — resolve to variable name(s) that may be scheme-checked
  if (rhsNode) {
    const varName = nodeToString(rhsNode);
    if (varName && env.schemeCheckedVars.has(varName)) return 'Open Redirect';
    // Also check for URL object patterns: if url is scheme-checked, url.href inherits it
    if (rhsNode.type === 'MemberExpression' || rhsNode.type === 'OptionalMemberExpression') {
      const objName = nodeToString(rhsNode.object);
      if (objName && env.schemeCheckedVars.has(objName)) return 'Open Redirect';
    }
    // Check if the variable references a new URL() result — new URL() with validated protocol
    if (rhsNode.type === 'Identifier') {
      // Check by raw name and scope-resolved key (via resolveId)
      if (env.schemeCheckedVars.has(rhsNode.name)) return 'Open Redirect';
      if (ctx) {
        const resolvedKey = resolveId(rhsNode, ctx);
        if (env.schemeCheckedVars.has(resolvedKey)) return 'Open Redirect';
      }
      if (env.schemeCheckedVars.has(`global:${rhsNode.name}`)) return 'Open Redirect';
    }
  }

  return sinkInfo.type; // default: XSS
}

// ── Script element sink: el.src = tainted when el is createElement('script') ──
function checkScriptElementSink(leftNode, rhsTaint, env, ctx) {
  if (!rhsTaint.tainted) return;
  if (leftNode.type !== 'MemberExpression' && leftNode.type !== 'OptionalMemberExpression') return;
  const propName = leftNode.property?.name;
  if (propName !== 'src' && propName !== 'textContent' && propName !== 'text') return;
  const objName = nodeToString(leftNode.object);
  if (!objName) return;
  // Check if the object is a known script element
  const objKey = leftNode.object.type === 'Identifier' ? resolveId(leftNode.object, ctx) : objName;
  if (!ctx.scriptElements.has(objKey) && !ctx.scriptElements.has(objName)) return;
  const loc = leftNode.loc?.start || {};
  ctx.findings.push({
    type: 'Script Injection',
    severity: 'critical',
    title: `Script Injection: tainted data flows to script element ${propName}`,
    sink: { expression: `${objName}.${propName}`, file: ctx.file, line: loc.line || 0, col: loc.column || 0 },
    source: rhsTaint.toArray().map(l => ({ type: l.sourceType, description: l.description, file: l.file, line: l.line })),
    path: buildTaintPath(rhsTaint, `${objName}.${propName}`),
  });
}

function checkSinkAssignment(leftNode, rhsTaint, rhsNode, env, ctx) {
  if (!rhsTaint.tainted) return;

  const leftStr = nodeToString(leftNode);
  const propName = leftNode.type === 'MemberExpression' ? leftNode.property?.name : null;
  const sinkInfo = checkAssignmentSink(leftStr, propName);
  if (!sinkInfo) return;

  // Skip self-redirect: top.location.href = self.location.href
  if (sinkInfo.navigation && isSelfRedirect(sinkInfo, rhsNode)) return;

  const type = classifyNavigationType(sinkInfo, env, rhsNode, ctx);
  const severity = type === 'Open Redirect' ? 'high' : (type === 'XSS' ? 'critical' : 'high');
  const loc = leftNode.loc?.start || {};
  ctx.findings.push({
    type,
    severity,
    title: `${type}: tainted data flows to ${leftStr || propName}`,
    sink: { expression: leftStr || propName, file: ctx.file, line: loc.line || 0, col: loc.column || 0 },
    source: rhsTaint.toArray().map(l => ({ type: l.sourceType, description: l.description, file: l.file, line: l.line })),
    path: buildTaintPath(rhsTaint, leftStr || propName),
  });
}

function isSelfRedirect(sinkInfo, argNode) {
  // Suppress location.replace(location.href) / location.assign(self.location.href) etc.
  // These are frame-busting or same-page reloads, not exploitable
  if (!sinkInfo.navigation || !argNode) return false;
  const argStr = nodeToString(argNode);
  if (!argStr) return false;
  const SELF_LOCATION_READS = new Set([
    'location.href', 'window.location.href', 'self.location.href',
    'document.location.href', 'top.location.href',
    'location.toString()', 'window.location.toString()',
  ]);
  return SELF_LOCATION_READS.has(argStr);
}

function checkSinkCall(callNode, sinkInfo, argTaints, calleeStr, env, ctx) {
  if (!sinkInfo.taintedArgs) return;
  for (const argIdx of sinkInfo.taintedArgs) {
    const argTaint = argTaints[argIdx];
    if (!argTaint || !argTaint.tainted) continue;

    if (sinkInfo.stringOnly && callNode.arguments[argIdx]) {
      const argNode = callNode.arguments[argIdx];
      if (argNode.type === 'ArrowFunctionExpression' || argNode.type === 'FunctionExpression') continue;
    }

    // Skip self-redirect patterns: location.replace(self.location.href)
    if (isSelfRedirect(sinkInfo, callNode.arguments[argIdx])) continue;

    const type = classifyNavigationType(sinkInfo, env, callNode.arguments[argIdx], ctx);
    const severity = type === 'Open Redirect' ? 'high' : (type === 'XSS' ? 'critical' : 'high');
    const loc = callNode.loc?.start || {};
    ctx.findings.push({
      type,
      severity,
      title: `${type}: tainted data flows to ${calleeStr}()`,
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
  if (left.type !== 'MemberExpression') return;

  // Pattern 1: obj[key1][key2] = tainted (both keys tainted)
  if (left.computed && left.object.type === 'MemberExpression' && left.object.computed) {
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

  // Pattern 2: obj.__proto__.X = tainted or obj.prototype.X = tainted (tainted value)
  // Pattern 2b: obj.__proto__[taintedKey] = anything or obj.prototype[taintedKey] = anything (tainted key)
  // Pattern 2c: obj.constructor.prototype[taintedKey] = anything (tainted key via constructor)
  if (left.object?.type === 'MemberExpression' && !left.object.computed) {
    const objProp = left.object.property?.name;
    if (objProp === '__proto__' || objProp === 'prototype') {
      // Skip standard constructor assignment (e.g., A.prototype.constructor = A)
      const assignedProp = !left.computed && left.property?.name;
      if (assignedProp === 'constructor') return;

      const rhsTaint = evaluateExpr(node.right, env, ctx);
      // Check tainted value OR tainted key
      const keyTaint = left.computed ? evaluateExpr(left.property, env, ctx) : TaintSet.empty();
      const combinedTaint = rhsTaint.tainted ? rhsTaint : keyTaint;
      if (combinedTaint.tainted) {
        const loc = node.loc?.start || {};
        const expr = nodeToString(left) || `obj.${objProp}.prop`;
        const title = keyTaint.tainted
          ? `Prototype Pollution: attacker controls property key on ${objProp}`
          : `Prototype Pollution: tainted data assigned to ${objProp}`;
        ctx.findings.push({
          type: 'Prototype Pollution',
          severity: 'critical',
          title,
          sink: { expression: expr, file: ctx.file, line: loc.line || 0, col: loc.column || 0 },
          source: combinedTaint.toArray().map(l => ({ type: l.sourceType, description: l.description, file: l.file, line: l.line })),
          path: buildTaintPath(combinedTaint, expr),
        });
      }
    }
  }
  // Pattern 3: obj.constructor.prototype[taintedKey] = anything
  if (left.computed && left.object?.type === 'MemberExpression' && !left.object.computed &&
      left.object.property?.name === 'prototype' &&
      left.object.object?.type === 'MemberExpression' && !left.object.object.computed &&
      left.object.object.property?.name === 'constructor') {
    const keyTaint = evaluateExpr(left.property, env, ctx);
    if (keyTaint.tainted) {
      const loc = node.loc?.start || {};
      const expr = nodeToString(left) || 'obj.constructor.prototype[key]';
      ctx.findings.push({
        type: 'Prototype Pollution',
        severity: 'critical',
        title: 'Prototype Pollution: attacker controls property key on constructor.prototype',
        sink: { expression: expr, file: ctx.file, line: loc.line || 0, col: loc.column || 0 },
        source: keyTaint.toArray().map(l => ({ type: l.sourceType, description: l.description, file: l.file, line: l.line })),
        path: buildTaintPath(keyTaint, expr),
      });
    }
  }
}

function buildTaintPath(taintSet, sinkExpr) {
  return taintSet.toArray().map(label => `${label.description} (${label.file}:${label.line}) → ${sinkExpr}`);
}
