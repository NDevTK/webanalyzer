/* taint.js — Forward taint propagation over the CFG using a worklist algorithm.
   Tracks taint from sources through assignments, calls, returns, property access,
   and reports when tainted data reaches a dangerous sink.
   Uses Babel scope info for accurate binding resolution (shadowing, closures). */

import {
  checkMemberSource, checkCallSink, checkAssignmentSink,
  isSanitizer, isPassthrough, CALL_SOURCES, CONSTRUCTOR_SOURCES,
  EVENT_SOURCES, MEMBER_SOURCES,
} from './sources-sinks.js';
import { buildCFG } from './cfg.js';
import { buildScopeInfo } from './scope.js';
import { isElementPropertySink, getDOMPropertyInfo, getDOMPropertiesForInterface } from './idl-data.js';
import { PURE_FUNCTIONS, METHOD_RETURN_TYPES, PROPERTY_TYPES, TAINT_PASSTHROUGHS } from './ecma-builtins.js';
import { parse as babelParse } from '@babel/parser';

// ── Structured trace logging ──
// Enable: globalThis._TAINT_TRACE = true (all) or globalThis._TAINT_TRACE = 'pattern' (filter)
// Events: CALL-RESOLVE, ACF-ENTER, ACF-EXIT, ACF-MISS, SCOPE, FUNCMAP, ALIAS
let _traceDepth = 0;
function trace(event, data) {
  if (!globalThis._TAINT_TRACE) return;
  const filter = globalThis._TAINT_TRACE;
  if (typeof filter === 'string' && !data.callee?.includes(filter) && !data.key?.includes(filter) &&
      !data.calleeStr?.includes(filter) && !data.name?.includes(filter)) return;
  const indent = '  '.repeat(Math.min(_traceDepth, 20));
  const pairs = Object.entries(data).map(([k, v]) => `${k}=${typeof v === 'object' && v !== null ? JSON.stringify(v) : v}`).join(' ');
  console.log(`${indent}[${event}] ${pairs}`);
}

// ── Taint label: tracks where taint originated ──
const _NO_TRANSFORMS = [];
export class TaintLabel {
  constructor(sourceType, file, line, col, description, transforms, sourceKey) {
    this.sourceType = sourceType;
    this.file = file;
    this.line = line;
    this.col = col;
    this.description = description;
    this.transforms = transforms || _NO_TRANSFORMS;
    this.sourceKey = sourceKey || null; // actual param/key name from the source call
    this.stateSteps = null; // array of {action, handler, variable, delay} for multi-step PoCs
    this.constraints = null; // array of {variable, op, value} — path conditions this taint flows through
    // Structural control: attacker controls the object's SHAPE (keys, nested structure).
    // Set to true for: JSON.parse(tainted), postMessage event.data, URL params parsed to object.
    // Set to false for: location.hash (string value), document.cookie (string value).
    // When structural=true, for-in keys on this object are attacker-controlled.
    // When structural=false, for-in keys are programmer-defined (only values are tainted).
    this.structural = false;
    // Encoding state: tracks how the value is encoded in transit.
    // 'url' = value arrives URL-encoded (location.hash, location.search, location.href)
    // null = no encoding (postMessage, localStorage, eval argument)
    // Set automatically from sourceType — URL sources deliver encoded values.
    // decodeURIComponent transform clears this (value is now decoded).
    this.encoding = sourceType?.startsWith('url.') ? 'url' : null;
  }

  get id() {
    return `${this.sourceType}@${this.file}:${this.line}:${this.col}`;
  }

  withTransform(op) {
    const l = new TaintLabel(this.sourceType, this.file, this.line, this.col, this.description,
      this.transforms === _NO_TRANSFORMS ? [op] : [...this.transforms, op]);
    l.sourceKey = this.sourceKey;
    l.stateSteps = this.stateSteps;
    l.constraints = this.constraints;
    // JSON.parse produces structural control — attacker chose the object shape
    l.structural = this.structural || op.op === 'JSON.parse';
    // decodeURIComponent/decodeURI clears URL encoding
    if (op.op === 'decodeURIComponent' || op.op === 'decodeURI') {
      l.encoding = null;
    } else {
      l.encoding = this.encoding;
    }
    return l;
  }

  addStateStep(step) {
    const l = new TaintLabel(this.sourceType, this.file, this.line, this.col, this.description,
      this.transforms === _NO_TRANSFORMS ? [] : [...this.transforms]);
    l.sourceKey = this.sourceKey;
    l.stateSteps = this.stateSteps ? [...this.stateSteps, step] : [step];
    l.constraints = this.constraints;
    l.structural = this.structural;
    l.encoding = this.encoding;
    return l;
  }

  // Add a path constraint: {variable, op, value}
  // op can be: '!==', '!=', '===', '==', 'typeof', 'typeof!='
  withConstraint(constraint) {
    const l = new TaintLabel(this.sourceType, this.file, this.line, this.col, this.description,
      this.transforms === _NO_TRANSFORMS ? [] : [...this.transforms]);
    l.sourceKey = this.sourceKey;
    l.stateSteps = this.stateSteps;
    l.constraints = this.constraints ? [...this.constraints, constraint] : [constraint];
    l.structural = this.structural;
    l.encoding = this.encoding;
    return l;
  }
}

// ── Taint set: a set of labels attached to a value ──
// Uses lazy Map allocation: labels is null when empty, avoiding Map overhead
// for the vast majority of TaintSets that are never tainted.
const _EMPTY_MAP = Object.freeze(new Map());
export class TaintSet {
  constructor(labels) {
    this.labels = labels || null;
  }

  get tainted() { return this.labels !== null && this.labels.size > 0; }
  get size() { return this.labels !== null ? this.labels.size : 0; }

  add(label) {
    if (this.labels === null) this.labels = new Map();
    this.labels.set(label.id, label);
  }

  merge(other) {
    if (!other || other.labels === null || other.labels.size === 0) return this;
    if (this.labels === null) this.labels = new Map();
    for (const [id, label] of other.labels) {
      const existing = this.labels.get(id);
      if (!existing) {
        this.labels.set(id, label);
      } else {
        // Same source on two paths: one may have constraints, the other not.
        // An unconstrained label means taint flows unconditionally on that path.
        // Keep the LESS constrained version — the attacker picks the easier path.
        const existingCount = existing.constraints?.length || 0;
        const newCount = label.constraints?.length || 0;
        if (newCount < existingCount) this.labels.set(id, label);
      }
    }
    return this;
  }

  clone() {
    if (this.labels === null || this.labels.size === 0) return new TaintSet();
    return new TaintSet(new Map(this.labels));
  }
  static empty() { return new TaintSet(); }

  static from(label) {
    const ts = new TaintSet();
    ts.add(label);
    return ts;
  }

  equals(other) {
    const thisSize = this.labels !== null ? this.labels.size : 0;
    const otherSize = other && other.labels !== null ? other.labels.size : 0;
    if (thisSize !== otherSize) return false;
    if (thisSize === 0) return true;
    for (const id of this.labels.keys()) {
      if (!other.labels.has(id)) return false;
    }
    return true;
  }

  toArray() { return this.labels !== null ? [...this.labels.values()] : []; }

  // Create a new TaintSet with a transform appended to all labels
  withTransform(op) {
    if (this.labels === null || this.labels.size === 0) return this;
    const newLabels = new Map();
    for (const [id, label] of this.labels) newLabels.set(id, label.withTransform(op));
    return new TaintSet(newLabels);
  }

  // Create a new TaintSet with a state step appended to all labels
  withStateStep(step) {
    if (this.labels === null || this.labels.size === 0) return this;
    const newLabels = new Map();
    for (const [id, label] of this.labels) {
      const nl = label.addStateStep(step);
      newLabels.set(nl.id, nl);
    }
    return new TaintSet(newLabels);
  }

  // Create a new TaintSet with a constraint appended to all labels
  withConstraint(constraint) {
    if (this.labels === null || this.labels.size === 0) return this;
    const newLabels = new Map();
    for (const [id, label] of this.labels) {
      const nl = label.withConstraint(constraint);
      newLabels.set(nl.id, nl);
    }
    return new TaintSet(newLabels);
  }
}

// ── COW function map: layered Map with O(1) fork and O(delta) iteration ──
// Stores function/method AST nodes keyed by binding name. Fork creates a child
// sharing the parent as a read-only base; writes go to an overlay. newEntries()
// returns only the overlay for efficient propagation in _finalizeFrame/postProcess.
class FuncMap {
  constructor(base) {
    this._base = base || null;  // shared read-only parent snapshot
    this._own = new Map();      // overlay: new/overwritten entries
  }

  get(key) {
    if (this._own.has(key)) return this._own.get(key);
    return this._base !== null ? this._base.get(key) : undefined;
  }

  has(key) {
    return this._own.has(key) || (this._base !== null && this._base.has(key));
  }

  set(key, val) { this._own.set(key, val); }

  get size() {
    if (this._base === null) return this._own.size;
    if (this._own.size === 0) return this._base.size;
    let count = this._base.size;
    for (const k of this._own.keys()) {
      if (!this._base.has(k)) count++;
    }
    return count;
  }

  // Create a child sharing this map as read-only base. O(own.size), not O(total).
  // Does NOT modify the parent — parent's _own stays intact for newEntries().
  fork() {
    const child = new FuncMap();
    if (this._own.size === 0) {
      child._base = this._base;
    } else if (this._base === null || this._base.size === 0) {
      child._base = this._own;  // child reads from parent's own
    } else {
      // Merge own on top of base for child's snapshot
      const merged = new Map(this._base);
      for (const [k, v] of this._own) merged.set(k, v);
      child._base = merged;
    }
    return child;
  }

  // Iterate all entries (own takes precedence over base)
  [Symbol.iterator]() {
    if (this._base === null || this._base.size === 0) return this._own[Symbol.iterator]();
    if (this._own.size === 0) return this._base[Symbol.iterator]();
    const merged = new Map(this._base);
    for (const [k, v] of this._own) merged.set(k, v);
    return merged[Symbol.iterator]();
  }

  // Only entries added/overwritten in this layer (not inherited from base)
  newEntries() { return this._own; }

  // Wrap a plain Map as a FuncMap (for initial funcMap from harness/analyzer)
  static from(map) {
    const fm = new FuncMap();
    fm._own = map;
    return fm;
  }
}

// ── Taint environment: maps binding keys to taint sets ──
// Keys are scope-resolved (e.g. "3:myVar") for locals, or dot-paths for properties.
// Uses copy-on-write: clone() is O(1) when no modifications exist, sharing a
// read-only _base snapshot. Writes go to _own overlay; _base TaintSets are cloned
// before mutation to avoid corrupting shared state.
export class TaintEnv {
  constructor(parent) {
    this._base = null;       // shared read-only snapshot (Map<string, TaintSet> | null)
    this._own = new Map();   // writable overlay for modifications
    this.parent = parent || null;
    // Path-sensitive: constraints active on this execution path (from branch conditions).
    // Each entry is {variable, op, value}. Accumulated as blocks with branchConditions are entered.
    // These propagate to return values so interprocedural callers know the return is conditional.
    this._branchConstraints = [];
    // Path-sensitive: variables confirmed to have http/https URL scheme on this path
    this.schemeCheckedVars = new Set();
    // Track new URL(x) origins: urlVar → sourceVar (so checking url.protocol also validates sourceVar)
    this.urlConstructorOrigins = new Map();
    // Type tracking: scope-qualified key → Set of possible JS typeof strings
    // e.g., "0:data" → Set(["string"]), "1:p" → Set(["object"])
    // Used for typeof branch folding and PP analysis (primitive values can't pollute prototypes)
    this.knownTypes = new Map();
    // Object aliases: varName → globalName (e.g., loc → location, doc → document)
    this.aliases = new Map();
    // Constant value tracking: scope-qualified key → JS value (number, string, boolean, null, undefined).
    // Propagated through closures via clone()/child() — constants computed in outer scopes
    // are visible in inner scopes. This replaces the _localConstants/_closureLocalConstants
    // side channel with proper data flow through the env/scope system.
    this.constants = null; // lazy Map<string, any>
    // Value tracking: maps variable keys to their AST init nodes.
    // Used to resolve variable types (regex, object, etc.) during analysis.
    // Walks parent chain like aliases — child env inherits parent's values.
    this._valueNodes = null; // lazy Map<string, ASTNode>
    // Definite assignment tracking: variables assigned with = (not +=) in this block.
    // At CFG join points, definite assignments REPLACE stale values from prior worklist
    // passes but MERGE with fresh values from current-pass predecessors.
    this._definiteAssigns = null; // lazy Set<string>
    // Per-key generation stamps: tracks when each variable was last set.
    // Used by mergeFrom to distinguish fresh values (from current-pass predecessors)
    // vs stale (from prior passes). Definite assignments replace stale but merge fresh.
    this._keyGen = null; // lazy Map<string, number>
    this._generation = 0; // env-level generation (max of all predecessors)
  }

  // Track the AST value node for a variable (e.g., var Yn = /regex/ → Yn → RegExpLiteral)
  setValueNode(key, node) {
    if (!this._valueNodes) this._valueNodes = new Map();
    this._valueNodes.set(key, node);
  }

  // Get the tracked AST value node for a variable, walking the parent chain
  getValueNode(key) {
    let cur = this;
    while (cur) {
      if (cur._valueNodes) {
        const val = cur._valueNodes.get(key);
        if (val !== undefined) return val;
      }
      cur = cur.parent;
    }
    return null;
  }

  get(key) {
    let cur = this;
    let depth = 0;
    while (cur) {
      if (cur._own.has(key)) {
        const v = cur._own.get(key);
        if (globalThis._TAINT_DEBUG && key === '216:o' && v.tainted) console.log(`[ENV-GET] 216:o TAINTED from _own at visited=${_visited.size}`);
        return v;
      }
      if (cur._base !== null && cur._base.has(key)) {
        const v = cur._base.get(key);
        if (globalThis._TAINT_DEBUG && key === '216:o' && v.tainted) console.log(`[ENV-GET] 216:o TAINTED from _base at visited=${_visited.size}`);
        return v;
      }
      cur = cur.parent;
      depth++;
    }
    return TaintSet.empty();
  }

  set(key, taintSet) {
    this._own.set(key, taintSet);
    if (this._generation > 0) {
      if (!this._keyGen) this._keyGen = new Map();
      this._keyGen.set(key, this._generation);
    }
  }

  // Mark a variable as definitively assigned (= not +=) in this env.
  // Used by mergeFrom to REPLACE instead of MERGE at join points.
  markDefinite(key) {
    if (!this._definiteAssigns) this._definiteAssigns = new Set();
    this._definiteAssigns.add(key);
  }

  has(key) {
    let cur = this;
    while (cur) {
      if (cur._own.has(key)) return true;
      if (cur._base !== null && cur._base.has(key)) return true;
      cur = cur.parent;
    }
    return false;
  }

  child() { return new TaintEnv(this); }

  // Walk the parent chain to find an alias (aliases don't need to be copied on child())
  getAlias(name) {
    let cur = this;
    while (cur) {
      const a = cur.aliases.get(name);
      if (a !== undefined) return a;
      cur = cur.parent;
    }
    return undefined;
  }

  // Flatten _own overlay into _base, returning the merged snapshot.
  // O(0) when _own is empty (most common after clone), O(_own.size) otherwise.
  _flatten() {
    if (this._own.size === 0) return this._base;
    if (this._base === null || this._base.size === 0) return this._own;
    const merged = new Map(this._base);
    for (const [k, v] of this._own) merged.set(k, v);
    return merged;
  }

  // COW clone: O(1) when _own is empty (common case: env cloned without modification).
  // TaintSets in _base are shared — mergeFrom() clones before mutating.
  clone() {
    const env = new TaintEnv(this.parent);
    const snapshot = this._flatten();
    // Both this and clone share the snapshot as read-only base
    this._base = snapshot;
    this._own = new Map();
    env._base = snapshot;
    env._branchConstraints = [...this._branchConstraints];
    env.schemeCheckedVars = new Set(this.schemeCheckedVars);
    env.urlConstructorOrigins = new Map(this.urlConstructorOrigins);
    env.aliases = new Map(this.aliases);
    env.knownTypes = new Map(this.knownTypes);
    if (this._valueNodes) env._valueNodes = new Map(this._valueNodes);
    if (this.constants) env.constants = new Map(this.constants);
    // _definiteAssigns: block-local, not propagated through clone.
    env._generation = this._generation;
    if (this._keyGen) env._keyGen = new Map(this._keyGen);
    return env;
  }

  // Iterate all bindings (_own overlay takes precedence over _base).
  // Returns a Map directly for fast iteration (avoids generator overhead).
  entries() {
    if (this._base === null || this._base.size === 0) return this._own;
    if (this._own.size === 0) return this._base;
    // Both exist — materialize merged view (overlay takes precedence)
    const merged = new Map(this._base);
    for (const [k, v] of this._own) merged.set(k, v);
    return merged;
  }

  get bindingSize() {
    if (this._base === null || this._base.size === 0) return this._own.size;
    if (this._own.size === 0) return this._base.size;
    let count = this._base.size;
    for (const k of this._own.keys()) {
      if (!this._base.has(k)) count++;
    }
    return count;
  }

  mergeFrom(other) {
    let changed = false;
    const definite = other._definiteAssigns;
    if (other._generation > this._generation) this._generation = other._generation;
    for (const [key, taint] of other.entries()) {
      // Definite assignment from OTHER env: only replace if this key's value
      // is STALE (from a prior worklist iteration, not from a current-pass predecessor).
      // Stale = the key hasn't been set during the current worklist pass.
      // We detect this by checking if our key generation is 0 (initial/prior pass).
      if (definite?.has(key)) {
        const ourKeyGen = this._keyGen?.get(key) || 0;
        if (ourKeyGen === 0) {
          // Stale: value is from initial env or prior pass → replace
          const cur = this._own.get(key) || (this._base !== null ? this._base.get(key) : undefined);
          if (!cur || !cur.equals(taint)) {
            this._own.set(key, taint.clone());
            if (!this._keyGen) this._keyGen = new Map();
            this._keyGen.set(key, other._keyGen?.get(key) || other._generation);
            changed = true;
          }
          continue;
        }
        // Fresh: value was set by a current-pass predecessor → normal merge
      }
      let existing = this._own.get(key);
      if (existing === undefined) {
        const baseVal = this._base !== null ? this._base.get(key) : undefined;
        if (baseVal === undefined) {
          // New key — clone the incoming TaintSet
          this._own.set(key, taint.clone());
          changed = true;
        } else {
          // Exists in shared _base — clone before mutating (COW)
          const before = baseVal.size;
          existing = baseVal.clone();
          existing.merge(taint);
          if (existing.size !== before) {
            this._own.set(key, existing);
            changed = true;
          }
        }
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
      if (!this.aliases.has(k)) { this.aliases.set(k, v); changed = true; }
    }
    // Type tracking: union at join points (conservative — a variable could be any type from any path)
    for (const [k, types] of other.knownTypes) {
      const existing = this.knownTypes.get(k);
      if (!existing) {
        this.knownTypes.set(k, new Set(types));
      } else {
        for (const t of types) existing.add(t);
      }
    }
    return changed;
  }

  // Replace bindings from other (overwrites instead of merging).
  // Used for sequential cross-file analysis where later scripts overwrite globals.
  replaceFrom(other) {
    for (const [key, taint] of other.entries()) {
      this._own.set(key, taint.clone());
    }
  }

  // Cross-file propagation: promote program-scope var declarations to global:
  // Only promotes keys whose base variable already has a global: version in the env
  // (set by assignToPattern for program-scope var/function declarations).
  // Does NOT promote let/const (module-scoped), block-scoped, or function-local vars.
  replaceFromCrossFile(other) {
    // First pass: copy everything and collect which base names have global: versions
    const globalBases = new Set();
    for (const [key, taint] of other.entries()) {
      this._own.set(key, taint.clone());
      if (key.startsWith('global:')) {
        const bare = key.slice(7);
        if (bare && !bare.includes('.')) globalBases.add(bare);
      }
    }
    // Second pass: for scope-qualified property keys (e.g., 0:app.data),
    // if the base variable (app) is global, also set global:app.data
    for (const [key, taint] of other.entries()) {
      if (!key.includes(':') || key.startsWith('global:') || key.startsWith('this.')) continue;
      const bare = _stripScopePrefix(key);
      if (bare === key) continue;
      const dotIdx = bare.indexOf('.');
      const baseName = dotIdx === -1 ? bare : bare.slice(0, dotIdx);
      if (globalBases.has(baseName)) {
        this._own.set(`global:${bare}`, taint.clone());
      }
    }
  }

  equals(other) {
    if (!other) return this.bindingSize === 0;
    if (this.bindingSize !== other.bindingSize) return false;
    for (const [key, taint] of this.entries()) {
      const otherTaint = other.get(key);
      if (!otherTaint || !taint.equals(otherTaint)) return false;
    }
    return true;
  }

  // Collect all tainted bindings matching a prefix (walks parent chain)
  getTaintedWithPrefix(prefix) {
    const results = new Map();
    let env = this;
    while (env) {
      for (const [key, taint] of env.entries()) {
        if (key.startsWith(prefix) && taint.tainted && !results.has(key)) {
          results.set(key, taint);
        }
      }
      env = env.parent;
    }
    return results;
  }

  // Like getTaintedWithPrefix but returns ALL entries (including non-tainted).
  // Used for per-index array propagation where clean entries matter for positioning.
  getAllWithPrefix(prefix) {
    const results = new Map();
    let env = this;
    while (env) {
      for (const [key, taint] of env.entries()) {
        if (key.startsWith(prefix) && !results.has(key)) {
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
    this.funcMap = funcMap instanceof FuncMap ? funcMap : FuncMap.from(funcMap);  // bindingKey|name → AST node
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
    this.elementTypes = new Map(); // tracks variable name → element tag name from createElement/querySelector
    this.domAttached = new Set(); // tracks variables holding DOM-attached elements (only after append/live DOM)
    this.variableTypes = new Map(); // tracks scopedKey → IDL interface name (e.g., "0:doc" → "Document")
    this._deferredElementTaints = null; // deferred sink checks for unattached elements
    this.thrownTaint = TaintSet.empty(); // tracks taint from ThrowStatement for catch param
    this.generatorTaint = new Map(); // maps generator function key → TaintSet from yield expressions
    this.eventListeners = new Map(); // eventName → [{callback, env}] for custom event dispatch tracking
    this.classBodyMap = new Map(); // className → classBody array
    this.superClassMap = new Map(); // className → parentClassName
    this.protoMethodMap = new Map(); // "ClassName" → [{methodName, funcNode}]
    this._findingKeys = new Set(); // dedup key set for findings (prevents duplicates from back-edge re-iteration)
    this._thisAliases = null; // Set<string> of variable names aliased to `this` (e.g., var a = this)
    this.domCatalog = null; // DOM catalog from HTML parsing: { elements: Map<id,tag>, inlineHandlers: [], clobberPaths: [] }
    // Prototype linkages: when X.prototype = Y, maps Y → [X, ...].
    // Used for reactive propagation: new methods on Y automatically create X#method entries.
    this._prototypeLinkages = new Map();
  }
}

// Push a finding with deduplication and universal SMT satisfiability check.
// Before emitting, checks if the constraints on the taint labels allow a
// viable exploit. If constraints make the exploit unsatisfiable, the finding
// is suppressed. This is the single code path for ALL finding types.
function pushFinding(ctx, finding) {
  // Reclassify as DOM Clobbering if all sources are dom-clobbering
  if (finding.source) {
    const sources = Array.isArray(finding.source) ? finding.source : [finding.source];
    const allClobber = sources.length > 0 && sources.every(s => s?.type === 'dom-clobbering');
    if (allClobber) {
      finding.type = 'DOM Clobbering';
      finding.severity = 'high';
      finding.title = `DOM Clobbering: ${finding.sink?.expression || 'element value'} controlled via named DOM element`;
    }
  }
  // Universal SMT check: collect constraints from all source labels
  // and verify the exploit payload is satisfiable.
  if (!_isFindingSatisfiable(finding)) {
    trace('SMT-SUPPRESS', { type: finding.type, sink: finding.sink?.expression, file: finding.sink?.file });
    return;
  }
  const key = `${finding.type}:${finding.sink?.expression}:${finding.sink?.file}:${finding.sink?.line}:${finding.sink?.col}`;
  if (!ctx._findingKeys) ctx._findingKeys = new Set();
  if (ctx._findingKeys.has(key)) return;
  ctx._findingKeys.add(key);
  ctx.findings.push(finding);
}

// ── Danger set: property names with prototype-traversal semantics ──
// Discovered from the JS runtime at load time, not hardcoded.
// These are Object.prototype properties with setter accessors — assigning to
// obj[key] where key is one of these triggers the accessor and modifies the
// prototype chain (e.g., __proto__).
const _PROTO_SETTER_KEYS = (() => {
  const keys = [];
  for (const k of Object.getOwnPropertyNames(Object.prototype)) {
    const d = Object.getOwnPropertyDescriptor(Object.prototype, k);
    if (d && d.set) keys.push(k);
  }
  return keys;
})();

// ── Universal constraint satisfiability solver ──
// Type-agnostic: works the same for PP, XSS, Open Redirect, CSS Injection, etc.
// Checks if the constraints on a finding's taint labels allow any dangerous value
// to reach the sink. The danger set comes from the finding's sinkModel (if present).
//
// 1. Collect constraints from the finding's constraint source
// 2. Check for internal contradictions (=== X and !== X on same variable)
// 3. If finding has a sinkModel with a danger set, check if ANY value survives
// 4. No sinkModel → infinite danger set → always satisfiable unless contradiction
function _isFindingSatisfiable(finding) {
  // Use sinkModel.constraintSource if provided (separates key vs value constraints),
  // otherwise fall back to finding.source
  const constraintSrc = finding.sinkModel?.constraintSource;
  let constraints;
  if (constraintSrc) {
    // constraintSource is a TaintSet — extract constraints from its labels
    constraints = [];
    if (constraintSrc.tainted) {
      for (const label of constraintSrc.toArray()) {
        if (label.constraints) {
          for (const c of label.constraints) constraints.push(c);
        }
      }
    }
  } else {
    // Fall back to finding.source (formatted source objects)
    const sources = finding.source;
    if (!sources) return true;
    const sourceArr = Array.isArray(sources) ? sources : [sources];
    constraints = [];
    for (const src of sourceArr) {
      if (src.constraints) {
        for (const c of src.constraints) constraints.push(c);
      }
    }
  }
  // Also collect constraints from valueConstraintSource (e.g., safeGet return constraints)
  // These restrict which key values can produce tainted values.
  const valSrc = finding.sinkModel?.valueConstraintSource;
  if (valSrc && valSrc.tainted) {
    for (const label of valSrc.toArray()) {
      if (label.constraints) {
        for (const c of label.constraints) constraints.push(c);
      }
    }
  }

  if (constraints.length === 0) return true;
  if (finding.type === 'Prototype Pollution') {
    trace('SMT-PP-CONSTRAINTS', { count: constraints.length, ops: constraints.map(c => c.op + ':' + (c.value || c.pattern || '?')).join(', '), dangerousValues: finding.sinkModel?.dangerousValues?.join(',') || 'none' });
  }

  // Check for internal contradictions: === X and !== X on the same variable
  if (_hasContradiction(constraints)) return false;

  // Regex constraints: evaluate the PoC payload against any regex constraints
  // using the JS runtime's own regex engine. If a 'regex' constraint (value MUST
  // match) rejects the payload, or a '!regex' constraint (value must NOT match)
  // accepts it, the exploit is unsatisfiable.
  const regexConstraints = constraints.filter(c => c.op === 'regex' || c.op === '!regex');
  if (regexConstraints.length > 0) {
    const poc = generatePoC(finding);
    if (poc) {
      for (const c of regexConstraints) {
        try {
          const re = new RegExp(c.pattern, c.flags || '');
          const payload = poc.payload;
          if (c.op === 'regex' && !re.test(payload)) return false;  // must match but doesn't
          if (c.op === '!regex' && re.test(payload)) return false;   // must not match but does
        } catch { /* invalid regex — skip */ }
      }
    }
  }

  // If the finding has a sink model with a finite danger set,
  // check if ANY dangerous value is permitted by the constraints
  if (finding.sinkModel?.dangerousValues) {
    return _anyValuePermitted(finding.sinkModel.dangerousValues, constraints);
  }

  // No sink model → infinite danger set → satisfiable (constraints can't block everything)
  return true;
}

// Check if at least one value from the danger set is NOT excluded by constraints.
function _anyValuePermitted(dangerousValues, constraints) {
  for (const val of dangerousValues) {
    let permitted = true;
    for (const c of constraints) {
      if ((c.op === '!==' || c.op === '!=') && c.value === val) {
        permitted = false;
        break;
      }
      // Disjunction: {op: 'or', clauses: [{op:'!==', value:'__proto__'}, ...]}
      // Value is blocked if ANY clause blocks it (since at least one clause is true)
      if (c.op === 'or' && c.clauses) {
        const blockedByAny = c.clauses.some(clause =>
          (clause.op === '!==' || clause.op === '!=') && clause.value === val);
        if (blockedByAny) {
          permitted = false;
          break;
        }
      }
    }
    if (permitted) return true;
  }
  return false;
}

// Check if constraints contain a TRUE contradiction — where ALL paths are blocked.
// === X and !== X from the SAME variable means the taint flows through BOTH branches
// of a conditional (merged at join point). This is NOT a contradiction — each branch
// is a viable path. A contradiction only occurs if a SINGLE path has both === X and !== X,
// which can't happen in well-formed branch analysis.
function _hasContradiction(_constraints) {
  // Check for vacuous constraints: when BOTH === X and !== X exist for the same
  // variable and value, the taint flowed through BOTH branches of a conditional.
  // Neither branch actually constrains the payload — both paths are taken.
  // Remove these vacuous constraint pairs so they don't affect PoC generation.
  // This is NOT a contradiction — it's a merged branch state.
  return false;
}

// Remove vacuous constraint pairs where the same variable has both ===X and !==X.
// Returns a filtered constraint array with the contradictory pairs removed.
function _removeVacuousConstraints(constraints) {
  if (!constraints || constraints.length === 0) return constraints;
  // Find ===X values per variable
  const eqVals = new Map(); // variable → Set of values with ===
  const neqVals = new Map(); // variable → Set of values with !==
  for (const c of constraints) {
    if (c.op === '===' || c.op === '==') {
      if (!eqVals.has(c.variable)) eqVals.set(c.variable, new Set());
      eqVals.get(c.variable).add(c.value);
    }
    if (c.op === '!==' || c.op === '!=') {
      if (!neqVals.has(c.variable)) neqVals.set(c.variable, new Set());
      neqVals.get(c.variable).add(c.value);
    }
  }
  // Find vacuous pairs: variable has both ===X and !==X
  const vacuousPairs = new Set(); // "variable:value"
  for (const [variable, eqSet] of eqVals) {
    const neqSet = neqVals.get(variable);
    if (neqSet) {
      for (const val of eqSet) {
        if (neqSet.has(val)) vacuousPairs.add(`${variable}:${val}`);
      }
    }
  }
  if (vacuousPairs.size === 0) return constraints;
  // Filter out vacuous constraints
  return constraints.filter(c => {
    if ((c.op === '===' || c.op === '==' || c.op === '!==' || c.op === '!=') && c.variable) {
      if (vacuousPairs.has(`${c.variable}:${c.value}`)) return false;
    }
    return true;
  });
}

// ── Evaluate whether an AST node refers to a prototype object ──
// Used by APIs that set own properties (Object.defineProperty, Reflect.defineProperty)
// to determine if the target is a shared prototype. These APIs only cause PP when
// the target IS a prototype — setting own properties on regular objects is safe.
function _isPrototypeNode(node) {
  if (!node) return false;
  // Direct: X.prototype
  if (node.type === 'MemberExpression' && !node.computed && node.property?.name === 'prototype') return true;
  // Global: Object.prototype
  if (node.type === 'MemberExpression' && !node.computed) {
    const obj = node.object;
    if (obj.type === 'Identifier' && node.property?.name === 'prototype') return true;
  }
  return false;
}

// ── Extract property key name as a string (handles NumericLiteral → "2") ──
function propKeyName(key) {
  if (!key) return null;
  const name = key.name || key.value;
  return name != null ? String(name) : null;
}

// ── Resolve an Identifier node to its canonical binding key ──
// Uses Babel scope info when available, falls back to raw name
function resolveId(node, scopeInfo, env) {
  if (node.name === 'arguments') return 'arguments';
  let key;
  if (scopeInfo) {
    key = scopeInfo.resolve(node);
  }
  if (!key) key = `global:${node.name}`;
  if (env) {
    const alias = env.getAlias ? env.getAlias(key) : env.aliases?.get(key);
    if (alias && _GLOBAL_SCOPE_OBJECTS.has(alias)) return alias;
  }
  return key;
}

// ── Main entry: analyze a CFG with initial taint environment ──
export function analyzeCFG(cfg, env, file, funcMap, globalEnv, scopeInfo, isWorker, domCatalog) {
  const findings = [];
  const _originalFuncMap = funcMap instanceof Map ? funcMap : null;
  const ctx = new AnalysisContext(file, funcMap, findings, globalEnv || new TaintEnv(), scopeInfo);
  ctx.isWorker = !!isWorker;

  // Seed variable types for known globals (from IDL interface names)
  ctx.variableTypes.set('global:document', 'Document');
  ctx.variableTypes.set('global:window', 'Window');
  ctx.variableTypes.set('global:location', 'Location');
  ctx.variableTypes.set('global:navigator', 'Navigator');
  ctx.variableTypes.set('global:history', 'History');
  ctx.variableTypes.set('global:screen', 'Screen');
  // document.body/head/documentElement are always DOM-attached
  ctx.domAttached.add('global:document.body');
  ctx.domAttached.add('global:document.head');
  ctx.domAttached.add('global:document.documentElement');

  // Seed element type tracking from DOM catalog (live DOM from Debugger API)
  // These elements are in the actual DOM — they're attached and their types are ground truth
  // This is more reliable than getElementById() which can be clobbered
  if (domCatalog) {
    ctx.domCatalog = domCatalog;
    if (domCatalog.elements) {
      for (const [id, tag] of domCatalog.elements) {
        ctx.elementTypes.set(id, tag);
        ctx.elementTypes.set(`global:${id}`, tag);
        ctx.domAttached.add(id);
        ctx.domAttached.add(`global:${id}`);
        if (tag === 'script') {
          ctx.scriptElements.add(id);
          ctx.scriptElements.add(`global:${id}`);
        }
      }
    }
    // Seed clobber paths: form.childName → child element type
    // <form id="x"><input name="y"> → x.y is an input element, attached
    // This also handles DOM clobbering: <form id="getElementById"><input name="a">
    // → getElementById is a form element, getElementById.a is an input element
    if (domCatalog.clobberPaths) {
      for (const cp of domCatalog.clobberPaths) {
        const key = `${cp.id}.${cp.name}`;
        const gkey = `global:${key}`;
        ctx.elementTypes.set(key, cp.childTag);
        ctx.elementTypes.set(gkey, cp.childTag);
        ctx.domAttached.add(key);
        ctx.domAttached.add(gkey);
        // Also mark the form itself as attached element
        ctx.elementTypes.set(cp.id, cp.tag);
        ctx.elementTypes.set(`global:${cp.id}`, cp.tag);
        ctx.domAttached.add(cp.id);
        ctx.domAttached.add(`global:${cp.id}`);
      }
    }
  }

  const blockEnvs = new Map();
  blockEnvs.set(cfg.entry.id, env.clone());

  const worklist = [cfg.entry];
  const inWorklist = new Set([cfg.entry.id]);
  let _wlGeneration = 1; // global worklist generation counter

  while (worklist.length > 0) {
    const block = worklist.shift();
    inWorklist.delete(block.id);

    const entryEnv = blockEnvs.get(block.id);
    if (!entryEnv) continue;

    const _blockGen = _wlGeneration++;
    const _processEnv = entryEnv.clone();
    _processEnv._generation = _blockGen;
    const exitEnv = processBlock(block, _processEnv, ctx);

    for (const succ of block.successors) {
      // Constant-fold: skip unreachable branches (e.g., if(false) consequent,
      // or if(taintedVar) where tainted source strings are always truthy)
      if (succ.branchCondition && isConstantBool(succ.branchCondition, ctx, exitEnv) !== null) {
        const val = isConstantBool(succ.branchCondition, ctx, exitEnv);
        if (val === false && succ.branchPolarity === true) continue;
        if (val === true && succ.branchPolarity === false) continue;
      }
      const existing = blockEnvs.get(succ.id);
      if (!existing) {
        blockEnvs.set(succ.id, exitEnv.clone());
        if (!inWorklist.has(succ.id)) { worklist.push(succ); inWorklist.add(succ.id); }
      } else {
        const changed = existing.mergeFrom(exitEnv);
        // Re-queue when taint changed OR when a for-loop counter is still iterating.
        // The flag is consumed (reset) after use to prevent forcing ALL subsequent
        // blocks — only the loop's direct successors should be requeued.
        let _forceRequeue = false;
        if (ctx._forLoopCounterActive && ctx._forLoopRequeueRemaining) {
          for (const [lk, rem] of ctx._forLoopRequeueRemaining) {
            if (rem > 0) { _forceRequeue = true; ctx._forLoopRequeueRemaining.set(lk, rem - 1); break; }
          }
          if (!_forceRequeue) ctx._forLoopCounterActive = false;
        }
        if ((changed || _forceRequeue) && !inWorklist.has(succ.id)) { worklist.push(succ); inWorklist.add(succ.id); }
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

  // Sync COW funcMap entries back to the original plain Map (if provided)
  // so callers (test harness, analyzeMultiple) see discovered functions
  if (_originalFuncMap && ctx.funcMap.newEntries) {
    for (const [k, v] of ctx.funcMap.newEntries()) {
      _originalFuncMap.set(k, v);
    }
  }

  return findings;
}

function processBlock(block, env, ctx) {
  // Invalidate resolveToConstant cache — env state changes between blocks
  ctx._rtcCache = null;
  // Path-sensitive: if this block is a branch consequent, check for URL scheme guards
  if (block.branchCondition) {
    applyBranchCondition(block.branchCondition, block.branchPolarity, env, ctx);
  }
  // Track current branch condition for multi-step PoC annotation
  const prevBranch = ctx._currentBranchCondition;
  if (block.branchCondition) {
    ctx._currentBranchCondition = { node: block.branchCondition, polarity: block.branchPolarity };
  } else if (block.nodes.length > 0 && block.nodes[0].type === '_Test' && block.nodes[0].test) {
    // Switch-case block: _Test node has the case value, discriminant is in the switch entry.
    // Synthesize a BinaryExpression condition: discriminant === caseValue
    const testNode = block.nodes[0].test;
    // Find the switch discriminant from predecessor block's last node
    let switchDiscriminant = null;
    for (const pred of block.predecessors) {
      if (pred.nodes.length > 0 && pred.successors.length > 1) {
        // Switch entry block has the discriminant as its last node and fans out to case blocks
        const lastNode = pred.nodes[pred.nodes.length - 1];
        if (lastNode.type !== '_Test') {
          switchDiscriminant = lastNode;
          break;
        }
      }
    }
    if (switchDiscriminant && (testNode.type === 'StringLiteral' || testNode.type === 'NumericLiteral' ||
        (testNode.type === 'Literal' && (typeof testNode.value === 'string' || typeof testNode.value === 'number')))) {
      ctx._currentBranchCondition = {
        node: { type: 'BinaryExpression', operator: '===', left: switchDiscriminant, right: testNode },
        polarity: true,
      };
    } else {
      ctx._currentBranchCondition = null;
    }
  } else {
    ctx._currentBranchCondition = null;
  }
  const startIdx = ctx._resumeNodeIdx || 0;
  ctx._resumeNodeIdx = 0;
  for (let i = startIdx; i < block.nodes.length; i++) {
    const savedInlineIdx = ctx._inlineCallIdx;
    processNode(block.nodes[i], env, ctx);
    if (ctx._ipSuspended) {
      ctx._suspendedNodeIdx = i;
      ctx._suspendedInlineIdx = savedInlineIdx;
      break;
    }
  }
  ctx._currentBranchCondition = prevBranch;
  return env;
}

// ── Path-sensitive URL scheme check detection ──
// Examines if-test conditions to determine if a variable's URL scheme has been validated.
// When a navigation sink is reached, scheme-checked vars produce "Open Redirect"
// instead of "XSS" (since javascript: URIs are blocked).

function applyBranchCondition(testNode, polarity, env, ctx) {
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
    // if (a && b) in the false branch → NOT (a && b) = !a || !b
    // If one operand is provably truthy, the other must be false.
    if (node.type === 'LogicalExpression' && node.operator === '&&' && !positive) {
      const leftConst = isConstantBool(node.left, ctx);
      const rightConst = isConstantBool(node.right, ctx);
      if (leftConst === true) {
        // Left is always true → right must be false
        stack.push({ node: node.right, positive: false });
        continue;
      }
      if (rightConst === true) {
        // Right is always true → left must be false
        stack.push({ node: node.left, positive: false });
        continue;
      }
      // If one side is non-tainted (no attacker influence), the attacker can only
      // control the other side. Apply the negation to the potentially tainted side.
      // This handles patterns like: `"x" == key && obj` where `obj` is always defined.
      const leftTaint = env.get(node.left.type === 'Identifier' ? resolveId(node.left, ctx.scopeInfo) : '');
      const rightTaint = env.get(node.right.type === 'Identifier' ? resolveId(node.right, ctx.scopeInfo) : '');
      if (node.right.type === 'Identifier' && !rightTaint.tainted) {
        stack.push({ node: node.left, positive: false });
        continue;
      }
      if (node.left.type === 'Identifier' && !leftTaint.tainted) {
        stack.push({ node: node.right, positive: false });
        continue;
      }
      // NOT(A && B) = !A || !B — disjunction. Either side could have failed.
      // Extract negated constraints from both sides and combine as OR.
      // This enables PP guard recognition: "__proto__"!==m && recurse()
      // → on false branch: m==="__proto__" OR recurse() didn't run.
      // Extract the original (non-negated) comparison from the left side of &&.
      // NOT(A && B) — the OR means A could be false. The ORIGINAL A (before negation)
      // provides the exclusion constraint. E.g., A = "__proto__"!==m → the original
      // exclusion !== still applies as one possible branch of the disjunction.
      // For _anyValuePermitted: if any clause of the OR blocks a value, it's blocked
      // (because at least one clause IS true on this path).
      if (node.left.type === 'BinaryExpression' &&
          (node.left.operator === '!==' || node.left.operator === '!=')) {
        let _varSide = null, _valSide = null;
        if (node.left.left.type === 'Identifier' && isStringLiteral(node.left.right)) {
          _varSide = node.left.left.name; _valSide = stringLiteralValue(node.left.right);
        } else if (node.left.right.type === 'Identifier' && isStringLiteral(node.left.left)) {
          _varSide = node.left.right.name; _valSide = stringLiteralValue(node.left.left);
        }
        if (_varSide && _valSide) {
          const orConstraint = { op: 'or', clauses: [
            { op: '!==', variable: _varSide, value: _valSide }
          ]};
          _addConstraintToVar(env, _varSide, orConstraint);
          env._branchConstraints.push(orConstraint);
        }
      }
      // NOT(A && B) where B is a type predicate call (e.g., D(p)):
      // On the false path, either A is false OR B is false.
      // If A is provably truthy, then B must be false → apply negated type predicate.
      // This handles: d && isObject(p) ? recurse : a[m]=p
      // On the else path: isObject(p) was false → p is NOT an object → PP not exploitable.
      if (node.right.type === 'CallExpression' && node.right.arguments?.length > 0) {
        let predFunc = null;
        if (node.right.callee?.type === 'Identifier') {
          const callKey = ctx ? resolveId(node.right.callee, ctx.scopeInfo) : null;
          predFunc = callKey ? ctx?.funcMap?.get(callKey) : null;
        }
        if (predFunc?._typePredicate) {
          const pred = predFunc._typePredicate;
          const argNode = node.right.arguments[pred.paramIndex];
          if (argNode?.type === 'Identifier') {
            const argKey = ctx ? resolveId(argNode, ctx.scopeInfo) : argNode.name;
            // NOT(D(p)) → p is NOT this type (or negated: p IS this type)
            const isTrue = pred.negated ? true : false; // negated because NOT(B)
            if (!isTrue) {
              // p is NOT the predicate type
              const existing = env.knownTypes.get(argKey);
              if (existing) {
                existing.delete(pred.type);
              } else {
                const allTypes = new Set(['string', 'number', 'boolean', 'object', 'function', 'undefined', 'symbol', 'bigint']);
                allTypes.delete(pred.type);
                env.knownTypes.set(argKey, allTypes);
              }
            }
          }
        }
      }
      // Same check for the LEFT side: isObject(p) && condition ? ... : ...
      if (node.left.type === 'CallExpression' && node.left.arguments?.length > 0) {
        let predFunc = null;
        if (node.left.callee?.type === 'Identifier') {
          const callKey = ctx ? resolveId(node.left.callee, ctx.scopeInfo) : null;
          predFunc = callKey ? ctx?.funcMap?.get(callKey) : null;
        }
        if (predFunc?._typePredicate) {
          const pred = predFunc._typePredicate;
          const argNode = node.left.arguments[pred.paramIndex];
          if (argNode?.type === 'Identifier') {
            const argKey = ctx ? resolveId(argNode, ctx.scopeInfo) : argNode.name;
            const isTrue = pred.negated ? true : false;
            if (!isTrue) {
              const existing = env.knownTypes.get(argKey);
              if (existing) {
                existing.delete(pred.type);
              } else {
                const allTypes = new Set(['string', 'number', 'boolean', 'object', 'function', 'undefined', 'symbol', 'bigint']);
                allTypes.delete(pred.type);
                env.knownTypes.set(argKey, allTypes);
              }
            }
          }
        }
      }
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
      const leftVar = extractSchemeCheck(node.left, true, ctx);
      const rightVar = extractSchemeCheck(node.right, true, ctx);
      if (leftVar && rightVar && leftVar === rightVar) {
        env.schemeCheckedVars.add(leftVar);
        const origin = env.urlConstructorOrigins.get(leftVar);
        if (origin) env.schemeCheckedVars.add(origin);
        continue;
      }
      // Allowlist check: val === 'a' || val === 'b' || val === 'c'
      // When all operands test the same variable against string literals, the variable
      // is constrained to one of those safe values → clear its taint
      const allowlistVar = extractAllowlistVar(node);
      if (allowlistVar) {
        env.set(allowlistVar, TaintSet.empty());
        env.set(`global:${allowlistVar}`, TaintSet.empty());
        const suffix = `:${allowlistVar}`;
        for (const [key] of env.entries()) {
          if (key.endsWith(suffix)) env.set(key, TaintSet.empty());
        }
        continue;
      }
      stack.push({ node: node.left, positive: true });
      stack.push({ node: node.right, positive: true });
      continue;
    }

    const checkedVar = extractSchemeCheck(node, positive, ctx);
    if (checkedVar) {
      env.schemeCheckedVars.add(checkedVar);
      const origin = env.urlConstructorOrigins.get(checkedVar);
      if (origin) env.schemeCheckedVars.add(origin);
    }

    // Extract typeof comparison from BinaryExpression: typeof x === "type" or typeof x !== "type"
    let typeofArg = null, typeVal = null;
    if (node.type === 'BinaryExpression' &&
        (node.operator === '===' || node.operator === '==' || node.operator === '!==' || node.operator === '!=')) {
      if (node.left.type === 'UnaryExpression' && node.left.operator === 'typeof' &&
          node.left.argument.type === 'Identifier' && isStringLiteral(node.right)) {
        typeofArg = node.left.argument.name;
        typeVal = stringLiteralValue(node.right);
      } else if (node.right.type === 'UnaryExpression' && node.right.operator === 'typeof' &&
          node.right.argument.type === 'Identifier' && isStringLiteral(node.left)) {
        typeofArg = node.right.argument.name;
        typeVal = stringLiteralValue(node.left);
      }
    }

    // typeof guard: if (typeof x === "number") → x is not a string, clear taint in true branch
    // Non-string types cannot cause XSS via innerHTML/etc.
    if (typeofArg && typeVal && positive && (node.operator === '===' || node.operator === '==')) {
      const safeTypes = new Set(['number', 'boolean', 'undefined', 'bigint', 'symbol']);
      if (safeTypes.has(typeVal)) {
        // Primitive non-string type confirmed — clear taint (can't contain XSS payload)
        // Note: 'object' and 'function' are NOT safe due to toString() coercion
        env.set(typeofArg, TaintSet.empty());
        env.set(`global:${typeofArg}`, TaintSet.empty());
        // Also clear scoped bindings (e.g., "0:data" from CFG scope resolution)
        const suffix = `:${typeofArg}`;
        for (const [key] of env.entries()) {
          if (key.endsWith(suffix)) env.set(key, TaintSet.empty());
        }
      }
    }

    // Type narrowing: typeof x === "type" → track known type on this branch
    // typeof x !== "type" → exclude that type on this branch
    if (typeofArg && typeVal) {
      const varKey = ctx ? resolveId({ type: 'Identifier', name: typeofArg }, ctx.scopeInfo) : typeofArg;
      if (positive && (node.operator === '===' || node.operator === '==')) {
        // typeof x === "type" → x is exactly this type
        env.knownTypes.set(varKey, new Set([typeVal]));
      } else if (!positive && (node.operator === '===' || node.operator === '==')) {
        // NOT(typeof x === "type") → x is NOT this type
        const existing = env.knownTypes.get(varKey);
        if (existing) {
          existing.delete(typeVal);
        }
      } else if (positive && (node.operator === '!==' || node.operator === '!=')) {
        // typeof x !== "type" → x is NOT this type
        const existing = env.knownTypes.get(varKey);
        if (existing) {
          existing.delete(typeVal);
        }
      } else if (!positive && (node.operator === '!==' || node.operator === '!=')) {
        // NOT(typeof x !== "type") → x IS this type
        env.knownTypes.set(varKey, new Set([typeVal]));
      }
    }

    // Type predicate narrowing: if (isObject(x)) → narrow x's type
    // When a CallExpression is used as a branch condition and the callee has _typePredicate,
    // narrow the argument's knownTypes based on the predicate and branch polarity.
    if (node.type === 'CallExpression' && node.callee && node.arguments?.length > 0) {
      let predFunc = null;
      if (node.callee.type === 'Identifier') {
        const callKey = ctx ? resolveId(node.callee, ctx.scopeInfo) : null;
        predFunc = callKey ? ctx?.funcMap?.get(callKey) : null;
      }
      if (predFunc?._typePredicate) {
        const pred = predFunc._typePredicate;
        const argNode = node.arguments[pred.paramIndex];
        if (argNode?.type === 'Identifier') {
          const argKey = ctx ? resolveId(argNode, ctx.scopeInfo) : argNode.name;
          const isTrue = pred.negated ? !positive : positive;
          if (isTrue) {
            // Predicate confirmed: x IS this type
            env.knownTypes.set(argKey, new Set([pred.type]));
          } else {
            // Predicate denied: x is NOT this type
            const existing = env.knownTypes.get(argKey);
            if (existing) {
              existing.delete(pred.type);
            } else {
              // All JS types minus the excluded one
              const allTypes = new Set(['string', 'number', 'boolean', 'object', 'function', 'undefined', 'symbol', 'bigint']);
              allTypes.delete(pred.type);
              env.knownTypes.set(argKey, allTypes);
            }
          }
        }
      }
    }

    // Generic constraint: key !== "value" (exclusion) or key === "value" (inclusion)
    // Adds a constraint to the taint labels on the variable, recording that on this
    // branch the variable can/cannot equal this specific string value. This is used by
    // the universal SMT satisfiability check in pushFinding.
    if (node.type === 'BinaryExpression') {
      const isExclude = (node.operator === '!==' || node.operator === '!=') && positive;
      const isExcludeFlip = (node.operator === '===' || node.operator === '==') && !positive;
      const isInclude = (node.operator === '===' || node.operator === '==') && positive;
      const isIncludeFlip = (node.operator === '!==' || node.operator === '!=') && !positive;
      if (isExclude || isExcludeFlip || isInclude || isIncludeFlip) {
        let varNode = null, strVal = null;
        if (isStringLiteral(node.right) && !isStringLiteral(node.left)) {
          varNode = node.left;
          strVal = stringLiteralValue(node.right);
        } else if (isStringLiteral(node.left) && !isStringLiteral(node.right)) {
          varNode = node.right;
          strVal = stringLiteralValue(node.left);
        }
        if (varNode && typeof strVal === 'string') {
          const op = (isExclude || isExcludeFlip) ? '!==' : '===';
          // Get the variable name: bare Identifier or dotted MemberExpression path
          let varName = null;
          if (varNode.type === 'Identifier') {
            varName = varNode.name;
          } else if (varNode.type === 'MemberExpression') {
            varName = _scopeQualifyMemberExpr(varNode, ctx);
          }
          if (varName) {
            const constraint = { variable: varName, op, value: strVal };
            if (varNode.type === 'Identifier') {
              // Identifier: suffix-match all scoped bindings (existing behavior)
              _addConstraintToVar(env, varName, constraint);
            } else {
              // MemberExpression: exact-match only (no suffix scan to avoid worklist divergence)
              const taint = env.get(varName);
              if (taint && taint.tainted) {
                env.set(varName, taint.withConstraint(constraint));
              }
            }
            env._branchConstraints.push(constraint);
          }
        }
      }
    }

    // Regex constraint: regex.test(var) or var.match(regex) in branch condition.
    // Resolves regex values through env.getValueNode() — the general-purpose
    // value tracking system that knows what each variable was assigned to.
    // The SMT solver evaluates the regex against the PoC payload using the
    // JS runtime's own regex engine.
    if (node.type === 'CallExpression' && node.callee?.type === 'MemberExpression') {
      const method = node.callee.property?.name;
      if (method === 'test' && node.arguments?.length >= 1) {
        const regexObj = node.callee.object;
        const argNode = node.arguments[0];
        // Resolve the regex: inline literal or variable with tracked value
        const regex = _resolveRegex(regexObj, env, ctx);
        if (regex && (argNode.type === 'Identifier' || argNode.type === 'MemberExpression')) {
          const varName = _scopeQualifyMemberExpr(argNode, ctx);
          if (varName) {
            const constraint = { variable: varName, op: positive ? 'regex' : '!regex', pattern: regex.pattern, flags: regex.flags || '' };
            _addConstraintToVar(env, varName, constraint);
            env._branchConstraints.push(constraint);
          }
        }
      }
      if ((method === 'match' || method === 'search') && node.arguments?.length >= 1) {
        const objNode = node.callee.object;
        const regexArg = node.arguments[0];
        const regex = _resolveRegex(regexArg, env, ctx);
        if (regex && (objNode.type === 'Identifier' || objNode.type === 'MemberExpression')) {
          const varName = _scopeQualifyMemberExpr(objNode, ctx);
          if (varName) {
            const constraint = { variable: varName, op: positive ? 'regex' : '!regex', pattern: regex.pattern, flags: regex.flags || '' };
            _addConstraintToVar(env, varName, constraint);
            env._branchConstraints.push(constraint);
          }
        }
      }
    }
  }
}

// Resolve an AST node to a regex object {pattern, flags}.
// Handles: inline /regex/, Identifier resolved through env value tracking.
// Extract regex {pattern, flags} from an AST node.
// Handles both Babel 7 ({regex: {pattern, flags}}) and Babel 8 ({pattern, flags}).
function _getRegex(node) {
  if (!node) return null;
  if (node.regex) return node.regex;  // Babel 7
  if (node.type === 'RegExpLiteral' && node.pattern) return { pattern: node.pattern, flags: node.flags || '' };  // Babel 8
  return null;
}

function _resolveRegex(node, env, ctx) {
  if (!node) return null;
  // Inline regex literal
  const inline = _getRegex(node);
  if (inline) return inline;
  // Identifier: look up tracked value in env
  if (node.type === 'Identifier') {
    const key = resolveId(node, ctx.scopeInfo);
    const valueNode = env.getValueNode(key);
    const resolved = _getRegex(valueNode);
    if (resolved) return resolved;
  }
  return null;
}

// Propagate tainted closure mutations from an inner function's env back to the
// outer closure env. Only propagates ACTUAL closure variables — skips inner-local
// variables that happen to share names with outer variables.
// This is the single DRY implementation used by all three propagation sites:
// analyzeInlineFunction postProcess, analyzeInlineFunction direct, and ACF postProcess.
function _propagateClosureMutations(innerEnv, closureEnv, paramNames) {
  for (const [key, taint] of innerEnv.entries()) {
    if (!taint.tainted || key.startsWith('this.') || paramNames.has(key) || key === 'this') continue;
    // Skip scope-qualified keys that are local to the inner function
    // For property keys (e.g., 0:Config.html), check if the base variable (0:Config) exists in closure
    if (key.includes(':') && !closureEnv.has(key)) {
      const dotIdx = key.indexOf('.');
      if (dotIdx === -1 || !closureEnv.has(key.slice(0, dotIdx))) continue;
    }
    // Skip global: keys for inner-local variables (the inner function declared
    // its own variable with this name — it's NOT a closure reference).
    // A scope-qualified key like "66:o" indicates a function-local declaration.
    // Program-scope "0:o" does NOT count as inner-local — it's the outer declaration.
    if (key.startsWith('global:')) {
      const bareName = key.slice(7);
      if (paramNames.has(bareName)) continue;
      // Check if the inner function declared its own variable with this name.
      // A scope-qualified key like "66:o" (but NOT "0:o") means the inner function
      // has a local declaration — the global:o is NOT a closure reference.
      let isInnerLocal = false;
      for (const [ek] of innerEnv.entries()) {
        if (ek !== key && ek !== `global:${bareName}` && !ek.startsWith('0:') &&
            ek.endsWith(':' + bareName)) {
          isInnerLocal = true; break;
        }
      }
      if (isInnerLocal) continue;
    }
    closureEnv.set(key, closureEnv.get(key).clone().merge(taint));
    // Propagate to scope-resolved variants in the outer env
    if (!key.includes(':') && !key.includes('.')) {
      for (const [existingKey] of closureEnv.entries()) {
        if (existingKey.endsWith(':' + key) || (existingKey.startsWith(key + '.') && existingKey.length > key.length + 1)) {
          closureEnv.set(existingKey, closureEnv.get(existingKey).clone().merge(taint));
        }
      }
    }
  }
}

// Register a method in funcMap under both bare and scope-qualified keys.
// This enables scope-aware lookups that prevent cross-scope collisions
// in minified code where different functions reuse variable names.
// objNameOrNode: either a string (bare name) or an Identifier AST node.
// prefix: optional prefix like 'getter:' or 'setter:'
// Build a scope-qualified dotted path from a MemberExpression.
// Resolves the root Identifier via scopeInfo, keeps the rest as property chain.
// E.g., a.b.c where a resolves to "3:a" → "3:a.b.c"
function _scopeQualifyMemberExpr(node, ctx, env) {
  if (!node) return null;
  if (node.type === 'Identifier') return _resolveObjKey(node, ctx, env);
  if (node.type === 'ThisExpression') return 'this';
  if (node.type === 'NewExpression') {
    if (node.callee?.type === 'Identifier') return resolveId(node.callee, ctx.scopeInfo);
    return _scopeQualifyMemberExpr(node.callee, ctx);
  }
  // Literals — return their string representation
  if (node.type === 'StringLiteral' || (node.type === 'Literal' && typeof node.value === 'string')) return node.value;
  if (node.type === 'NumericLiteral' || (node.type === 'Literal' && typeof node.value === 'number')) return String(node.value);
  // Unwrap parenthesized expressions
  if (node.type === 'ParenthesizedExpression') return _scopeQualifyMemberExpr(node.expression, ctx, env);
  // MemberExpression / OptionalMemberExpression — scope-qualify the chain
  if (node.type !== 'MemberExpression' && node.type !== 'OptionalMemberExpression') return null;
  const prop = node.computed ? null : (node.property?.name || node.property?.value || node.property?.id?.name);
  if (!prop) return null;
  const objKey = _scopeQualifyMemberExpr(node.object, ctx, env);
  if (!objKey) return null;
  if (node.object.type === 'NewExpression') return `${objKey}#${prop}`;
  return `${objKey}.${prop}`;
}

// Strip scope prefix from a key: "3:eval" → "eval", "global:document.write" → "document.write"
// Used for matching against external APIs (sinks, sources, sanitizers) that use bare names.
function _stripScopePrefix(key) {
  if (!key) return key;
  const colon = key.indexOf(':');
  if (colon === -1) return key;
  const prefix = key.slice(0, colon);
  if (prefix === 'global' || /^\d+$/.test(prefix)) return key.slice(colon + 1);
  return key;
}

/**
 * Infer the JavaScript typeof string for an AST node.
 * Returns a Set of possible types, or null if unknown.
 * Uses AST node types for literals and IDL data for browser API return types.
 */
function _inferType(node, env, ctx) {
  if (!node) return null;
  switch (node.type) {
    case 'StringLiteral':
    case 'TemplateLiteral':
      return new Set(['string']);
    case 'NumericLiteral':
      return new Set(['number']);
    case 'BooleanLiteral':
      return new Set(['boolean']);
    case 'NullLiteral':
      return new Set(['object']); // typeof null === "object"
    case 'BigIntLiteral':
      return new Set(['bigint']);
    case 'ObjectExpression':
    case 'ArrayExpression':
      return new Set(['object']);
    case 'FunctionExpression':
    case 'ArrowFunctionExpression':
      return new Set(['function']);
    case 'RegExpLiteral':
      return new Set(['object']);
    case 'UnaryExpression':
      if (node.operator === 'void') return new Set(['undefined']);
      if (node.operator === 'typeof') return new Set(['string']); // typeof always returns string
      if (node.operator === '!' || node.operator === 'delete') return new Set(['boolean']);
      return null;
    case 'BinaryExpression':
      if (node.operator === '+') {
        // string + anything = string, number + number = number
        const lt = _inferType(node.left, env, ctx);
        const rt = _inferType(node.right, env, ctx);
        if (lt?.has('string') || rt?.has('string')) return new Set(['string']);
        if (lt?.has('number') && rt?.has('number')) return new Set(['number']);
      }
      if (['<', '>', '<=', '>=', '==', '===', '!=', '!==', 'in', 'instanceof'].includes(node.operator))
        return new Set(['boolean']);
      if (['-', '*', '/', '%', '**', '|', '&', '^', '<<', '>>', '>>>'].includes(node.operator))
        return new Set(['number']);
      return null;
    case 'LogicalExpression': {
      // a || b → type of the non-falsy branch. a && b → type of b if a is truthy.
      // a ?? b → type of both (either could be the result).
      const lt = _inferType(node.left, env, ctx);
      const rt = _inferType(node.right, env, ctx);
      if (node.operator === '||') {
        // || returns first truthy: if both are same type, that type. Otherwise union.
        if (lt && rt) { const u = new Set([...lt, ...rt]); return u; }
        return lt || rt;
      }
      if (node.operator === '&&') {
        // && returns last if both truthy: type of RHS
        return rt || lt;
      }
      // ?? returns either side
      if (lt && rt) { const u = new Set([...lt, ...rt]); return u; }
      return lt || rt;
    }
    case 'ConditionalExpression': {
      const ct = _inferType(node.consequent, env, ctx);
      const at = _inferType(node.alternate, env, ctx);
      if (ct && at) { const u = new Set([...ct, ...at]); return u; }
      return ct || at;
    }
    case 'NewExpression':
      return new Set(['object']); // new always returns object
    case 'CallExpression': {
      // Resolve return type from ecma-builtins.js METHOD_RETURN_TYPES and Chromium IDL typeIndex.
      // Handles: Math.round() → number, str.split() → array, document.createElement() → object
      if (node.callee?.type === 'MemberExpression' || node.callee?.type === 'OptionalMemberExpression') {
        const prop = node.callee.property?.name || node.callee.property?.value;
        if (prop) {
          const objName = node.callee.object?.type === 'Identifier' ? node.callee.object.name : null;
          // Check METHOD_RETURN_TYPES: Object.method or Object.prototype.method
          if (objName) {
            const staticKey = `${objName}.${prop}`;
            if (METHOD_RETURN_TYPES[staticKey]) {
              const rt = METHOD_RETURN_TYPES[staticKey];
              return new Set([rt === 'array' ? 'object' : rt]);
            }
          }
          // Check prototype methods: str.split() → String.prototype.split
          const protoKeys = [
            `String.prototype.${prop}`, `Array.prototype.${prop}`,
            `Number.prototype.${prop}`, `Object.prototype.${prop}`,
            `RegExp.prototype.${prop}`, `Date.prototype.${prop}`,
            `Map.prototype.${prop}`, `Set.prototype.${prop}`,
            `Promise.prototype.${prop}`,
          ];
          for (const pk of protoKeys) {
            if (METHOD_RETURN_TYPES[pk]) {
              const rt = METHOD_RETURN_TYPES[pk];
              return new Set([rt === 'array' ? 'object' : rt]);
            }
          }
        }
      }
      // Global function calls: parseInt(), parseFloat(), etc.
      if (node.callee?.type === 'Identifier') {
        const rt = METHOD_RETURN_TYPES[node.callee.name];
        if (rt) return new Set([rt === 'array' ? 'object' : rt]);
        // Aliased calls: resolve through scope chain
        if (ctx) {
          const identity = resolveCalleeIdentity(node.callee, env, ctx);
          if (identity && METHOD_RETURN_TYPES[identity]) {
            const rt2 = METHOD_RETURN_TYPES[identity];
            return new Set([rt2 === 'array' ? 'object' : rt2]);
          }
        }
      }
      return null;
    }
    case 'Identifier': {
      // Check knownTypes from prior typeof checks
      if (ctx && env) {
        const key = resolveId(node, ctx.scopeInfo);
        const known = env.knownTypes.get(key);
        if (known && known.size > 0) return new Set(known);
      }
      // undefined
      if (node.name === 'undefined') return new Set(['undefined']);
      return null;
    }
    case 'MemberExpression':
    case 'OptionalMemberExpression': {
      const prop = !node.computed ? (node.property?.name || node.property?.value) : null;
      if (prop) {
        // Check PROPERTY_TYPES from ecma-builtins.js (Math.PI → number, etc.)
        if (node.object?.type === 'Identifier') {
          const key = `${node.object.name}.${prop}`;
          if (PROPERTY_TYPES[key]) return new Set([PROPERTY_TYPES[key]]);
        }
        // Check Chromium IDL typeIndex via scope-qualified object key
        if (ctx) {
          const objKey = _stripScopePrefix(_scopeQualifyMemberExpr(node.object, ctx) || '');
          // DOM string properties (DOMString/USVString in IDL)
          if (objKey === 'location' && ['hash', 'href', 'pathname', 'search', 'origin',
              'protocol', 'host', 'hostname', 'port', 'username', 'password'].includes(prop))
            return new Set(['string']);
          if (objKey === 'document' && ['title', 'cookie', 'domain', 'referrer', 'URL',
              'documentURI', 'readyState'].includes(prop))
            return new Set(['string']);
        }
        // Common DOM properties by name (spec-stable, not library-specific)
        if (prop === 'textContent' || prop === 'innerText' || prop === 'innerHTML' ||
            prop === 'outerHTML' || prop === 'className' || prop === 'id' ||
            prop === 'tagName' || prop === 'nodeName' || prop === 'nodeValue' ||
            prop === 'value' || prop === 'name' || prop === 'type' || prop === 'src' ||
            prop === 'href' || prop === 'action' || prop === 'data')
          return new Set(['string']);
        if (prop === 'length' || prop === 'childElementCount' || prop === 'nodeType' ||
            prop === 'scrollTop' || prop === 'scrollLeft' || prop === 'clientHeight' ||
            prop === 'clientWidth' || prop === 'offsetHeight' || prop === 'offsetWidth')
          return new Set(['number']);
        if (prop === 'checked' || prop === 'disabled' || prop === 'hidden' ||
            prop === 'required' || prop === 'readOnly')
          return new Set(['boolean']);
      }
      // Check knownTypes for resolved key
      if (ctx && env) {
        const key = _scopeQualifyMemberExpr(node, ctx);
        if (key) {
          const known = env.knownTypes.get(key);
          if (known && known.size > 0) return new Set(known);
        }
      }
      return null;
    }
    default:
      return null;
  }
}

// Resolve a bare object name to its IDL interface name.
// Uses IDL naming conventions: document → Document, window → Window, etc.
const _GLOBAL_TO_INTERFACE = {
  'document': 'Document', 'window': 'Window', 'location': 'Location',
  'navigator': 'Navigator', 'history': 'History', 'screen': 'Screen',
  'self': 'Window', 'globalThis': 'Window',
};
function _resolveInterfaceName(objName) {
  // Direct global mapping
  if (_GLOBAL_TO_INTERFACE[objName]) return _GLOBAL_TO_INTERFACE[objName];
  // Already capitalized interface name (e.g., from tracked element types)
  if (objName[0] >= 'A' && objName[0] <= 'Z') return objName;
  return null;
}

// Inherit parent class methods into child class funcMap.
// Both parentName and childName are scope-qualified keys (e.g., "1:Base", "1:Child").
// Iterates funcMap entries that start with parentName# or parentName. and registers
// equivalent entries under childName, preserving the separator and method name.
function _inheritClassMethods(parentName, childName, ctx) {
  const visited = new Set();
  let current = parentName;
  while (current && !visited.has(current)) {
    visited.add(current);
    for (const sep of ['#', '.']) {
      const prefix = current + sep;
      for (const [k, v] of ctx.funcMap) {
        if (k.startsWith(prefix)) {
          const methodPart = k.slice(current.length); // e.g., "#render"
          const childKey = childName + methodPart;
          if (!ctx.funcMap.has(childKey)) {
            ctx.funcMap.set(childKey, v);
          }
        }
      }
    }
    current = ctx.superClassMap.get(current);
  }
}

// Convert a DOM property info's return type tag to an interface name
function _returnTypeToInterface(domPropInfo) {
  if (!domPropInfo) return null;
  // If tag is known (e.g., 'head' → HTMLHeadElement), convert to interface
  if (domPropInfo.tag) {
    const cap = domPropInfo.tag.charAt(0).toUpperCase() + domPropInfo.tag.slice(1);
    return 'HTML' + cap + 'Element';
  }
  // Generic Element — still useful for DOM attachment
  return null;
}

// Resolve an object reference to its scope-qualified key.
// AST Identifier nodes → scope resolution via ctx.scopeInfo.
// Strings pass through as-is (caller must already have resolved).
function _resolveObjKey(objNameOrNode, ctx, env) {
  if (typeof objNameOrNode === 'string') return objNameOrNode;
  if (objNameOrNode?.type === 'Identifier') {
    return resolveId(objNameOrNode, ctx.scopeInfo, env);
  }
  if (objNameOrNode?.type === 'ThisExpression') return 'this';
  if (objNameOrNode?.type === 'MemberExpression' || objNameOrNode?.type === 'OptionalMemberExpression') {
    return _scopeQualifyMemberExpr(objNameOrNode, ctx, env);
  }
  return '';
}

// Register a method in funcMap under its scope-qualified key ONLY.
function _registerMethod(funcMap, objNameOrNode, propName, funcNode, ctx, prefix) {
  const objKey = _resolveObjKey(objNameOrNode, ctx);
  if (!objKey) return;
  const fullKey = prefix ? `${prefix}${objKey}.${propName}` : `${objKey}.${propName}`;
  funcMap.set(fullKey, funcNode);
}

// Look up a method in funcMap by scope-qualified key ONLY.
// Walks the class inheritance chain via superClassMap if not found directly.
function _lookupMethod(funcMap, objNameOrNode, propName, ctx, prefix) {
  const objKey = _resolveObjKey(objNameOrNode, ctx);
  if (!objKey) return undefined;
  const fullKey = prefix ? `${prefix}${objKey}.${propName}` : `${objKey}.${propName}`;
  const direct = funcMap.get(fullKey);
  if (direct) return direct;

  // Walk class inheritance: if objKey ends with a class name, try parent class
  // e.g., "0:Child#render" not found → check superClassMap("Child") → "Base" → "0:Base#render"
  if (ctx?.superClassMap && fullKey.includes('#')) {
    const hashIdx = fullKey.indexOf('#');
    const classKey = fullKey.slice(0, hashIdx);
    const methodPart = fullKey.slice(hashIdx);
    // Strip scope prefix to get bare class name
    const bareClass = _stripScopePrefix(classKey);
    let parentClass = ctx.superClassMap.get(bareClass);
    const visited = new Set([bareClass]);
    while (parentClass && !visited.has(parentClass)) {
      visited.add(parentClass);
      // Try with same scope prefix as original
      const scopePrefix = classKey.slice(0, classKey.length - bareClass.length);
      const parentKey = `${scopePrefix}${parentClass}${methodPart}`;
      const parentFunc = funcMap.get(parentKey);
      if (parentFunc) return parentFunc;
      // Try global scope
      const globalKey = `global:${parentClass}${methodPart}`;
      const globalFunc = funcMap.get(globalKey);
      if (globalFunc) return globalFunc;
      // Try without scope prefix
      const bareKey = `${parentClass}${methodPart}`;
      const bareFunc = funcMap.get(bareKey);
      if (bareFunc) return bareFunc;
      // Walk further up
      parentClass = ctx.superClassMap.get(parentClass);
    }
  }

  return undefined;
}

// Add a constraint to all taint labels on a variable in the env.
// Looks up the variable by bare name and all scoped bindings (e.g., "0:varName").
function _addConstraintToVar(env, varName, constraint) {
  const suffix = `:${varName}`;
  for (const [key] of env.entries()) {
    if (key === varName || key === `global:${varName}` || key.endsWith(suffix)) {
      const taint = env.get(key);
      if (taint && taint.tainted) {
        env.set(key, taint.withConstraint(constraint));
      }
    }
  }
}

// Detect allowlist pattern: x === 'a' || x === 'b' || x === 'c'
// Returns the variable name if all operands in an || chain test the same Identifier against string literals.
function extractAllowlistVar(node) {
  // Flatten the || chain
  const comparisons = [];
  const stack = [node];
  while (stack.length > 0) {
    const n = stack.pop();
    if (n.type === 'LogicalExpression' && n.operator === '||') {
      stack.push(n.left);
      stack.push(n.right);
    } else if (n.type === 'BinaryExpression' && (n.operator === '===' || n.operator === '==')) {
      comparisons.push(n);
    } else {
      return null; // non-comparison operand → not an allowlist
    }
  }
  if (comparisons.length < 2) return null;
  let varName = null;
  for (const cmp of comparisons) {
    let identSide, litSide;
    if (cmp.left.type === 'Identifier' && isStringLiteral(cmp.right)) {
      identSide = cmp.left; litSide = cmp.right;
    } else if (cmp.right.type === 'Identifier' && isStringLiteral(cmp.left)) {
      identSide = cmp.right; litSide = cmp.left;
    } else {
      return null; // not identifier === literal
    }
    if (varName === null) varName = identSide.name;
    else if (varName !== identSide.name) return null; // different variables
  }
  return varName;
}

// Extract condition discriminant and value from a branch condition AST node.
// e.g. e.data.type === 'init' → { discriminant: 'e.data.type', propName: 'type', value: 'init' }
// Returns null if the condition isn't a simple equality check we can use for multi-step PoCs.
function extractConditionInfo(testNode, polarity, ctx) {
  let node = testNode;
  let pos = polarity;
  // Unwrap negation: !(expr) flips polarity
  while (node.type === 'UnaryExpression' && node.operator === '!') {
    pos = !pos;
    node = node.argument;
  }
  if (node.type === 'BinaryExpression') {
    const op = node.operator;
    // Handle === / == / !== / !=
    const isEq = op === '===' || op === '==';
    const isNeq = op === '!==' || op === '!=';
    if (!isEq && !isNeq) return null;
    // !== with positive polarity means the value must NOT equal
    // !== with negative polarity (inside negated branch) means it MUST equal
    const mustEqual = isEq ? pos : !pos;

    let memberSide, literalSide;
    if (isLiteral(node.right) && !isLiteral(node.left)) {
      memberSide = node.left; literalSide = node.right;
    } else if (isLiteral(node.left) && !isLiteral(node.right)) {
      memberSide = node.right; literalSide = node.left;
    } else return null;

    const discriminant = _scopeQualifyMemberExpr(memberSide, ctx);
    if (!discriminant) return null;
    // Extract the leaf property name (last part after '.')
    const parts = discriminant.split('.');
    const propName = parts[parts.length - 1];
    const value = literalSide.value;
    return { discriminant, propName, value, negated: !mustEqual };
  }
  return null;
}

function isLiteral(node) {
  return node.type === 'StringLiteral' || node.type === 'NumericLiteral' ||
    (node.type === 'Literal' && (typeof node.value === 'string' || typeof node.value === 'number'));
}

// Returns the variable name if `node` (with given polarity) represents a URL scheme check.
// Recognizes:
//   url.startsWith('http') / url.startsWith('https') / url.startsWith('/')
//   url.indexOf('http') === 0
//   url.protocol === 'http:' / 'https:'
//   url.protocol !== 'javascript:'
//   /^https?:\/\//.test(url)  /  url.match(/^https?:/)
//   url.slice(0,4) === 'http' / url.substring(0,4) === 'http'
function extractSchemeCheck(node, positive, ctx) {
  // Pattern: url.startsWith('http') or url.startsWith('https') or url.startsWith('/')
  if (node.type === 'CallExpression' && positive) {
    const callee = node.callee;
    if (callee.type === 'MemberExpression' && callee.property?.name === 'startsWith') {
      const arg = node.arguments[0];
      if (arg && isStringLiteral(arg)) {
        const val = stringLiteralValue(arg);
        if (isSafeSchemeValue(val)) {
          return _scopeQualifyMemberExpr(callee.object, ctx);
        }
      }
    }
    // Pattern: /^https?:\/\//.test(url)  or  regex.test(url)
    if (callee.type === 'MemberExpression' && callee.property?.name === 'test') {
      if (callee.object.type === 'RegExpLiteral' || callee.object.regex) {
        const pattern = callee.object.pattern || callee.object.regex?.pattern || '';
        if (isHttpSchemeRegex(pattern)) {
          const arg = node.arguments[0];
          return arg ? (_scopeQualifyMemberExpr(arg, ctx)) : null;
        }
      }
    }
    // Pattern: url.match(/^https?:/)
    if (callee.type === 'MemberExpression' && callee.property?.name === 'match') {
      const arg = node.arguments[0];
      if (arg && (arg.type === 'RegExpLiteral' || arg.regex)) {
        const pattern = arg.pattern || arg.regex?.pattern || '';
        if (isHttpSchemeRegex(pattern)) {
          return _scopeQualifyMemberExpr(callee.object, ctx);
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
        return _scopeQualifyMemberExpr(callee.object, ctx);
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
      const varSide = findProtocolMember(node.left, ctx) || findProtocolMember(node.right, ctx);
      const litSide = getStringLiteral(node.left) || getStringLiteral(node.right);
      if (varSide && litSide && isHttpProtocol(litSide)) {
        return varSide;
      }
    }

    // Pattern: url.protocol !== 'javascript:' (inequality check blocks javascript:)
    if (isNotEquals) {
      const varSide = findProtocolMember(node.left, ctx) || findProtocolMember(node.right, ctx);
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
              return _scopeQualifyMemberExpr(cc.object, ctx);
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
          return _scopeQualifyMemberExpr(cc.object, ctx);
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
// ── DRY helpers for repeated patterns ──
function isObjectProp(node) {
  return node.type === 'ObjectProperty' || node.type === 'Property';
}

function isNumericLit(node) {
  return node.type === 'NumericLiteral' || (node.type === 'Literal' && typeof node.value === 'number');
}

function isFuncExpr(node) {
  return node.type === 'ArrowFunctionExpression' || node.type === 'FunctionExpression';
}

function getNodeLoc(node) {
  return node.loc?.start || {};
}

function formatSources(taint) {
  return taint.toArray().map(l => ({
    type: l.sourceType, description: l.description, file: l.file, line: l.line,
    transforms: l.transforms.length > 0 ? l.transforms : undefined,
    sourceKey: l.sourceKey || undefined,
    stateSteps: l.stateSteps || undefined,
    constraints: l.constraints && l.constraints.length > 0 ? l.constraints : undefined,
  }));
}

// Add sink stateStep to taint labels for multi-step PoC generation.
// Handles two cases:
// 1. Same-handler multi-step: taint was stored under one condition, sink under another
// 2. Cross-handler prerequisite: branch condition depends on a variable set by a
//    different event source (hashchange, URL param, etc.)
function annotateSinkSteps(taint, ctx, env) {
  if (!taint.tainted) return taint;
  const hasStore = taint.toArray().some(l => l.stateSteps && l.stateSteps.some(s => s.action === 'store'));

  if (ctx._currentBranchCondition) {
    const cond = extractConditionInfo(ctx._currentBranchCondition.node, ctx._currentBranchCondition.polarity, ctx);
    if (cond) {
      if (hasStore) {
        // Case 1: same-handler multi-step — add sink step
        return taint.withStateStep({
          action: 'sink',
          condition: cond,
          handler: ctx._handlerContext?.type || null,
        });
      }
      // Case 2: cross-handler prerequisite — the branch condition references a
      // variable set by a different event source (hashchange, URL, storage, etc.)
      if (env && cond.discriminant) {
        const condTaint = env.get(cond.discriminant);
        if (condTaint && condTaint.tainted) {
          const condLabels = condTaint.toArray();
          const sourceType = condLabels[0]?.sourceType || 'unknown';
          return taint.withStateStep({
            action: 'prerequisite',
            condition: cond,
            sourceType,
            handler: ctx._handlerContext?.type || null,
          });
        }
      }
    }
  }
  // Timer sink step
  if (hasStore && ctx._handlerContext?.type === 'timer') {
    return taint.withStateStep({
      action: 'sink',
      handler: 'timer',
      delay: ctx._handlerContext.delay || 0,
    });
  }
  return taint;
}

// sinkClass: the IDL/TrustedType classification that determines what payload format the sink accepts.
// Values: 'TrustedHTML' (innerHTML), 'TrustedScript' (eval/Function), 'TrustedScriptURL' (script.src),
//         'navigation' (location.href), null (unclassified)
function makeSinkInfo(expression, ctx, loc, sinkClass) {
  const line = loc.line || 0;
  const col = loc.column || 0;
  const file = ctx._sinkFile || ctx.file;
  const fingerprint = `${file}:${line}:${col}:${expression}`;
  const info = { expression, file, line, col, fingerprint };
  if (sinkClass) info.sinkClass = sinkClass;
  return info;
}

function getSeverity(type) {
  return type === 'Open Redirect' ? 'high' : (type === 'XSS' ? 'critical' : 'high');
}

function resolveInitFromScope(identNode, ctx) {
  if (identNode.type === 'Identifier' && ctx.scopeInfo) {
    const bindingKey = ctx.scopeInfo.resolve(identNode);
    if (bindingKey) {
      const declNode = ctx.scopeInfo.bindingNodes.get(bindingKey);
      if (declNode?.type === 'VariableDeclarator' && declNode.init) return declNode.init;
    }
  }
  return null;
}
// Resolve an identifier to its constant string value if possible
// Uses scope info to find the variable's binding and check if it's a string literal


// Check if an AST node contains a reference to a specific identifier name
function _containsIdentifier(node, name) {
  if (!node || typeof node !== 'object') return false;
  if (node.type === 'Identifier' && node.name === name) return true;
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'start' || key === 'end') continue;
    const child = node[key];
    if (Array.isArray(child)) { for (const c of child) if (_containsIdentifier(c, name)) return true; }
    else if (child && typeof child === 'object' && child.type && _containsIdentifier(child, name)) return true;
  }
  return false;
}

// ── Abstract Value System ──
// Tracks both TYPE and VALUE through the analysis. Replaces the binary
// "concrete value or UNRESOLVED" with a three-level lattice:
//   1. Concrete: type + value known (e.g., {type:'number', value:3, concrete:true})
//   2. Type-only: type known, value not (e.g., {type:'object', value:undefined, concrete:false})
//   3. Unknown: neither type nor value ({type:null, value:undefined, concrete:false})
//
// This enables: typeof folding when value is unknown but type is tracked,
// loop counter convergence that preserves type, and prototype-aware resolution.
function AV(type, value) { return { type, value, concrete: true }; }
function AVType(type) { return { type, value: undefined, concrete: false }; }
const AV_UNKNOWN = Object.freeze({ type: null, value: undefined, concrete: false });

// Resolve an AST node to an AbstractValue. Always returns an AV — never raw JS values.
function resolveAbstract(node, _env, ctx, _visited) {
  if (!node) return AV_UNKNOWN;
  // Try concrete resolution first
  const concrete = _resolveConcreteInner(node, _env, ctx, _visited);
  if (concrete !== _NO_CONCRETE) {
    return AV(typeof concrete, concrete);
  }
  // Concrete resolution failed — try type inference from AST
  const types = _inferType(node, _env, ctx);
  if (types && types.size === 1) return AVType([...types][0]);
  // Check knownTypes for identifiers (populated by processAssignment from _inferType)
  if (node.type === 'Identifier' && ctx?.scopeInfo) {
    const key = resolveId(node, ctx.scopeInfo);
    const known = _env?.knownTypes?.get(key);
    if (known && known.size === 1) return AVType([...known][0]);
    // Also follow init chain for type inference
    const _initNode = resolveInitFromScope(node, ctx);
    if (_initNode) {
      const initTypes = _inferType(_initNode, _env, ctx);
      if (initTypes && initTypes.size === 1) return AVType([...initTypes][0]);
    }
  }
  if (types && types.size > 0) return { type: null, value: undefined, concrete: false, possibleTypes: types };
  return AV_UNKNOWN;
}

// Local reference to PURE_FUNCTIONS for use in _resolveConcreteInner
const _PURE_FUNCTIONS = PURE_FUNCTIONS;

// _NO_CONCRETE: internal sentinel for the concrete value resolution chain.
// Never exposed publicly — all external code uses resolveAbstract() which returns AbstractValue.
const _NO_CONCRETE = Symbol('_NO_CONCRETE');

// Legacy aliases — will be fully removed once _resolveConcreteInner is cleaned up.
// These exist only because _resolveConcreteInner and resolveConstantLeaf use them internally.
const UNRESOLVED = _NO_CONCRETE;
function isResolved(val) { return val !== _NO_CONCRETE; }

// Internal: extract concrete JS value from resolveAbstract. Returns _NO_CONCRETE if not concrete.
// Used by _resolveConcreteInner's recursive calls and resolveConstantLeaf's delegation.
function resolveToConstant(node, _env, ctx, _visited) {
  if (!node) return _NO_CONCRETE;
  return _resolveConcreteInner(node, _env, ctx, _visited);
}
function _resolveConcreteInner(node, _env, ctx, _visited) {
  if (!node) return _NO_CONCRETE;
  // Prevent infinite recursion from mutual init chain cycles (a→b.init→a.init→...)
  if (!_visited) _visited = new Set();
  if (_visited.has(node)) return UNRESOLVED;
  _visited.add(node);
  // BinaryExpression '+': flatten chain into leaves, resolve each iteratively
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const l = resolveToConstant(node.left, _env, ctx, _visited);
    const r = resolveToConstant(node.right, _env, ctx, _visited);
    if (!isResolved(l) || !isResolved(r)) return UNRESOLVED;
    // JS semantics: number + number → arithmetic, otherwise string concatenation
    if (typeof l === 'number' && typeof r === 'number') return l + r;
    return String(l) + String(r);
  }
  // Arithmetic: -, *, /, %, |, &, ^, <<, >>, >>>
  if (node.type === 'BinaryExpression' && /^[-*/%|&^]|<<|>>>?$/.test(node.operator)) {
    const l = resolveToConstant(node.left, _env, ctx, _visited);
    const r = resolveToConstant(node.right, _env, ctx, _visited);
    if (typeof l === 'number' && typeof r === 'number') {
      switch (node.operator) {
        case '-': return l - r;
        case '*': return l * r;
        case '/': return r !== 0 ? l / r : undefined;
        case '%': return r !== 0 ? l % r : undefined;
        case '|': return l | r;
        case '&': return l & r;
        case '^': return l ^ r;
        case '<<': return l << r;
        case '>>': return l >> r;
        case '>>>': return l >>> r;
      }
    }
    return UNRESOLVED;
  }
  // typeof expression: resolve to constant type string for known globals
  if (node.type === 'UnaryExpression' && node.operator === 'typeof') {
    const argType = _resolveTypeofResult(node.argument, _env, ctx);
    if (argType) return argType;
    return UNRESOLVED;
  }
  // Pure function execution: deterministic functions from ecma-builtins.js PURE_FUNCTIONS map.
  // When all arguments resolve to concrete values, execute the function and return the result.
  // Handles: Math.max(3,5)→5, parseInt("42")→42, JSON.parse('{"a":1}')→{a:1}, etc.
  // Also handles aliased calls: Li = Math.max → Li(a, b) executed as Math.max(a, b)
  if (node.type === 'CallExpression' && node.arguments) {
    let calleeId = null;
    if (node.callee?.type === 'MemberExpression' &&
        node.callee.object?.type === 'Identifier' && !node.callee.computed &&
        node.callee.property?.type === 'Identifier') {
      calleeId = `${node.callee.object.name}.${node.callee.property.name}`;
    } else if (node.callee?.type === 'Identifier') {
      // Direct global call or aliased: parseInt(...), Li(...)
      const identity = resolveCalleeIdentity(node.callee, _env, ctx);
      calleeId = identity || node.callee.name;
    }
    if (calleeId) {
      const pureFn = _PURE_FUNCTIONS[calleeId];
      if (pureFn) {
        const args = node.arguments.map(a => resolveToConstant(a, _env, ctx));
        if (args.every(a => a !== _NO_CONCRETE)) {
          try { return pureFn(...args); } catch { /* non-pure edge case — skip */ }
        }
      }
    }
  }
  // ConditionalExpression: cond ? A : B — resolve condition, then chosen branch
  if (node.type === 'ConditionalExpression') {
    const condVal = resolveToConstant(node.test, _env, ctx, _visited);
    if (condVal === true || condVal === false) {
      return resolveToConstant(condVal ? node.consequent : node.alternate, _env, ctx);
    }
    // Also try isConstantBool for complex boolean expressions
    const condBool = isConstantBool(node.test, ctx);
    if (condBool === true || condBool === false) {
      return resolveToConstant(condBool ? node.consequent : node.alternate, _env, ctx);
    }
    return UNRESOLVED;
  }
  // Comparison operators: ==, ===, !=, !==
  if (node.type === 'BinaryExpression' && (node.operator === '==' || node.operator === '===' ||
      node.operator === '!=' || node.operator === '!==')) {
    const l = resolveToConstant(node.left, _env, ctx, _visited);
    const r = resolveToConstant(node.right, _env, ctx, _visited);
    if (globalThis._TAINT_DEBUG && node.right?.name === 'mn') {
      console.log(`[RTC-EQ] null==mn: l=${l} (${typeof l}) r=${r !== undefined ? String(r).slice(0,30) : 'UNDEF'} (${typeof r}) paramConst=${ctx?._paramConstants?.has('mn')} localConst=${ctx?._localConstants?.has('mn')}`);
    }
    if (isResolved(l) && isResolved(r)) {
      const strict = node.operator === '===' || node.operator === '!==';
      const eq = strict ? l === r : l == r;
      return (node.operator === '!=' || node.operator === '!==') ? !eq : eq;
    }
    return UNRESOLVED;
  }
  // LogicalExpression: a || b, a && b, a ?? b — resolve when operands are constants
  if (node.type === 'LogicalExpression') {
    const l = resolveToConstant(node.left, _env, ctx, _visited);
    if (node.operator === '||') {
      if (isResolved(l) && l) return l; // truthy LHS → short-circuit
      if (isResolved(l) && !l) return resolveToConstant(node.right, _env, ctx, _visited); // falsy LHS → RHS
    } else if (node.operator === '&&') {
      if (isResolved(l) && !l) return l; // falsy LHS → short-circuit
      if (isResolved(l) && l) return resolveToConstant(node.right, _env, ctx, _visited); // truthy LHS → RHS
    } else if (node.operator === '??') {
      if (isResolved(l) && l != null) return l; // non-nullish LHS → short-circuit
      if (isResolved(l) && l == null) return resolveToConstant(node.right, _env, ctx, _visited); // nullish → RHS
    }
    return UNRESOLVED;
  }
  // ConditionalExpression: cond ? a : b — resolve when condition is constant
  if (node.type === 'ConditionalExpression') {
    const cond = resolveToConstant(node.test, _env, ctx, _visited);
    if (isResolved(cond)) {
      return cond ? resolveToConstant(node.consequent, _env, ctx, _visited)
                  : resolveToConstant(node.alternate, _env, ctx, _visited);
    }
    return UNRESOLVED;
  }
  // UnaryExpression: !x, -x, +x, ~x
  if (node.type === 'UnaryExpression') {
    if (node.operator === '!') {
      const arg = resolveToConstant(node.argument, _env, ctx, _visited);
      if (isResolved(arg)) return !arg;
    }
    if (node.operator === '-') {
      const arg = resolveToConstant(node.argument, _env, ctx, _visited);
      if (isResolved(arg) && typeof arg === 'number') return -arg;
    }
    if (node.operator === '+') {
      const arg = resolveToConstant(node.argument, _env, ctx, _visited);
      if (isResolved(arg)) return +arg;
    }
    if (node.operator === '~') {
      const arg = resolveToConstant(node.argument, _env, ctx, _visited);
      if (isResolved(arg) && typeof arg === 'number') return ~arg;
    }
    if (node.operator === 'void') return undefined;
    return UNRESOLVED;
  }
  // MemberExpression: resolve arguments[N] and obj.prop via _localConstants
  if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
    // Computed: arguments[0], arr[idx]
    if (node.computed) {
      const idx = resolveToConstant(node.property, _env, ctx, _visited);
      if (isResolved(idx) && node.object?.type === 'Identifier') {
        const key = node.object.name + '.' + idx;
        if (ctx?._localConstants?.has(key)) return ctx._localConstants.get(key);
        // Check scope-qualified key
        const scopedKey = resolveId(node.object, ctx.scopeInfo) + '.' + idx;
        if (ctx?._localConstants?.has(scopedKey)) return ctx._localConstants.get(scopedKey);
      }
    }
    // Non-computed: obj.length, arguments.length
    if (!node.computed && node.property?.name) {
      if (node.object?.type === 'Identifier') {
        const key = node.object.name + '.' + node.property.name;
        if (ctx?._localConstants?.has(key)) return ctx._localConstants.get(key);
        const scopedKey = resolveId(node.object, ctx.scopeInfo) + '.' + node.property.name;
        if (ctx?._localConstants?.has(scopedKey)) return ctx._localConstants.get(scopedKey);
      }
    }
  }
  return resolveConstantLeaf(node, _env, ctx, _visited);
}

// Resolve typeof to a constant type string using the abstract value system.
// Uses resolveAbstract to get type information even when concrete value is unknown.
function _resolveTypeofResult(argNode, _env, ctx) {
  if (!argNode) return UNRESOLVED;
  // Use resolveAbstract — it checks concrete values, _inferType, knownTypes, and init chains.
  // For CONCRETE values (av.concrete=true), the typeof is always correct.
  // For TYPE-ONLY values (av.concrete=false), the type is inferred from the AST/knownTypes.
  // Don't fold type-only results for TAINTED variables — the attacker controls the value
  // and typeof guards like "typeof x === 'object'" are runtime checks that must be preserved.
  const av = resolveAbstract(argNode, _env, ctx);
  if (av.concrete) return av.type;
  if (av.type && argNode.type === 'Identifier' && _env) {
    const _taintKey = ctx?.scopeInfo ? resolveId(argNode, ctx.scopeInfo) : null;
    if (_taintKey && _env.get(_taintKey)?.tainted) return UNRESOLVED; // tainted — don't fold typeof
  }
  if (av.type) return av.type;
  // For identifiers: check runtime globals and undeclared identifiers
  if (argNode.type === 'Identifier') {
    const identity = resolveCalleeIdentity(argNode, _env, ctx);
    if (identity) return _runtimeGlobalTypeof(identity);
    // Undeclared identifier in browser context → typeof is "undefined"
    if (ctx?.scopeInfo) {
      const _binding = ctx.scopeInfo.resolve(argNode);
      if (!_binding || _binding === `global:${argNode.name}`) {
        if (_RUNTIME_GLOBALS.has(argNode.name)) return _runtimeGlobalTypeof(argNode.name);
        return 'undefined';
      }
    }
  }
  // MemberExpression: typeof arguments[0]
  if (argNode.type === 'MemberExpression' || argNode.type === 'OptionalMemberExpression') {
    // resolveAbstract already handled this, but check concrete fallback
    const constVal = resolveToConstant(argNode, _env, ctx);
    if (isResolved(constVal)) return typeof constVal;
  }
  return UNRESOLVED;
}

// Runtime globals that are typeof "object" (not "function")
// Browser-context globals with typeof === "object".
// Does NOT include 'global' (Node.js-only) — typeof global === "undefined" in browser.
const _TYPEOF_OBJECT_GLOBALS = new Set([
  'window', 'self', 'globalThis',
  'document', 'navigator', 'location', 'console', 'performance', 'crypto',
  'localStorage', 'sessionStorage', 'history', 'screen',
  'JSON', 'Math', 'Reflect',
]);

// Return the typeof result for a known runtime global identity
function _runtimeGlobalTypeof(identity) {
  if (_TYPEOF_OBJECT_GLOBALS.has(identity)) return 'object';
  if (_RUNTIME_GLOBALS.has(identity)) return 'function';
  return UNRESOLVED;
}
// Iterative leaf resolver: follows Identifier → declaration init chains without recursion
function resolveConstantLeaf(node, _env, ctx, _visited) {
  let cur = node;
  while (cur) {
    if (!cur) return UNRESOLVED;
    if (isStringLiteral(cur)) return cur.value;
    if (isNumericLit(cur)) return cur.value;
    if (cur.type === 'BooleanLiteral' || (cur.type === 'Literal' && typeof cur.value === 'boolean')) return cur.value;
    if (cur.type === 'NullLiteral' || (cur.type === 'Literal' && cur.value === null)) return null;
    if (cur.type === 'Identifier') {
      const _lcKey = resolveId(cur, ctx.scopeInfo);
      // Local constants (loop counter values from unrolling) take precedence over mutation tracking
      if (ctx?._localConstants?.has(_lcKey)) {
        return ctx._localConstants.get(_lcKey);
      }
      if (ctx?._paramConstants?.has(cur.name)) {
        return ctx._paramConstants.get(cur.name);
      }
      if (ctx?._paramConstants?.has(_lcKey)) {
        return ctx._paramConstants.get(_lcKey);
      }
      // Param not passed at call site → deterministically undefined
      if (ctx?._undefinedParams?.has(cur.name) || ctx?._undefinedParams?.has(_lcKey)) {
        return undefined;
      }
      // _mutatedVars check removed — env.constants (updated by processAssignment routing
      // for UpdateExpression) is the source of truth for variable values. When i++ fires,
      // processAssignment stores the new value (i = old+1) in env.constants.
      // On back-edge re-evaluation, the _prevConst !== _assignConst check in processAssignment
      // detects changing values and marks them as UNRESOLVED.
      // env.constants stores AbstractValue objects: {type, value, concrete}.
      // Concrete AVs → return the value. Type-only AVs → return UNRESOLVED (no concrete value).
      // No entry → not yet processed, follow init chain for lazy resolution.
      if (_env?.constants?.has(_lcKey)) {
        const _av = _env.constants.get(_lcKey);
        if (_av?.concrete) return _av.value;
        return UNRESOLVED; // type-only or unknown — no concrete value
      }
      if (_env?.constants?.has(cur.name)) {
        const _av = _env.constants.get(cur.name);
        if (_av?.concrete) return _av.value;
        return UNRESOLVED;
      }
      const _init = resolveInitFromScope(cur, ctx);
      if (_init) {
        // If the init is a complex expression, delegate to resolveToConstant.
        // Only for expression types that can't be followed as a leaf (LogicalExpression etc.)
        // but NOT BinaryExpression (already handled) or MemberExpression (handled in leaf).
        if (_init.type === 'LogicalExpression' || _init.type === 'ConditionalExpression' ||
            _init.type === 'UnaryExpression') {
          return resolveToConstant(_init, _env, ctx, _visited);
        }
        cur = _init; continue;
      }
      // Uninitialized declaration: var T; → T is undefined (JS semantics)
      if (ctx?.scopeInfo) {
        const _bk = ctx.scopeInfo.resolve(cur);
        if (_bk) {
          const _dn = ctx.scopeInfo.bindingNodes.get(_bk);
          if (_dn?.type === 'VariableDeclarator' && !_dn.init) return undefined;
        }
      }
      return UNRESOLVED;
    }
    // MemberExpression computed: arr[i] where arr has per-index constants from Object.keys
    if (cur.type === 'MemberExpression' && cur.computed && ctx?._arrayIndexConstants) {
      const arrKey = cur.object?.type === 'Identifier' ? cur.object.name : null;
      const scopedArrKey = cur.object?.type === 'Identifier' ? resolveId(cur.object, ctx.scopeInfo) : null;
      const idxVal = resolveConstantLeaf(cur.property, _env, ctx);
      if (arrKey != null && typeof idxVal === 'number') {
        const val = ctx._arrayIndexConstants.get(`${scopedArrKey}:${idxVal}`)
          || ctx._arrayIndexConstants.get(`${arrKey}:${idxVal}`);
        if (isResolved(val)) return val;
      }
    }
    // MemberExpression: handle func.length for function references
    if (cur.type === 'MemberExpression' && !cur.computed &&
        cur.property?.name === 'length' && cur.object?.type === 'Identifier') {
      const objName = cur.object.name;
      // Check _paramArgNames first (parameter→arg name mapping from call site)
      const resolvedObjName = ctx?._paramArgNames?.get(objName) || objName;
      const scopedObjName = resolveId(cur.object, ctx.scopeInfo);
      const funcNode = ctx?.funcMap?.get(scopedObjName) || ctx?.funcMap?.get(resolvedObjName) || ctx?.funcMap?.get(objName);
      if (funcNode?.params) return funcNode.params.length;
      // Check string/array length via _paramConstants
      const constVal = ctx?._paramConstants?.get(objName);
      if (typeof constVal === 'string') return constVal.length;
      // Check _localConstants for array length from Object.keys
      const lcVal = ctx?._localConstants?.get(`${objName}.length`);
      if (typeof lcVal === 'number') return lcVal;
      const scopedName = resolveId(cur.object, ctx.scopeInfo);
      const lcVal2 = ctx?._localConstants?.get(`${scopedName}.length`);
      if (typeof lcVal2 === 'number') return lcVal2;
      // Array initializer: var arr = [a, b, c] → arr.length = 3
      if (ctx?.scopeInfo) {
        const _arrInit = resolveInitFromScope(cur.object, ctx);
        if (_arrInit?.type === 'ArrayExpression') return _arrInit.elements.length;
      }
    }
    return UNRESOLVED;
  }
  return UNRESOLVED;
}

// Resolve the root identifier in a dotted path through env.aliases
// e.g., "w.location.hash" where w→window becomes "window.location.hash"
function resolveAliasedPath(path, env) {
  if (!path) return path;
  const dotIdx = path.indexOf('.');
  const root = dotIdx === -1 ? path : path.slice(0, dotIdx);
  const alias = env.getAlias ? env.getAlias(root) : env.aliases.get(root);
  if (!alias || alias === root) return path;
  const resolved = dotIdx === -1 ? alias : `${alias}${path.slice(dotIdx)}`;
  // Global scope objects: window.X.Y → X.Y (window.location.hash → location.hash)
  if (_GLOBAL_SCOPE_OBJECTS.has(alias) && dotIdx !== -1) {
    return path.slice(dotIdx + 1);
  }
  return resolved;
}

// Global scope objects — accessing a property on these is equivalent to accessing the global directly.
// window.Object === Object, self.Array === Array, etc.
const _GLOBAL_SCOPE_OBJECTS = new Set(['window', 'self', 'globalThis']);

// Browser runtime globals — objects and constructors that exist in browser JS environments.
// Does NOT include 'global' (Node.js-only) — undeclared in browser context.
const _RUNTIME_GLOBALS = new Set([
  // Global scope references (browser)
  'window', 'self', 'globalThis',
  // Constructors / namespaces
  'Object', 'Array', 'Function', 'String', 'Number', 'Boolean', 'Symbol',
  'RegExp', 'Date', 'Map', 'Set', 'WeakMap', 'WeakSet', 'Promise', 'Proxy',
  'Reflect', 'JSON', 'Math', 'Error', 'TypeError', 'RangeError', 'SyntaxError',
  'ArrayBuffer', 'DataView', 'Int8Array', 'Uint8Array', 'Float32Array', 'Float64Array',
  // DOM / Web APIs
  'document', 'navigator', 'location', 'console', 'performance', 'crypto',
  'localStorage', 'sessionStorage', 'history', 'screen',
  // Functions
  'eval', 'parseInt', 'parseFloat', 'isNaN', 'isFinite',
  'encodeURIComponent', 'decodeURIComponent', 'encodeURI', 'decodeURI',
  'atob', 'btoa', 'setTimeout', 'setInterval', 'fetch',
  'alert', 'confirm', 'prompt', 'requestAnimationFrame', 'queueMicrotask', 'structuredClone',
]);

// Resolve an identifier's callee identity by following assignment/scope chains.
// Returns a canonical callee string (e.g., "Object", "Object.defineProperty") or null.
// This traces through: Identifier → init expression → MemberExpression → object resolution
// enabling interprocedural resolution of aliased builtins like Qu = mn.Object → "Object".
function resolveCalleeIdentity(node, env, ctx, _visited) {
  if (!node) return null;
  // Cycle detection: track visited AST nodes to prevent infinite loops
  // when alias chains form cycles (e.g., a = b, b = a).
  if (!_visited) _visited = new Set();
  if (_visited.has(node)) return null;
  _visited.add(node);

  // In sloppy mode (non-module scripts), top-level `this` IS the global object.
  // UMD libraries use (function(root){...})(this) to pass the global context.
  if (node.type === 'ThisExpression') return 'window';

  if (node.type === 'Identifier') {
    // Check alias first
    const alias = env?.getAlias ? env.getAlias(resolveId(node, ctx.scopeInfo)) : env?.aliases?.get(resolveId(node, ctx.scopeInfo));
    if (globalThis._TAINT_DEBUG && node.name === '$n') console.log(`[RCI-ID] $n alias=${alias} visited=${_visited.size}`);
    if (alias) return alias;
    // Known runtime globals — these exist in every JS environment and resolve to themselves.
    // This is the JS runtime's API surface, not pattern matching.
    if (_RUNTIME_GLOBALS.has(node.name)) return node.name;
    // Follow scope to init expression
    const init = resolveInitFromScope(node, ctx);
    if (globalThis._TRACE_RESOLVE && (node.name === 'Mn' || node.name === 'Tn' || node.name === '$n' || node.name === 'mn' || node.name === 'Qu')) {
      console.log('[RESOLVE]', node.name, 'init=', init?.type, 'scopeInfo=', !!ctx.scopeInfo);
    }
    if (init) return resolveCalleeIdentity(init, env, ctx, _visited);
    return null;
  }

  if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
    if (node.computed) return null;
    const propName = node.property?.name;
    if (!propName) return null;
    // Resolve the object to its identity
    const objIdentity = resolveCalleeIdentity(node.object, env, ctx, _visited);
    if (objIdentity) {
      // When the object is a global scope reference (window, self, globalThis, global),
      // accessing a property is the same as accessing the global directly.
      // window.Object === Object, self.Array === Array, etc.
      if (_GLOBAL_SCOPE_OBJECTS.has(objIdentity)) {
        // Check if the property is itself a known global
        if (_RUNTIME_GLOBALS.has(propName)) return propName;
        // Otherwise return the full path
        return `${objIdentity}.${propName}`;
      }
      return `${objIdentity}.${propName}`;
    }
    return null;
  }

  // LogicalExpression ||: A || B — try resolving each branch
  if (node.type === 'LogicalExpression' && node.operator === '||') {
    if (globalThis._TRACE_RESOLVE) console.log('[RCI-OR] visited=', _visited.size, 'left=', node.left.type, node.left.name||'', 'right=', node.right.type);
    const left = resolveCalleeIdentity(node.left, env, ctx, _visited);
    if (left) return left;
    return resolveCalleeIdentity(node.right, env, ctx, _visited);
  }

  // LogicalExpression &&: A && B — value is the RHS only if LHS is truthy.
  // If LHS is provably false (e.g., typeof global == "object" in browser), short-circuit to null.
  if (node.type === 'LogicalExpression' && node.operator === '&&') {
    const lhsBool = isConstantBool(node.left, ctx, env);
    if (lhsBool === false) return null; // LHS is false → && short-circuits, value is falsy
    return resolveCalleeIdentity(node.right, env, ctx, _visited);
  }

  // ConditionalExpression: cond ? A : B — try to resolve condition, otherwise try both
  if (node.type === 'ConditionalExpression') {
    const condBool = isConstantBool(node.test, ctx);
    if (globalThis._TAINT_DEBUG && (node.consequent?.name === '$n' || node.alternate?.name === '$n')) {
      console.log(`[RCI-COND] visited=${_visited.size} condBool=${condBool} test=${node.test?.type}/${node.test?.operator||''} cons=${node.consequent?.name||node.consequent?.type} alt=${node.alternate?.name||node.alternate?.type}`);
    }
    if (condBool === true) return resolveCalleeIdentity(node.consequent, env, ctx, _visited);
    if (condBool === false) return resolveCalleeIdentity(node.alternate, env, ctx, _visited);
    // Unknown condition: try both, prefer consequent
    return resolveCalleeIdentity(node.consequent, env, ctx, _visited) ||
           resolveCalleeIdentity(node.alternate, env, ctx, _visited);
  }

  // AssignmentExpression: a = expr — the value is the RHS
  if (node.type === 'AssignmentExpression' && node.operator === '=') {
    return resolveCalleeIdentity(node.right, env, ctx, _visited);
  }

  // CallExpression: Function("return this")() → global scope
  if (node.type === 'CallExpression' && node.callee?.type === 'CallExpression') {
    const innerCallee = resolveCalleeIdentity(node.callee.callee, env, ctx, _visited);
    if (innerCallee === 'Function' && node.callee.arguments?.length > 0) {
      const bodyArg = node.callee.arguments[node.callee.arguments.length - 1];
      if (isStringLiteral(bodyArg)) {
        const bodyStr = stringLiteralValue(bodyArg).trim();
        // Parse body with Babel and check if it returns `this`
        const parsed = parseFunctionConstructor(node.callee.arguments);
        if (parsed?.body?.body?.length === 1 &&
            parsed.body.body[0].type === 'ReturnStatement' &&
            parsed.body.body[0].argument?.type === 'ThisExpression') {
          return 'window'; // Function("return this")() in sloppy mode = global scope
        }
      }
    }
  }

  return null;
}

// Parse a string literal body from Function(bodyStr) into a synthetic function AST node.
// Returns a FunctionExpression node or null if parsing fails.
function parseFunctionConstructor(args) {
  if (!args || args.length === 0) return null;
  // Extract string values: Function(body) or Function(param1, param2, ..., body)
  const strArgs = [];
  for (const arg of args) {
    if (isStringLiteral(arg)) strArgs.push(stringLiteralValue(arg));
    else return null; // non-constant arg, can't parse
  }
  const bodyStr = strArgs[strArgs.length - 1];
  const paramStrs = strArgs.slice(0, -1);
  try {
    const ast = babelParse(`(function(${paramStrs.join(',')}) { ${bodyStr} })`, {
      sourceType: 'unambiguous',
      plugins: ['optionalChaining', 'nullishCoalescingOperator'],
      errorRecovery: true,
    });
    const expr = ast.program.body[0]?.expression;
    if (expr && expr.type === 'FunctionExpression') return expr;
  } catch (_) { /* parsing failed */ }
  return null;
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
function isConstantBoolLeaf(node, ctx, env) {
  // Iterative: loop follows Identifier → declaration init chains
  let cur = node;
  const _visited = new Set();
  while (cur) {
    if (cur.type === 'BooleanLiteral') return cur.value;
    if (cur.type === 'Literal' && typeof cur.value === 'boolean') return cur.value;
    if (isNumericLit(cur))
      return cur.value !== 0;
    if (cur.type === 'StringLiteral' || (cur.type === 'Literal' && typeof cur.value === 'string'))
      return cur.value !== '';
    if (cur.type === 'NullLiteral' || (cur.type === 'Literal' && cur.value === null)) return false;
    if (cur.type === 'Identifier' && cur.name === 'undefined') return false;
    // BinaryExpression comparison: typeof X == "object", etc.
    if (cur.type === 'BinaryExpression' && (cur.operator === '==' || cur.operator === '===' ||
        cur.operator === '!=' || cur.operator === '!==')) {
      const _av = resolveAbstract(cur, env, ctx);
      if (_av.concrete && typeof _av.value === 'boolean') return _av.value;
      return null;
    }
    // UnaryExpression !: negate the argument
    if (cur.type === 'UnaryExpression' && cur.operator === '!') {
      const argBool = isConstantBoolLeaf(cur.argument, ctx, env);
      if (argBool !== null) return !argBool;
      return null;
    }
    if (cur.type === 'Identifier' && ctx.scopeInfo && !_visited.has(cur)) {
      _visited.add(cur);
      const bindingKey = ctx.scopeInfo.resolve(cur);
      if (bindingKey) {
        const declNode = ctx.scopeInfo.bindingNodes.get(bindingKey);
        if (declNode?.type === 'VariableDeclarator' && declNode.init) {
          cur = declNode.init;
          continue;
        }
      }
    }
    // Tainted values are source strings (e.g., location.hash, postMessage.data).
    // Source strings are always non-empty → truthy. If the variable is tainted
    // in the env, resolve as truthy for short-circuit evaluation.
    if (env && (cur.type === 'Identifier' || cur.type === 'MemberExpression')) {
      let taint = null;
      if (cur.type === 'Identifier') {
        const key = resolveId(cur, ctx.scopeInfo);
        taint = env.get(key);
      } else {
        // MemberExpression: obj.prop — check if the dotted path is tainted
        const path = _scopeQualifyMemberExpr(cur, ctx);
        if (path) taint = env.get(path);
        // Also check if the base object is tainted (obj.anything is truthy if obj is tainted string)
        if (!taint?.tainted && cur.object?.type === 'Identifier') {
          taint = env.get(resolveId(cur.object, ctx.scopeInfo));
        }
      }
      if (taint?.tainted) return true;
    }
    return null;
  }
  return null;
}
function isConstantBool(node, ctx, env) {
  if (!node) return null;
  if (node.type !== 'LogicalExpression') return isConstantBoolLeaf(node, ctx, env);
  // Fully iterative: frame stack for nested LogicalExpression evaluation
  // Each frame: { work: [{op, node}], idx: number, result: bool|null }
  const frames = [];
  let cur = node;

  for (;;) {
    // Flatten left spine of current LogicalExpression into work array
    const work = [];
    while (cur.type === 'LogicalExpression') {
      work.push({ op: cur.operator, node: cur.right });
      cur = cur.left;
    }
    frames.push({ work, idx: work.length - 1, result: isConstantBoolLeaf(cur, ctx, env) });

    processFrames:
    while (frames.length > 0) {
      const frame = frames[frames.length - 1];

      while (frame.idx >= 0) {
        const { op, node: rhs } = frame.work[frame.idx];
        // Short-circuit logic
        if (op === '||') {
          if (frame.result === true) { frame.idx = -1; break; }
          if (frame.result === null) { frame.idx = -1; frame.result = null; break; }
        } else if (op === '&&') {
          if (frame.result === false) { frame.idx = -1; break; }
          if (frame.result === null) { frame.idx = -1; frame.result = null; break; }
        } else if (op === '??') {
          if (frame.result !== null && frame.result !== undefined) { frame.idx--; continue; }
          frame.idx = -1; frame.result = null; break;
        }
        frame.idx--;
        // If rhs is a nested LogicalExpression, push new frame and descend
        if (rhs.type === 'LogicalExpression') {
          cur = rhs;
          break processFrames;
        }
        frame.result = isConstantBoolLeaf(rhs, ctx, env);
      }

      // Frame done — pop and feed result to parent
      const doneResult = frames.pop().result;
      if (frames.length === 0) return doneResult;
      frames[frames.length - 1].result = doneResult;
    }
  }
}
function findProtocolMember(node, ctx) {
  // Returns the scope-qualified base object key if node is X.protocol
  if (node?.type === 'MemberExpression' && node.property?.name === 'protocol') {
    return _scopeQualifyMemberExpr(node.object, ctx);
  }
  return null;
}
// Detect if a function is a type predicate (type guard).
// A type predicate function has a single return statement whose value is a typeof comparison.
// e.g., function isObject(a) { return typeof a === "object" && a !== null; }
// Tags the function node with _typePredicate = { paramIndex, type, negated }
function _detectTypePredicate(funcNode) {
  if (funcNode._typePredicate !== undefined) return; // already checked
  funcNode._typePredicate = null;
  if (!funcNode.body?.body || !funcNode.params?.length) return;
  // Must have exactly one meaningful statement (return)
  const stmts = funcNode.body.body.filter(s => s.type !== 'EmptyStatement');
  if (stmts.length !== 1 || stmts[0].type !== 'ReturnStatement' || !stmts[0].argument) return;
  const ret = stmts[0].argument;
  // Extract typeof comparison from return expression
  // Handles: typeof a === "object", "object" === typeof a
  // Also handles: typeof a === "object" && a !== null (conjunction with null check)
  const _extractTypeofCheck = (expr) => {
    if (expr.type === 'BinaryExpression' && (expr.operator === '===' || expr.operator === '==')) {
      let typeofNode = null, typeStr = null;
      if (expr.left.type === 'UnaryExpression' && expr.left.operator === 'typeof' && isStringLiteral(expr.right)) {
        typeofNode = expr.left.argument; typeStr = stringLiteralValue(expr.right);
      } else if (expr.right.type === 'UnaryExpression' && expr.right.operator === 'typeof' && isStringLiteral(expr.left)) {
        typeofNode = expr.right.argument; typeStr = stringLiteralValue(expr.left);
      }
      if (typeofNode?.type === 'Identifier' && typeStr) {
        // Find which parameter this is
        for (let i = 0; i < funcNode.params.length; i++) {
          if (funcNode.params[i].type === 'Identifier' && funcNode.params[i].name === typeofNode.name) {
            return { paramIndex: i, type: typeStr };
          }
        }
      }
    }
    return null;
  };
  // Direct typeof comparison
  let pred = _extractTypeofCheck(ret);
  if (pred) { funcNode._typePredicate = pred; return; }
  // Conjunction: typeof a === "object" && a !== null
  if (ret.type === 'LogicalExpression' && ret.operator === '&&') {
    pred = _extractTypeofCheck(ret.left) || _extractTypeofCheck(ret.right);
    if (pred) { funcNode._typePredicate = pred; return; }
  }
  // Negated: typeof a !== "object" (returns true when NOT that type)
  if (ret.type === 'BinaryExpression' && (ret.operator === '!==' || ret.operator === '!=')) {
    let typeofNode = null, typeStr = null;
    if (ret.left.type === 'UnaryExpression' && ret.left.operator === 'typeof' && isStringLiteral(ret.right)) {
      typeofNode = ret.left.argument; typeStr = stringLiteralValue(ret.right);
    } else if (ret.right.type === 'UnaryExpression' && ret.right.operator === 'typeof' && isStringLiteral(ret.left)) {
      typeofNode = ret.right.argument; typeStr = stringLiteralValue(ret.left);
    }
    if (typeofNode?.type === 'Identifier' && typeStr) {
      for (let i = 0; i < funcNode.params.length; i++) {
        if (funcNode.params[i].type === 'Identifier' && funcNode.params[i].name === typeofNode.name) {
          funcNode._typePredicate = { paramIndex: i, type: typeStr, negated: true };
          return;
        }
      }
    }
  }
}

function processNode(node, env, ctx) {
  if (!node) return;

  switch (node.type) {
    case 'VariableDeclarator':
      processVarDeclarator(node, env, ctx);
      break;

    case 'AssignmentExpression':
      if (globalThis._TAINT_DEBUG && node.left?.name === 'mn' && node.right?.type === 'ConditionalExpression') {
        const test = node.right.test;
        console.log(`[PROCESS-NODE] mn test: type=${test.type} op=${test.operator} left=${test.left?.type}/${test.left?.value} right=${test.right?.type}/${test.right?.name}`);
        // Try resolveToConstant on each side
        const _lAV = resolveAbstract(test.left, null, ctx);
        const _rAV = resolveAbstract(test.right, null, ctx);
        console.log(`[PROCESS-NODE] mn test resolveAbstract: left=${_lAV.value} (${typeof _lAV.value}) right=${_rAV.value} (${typeof _rAV.value})`);
        const _cb = isConstantBool(test, ctx);
        console.log(`[PROCESS-NODE] mn test condBool=${_cb}`);
      }
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
        // For SequenceExpression (comma operator), the effective return value is the last expression
        // but we must evaluate the FULL expression for side effects (e.g., An.merge=Sf, An)
        const effectiveReturn = (arg.type === 'SequenceExpression' && arg.expressions?.length > 0)
          ? arg.expressions[arg.expressions.length - 1] : arg;
        // Track returned objects with function-valued properties (module pattern)
        // Must be done BEFORE evaluateExpr to capture the object structure
        // Extract methods from the returned value — handles ObjectExpression directly
        // or Identifier that resolves to an ObjectExpression via scope init.
        let _returnedObjExpr = null;
        if (arg.type === 'ObjectExpression') {
          _returnedObjExpr = arg;
        } else if (effectiveReturn.type === 'Identifier') {
          const _init = resolveInitFromScope(effectiveReturn, ctx);
          if (_init?.type === 'ObjectExpression') _returnedObjExpr = _init;
          // If the Identifier has methods registered in funcMap (from a prior
          // assignment like Yr = factoryCall({...methods...})), collect them
          // and propagate as returnedMethods so the caller receives them.
          if (!_returnedObjExpr) {
            const _scopedName = resolveId(effectiveReturn, ctx.scopeInfo);
            const _prefixes = [`${_scopedName}.`];
            if (_scopedName !== effectiveReturn.name) _prefixes.push(`${effectiveReturn.name}.`);
            // Follow alias chain: if the returned var aliases to another name (e.g., Yr → arguments.#idx_0),
            // include aliased prefixes so methods registered under the alias are captured.
            const _retAlias = env.getAlias ? env.getAlias(_scopedName) : env.aliases?.get(_scopedName);
            if (_retAlias && _retAlias !== _scopedName) _prefixes.push(`${_retAlias}.`);
            const _methods = {};
            for (const [key, val] of ctx.funcMap) {
              for (const _prefix of _prefixes) {
                if (typeof key === 'string' && key.startsWith(_prefix) && !key.includes('.', _prefix.length)) {
                  _methods[key.slice(_prefix.length)] = val;
                  break;
                }
              }
            }
            if (Object.keys(_methods).length > 0) ctx.returnedMethods = _methods;
          }
        }
        if (_returnedObjExpr) {
          const methods = {};
          for (const prop of _returnedObjExpr.properties) {
            if (isObjectProp(prop) &&
                prop.key && (prop.key.type === 'Identifier' || prop.key.type === 'StringLiteral')) {
              const name = propKeyName(prop.key);
              const val = prop.value;
              if (val && (val.type === 'FunctionExpression' || val.type === 'ArrowFunctionExpression')) {
                val._closureEnv = env;
                methods[name] = val;
              }
              if (val && val.type === 'Identifier') {
                const refKey = resolveId(val, ctx.scopeInfo);
                const refFunc = ctx.funcMap.get(refKey);
                if (refFunc) {
                  if (!refFunc._closureEnv) refFunc._closureEnv = env;
                  methods[name] = refFunc;
                }
              }
            }
            if (prop.type === 'ObjectMethod' && prop.key) {
              const name = propKeyName(prop.key);
              prop._closureEnv = env;
              methods[name] = prop;
            }
          }
          if (Object.keys(methods).length > 0) ctx.returnedMethods = methods;
        }
        // If ObjectExpression had no methods, try funcMap scan (methods added via assignment)
        if (!ctx.returnedMethods && effectiveReturn.type === 'Identifier') {
          const _scopedName2 = resolveId(effectiveReturn, ctx.scopeInfo);
          const _prefixes2 = [`${_scopedName2}.`];
          if (_scopedName2 !== effectiveReturn.name) _prefixes2.push(`${effectiveReturn.name}.`);
          const _methods2 = {};
          for (const [key, val] of ctx.funcMap) {
            for (const _prefix of _prefixes2) {
              if (typeof key === 'string' && key.startsWith(_prefix) && !key.includes('.', _prefix.length)) {
                _methods2[key.slice(_prefix.length)] = val;
                break;
              }
            }
          }
          if (Object.keys(_methods2).length > 0) ctx.returnedMethods = _methods2;
        }
        // Propagate _objectKeysVars data for returned arrays (e.g., keys() function returns array of property names)
        // Save the returned variable key for deferred resolution at finalization.
        // The worklist may process the return block before the loop body's push block
        // sets _objectKeysVars. Saving the key allows finalization to resolve later.
        {
          let _retKeysNode = effectiveReturn;
          if (_retKeysNode.type === 'CallExpression' && _retKeysNode.callee?.type === 'MemberExpression' &&
              _retKeysNode.callee.object?.type === 'Identifier') {
            _retKeysNode = _retKeysNode.callee.object;
          }
          if (_retKeysNode.type === 'Identifier') {
            const retKey = resolveId(_retKeysNode, ctx.scopeInfo);
            ctx._returnedVarKey = retKey;
            if (ctx._objectKeysVars) {
              const keysData = ctx._objectKeysVars.get(retKey);
              if (keysData) ctx._returnedObjectKeysData = keysData;
            }
          }
        }
        // Evaluate the full return expression for side effects and taint.
        // Save returnedMethods/returnedFuncNode before evaluateExpr — the return
        // expression may contain assignments (e.g., return Yr._=Yr, Yr) whose
        // processAssignment clears these values.
        const _savedReturnedMethods = ctx.returnedMethods;
        const _savedReturnedFuncNode = ctx.returnedFuncNode;
        const _savedReturnedObjKeysData = ctx._returnedObjectKeysData;
        let _retExprTaint = evaluateExpr(arg, env, ctx);
        if (_savedReturnedMethods && !ctx.returnedMethods) ctx.returnedMethods = _savedReturnedMethods;
        if (_savedReturnedFuncNode && !ctx.returnedFuncNode) ctx.returnedFuncNode = _savedReturnedFuncNode;
        if (_savedReturnedObjKeysData && !ctx._returnedObjectKeysData) ctx._returnedObjectKeysData = _savedReturnedObjKeysData;
        if (_retExprTaint.tainted && env._branchConstraints.length > 0) {
          for (const c of env._branchConstraints) {
            _retExprTaint = _retExprTaint.withConstraint(c);
          }
        }
        ctx.returnTaint.merge(_retExprTaint);
        // Track per-element taints for array returns: return [expr1, expr2, ...]
        if (arg.type === 'ArrayExpression' && arg.elements.length > 0) {
          ctx.returnElementTaints = arg.elements.map(e => e ? evaluateExpr(e, env, ctx) : TaintSet.empty());
        }
        // When returning an Identifier that has per-index taints (e.g., return args
        // where args is an array variable), propagate those per-index taints so the
        // caller can access elements of the returned value.
        if (effectiveReturn.type === 'Identifier' && !ctx.returnElementTaints) {
          const retName = resolveId(effectiveReturn, ctx.scopeInfo);
          const retPerIdx = env.getTaintedWithPrefix(`${retName}.#idx_`);
          if (retPerIdx.size > 0) {
            const elemTaints = [];
            for (const [key, taint] of retPerIdx) {
              const m = key.match(/\.#idx_(\d+)$/);
              if (m) elemTaints[parseInt(m[1])] = taint;
            }
            if (elemTaints.length > 0) ctx.returnElementTaints = elemTaints;
          }
        }
        // return this (or return alias_of_this) → propagate this.* properties and methods
        const _isReturnThis = effectiveReturn.type === 'ThisExpression' ||
          (effectiveReturn.type === 'Identifier' && ctx._thisAliases?.has(resolveId(effectiveReturn, ctx.scopeInfo)));
        if (_isReturnThis) {
          const thisPropTaints = new Map();
          for (const [key, taint] of env.entries()) {
            if (key.startsWith('this.') && key.length > 5) {
              thisPropTaints.set(key.slice(5), taint);
            }
          }
          if (thisPropTaints.size > 0) ctx.returnPropertyTaints = thisPropTaints;
          // Carry methods so chained calls (e.g., .set().build()) can resolve
          const thisMethods = {};
          for (const [key, val] of ctx.funcMap) {
            if (key.startsWith('this.') && key.length > 5) {
              thisMethods[key.slice(5)] = val;
            }
          }
          if (Object.keys(thisMethods).length > 0 && !ctx.returnedMethods) {
            ctx.returnedMethods = thisMethods;
          }
        }
        // Track per-property taints for object returns: return { a: tainted, b: safe }
        if (arg.type === 'ObjectExpression' && arg.properties.length > 0) {
          const propTaints = new Map();
          for (const prop of arg.properties) {
            if (isObjectProp(prop) && prop.key) {
              const pName = propKeyName(prop.key);
              if (pName) propTaints.set(pName, evaluateExpr(prop.value, env, ctx));
            }
          }
          if (propTaints.size > 0) ctx.returnPropertyTaints = propTaints;
        }
        // Track returned function nodes AFTER evaluateExpr so that SequenceExpression
        // side effects (which clear returnedFuncNode via processAssignment) don't
        // clobber the value. The funcMap is fully populated after evaluateExpr.
        // Only create Object.create wrappers inside interprocedural analysis (IP stack),
        // where the same function can be returned from multiple calls with different closures.
        // At the top level, direct mutation is safe since there's no re-use concern.
        if (isFuncExpr(effectiveReturn)) {
          if (ctx._ipStack) {
            const wrapper = Object.create(effectiveReturn);
            wrapper._closureEnv = env;
            // The wrapper's closure funcMap must include BOTH the outer scope's entries
            // (ctx.funcMap) AND the inner function's closure bindings (e.g., 312:n → Yt).
            // Fork the inner funcMap and layer the outer scope on top via COW parent chain.
            const innerCfm = effectiveReturn._closureFuncMap;
            if (innerCfm && innerCfm !== ctx.funcMap && innerCfm.fork) {
              const merged = innerCfm.fork();
              // Add outer scope entries that aren't in the inner funcMap
              const outerEntries = ctx.funcMap.newEntries ? ctx.funcMap.newEntries() : ctx.funcMap;
              for (const [k, v] of outerEntries) merged.set(k, v);
              wrapper._closureFuncMap = merged;
            } else {
              wrapper._closureFuncMap = ctx.funcMap;
            }
            wrapper._closureScopeInfo = ctx.scopeInfo;
            wrapper._wrapperId = ++_wrapperIdCounter;
            if (ctx._paramArgNames) wrapper._closureParamArgNames = ctx._paramArgNames;
            // Store closure env/funcMap on the AST node so re-wrapped functions inherit it.
            if (!effectiveReturn.hasOwnProperty('_closureEnv')) {
              effectiveReturn._closureEnv = env;
            }
            if (!effectiveReturn.hasOwnProperty('_closureFuncMap')) {
              effectiveReturn._closureFuncMap = ctx.funcMap;
            }
            ctx.returnedFuncNode = wrapper;
            if (globalThis._TAINT_DEBUG && effectiveReturn.params?.length === 0) {
              const entries = [];
              for (const [k, v] of ctx.funcMap) {
                if (k === 't' || k === 'n' || k.endsWith(':t') || k.endsWith(':n')) {
                  entries.push(`${k}→${v?.id?.name||v?.type||'?'}(${v?.params?.length||'?'})`);
                }
              }
              console.log(`[RET-FUNCEXPR-0PARAM] wrapperId=${wrapper._wrapperId} proto=${Object.getPrototypeOf(effectiveReturn)?._wrapperId||'ast'} funcMap t/n entries: ${entries.join(', ')}`);
            }
          } else {
            effectiveReturn._closureEnv = env;
            effectiveReturn._closureFuncMap = ctx.funcMap;
            effectiveReturn._closureScopeInfo = ctx.scopeInfo;
            if (ctx._localConstants?.size > 0) effectiveReturn._closureLocalConstants = new Map(ctx._localConstants);
            ctx.returnedFuncNode = effectiveReturn;
          }
        }
        if (effectiveReturn.type === 'Identifier') {
          const refKey = resolveId(effectiveReturn, ctx.scopeInfo);
          // Only fall back to bare name when resolveId returned the bare name itself
          // (no scope-aware binding). When a scope-qualified key exists, the local
          // binding (parameter/variable) shadows outer function declarations —
          // falling back to the bare name would bypass scope shadowing.
          let refFunc = ctx.funcMap.get(refKey);
          if (refFunc && refFunc.body) {
            ctx.returnedFuncNode = refFunc;
          } else {
            // The returned identifier is not a function reference.
            // Clear any stale returnedFuncNode set by sub-calls in the body,
            // which would incorrectly propagate to the caller via _finalizeFrame.
            ctx.returnedFuncNode = null;
          }
        }
        // Propagate alias through return statements
        // When returning an Identifier that has an alias (e.g., return n where n is aliased
        // to Object.defineProperty or 'self'), set _returnedBuiltinAlias so the caller registers it.
        // Also handles ternary: return cond ? aliasedVar : other
        if (!ctx._returnedBuiltinAlias) {
          const _checkReturnAlias = (node) => {
            if (node.type !== 'Identifier') return null;
            const _retKey = resolveId(node, ctx.scopeInfo);
            const alias = env.getAlias ? env.getAlias(_retKey) : env.aliases?.get(_retKey);
            return alias || null;
          };
          let retAlias = _checkReturnAlias(effectiveReturn);
          // Check ternary branches: return cond ? r : T
          if (!retAlias && effectiveReturn.type === 'ConditionalExpression') {
            retAlias = _checkReturnAlias(effectiveReturn.consequent) ||
                       _checkReturnAlias(effectiveReturn.alternate);
          }
          if (retAlias) {
            ctx._returnedBuiltinAlias = retAlias;
          }
        }
        // Propagate property aliases from returned variable
        // When `return target` where target has aliases like target.Object → Object,
        // collect them so the caller can apply them to the LHS variable
        if (effectiveReturn.type === 'Identifier') {
          const retName = effectiveReturn.name;
          const prefix = retName + '.';
          for (const [aliasKey, aliasValue] of env.aliases) {
            if (aliasKey.startsWith(prefix)) {
              if (!ctx._returnedAliases) ctx._returnedAliases = new Map();
              const suffix = aliasKey.slice(prefix.length);
              ctx._returnedAliases.set(suffix, aliasValue);
            }
          }
        }
      }
      break;

    case 'FunctionDeclaration':
      if (node.id) {
        node._closureEnv = env;
        node._closureFuncMap = ctx.funcMap;
        node._closureScopeInfo = ctx.scopeInfo;
        // Detect type predicates: function D(a) { return typeof a === "object" && a !== null }
        _detectTypePredicate(node);
        const key = resolveId(node.id, ctx.scopeInfo);
        ctx.funcMap.set(key, node);
        // Program-scope functions are visible across files — also store under global: prefix
        if (ctx.scopeInfo.isProgramScope(key)) {
          ctx.funcMap.set(`global:${node.id.name}`, node);
        }
      }
      break;

    // Register class name in env for closure mutation propagation visibility
    case 'ClassDeclaration':
      if (node.id?.type === 'Identifier') {
        env.set(resolveId(node.id, ctx.scopeInfo), TaintSet.empty());
      }
      if (node.id && node.body && node.body.body) {
        const className = resolveId(node.id, ctx.scopeInfo);
        // Store superclass reference for super() resolution
        const superName = node.superClass ? (node.superClass.type === 'Identifier' ? resolveId(node.superClass, ctx.scopeInfo) : _scopeQualifyMemberExpr(node.superClass, ctx)) : null;
        let hasConstructor = false;
        for (const member of node.body.body) {
          if (member.type !== 'ClassMethod' && member.type !== 'MethodDefinition') continue;
          let mname;
          if (member.computed && member.key) {
            const _av = resolveAbstract(member.key, env, ctx);
            if (_av.concrete && typeof _av.value === 'string') mname = _av.value;
          } else {
            mname = propKeyName(member.key);
          }
          if (!mname) continue;
          if (member.static) {
            const getterPrefix = member.kind === 'get' ? 'getter:' : '';
            ctx.funcMap.set(`${getterPrefix}${className}.${mname}`, member);
            if (!getterPrefix) {
              ctx.funcMap.set(`${className}.${mname}`, member);
            }
          } else if (mname === 'constructor') {
            hasConstructor = true;
            if (superName) {
              member._superClass = superName;
              ctx.superClassMap.set(className, superName);
            }
            member._classBody = node.body.body;
            ctx.classBodyMap.set(className, node.body.body);
            ctx.funcMap.set(className, member);
          } else {
            const getterPrefix = member.kind === 'get' ? 'getter:' : (member.kind === 'set' ? 'setter:' : '');
            ctx.funcMap.set(`${getterPrefix}${className}#${mname}`, member);
            if (getterPrefix) {
              ctx.funcMap.set(`${className}#${mname}`, member);
            }
          }
        }
        // Initialize static fields
        for (const member of node.body.body) {
          if ((member.type === 'ClassProperty' || member.type === 'PropertyDefinition') &&
              member.static && member.value && member.key) {
            const fieldName = propKeyName(member.key);
            if (fieldName) {
              const fieldTaint = evaluateExpr(member.value, env, ctx);
              env.set(`${className}.${fieldName}`, fieldTaint);
            }
          }
        }
        // For classes without explicit constructor, store a synthetic entry
        if (!hasConstructor) {
          const synthBody = [];
          if (superName) {
            synthBody.push({
              type: 'ExpressionStatement',
              expression: {
                type: 'CallExpression',
                callee: { type: 'Super' },
                arguments: [],
              },
            });
          }
          const synth = { type: 'ClassMethod', key: { name: 'constructor' },
            params: [{ type: 'RestElement', argument: { type: 'Identifier', name: '_args' } }],
            body: { type: 'BlockStatement', body: synthBody } };
          if (superName) {
            synth._superClass = superName;
            ctx.superClassMap.set(className, superName);
          }
          synth._classBody = node.body.body;
          ctx.classBodyMap.set(className, node.body.body);
          ctx.funcMap.set(className, synth);
        }
        // Inherit parent class methods into child class
        if (superName) {
          _inheritClassMethods(superName, className, ctx);
        }
        // Program-scope classes are visible across files
        if (ctx.scopeInfo.isProgramScope(className)) {
          const globalName = `global:${node.id.name}`;
          // Mirror constructor, methods, and classBodyMap under global: prefix
          const ctor = ctx.funcMap.get(className);
          if (ctor) ctx.funcMap.set(globalName, ctor);
          ctx.classBodyMap.set(globalName, node.body.body);
          if (superName) ctx.superClassMap.set(globalName, superName);
          for (const [k, v] of ctx.funcMap) {
            if (k.startsWith(className + '#') || k.startsWith(className + '.')) {
              const suffix = k.slice(className.length);
              ctx.funcMap.set(globalName + suffix, v);
            }
          }
          // Inherit parent class methods: if class Child extends Base,
          // copy Base#method → Child#method for all parent methods not overridden
          if (superName) {
            _inheritClassMethods(superName, className, ctx);
            _inheritClassMethods(superName, globalName, ctx);
          }
        }
      }
      break;

    case '_Test':
      evaluateExpr(node.test, env, ctx);
      // Bounded for-loop counter tracking: resolve the loop bound and set counter as local constant.
      // Enables deterministic resolution of arguments[i], arr[i], etc. inside loop bodies.
      if (node._forLoopCounter) {
        const counterName = node._forLoopCounter;
        const counterNode = node._forLoopCounterNode || { type: 'Identifier', name: counterName };
        const counterKey = resolveId(counterNode, ctx.scopeInfo);
        // Resolve the loop bound from the test expression.
        let boundExpr = null;
        let hasTestPrefixInc = false;
        const test = node.test;
        if (test.type === 'BinaryExpression' && (test.operator === '<' || test.operator === '<=')) {
          boundExpr = test.right;
          if (test.left.type === 'UpdateExpression' && test.left.operator === '++' && test.left.prefix &&
              test.left.argument?.type === 'Identifier' && test.left.argument.name === counterName) {
            hasTestPrefixInc = true;
          }
        } else if (test.type === 'BinaryExpression' && (test.operator === '>' || test.operator === '>=')) {
          boundExpr = test.left;
        }
        if (boundExpr) {
          const _boundAV = resolveAbstract(boundExpr, env, ctx);
          if (_boundAV.concrete && typeof _boundAV.value === 'number' && _boundAV.value >= 0 && _boundAV.value <= 32) {
            const bound = _boundAV.value;
            // Get init value: from for-loop init expression, or from env (while loop)
            let initVal;
            if (node._forLoopInit) {
              const _initAV = resolveAbstract(node._forLoopInit, env, ctx);
              if (_initAV.concrete) initVal = _initAV.value;
            } else {
              // For-loop without init or while loop: use env.constants first (captures
              // modifications like s-- before the loop), then fall back to declaration init.
              if (env.constants?.has(counterKey)) {
                const cv = env.constants.get(counterKey);
                if (cv?.concrete && typeof cv.value === 'number') initVal = cv.value;
              }
              if (initVal === undefined) {
                const _counterInit = resolveInitFromScope(counterNode, ctx);
                if (_counterInit) {
                  const _ciAV = resolveAbstract(_counterInit, env, ctx);
                  if (_ciAV.concrete) initVal = _ciAV.value;
                }
              }
            }
            if (initVal === undefined) initVal = 0;
            // Key by both counter variable AND loop identity (test node) to handle
            // reuse of the same counter in multiple loops: for(i=0;i<a;i++) ... for(i=0;i<b;i++)
            if (!ctx._forLoopCounters) ctx._forLoopCounters = new Map();
            const _loopKey = `${counterKey}@${node.loc?.start?.line || 0}:${node.loc?.start?.column || 0}`;
            let iterVal = ctx._forLoopCounters.get(_loopKey);
            if (iterVal === undefined) {
              iterVal = hasTestPrefixInc ? initVal + 1 : initVal;
            }
            if (iterVal < bound) {
              if (!ctx._localConstants) ctx._localConstants = new Map();
              ctx._localConstants.set(counterKey, iterVal);
              ctx._forLoopCounters.set(_loopKey, iterVal + 1);
              // Signal worklist to re-process successor blocks even without taint change.
              // Uses a per-loop counter to limit re-processing to the loop's iteration count.
              if (!ctx._forLoopRequeueRemaining) ctx._forLoopRequeueRemaining = new Map();
              ctx._forLoopRequeueRemaining.set(_loopKey, (bound - iterVal) * 2); // body + test per iter
              ctx._forLoopCounterActive = true;
            } else {
              ctx._forLoopCounterActive = false;
            }
          }
        }
      }
      break;

    case '_ForInOf':
      processForBinding(node, env, ctx);
      break;

    case '_CatchParam':
      // Assign taint from ThrowStatement to the catch parameter
      // Catch params are block-scoped — always shadow outer scope variables
      if (node.param) {
        const savedBlockScoped = ctx._blockScopedDecl;
        ctx._blockScopedDecl = true;
        // Always assign to catch param (even empty taint) to shadow outer vars
        assignToPattern(node.param, ctx.thrownTaint.tainted ? ctx.thrownTaint.clone() : TaintSet.empty(), env, ctx);
        // Propagate property-level taint from thrown object (e.g. err.html = tainted)
        if (ctx._thrownProperties && node.param.type === 'Identifier') {
          const catchKey = resolveId(node.param, ctx.scopeInfo);
          for (const [suffix, propTaint] of ctx._thrownProperties) {
            env.set(`${catchKey}${suffix}`, propTaint);
          }
        }
        ctx._blockScopedDecl = savedBlockScoped;
      }
      break;

    case 'ThrowStatement':
      if (node.argument) {
        const throwTaint = evaluateExpr(node.argument, env, ctx);
        if (throwTaint.tainted) {
          ctx.thrownTaint.merge(throwTaint);
        }
        // Capture property-level taint from thrown variable (e.g. err.html = location.hash; throw err;)
        if (node.argument.type === 'Identifier') {
          const thrownKey = resolveId(node.argument, ctx.scopeInfo);
          const props = new Map();
          for (const [key, taint] of env.entries()) {
            if (key.startsWith(`${thrownKey}.`) && taint.tainted) {
              props.set(key.slice(thrownKey.length), taint.clone());
            }
          }
          if (props.size > 0) {
            ctx._thrownProperties = props;
            // Also ensure catch param gets taint even if aggregate isn't tainted
            if (!throwTaint.tainted) ctx.thrownTaint.merge(throwTaint);
          }
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

    case '_WithScope': {
      // with(obj) {} — inject obj's known source properties as bare identifiers
      const withObj = _scopeQualifyMemberExpr(node.object, ctx);
      const withObjBare = _stripScopePrefix(withObj);
      if (withObjBare) {
        // Find all MEMBER_SOURCES that start with withObj + '.' and inject their property names
        for (const [sourcePath, label] of Object.entries(MEMBER_SOURCES)) {
          if (sourcePath.startsWith(withObjBare + '.')) {
            const propName = sourcePath.slice(withObjBare.length + 1);
            // Only inject simple property names (no nested dots)
            if (propName && !propName.includes('.')) {
              const loc = getNodeLoc(node);
              const taint = TaintSet.from(new TaintLabel(label, ctx.file, loc.line || 0, loc.column || 0, `with(${withObjBare}).${propName}`));
              env.set(propName, taint);
              env.set(`global:${propName}`, taint);
            }
          }
        }
        // Inject DOM property info for with(document)/with(window) etc.
        // e.g., with(document) { body.innerHTML = tainted } → body is DOM-attached
        const ifaceName = _resolveInterfaceName(withObjBare);
        if (ifaceName) {
          // Mark the with-object's variable type so member access resolves
          ctx.variableTypes.set(withObj, ifaceName);
          ctx.variableTypes.set(`global:${withObj}`, ifaceName);
          // Inject DOM-producing properties as DOM-attached bare identifiers
          // e.g., with(document) → body is DOM-attached, head has tag 'head'
          const idlData = getDOMPropertiesForInterface(ifaceName);
          if (idlData) {
            for (const [prop, info] of Object.entries(idlData)) {
              ctx.domAttached.add(prop);
              ctx.domAttached.add(`global:${prop}`);
              if (info.tag) {
                ctx.elementTypes.set(prop, info.tag);
                ctx.elementTypes.set(`global:${prop}`, info.tag);
              }
            }
          }
        }
      }
      break;
    }

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
        const _av = resolveAbstract(prop.key, env, ctx);
        if (_av.concrete && typeof _av.value === 'string') keyName = _av.value;
      }
    } else if (prop.key) {
      keyName = propKeyName(prop.key);
    }
    if (keyName) {
      const propKey = `${srcStr}.${keyName}`;
      // Use per-property taint if the binding exists (even if empty/clean)
      if (env.has(propKey)) {
        assignToPattern(prop.value, env.get(propKey), env, ctx);
      } else if (MEMBER_SOURCES[_stripScopePrefix(propKey)] || (resolvedSrc !== srcStr && MEMBER_SOURCES[`${resolvedSrc}.${keyName}`])) {
        // Destructuring from a known source: var { hash } = location → location.hash is a source
        const label = MEMBER_SOURCES[_stripScopePrefix(propKey)] || MEMBER_SOURCES[`${resolvedSrc}.${keyName}`];
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
      const srcStr = _scopeQualifyMemberExpr(prop.argument, ctx);
      if (srcStr) {
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
    if (isObjectProp(prop) && prop.key) {
      let propName;
      // Resolve computed property keys: { [varName]: tainted }
      if (prop.computed) {
        const _av = resolveAbstract(prop.key, env, ctx);
        if (_av.concrete && typeof _av.value === 'string') propName = _av.value;
      }
      if (!propName) propName = propKeyName(prop.key);
      if (propName) {
        const propTaint = evaluateExpr(prop.value, env, ctx);
        env.set(`${varName}.${propName}`, propTaint);
        // Propagate DOM attachment from property value
        // e.g., { el: document.body } → varName.el is DOM-attached
        const valKey = _scopeQualifyMemberExpr(prop.value, ctx);
        if (valKey) {
          const fullKey = `${varName}.${propName}`;
          if (ctx.domAttached.has(valKey)) ctx.domAttached.add(fullKey);
          const valTag = ctx.elementTypes.get(valKey);
          if (valTag) ctx.elementTypes.set(fullKey, valTag);
          // Check IDL: document.body → DOM-attached
          if (!ctx.domAttached.has(valKey) && prop.value.type === 'MemberExpression') {
            const stripped = _stripScopePrefix(valKey);
            const dotIdx = stripped.lastIndexOf('.');
            if (dotIdx > 0) {
              const ifaceName = _resolveInterfaceName(stripped.slice(0, dotIdx));
              if (ifaceName) {
                const domInfo = getDOMPropertyInfo(ifaceName, stripped.slice(dotIdx + 1));
                if (domInfo) {
                  ctx.domAttached.add(fullKey);
                  if (domInfo.tag) ctx.elementTypes.set(fullKey, domInfo.tag);
                }
              }
            }
          }
        }
      }
    }
  }
}

// ── Check if a node is document.createElement(tagName) and return the tag ──
// Uses AST structure walk instead of string comparison to handle aliases
function getCreateElementTag(node, env, ctx) {
  if (node.type !== 'CallExpression') return null;
  const callee = node.callee;
  if (!callee || callee.type !== 'MemberExpression' || callee.computed) return null;
  if (callee.property?.name !== 'createElement') return null;
  // Verify the object is `document` (or an alias to it)
  const obj = callee.object;
  if (obj.type === 'Identifier') {
    if (obj.name !== 'document') {
      const _ceKey = resolveId(obj, ctx.scopeInfo);
      const alias = env?.getAlias ? env.getAlias(_ceKey) : env?.aliases?.get(_ceKey);
      if (alias !== 'document') return null;
    }
  } else return null;
  const arg = node.arguments[0];
  if (arg && isStringLiteral(arg)) return stringLiteralValue(arg).toLowerCase();
  return null;
}
// Backward compat wrapper
function isCreateScriptElement(node, env) {
  return getCreateElementTag(node, env, ctx) === 'script';
}

// ── Check if a node is a DOM query (querySelector, getElementById, etc.) ──
// Returns { method, tag } where tag is extracted from selector if possible
const DOM_QUERY_METHODS = new Set(['querySelector', 'querySelectorAll', 'getElementById',
  'getElementsByClassName', 'getElementsByTagName', 'getElementsByTagNameNS']);
const VALID_HTML_TAGS = new Set(['a','abbr','address','area','article','aside','audio','b','base','bdi',
  'bdo','blockquote','body','br','button','canvas','caption','cite','code','col','colgroup','data',
  'datalist','dd','del','details','dfn','dialog','div','dl','dt','em','embed','fieldset','figcaption',
  'figure','footer','form','h1','h2','h3','h4','h5','h6','head','header','hgroup','hr','html','i',
  'iframe','img','input','ins','kbd','label','legend','li','link','main','map','mark','menu','meta',
  'meter','nav','noscript','object','ol','optgroup','option','output','p','picture','pre','progress',
  'q','rp','rt','ruby','s','samp','script','search','section','select','slot','small','source','span',
  'strong','style','sub','summary','sup','table','tbody','td','template','textarea','tfoot','th',
  'thead','time','title','tr','track','u','ul','var','video','wbr']);

function getDOMQueryInfo(node, env, ctx) {
  if (node.type !== 'CallExpression') return null;
  const callee = node.callee;
  if (!callee || callee.type !== 'MemberExpression' || callee.computed) return null;
  const method = callee.property?.name;
  if (!method || !DOM_QUERY_METHODS.has(method)) return null;
  // Object is assumed to be document or an element (callee structure already verified)

  let tag = null;
  const arg = node.arguments?.[0];
  if (arg && isStringLiteral(arg)) {
    const selector = stringLiteralValue(arg);
    if (method === 'getElementsByTagName' || method === 'getElementsByTagNameNS') {
      // getElementsByTagName('script') → tag = 'script'
      const t = selector.toLowerCase();
      if (VALID_HTML_TAGS.has(t)) tag = t;
    } else if (method === 'querySelector' || method === 'querySelectorAll') {
      // Extract leading tag name from CSS selector: 'script.external' → 'script'
      const m = selector.match(/^([a-zA-Z][a-zA-Z0-9]*)/);
      if (m) {
        const t = m[1].toLowerCase();
        if (VALID_HTML_TAGS.has(t)) tag = t;
      }
      // Also try DOM catalog: querySelector('#myId') → look up ID
      if (!tag && ctx?.domCatalog?.elements) {
        const idMatch = selector.match(/^#([a-zA-Z_][a-zA-Z0-9_-]*)/);
        if (idMatch && ctx.domCatalog.elements.has(idMatch[1])) {
          tag = ctx.domCatalog.elements.get(idMatch[1]);
        }
      }
    } else if (method === 'getElementById') {
      // Look up element ID in DOM catalog
      if (ctx?.domCatalog?.elements?.has(selector)) {
        tag = ctx.domCatalog.elements.get(selector);
      }
    }
  }
  return { method, tag, isDomAttached: true };
}

// ── Per-property propagation helper ──
// When assigning `target = source`, propagate source's per-property taints and funcMap entries
// to the target. Resolves the source expression to a prefix in env/funcMap.
function propagatePerPropertyEntries(sourceExpr, targetName, env, ctx, targetNode) {
  // Unwrap common wrapper expressions to find the meaningful source
  // LogicalExpression: arguments[0] || {} → try left side first
  if (sourceExpr.type === 'LogicalExpression') {
    propagatePerPropertyEntries(sourceExpr.left, targetName, env, ctx, targetNode);
    return;
  }
  // ConditionalExpression: cond ? a : b → try both branches
  if (sourceExpr.type === 'ConditionalExpression') {
    propagatePerPropertyEntries(sourceExpr.consequent, targetName, env, ctx, targetNode);
    propagatePerPropertyEntries(sourceExpr.alternate, targetName, env, ctx, targetNode);
    return;
  }

  // Determine the source prefix in env/funcMap
  let srcPrefix = null;
  if (sourceExpr.type === 'Identifier') {
    const name = sourceExpr.name;
    const key = resolveId(sourceExpr, ctx.scopeInfo);
    // Check if this identifier has per-property entries
    if (env.getTaintedWithPrefix(`${key}.`).size > 0) srcPrefix = key;
    else if (key !== name && env.getTaintedWithPrefix(`${name}.`).size > 0) srcPrefix = name;
  } else if (sourceExpr.type === 'MemberExpression' && sourceExpr.computed) {
    const objStr = _scopeQualifyMemberExpr(sourceExpr.object, ctx);
    if (objStr) {
      // Try constant resolution for the index
      let litKey = null;
      if (isStringLiteral(sourceExpr.property)) litKey = stringLiteralValue(sourceExpr.property);
      else if (isNumericLit(sourceExpr.property)) litKey = String(sourceExpr.property.value);
      else {
        const _av = resolveAbstract(sourceExpr.property, env, ctx);
        if (globalThis._TAINT_DEBUG && sourceExpr.property?.name === 's') {
          const _sk = resolveId(sourceExpr.property, ctx.scopeInfo);
        }
        if (_av.concrete) litKey = String(_av.value);
      }
      if (litKey !== null) {
        // Exact index: try obj.#idx_N then obj.N
        const idxPrefix = `${objStr}.#idx_${litKey}`;
        if (env.getTaintedWithPrefix(`${idxPrefix}.`).size > 0) srcPrefix = idxPrefix;
        else {
          const dotPrefix = `${objStr}.${litKey}`;
          if (env.getTaintedWithPrefix(`${dotPrefix}.`).size > 0) srcPrefix = dotPrefix;
        }
      }
      // Dynamic index on arguments: merge all arguments.#idx_N.* entries
      if (globalThis._TAINT_DEBUG && objStr === 'arguments') console.log(`[PPE-ARGS] objStr=${objStr} litKey=${litKey} targetName=${targetName} srcPrefix=${srcPrefix}`);
      if (!srcPrefix && objStr === 'arguments') {
        // Collect all per-property entries from any arguments.#idx_N.*
        const allArgProps = new Map(); // propName → taint
        const allArgFuncs = new Map(); // propName → funcNode
        for (const [key, taint] of env.entries()) {
          const m = key.match(/^arguments\.#idx_\d+\.(.+)$/);
          if (m && !m[1].startsWith('#')) {
            const propName = m[1];
            if (!allArgProps.has(propName)) allArgProps.set(propName, taint);
            else allArgProps.set(propName, allArgProps.get(propName).clone().merge(taint));
          }
        }
        for (const [key, val] of ctx.funcMap) {
          const m = key.match(/^arguments\.#idx_\d+\.(.+)$/);
          if (m) allArgFuncs.set(m[1], val);
        }
        // Propagate to target
        for (const [propName, taint] of allArgProps) {
          env.set(`${targetName}.${propName}`, taint);
        }
        for (const [propName, funcNode] of allArgFuncs) {
          ctx.funcMap.set(`${targetName}.${propName}`, funcNode);
        }
        return; // already propagated
      }
    }
  } else if (sourceExpr.type === 'MemberExpression' && !sourceExpr.computed) {
    const fullStr = _scopeQualifyMemberExpr(sourceExpr, ctx);
    if (fullStr && env.getTaintedWithPrefix(`${fullStr}.`).size > 0) srcPrefix = fullStr;
  }
  if (!srcPrefix) return;

  // Copy per-property taints
  for (const [key, taint] of env.getTaintedWithPrefix(`${srcPrefix}.`)) {
    const propName = key.slice(srcPrefix.length + 1);
    if (!propName) continue;
    // Skip internal tracking entries (#key_, #elem_) but allow per-index entries (#idx_)
    // which are needed for arguments aliasing (var u = arguments → u.#idx_0 = arguments.#idx_0)
    if (propName.startsWith('#') && !propName.startsWith('#idx_')) continue;
    env.set(`${targetName}.${propName}`, taint);
  }
  // Copy funcMap entries
  for (const [key, val] of ctx.funcMap) {
    if (key.startsWith(`${srcPrefix}.`)) {
      const propName = key.slice(srcPrefix.length + 1);
      if (propName) {
        ctx.funcMap.set(`${targetName}.${propName}`, val);
      }
    }
  }
}

// ── Variable declaration ──
function processVarDeclarator(node, env, ctx) {
  if (globalThis._TRACE_RESOLVE && node.id?.name && ['$n','Mn','Tn','mn','Qu'].includes(node.id.name)) {
    console.log('[PVD]', node.id.name, 'init=', node.init?.type);
  }
  if (!node.init) {
    // Register uninitialized var declarations so closure propagation's env.has() can find them.
    // Use scope-resolved key only (no global: prefix) to avoid overwriting existing entries.
    if (node.id?.type === 'Identifier') {
      const key = resolveId(node.id, ctx.scopeInfo);
      if (!env.has(key)) env.set(key, TaintSet.empty());
    }
    return;
  }
  ctx.returnedFuncNode = null;
  ctx.returnedMethods = null;
  ctx._blockScopedDecl = !!node._blockScoped;

  // Track `this` aliases: var a = this → mark 'a' as a this alias
  if (node.id.type === 'Identifier' && node.init && node.init.type === 'ThisExpression') {
    if (!ctx._thisAliases) ctx._thisAliases = new Set();
    ctx._thisAliases.add(resolveId(node.id, ctx.scopeInfo));
  }

  // Track variable value nodes: store the init AST node for type resolution.
  // Used by the regex constraint system and any future type-aware analysis.
  // Only store under scope-qualified key to prevent cross-scope leakage.
  if (node.id.type === 'Identifier' && node.init) {
    const valKey = resolveId(node.id, ctx.scopeInfo);
    env.setValueNode(valKey, node.init);
    // Infer and track the variable's JavaScript type from its initializer
    const inferredType = _inferType(node.init, env, ctx);
    if (inferredType && inferredType.size > 0) {
      env.knownTypes.set(valKey, inferredType);
    }
  }

  // Register function expressions in funcMap so they can be called later
  if (node.id.type === 'Identifier' && node.init &&
      (node.init.type === 'FunctionExpression' || node.init.type === 'ArrowFunctionExpression')) {
    node.init._closureEnv = env;
    node.init._closureFuncMap = ctx.funcMap;
    node.init._closureScopeInfo = ctx.scopeInfo;
    const key = resolveId(node.id, ctx.scopeInfo);
    ctx.funcMap.set(key, node.init);
    if (ctx.scopeInfo.isProgramScope(key)) {
      ctx.funcMap.set(`global:${node.id.name}`, node.init);
    }
  }
  // Register function-valued properties from object literals: var obj = { render: function(){} }
  // Also recurses into nested objects: var obj = { inner: { getData: function(){} } }
  if (node.id.type === 'Identifier' && node.init && node.init.type === 'ObjectExpression') {
    const scopePrefix = resolveId(node.id, ctx.scopeInfo);
    const romStack = [{objExpr: node.init, prefix: scopePrefix}];
    while (romStack.length > 0) {
      const {objExpr, prefix} = romStack.pop();
      for (const prop of objExpr.properties) {
        if (isObjectProp(prop) && prop.key) {
          let propName;
          if (prop.computed) {
            const _av = resolveAbstract(prop.key, env, ctx);
            if (_av.concrete && typeof _av.value === 'string') propName = _av.value;
          }
          if (!propName) propName = propKeyName(prop.key);
          const val = prop.value;
          if (propName && val && (val.type === 'FunctionExpression' || val.type === 'ArrowFunctionExpression')) {
            val._closureEnv = env;
            val._closureFuncMap = ctx.funcMap;
            ctx.funcMap.set(`${prefix}.${propName}`, val);
          }
          if (propName && val && val.type === 'Identifier') {
            const refKey = resolveId(val, ctx.scopeInfo);
            const refFunc = ctx.funcMap.get(refKey);
            if (refFunc) {
              ctx.funcMap.set(`${prefix}.${propName}`, refFunc);
            }
          }
          if (propName && val && val.type === 'ObjectExpression') {
            romStack.push({objExpr: val, prefix: `${prefix}.${propName}`});
          }
        }
        if (prop.type === 'ObjectMethod' && prop.key) {
          let propName;
          if (prop.computed) {
            const _av = resolveAbstract(prop.key, env, ctx);
            if (_av.concrete && typeof _av.value === 'string') propName = _av.value;
          }
          if (!propName) propName = propKeyName(prop.key);
          if (propName) {
            prop._closureEnv = env;
            prop._closureFuncMap = ctx.funcMap;
            const accessorPrefix = prop.kind === 'get' ? 'getter:' : (prop.kind === 'set' ? 'setter:' : '');
            ctx.funcMap.set(`${accessorPrefix}${prefix}.${propName}`, prop);
            if (accessorPrefix) {
              ctx.funcMap.set(`${prefix}.${propName}`, prop);
            }
          }
        }
      }
    }
    // Mirror program-scope object methods under global: prefix for cross-file access
    if (ctx.scopeInfo.isProgramScope(scopePrefix)) {
      const globalPrefix = `global:${node.id.name}`;
      for (const [k, v] of ctx.funcMap) {
        if (k.startsWith(scopePrefix + '.')) {
          const suffix = k.slice(scopePrefix.length);
          ctx.funcMap.set(globalPrefix + suffix, v);
        }
      }
    }
  }

  // Alias: var fn = existingFunc — register the alias in funcMap
  if (node.id.type === 'Identifier' && node.init.type === 'Identifier') {
    const refKey = resolveId(node.init, ctx.scopeInfo);
    const refFunc = ctx.funcMap.get(refKey);
    if (refFunc) {
      const key = resolveId(node.id, ctx.scopeInfo);
      ctx.funcMap.set(key, refFunc);
    }
  }
  // Alias: var r = obj.render — extract method reference from funcMap
  if (node.id.type === 'Identifier' && (node.init.type === 'MemberExpression' || node.init.type === 'OptionalMemberExpression')) {
    // Resolve the member expression to a scope-qualified funcMap key
    let initStr = null;
    if (node.init.object?.type === 'Identifier' && !node.init.computed) {
      const objKey = _resolveObjKey(node.init.object, ctx);
      const prop = node.init.property?.name;
      if (objKey && prop) initStr = `${objKey}.${prop}`;
    }
    if (!initStr) initStr = _scopeQualifyMemberExpr(node.init, ctx);
    // For computed members: var handler = this.handlers[event] → resolve event to constant
    if (!initStr && node.init.computed && node.init.property) {
      const objStr = _scopeQualifyMemberExpr(node.init.object, ctx);
      const _av = resolveAbstract(node.init.property, env, ctx);
      if (objStr && _av.concrete && typeof _av.value === 'string') initStr = `${objStr}.${_av.value}`;
    }
    const refFunc = initStr && ctx.funcMap.get(initStr);
    if (refFunc) {
      const key = resolveId(node.id, ctx.scopeInfo);
      ctx.funcMap.set(key, refFunc);
    }
    // Resolve callee identity through deep scope/init chain resolution.
    // Handles: var Ai = Object.defineProperty → Ai = "Object.defineProperty"
    //          var Qu = mn.Object → Qu = "window.Object" (when mn → window)
    // Uses resolveCalleeIdentity which follows Identifier→init→MemberExpression chains.
    if (!node.init.computed) {
      const identity = resolveCalleeIdentity(node.init, env, ctx);
      if (identity) {
        env.aliases.set(resolveId(node.id, ctx.scopeInfo), identity);
        if (globalThis._TAINT_DEBUG) console.log(`[ALIAS-RESOLVED] ${resolveId(node.id, ctx.scopeInfo)} → ${identity}`);
      }
    }
  }

  // Track document.createElement element types
  if (node.id.type === 'Identifier') {
    const tag = getCreateElementTag(node.init, env, ctx);
    if (tag) {
      const key = resolveId(node.id, ctx.scopeInfo);
      ctx.elementTypes.set(key, tag);
      if (tag === 'script') {
        ctx.scriptElements.add(key);
      }
    }
    // Track DOM query results: querySelector, getElementById, etc.
    const domInfo = getDOMQueryInfo(node.init, env, ctx);
    if (domInfo) {
      const key = resolveId(node.id, ctx.scopeInfo);
      if (domInfo.isDomAttached) {
        ctx.domAttached.add(key);
      }
      if (domInfo.tag) {
        ctx.elementTypes.set(key, domInfo.tag);
        if (domInfo.tag === 'script') {
          ctx.scriptElements.add(key);
        }
      }
    }
    // Propagate element type from member access (e.g., var el = document.body)
    if (!tag && !domInfo?.tag && node.init?.type === 'MemberExpression') {
      const initStr = _scopeQualifyMemberExpr(node.init, ctx);
      if (initStr) {
        let inheritedTag = ctx.elementTypes.get(initStr);
        // Query IDL data for DOM-producing properties (e.g., Document.body → HTMLElement)
        if (!inheritedTag) {
          const stripped = _stripScopePrefix(initStr);
          const dotIdx = stripped.lastIndexOf('.');
          if (dotIdx > 0) {
            let objPart = stripped.slice(0, dotIdx);
            const propPart = stripped.slice(dotIdx + 1);
            // Resolve aliases: d → document when d is aliased
            const _objPartResolved = resolveAliasedPath(initStr.slice(0, initStr.lastIndexOf('.')), env);
            if (_objPartResolved !== initStr.slice(0, initStr.lastIndexOf('.'))) {
              objPart = _stripScopePrefix(_objPartResolved);
            }
            // Resolve the interface name from the object part
            // document → Document, window → Window
            const ifaceName = _resolveInterfaceName(objPart);
            if (ifaceName) {
              const domPropInfo = getDOMPropertyInfo(ifaceName, propPart);
              if (domPropInfo) {
                inheritedTag = domPropInfo.tag; // may be null for generic Element
                const key = resolveId(node.id, ctx.scopeInfo);
                ctx.domAttached.add(key);
                if (inheritedTag) {
                  ctx.elementTypes.set(key, inheritedTag);
                  if (inheritedTag === 'script') ctx.scriptElements.add(key);
                }
              }
            }
          }
        }
        if (inheritedTag) {
          const key = resolveId(node.id, ctx.scopeInfo);
          ctx.elementTypes.set(key, inheritedTag);
          ctx.domAttached.add(key);
          if (inheritedTag === 'script') {
            ctx.scriptElements.add(key);
          }
        }
      }
    }
    // Propagate variable types: var doc = document → doc has type Document
    if (node.init?.type === 'Identifier') {
      const initKey = resolveId(node.init, ctx.scopeInfo);
      const initType = ctx.variableTypes.get(initKey);
      if (initType) {
        const key = resolveId(node.id, ctx.scopeInfo);
        ctx.variableTypes.set(key, initType);
      }
    }
    // Propagate variable types from member access: var body = document.body
    // Use IDL to determine the return type
    if (node.init?.type === 'MemberExpression') {
      const objKey = node.init.object.type === 'Identifier' ? resolveId(node.init.object, ctx.scopeInfo) : null;
      if (objKey) {
        const objType = ctx.variableTypes.get(objKey);
        if (objType && !node.init.computed) {
          const propName = node.init.property?.name;
          if (propName) {
            const domPropInfo = getDOMPropertyInfo(objType, propName);
            if (domPropInfo?.tag) {
              // Has a specific tag — also set elementTypes
              // (already handled above, but ensure variableTypes is set)
            }
            // Set the return type as the variable's interface type
            if (domPropInfo) {
              const key = resolveId(node.id, ctx.scopeInfo);
              const returnIface = _returnTypeToInterface(domPropInfo);
              if (returnIface) ctx.variableTypes.set(key, returnIface);
            }
          }
        }
      }
    }
  }

  const taint = evaluateExpr(node.init, env, ctx);
  // If init evaluation triggered IP suspension, skip assignment — node will be re-processed
  if (ctx._ipSuspended) return;

  // For ObjectPattern destructuring, resolve per-property taint from the source
  if (node.id.type === 'ObjectPattern') {
    const srcStr = _scopeQualifyMemberExpr(node.init, ctx);
    if (srcStr) {
      assignObjectPatternFromSource(node.id, srcStr, taint, env, ctx);
    } else if (node.init.type === 'ObjectExpression') {
      // Direct destructuring from object literal: var { x = default } = { x: 'safe' }
      // Build a map of property names → taint values from the RHS literal
      const literalProps = new Map();
      for (const prop of node.init.properties) {
        if (isObjectProp(prop) && prop.key) {
          const pName = propKeyName(prop.key);
          if (pName) literalProps.set(pName, evaluateExpr(prop.value, env, ctx));
        }
      }
      for (const prop of node.id.properties) {
        if (prop.type === 'RestElement') {
          assignToPattern(prop.argument, taint, env, ctx);
          continue;
        }
        const keyName = propKeyName(prop.key);
        if (keyName && literalProps.has(keyName)) {
          // Property exists in RHS literal — use its value, skip default
          const target = prop.value.type === 'AssignmentPattern' ? prop.value.left : prop.value;
          assignToPattern(target, literalProps.get(keyName), env, ctx);
        } else {
          assignToPattern(prop.value, taint, env, ctx);
        }
      }
    } else if (ctx.returnPropertyTaints && node.id.type === 'ObjectPattern') {
      // Per-property destructuring from function call: var { a, b } = getData()
      const retProps = ctx.returnPropertyTaints;
      ctx.returnPropertyTaints = null;
      for (const prop of node.id.properties) {
        if (prop.type === 'RestElement') { assignToPattern(prop.argument, taint, env, ctx); continue; }
        const keyName = propKeyName(prop.key);
        const target = prop.value?.type === 'AssignmentPattern' ? prop.value.left : prop.value;
        if (keyName && retProps.has(keyName)) {
          assignToPattern(target, retProps.get(keyName), env, ctx);
        } else {
          assignToPattern(target || prop, taint, env, ctx);
        }
      }
    } else {
      assignToPattern(node.id, taint, env, ctx);
      // Mark definite assignment for var/let/const declarations
      if (node.id.type === 'Identifier') {
        const key = resolveId(node.id, ctx.scopeInfo);
        env.markDefinite(key);
        env.markDefinite(`global:${node.id.name}`);
        // Propagate per-element taints from function return to the variable:
        // var result = f() where f() returns an array with known per-index taints
      }
    }
  } else if (node.id.type === 'ArrayPattern' && node.init.type === 'Identifier') {
    // Array destructuring from variable: var [, b] = arr
    // Check if arr has per-element taint stored
    const srcName = resolveId(node.init, ctx.scopeInfo);
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
        // If this index has a stored value, skip AssignmentPattern default
        const hasValue = env.has(`${srcName}.#idx_${i}`);
        if (hasValue && pat.type === 'AssignmentPattern') {
          assignToPattern(pat.left, elemTaint, env, ctx);
        } else {
          assignToPattern(pat, elemTaint, env, ctx);
        }
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
      // If the array literal has a value at this index, skip defaults (AssignmentPattern)
      if (i < elems.length && elems[i] !== null) {
        const target = pat.type === 'AssignmentPattern' ? pat.left : pat;
        assignToPattern(target, elemTaints[i], env, ctx);
      } else {
        assignToPattern(pat, TaintSet.empty(), env, ctx);
      }
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
  // Propagate per-element taints from function return to the variable:
  // var result = f() where f() returns an array with known per-index taints
  if (node.id.type === 'Identifier' && ctx.returnElementTaints) {
    const key = resolveId(node.id, ctx.scopeInfo);
    const retElems = ctx.returnElementTaints;
    ctx.returnElementTaints = null;
    for (let i = 0; i < retElems.length; i++) {
      if (retElems[i]) {
        env.set(`${key}.#idx_${i}`, retElems[i]);
        env.set(`${key}.${i}`, retElems[i]);
      }
    }
  }
  // Propagate per-property taints from function return:
  // var result = f() where f() returns object with known property taints
  if (node.id.type === 'Identifier' && ctx.returnPropertyTaints) {
    const key = resolveId(node.id, ctx.scopeInfo);
    const retProps = ctx.returnPropertyTaints;
    ctx.returnPropertyTaints = null;
    for (const [propName, propTaint] of retProps) {
      env.set(`${key}.${propName}`, propTaint);
    }
  }
  // Track compile-time constant declarations: var x = constExpr
  // Must pass env for alias resolution (e.g., Li → Math.max for o = Li(u.length-r, 0))
  if (node.id.type === 'Identifier' && node.init) {
    const _constKey = resolveId(node.id, ctx.scopeInfo);
    const _constAV = resolveAbstract(node.init, env, ctx);
    if (_constAV.concrete) {
      if (!ctx._localConstants) ctx._localConstants = new Map();
      ctx._localConstants.set(_constKey, _constAV.value);
      if (!env.constants) env.constants = new Map();
      env.constants.set(_constKey, _constAV);
    }
    // Don't mark initial declarations as UNRESOLVED — resolveInitFromScope is correct
    // for initial values. Only REASSIGNMENTS need UNRESOLVED marking (done in processAssignment).
  }
  // Propagate per-property taints from Object.assign: var config = Object.assign({}, src1, src2)
  // This ensures config.html reflects the LAST source's value (safe override wins)
  if (node.init._assignPerPropertyTaints && node.id.type === 'Identifier') {
    const varKey = resolveId(node.id, ctx.scopeInfo);
    for (const [propName, pTaint] of node.init._assignPerPropertyTaints) {
      env.set(`${varKey}.${propName}`, pTaint);
    }
    node.init._assignPerPropertyTaints = null;
  }

  // Object.keys(obj): set up for-in enumeration so computed property copies
  // (target[keys[i]] = source[keys[i]]) resolve like for-in iteration
  if (node.init?._objectKeysResult && node.id.type === 'Identifier') {
    const keys = node.init._objectKeysResult;
    const sourceKey = node.init._objectKeysSource;
    // Set up _forInEnumeration keyed by the ARRAY variable name
    // When we see target[keysVar[i]] = source[keysVar[i]], the keysVar references
    // this enumeration's source and properties
    if (!ctx._objectKeysVars) ctx._objectKeysVars = new Map();
    const varKey = resolveId(node.id, ctx.scopeInfo);
    ctx._objectKeysVars.set(varKey, { sourceName: sourceKey, properties: keys });
    node.init._objectKeysResult = null;
    node.init._objectKeysSource = null;
  }

  // Propagate _returnedObjectKeysData from function calls that return arrays of known property names
  // e.g., var keys = myKeysFunction(obj) where myKeysFunction uses for-in + push
  if (ctx._returnedObjectKeysData && node.id.type === 'Identifier') {
    if (!ctx._objectKeysVars) ctx._objectKeysVars = new Map();
    const varKey = resolveId(node.id, ctx.scopeInfo);
    ctx._objectKeysVars.set(varKey, ctx._returnedObjectKeysData);
    ctx._returnedObjectKeysData = null;
  }

  registerReturnedFunctions(node.id, ctx, env);

  // Level 3: Register builtin alias from interprocedural return
  // When var n = je(Object, "defineProperty") and je returned _returnedBuiltinAlias,
  // register the alias on n so later n(...) resolves as Object.defineProperty(...)
  if (ctx._returnedBuiltinAlias && node.id.type === 'Identifier') {
    env.aliases.set(resolveId(node.id, ctx.scopeInfo), ctx._returnedBuiltinAlias);
    if (globalThis._TAINT_DEBUG) console.log(`[ALIAS-BUILTIN-L3] ${resolveId(node.id, ctx.scopeInfo)} → ${ctx._returnedBuiltinAlias} (from call return)`);
    ctx._returnedBuiltinAlias = null;
  }

  // Apply returned aliases: var mn = rt.defaults(...) → mn.Object → Object
  if (ctx._returnedAliases && node.id.type === 'Identifier') {
    const lhsKey = resolveId(node.id, ctx.scopeInfo);
    for (const [suffix, aliasValue] of ctx._returnedAliases) {
      env.aliases.set(`${lhsKey}.${suffix}`, aliasValue);
    }
    ctx._returnedAliases = null;
  }

  // Track bound built-in callee: var w = document.write.bind(document) → alias w to document.write
  if (ctx._boundCalleeStr && node.id.type === 'Identifier') {
    env.aliases.set(resolveId(node.id, ctx.scopeInfo), ctx._boundCalleeStr);
    ctx._boundCalleeStr = null;
  }

  // Track CustomEvent type: var ev = new CustomEvent('type', ...) → map ev → type
  if (ctx._pendingCustomEventType && node.id.type === 'Identifier') {
    const evName = resolveId(node.id, ctx.scopeInfo);
    if (!ctx._customEventTypes) ctx._customEventTypes = new Map();
    ctx._customEventTypes.set(evName, ctx._pendingCustomEventType);
    if (ctx._pendingCustomEventDetailTaint) {
      env.set(`${evName}.detail`, ctx._pendingCustomEventDetailTaint);
      ctx._pendingCustomEventDetailTaint = null;
    }
    ctx._pendingCustomEventType = null;
  }

  // Track Object.getOwnPropertyDescriptor result: var desc = GOPD(obj, 'x') → desc.get = getter func
  if (ctx._pendingDescriptorGetter && node.id.type === 'Identifier') {
    const descName = resolveId(node.id, ctx.scopeInfo);
    const { getter } = ctx._pendingDescriptorGetter;
    ctx.funcMap.set(`${descName}.get`, getter);
    ctx._pendingDescriptorGetter = null;
  }

  // Track aliases to known globals: var loc = location; var doc = document; etc.
  if (node.id.type === 'Identifier' && node.init.type === 'Identifier') {
    const ALIASABLE_GLOBALS = new Set(['location', 'document', 'window', 'self', 'globalThis', 'navigator', 'top', 'parent',
      'eval', 'setTimeout', 'setInterval', 'Function', 'fetch', 'atob', 'decodeURIComponent', 'decodeURI',
      'encodeURIComponent', 'encodeURI', 'parseInt', 'parseFloat', 'Number', 'Boolean', 'String', 'JSON', 'Math',
      'DOMPurify', 'structuredClone', 'queueMicrotask', 'requestAnimationFrame']);
    const initName = node.init.name;
    const idKey = resolveId(node.id, ctx.scopeInfo);
    if (ALIASABLE_GLOBALS.has(initName)) {
      env.aliases.set(idKey, initName);
    }
    // Transitive: if init is itself an alias, propagate
    const initKey = resolveId(node.init, ctx.scopeInfo);
    const existing = env.getAlias ? env.getAlias(initKey) : env.aliases.get(initKey);
    if (existing) env.aliases.set(idKey, existing);
  }
  // Detect global scope references and other identity-carrying init expressions.
  // Uses resolveCalleeIdentity to trace through || chains, && guards, ternaries, and
  // Function("return this")() IIFEs. E.g., var $n = Mn || Tn || Function("return this")() → "window"
  if (node.id.type === 'Identifier' && node.init && !node.init.computed) {
    // Only try if not already resolved by the MemberExpression handler above
    const _aliasIdKey = resolveId(node.id, ctx.scopeInfo);
    if (!env.aliases.has(_aliasIdKey)) {
      const identity = resolveCalleeIdentity(node.init, env, ctx);
      if (identity) {
        env.aliases.set(_aliasIdKey, identity);
        if (globalThis._TAINT_DEBUG) console.log(`[ALIAS-INIT] ${_aliasIdKey} → ${identity}`);
      }
    }
  }
  // Resolve constant ternary: var fn = false ? console.log : eval → alias fn to eval
  if (node.id.type === 'Identifier' && node.init.type === 'ConditionalExpression') {
    const constCond = isConstantBool(node.init.test, ctx);
    const selectedBranch = constCond === true ? node.init.consequent :
                           constCond === false ? node.init.alternate : null;
    if (selectedBranch && selectedBranch.type === 'Identifier') {
      const ALIASABLE_GLOBALS = new Set(['location', 'document', 'window', 'self', 'globalThis', 'navigator', 'top', 'parent',
        'eval', 'setTimeout', 'setInterval', 'Function', 'fetch', 'atob', 'decodeURIComponent', 'decodeURI',
        'encodeURIComponent', 'encodeURI', 'parseInt', 'parseFloat', 'Number', 'Boolean', 'String', 'JSON', 'Math',
        'DOMPurify', 'structuredClone', 'queueMicrotask', 'requestAnimationFrame']);
      const branchName = selectedBranch.name;
      const branchKey = resolveId(selectedBranch, ctx.scopeInfo);
      const branchAlias = env.aliases.get(branchKey) || branchName;
      if (ALIASABLE_GLOBALS.has(branchAlias)) {
        env.aliases.set(resolveId(node.id, ctx.scopeInfo), branchAlias);
      }
      // Also register funcMap alias if the branch is a known function
      const refFunc = ctx.funcMap.get(resolveId(selectedBranch, ctx.scopeInfo));
      if (refFunc) {
        const key = resolveId(node.id, ctx.scopeInfo);
        ctx.funcMap.set(key, refFunc);
      }
    }
    // Handle MemberExpression branches: var fn = false ? a : document.write
    if (selectedBranch && (selectedBranch.type === 'MemberExpression' || selectedBranch.type === 'OptionalMemberExpression')) {
      let branchStr = null;
      if (selectedBranch.object?.type === 'Identifier' && selectedBranch.property?.name && !selectedBranch.computed) {
        branchStr = `${_resolveObjKey(selectedBranch.object, ctx)}.${selectedBranch.property.name}`;
      }
      if (!branchStr) branchStr = _scopeQualifyMemberExpr(selectedBranch, ctx);
      if (branchStr) {
        const refFunc = ctx.funcMap.get(branchStr);
        if (refFunc) {
          const key = resolveId(node.id, ctx.scopeInfo);
          ctx.funcMap.set(key, refFunc);
        } else {
          env.aliases.set(resolveId(node.id, ctx.scopeInfo), branchStr);
        }
      }
    }
    // Handle FunctionExpression branches
    if (selectedBranch && isFuncExpr(selectedBranch)) {
      selectedBranch._closureEnv = env;
      selectedBranch._closureFuncMap = ctx.funcMap;
      const key = resolveId(node.id, ctx.scopeInfo);
      if (!ctx.funcMap.has(key)) ctx.funcMap.set(key, selectedBranch);
    }
    if (!selectedBranch) {
      const con = node.init.consequent, alt = node.init.alternate;
      const picked = isFuncExpr(alt) ? alt : isFuncExpr(con) ? con : null;
      if (picked) {
        picked._closureEnv = env;
        picked._closureFuncMap = ctx.funcMap;
        const key = resolveId(node.id, ctx.scopeInfo);
        ctx.funcMap.set(key, picked);
      }
    }
  }
  // Also: var search = location.search (MemberExpression alias)
  if (node.id.type === 'Identifier' && (node.init.type === 'MemberExpression' || node.init.type === 'OptionalMemberExpression')) {
    const prop = node.init.property?.name || node.init.property?.value;
    if (prop) {
      // var loc = window.location → alias loc to 'location'
      // var loc = document.location → alias loc to 'location'
      if (prop === 'location' && node.init.object?.type === 'Identifier') {
        const parentKey = resolveId(node.init.object, ctx.scopeInfo);
        const resolvedParent = env.aliases.get(parentKey) || node.init.object.name;
        if (resolvedParent === 'window' || resolvedParent === 'document' ||
            resolvedParent === 'self' || resolvedParent === 'globalThis') {
          env.aliases.set(resolveId(node.id, ctx.scopeInfo), 'location');
        }
      }
      const objStr = _scopeQualifyMemberExpr(node.init.object, ctx);
      const objKey = node.init.object.type === 'Identifier' ? resolveId(node.init.object, ctx.scopeInfo) : objStr;
      const resolvedObj = (objKey && env.aliases.get(objKey)) || objStr;
      if (resolvedObj !== objStr) {
        // Store the resolved path so later lookups find it
        const resolvedPath = `${resolvedObj}.${prop}`;
        const sourceTaint = checkMemberSource({ type: 'MemberExpression', object: { type: 'Identifier', name: resolvedObj }, property: node.init.property, computed: false });
        if (sourceTaint) {
          const loc = getNodeLoc(node.init);
          const varKey = resolveId(node.id, ctx.scopeInfo);
          env.set(varKey, TaintSet.from(new TaintLabel(sourceTaint, ctx.file, loc.line || 0, loc.column || 0, resolvedPath)));
        }
      }
    }
  }

  // Store per-property taint for ObjectExpression: var obj = { a: tainted, b: safe }
  if (node.id.type === 'Identifier' && node.init.type === 'ObjectExpression') {
    storeObjectPropertyTaints(resolveId(node.id, ctx.scopeInfo), node.init, env, ctx);
  }
  // Store per-element taint for ArrayExpression: var arr = [tainted, safe]
  if (node.id.type === 'Identifier' && node.init.type === 'ArrayExpression') {
    const arrKey = resolveId(node.id, ctx.scopeInfo);
    for (let i = 0; i < node.init.elements.length; i++) {
      const elem = node.init.elements[i];
      if (elem) {
        const elemTaint = evaluateExpr(elem, env, ctx);
        env.set(`${arrKey}.#idx_${i}`, elemTaint);
      }
    }
  }

  // Store per-property taint from function returning object: var result = getConfig()
  if (node.id.type === 'Identifier' && ctx.returnPropertyTaints) {
    const resolvedKey = resolveId(node.id, ctx.scopeInfo);
    for (const [propName, propTaint] of ctx.returnPropertyTaints) {
      env.set(`${resolvedKey}.${propName}`, propTaint);
    }
    ctx.returnPropertyTaints = null;
  }

  // Propagate per-property taints and funcMap entries from source expression to target variable
  if (node.id.type === 'Identifier' && node.init.type !== 'ObjectExpression' && node.init.type !== 'ArrayExpression') {
    propagatePerPropertyEntries(node.init, resolveId(node.id, ctx.scopeInfo), env, ctx, node.id);
  }

  // Propagate element type / DOM attachment from init expression to variable
  if (node.id.type === 'Identifier' && node.init) {
    const initKey = _scopeQualifyMemberExpr(node.init, ctx);
    if (initKey) {
      const varKey = resolveId(node.id, ctx.scopeInfo);
      const tag = ctx.elementTypes.get(initKey);
      if (tag) ctx.elementTypes.set(varKey, tag);
      if (ctx.domAttached.has(initKey)) ctx.domAttached.add(varKey);
      if (ctx.scriptElements.has(initKey)) ctx.scriptElements.add(varKey);
    }
  }

  // For `new Constructor()` or `Reflect.construct(Constructor, args)` — propagate this.* taint to instance.*
  if (node.id.type === 'Identifier') {
    let ctorCallee = null;
    if (node.init.type === 'NewExpression') {
      ctorCallee = node.init.callee;
    } else if (node.init.type === 'CallExpression' && isCalleeMatch(node.init, 'Reflect', 'construct', env, ctx) && node.init.arguments[0]) {
      ctorCallee = node.init.arguments[0];
    }
    if (ctorCallee) {
      ctx._lastNewCallee = ctorCallee.type === 'Identifier' ? resolveId(ctorCallee, ctx.scopeInfo) : _scopeQualifyMemberExpr(ctorCallee, ctx);
      propagateThisToInstance(resolveId(node.id, ctx.scopeInfo), env, ctx);
      ctx._lastNewCallee = null;
      if (node.init.type === 'NewExpression' && isGlobalRef(node.init.callee, 'URL', env, ctx) && node.init.arguments[0]) {
        const argStr = _scopeQualifyMemberExpr(node.init.arguments[0], ctx);
        if (argStr) env.urlConstructorOrigins.set(resolveId(node.id, ctx.scopeInfo), argStr);
      }
    }
  }
}

// ── Assignment ──
function processAssignment(node, env, ctx) {
  ctx.returnedFuncNode = null;
  ctx.returnedMethods = null;

  // Track arithmetic compound assignments (+=, -=, *=, etc.) as variable mutations
  // so resolveToConstant won't return the initializer for modified variables.
  // Excludes logical assignments (??=, ||=, &&=) which need constant resolution
  // to determine whether the assignment fires.
  if (node.operator !== '=' && node.left.type === 'Identifier' &&
      node.operator !== '??=' && node.operator !== '||=' && node.operator !== '&&=') {
    if (!ctx._mutatedVars) ctx._mutatedVars = new Set();
    ctx._mutatedVars.add(node.left.name);
  }

  // Track `this` aliases: a = this → mark 'a' as a this alias
  if (node.operator === '=' && node.left.type === 'Identifier' && node.right.type === 'ThisExpression') {
    if (!ctx._thisAliases) ctx._thisAliases = new Set();
    const _taKey = resolveId(node.left, ctx.scopeInfo);
    ctx._thisAliases.add(_taKey);
  }

  // Track type on simple assignment: x = expr → infer type from expr
  if (node.operator === '=' && node.left.type === 'Identifier') {
    const inferredType = _inferType(node.right, env, ctx);
    if (inferredType && inferredType.size > 0) {
      env.knownTypes.set(resolveId(node.left, ctx.scopeInfo), inferredType);
    }
  }

  // Propagate callee identity on reassignment using deep resolution.
  // Handles: mn = $n, mn = null==mn ? $n : expr, mn = A || B || C, etc.
  if (node.operator === '=' && node.left.type === 'Identifier') {
    const identity = resolveCalleeIdentity(node.right, env, ctx);
    if (globalThis._TAINT_DEBUG && node.left.name === 'mn') console.log(`[DEBUG-MN] identity=${identity} right.type=${node.right.type}`);
    if (identity) {
      env.aliases.set(resolveId(node.left, ctx.scopeInfo), identity);
      if (globalThis._TAINT_DEBUG) console.log(`[ALIAS-ASSIGN] ${resolveId(node.left, ctx.scopeInfo)} → ${identity}`);
    }
    // Track variable values using abstract values: type + value when concrete,
    // type-only when value changes (loop counters). Enables typeof folding even
    // when concrete value is unknown (e.g., i++ in a loop → type:number, value:unknown).
    const _assignAV = resolveAbstract(node.right, env, ctx);
    if (node.left.type === 'Identifier') {
      const _constKey = resolveId(node.left, ctx.scopeInfo);
      if (!env.constants) env.constants = new Map();
      if (!ctx._localConstants) ctx._localConstants = new Map();
      const _hasPrev = env.constants.has(_constKey);
      const _prevAV = _hasPrev ? env.constants.get(_constKey) : null;
      if (_assignAV.concrete) {
        if (_hasPrev && _prevAV?.concrete && _prevAV.value !== _assignAV.value) {
          // Value changed (e.g., loop counter i=0 → i=1) — lose concrete value, keep type
          const mergedType = _prevAV.type === _assignAV.type ? _prevAV.type : null;
          const typeOnlyAV = mergedType ? AVType(mergedType) : AV_UNKNOWN;
          env.constants.set(_constKey, typeOnlyAV);
          ctx._localConstants.delete(_constKey);
        } else if (_hasPrev && _prevAV && !_prevAV.concrete) {
          // Previously demoted to type-only — don't promote back to concrete (convergence)
          // Just ensure the type is preserved
          if (!_prevAV.type && _assignAV.type) {
            env.constants.set(_constKey, AVType(_assignAV.type));
          }
          ctx._localConstants.delete(_constKey);
        } else {
          env.constants.set(_constKey, _assignAV);
          ctx._localConstants.set(_constKey, _assignAV.value);
        }
      } else if (_assignAV.type) {
        // Type known but value unknown — store type-only AV
        env.constants.set(_constKey, _assignAV);
        ctx._localConstants.delete(_constKey);
      } else {
        // Completely unknown
        env.constants.set(_constKey, AV_UNKNOWN);
        ctx._localConstants.delete(_constKey);
      }
    }
  }

  // Track document.createElement element types in assignments
  if (node.operator === '=') {
    let trackKey = null;
    if (node.left.type === 'Identifier') {
      trackKey = resolveId(node.left, ctx.scopeInfo);
    } else if (node.left.type === 'MemberExpression' && !node.left.computed) {
      const objStr = node.left.object.type === 'ThisExpression' ? 'this'
        : node.left.object.type === 'Identifier' ? _resolveObjKey(node.left.object, ctx) : null;
      const prop = node.left.property?.name;
      if (objStr && prop) trackKey = `${objStr}.${prop}`;
    }
    if (trackKey) {
      const tag = getCreateElementTag(node.right, env, ctx);
      if (tag) {
        ctx.elementTypes.set(trackKey, tag);
        if (tag === 'script') {
          ctx.scriptElements.add(trackKey);
        }
      }
      // Track DOM query results in assignments
      const domInfo = getDOMQueryInfo(node.right, env, ctx);
      if (domInfo) {
        if (domInfo.isDomAttached) {
          ctx.domAttached.add(trackKey);
        }
        if (domInfo.tag) {
          ctx.elementTypes.set(trackKey, domInfo.tag);
          if (domInfo.tag === 'script') {
            ctx.scriptElements.add(trackKey);
          }
        }
      }
    }
  }

  const rhsTaint = evaluateExpr(node.right, env, ctx);
  // If RHS evaluation triggered IP suspension, the result is a placeholder (empty).
  // Skip assignment and sink checks — the node will be re-processed after the inner frame completes.
  if (ctx._ipSuspended) return;
  checkSinkAssignment(node.left, rhsTaint, node.right, env, ctx);
  checkElementPropertySink(node.left, rhsTaint, node.right, env, ctx);
  // Pre-compute key taint for PP check (avoid evaluateExpr inside check function)
  {
    const left = node.left;
    if (left.type === 'MemberExpression') {
      const keyTaint = left.computed ? evaluateExpr(left.property, env, ctx) : TaintSet.empty();
      let outerKeyTaint = TaintSet.empty();
      if (left.computed && left.object.type === 'MemberExpression' && left.object.computed) {
        outerKeyTaint = evaluateExpr(left.object.property, env, ctx);
      }
      checkPrototypePollution(node, env, ctx, rhsTaint, keyTaint, outerKeyTaint);
    }
  }

  // Invoke setter if one is registered: obj.prop = value → setter:obj.prop(value)
  if (node.operator === '=' && node.left.type === 'MemberExpression') {
    let leftStr = null;
    if (!node.left.computed) {
      // Scope-qualify: obj.prop → scopeKey.prop
      if (node.left.object?.type === 'Identifier' && node.left.property?.name) {
        leftStr = `${_resolveObjKey(node.left.object, ctx)}.${node.left.property.name}`;
      } else {
        leftStr = _scopeQualifyMemberExpr(node.left, ctx);
      }
    } else {
      // Computed: obj["prop"] or obj[varName] → resolve to obj.prop
      const objStr = _resolveObjKey(node.left.object, ctx);
      if (objStr && node.left.property) {
        let resolved;
        if (isStringLiteral(node.left.property)) {
          resolved = stringLiteralValue(node.left.property);
        } else {
          const _av = resolveAbstract(node.left.property, env, ctx);
          if (_av.concrete) resolved = _av.value;
        }
        if (typeof resolved === 'string') leftStr = `${objStr}.${resolved}`;
      }
    }
    if (leftStr) {
      const setterFunc = ctx.funcMap.get(`setter:${leftStr}`);
      if (setterFunc) {
        const synthCall = { type: 'CallExpression', callee: node.left, arguments: [node.right], loc: node.loc };
        analyzeCalledFunction(synthCall, `setter:${leftStr}`, [rhsTaint], env, ctx);
      }
    }
  }

  // For-in static property enumeration: when target[key] = value and key is a for-in
  // variable iterating over an object with known properties, enumerate each property
  // and do individual target.prop = source.prop assignments and funcMap copies.
  if (globalThis._TAINT_DEBUG && node.operator === '=' && node.left.type === 'MemberExpression' && node.left.computed && node.left.property?.type === 'Identifier') {
  }
  if (node.operator === '=' && node.left.type === 'MemberExpression' && node.left.computed &&
      node.left.property?.type === 'Identifier' && ctx._forInEnumeration) {
    const _enumKey = resolveId(node.left.property, ctx.scopeInfo);
    const enumInfo = ctx._forInEnumeration.get(_enumKey);
    if (globalThis._TAINT_DEBUG && !enumInfo && ctx._forInEnumeration.size > 0) {
      console.log('[FORIN-MISS] key=' + _enumKey + ' enumKeys=[' + [...ctx._forInEnumeration.keys()].join(',') + ']');
    }
    if (enumInfo) {
      const targetStr = _resolveObjKey(node.left.object, ctx);
      if (targetStr) {
        const isThisAlias = ctx._thisAliases?.has(node.left.object?.type === 'Identifier' ? resolveId(node.left.object, ctx.scopeInfo) : null);
        for (const propName of enumInfo.properties) {
          // Copy per-property taints from source to target
          const srcKey = `${enumInfo.sourceName}.${propName}`;
          const srcTaint = env.get(srcKey);
          if (srcTaint) {
            env.set(`${targetStr}.${propName}`, srcTaint);
            if (isThisAlias) env.set(`this.${propName}`, srcTaint);
          }
          const srcFunc = ctx.funcMap.get(srcKey);
          if (srcFunc) {
            _registerMethod(ctx.funcMap, node.left.object, propName, srcFunc, ctx);
            if (isThisAlias) ctx.funcMap.set(`this.${propName}`, srcFunc);
          }
        }
      }
    }
  }

  // Object.keys iteration: target[keysArr[i]] = source[keysArr[i]]
  // Detect computed key that indexes an Object.keys result array
  if (node.operator === '=' && node.left.type === 'MemberExpression' && node.left.computed &&
      node.left.property?.type === 'MemberExpression' && node.left.property.computed &&
      node.left.property.object?.type === 'Identifier' && ctx._objectKeysVars) {
    const keysInfo = ctx._objectKeysVars.get(resolveId(node.left.property.object, ctx.scopeInfo));
    if (keysInfo) {
      const targetStr = _resolveObjKey(node.left.object, ctx);
      if (targetStr) {
        for (const propName of keysInfo.properties) {
          // Copy env taint
          const srcKey = `${keysInfo.sourceName}.${propName}`;
          const srcTaint = env.get(srcKey);
          if (srcTaint) env.set(`${targetStr}.${propName}`, srcTaint);
          // Copy funcMap entries
          const srcFunc = ctx.funcMap.get(srcKey);
          if (srcFunc) {
            _registerMethod(ctx.funcMap, node.left.object, propName, srcFunc, ctx);
          }
        }
      }
    }
  }

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
        const leftEnvTaint = node.left.type === 'Identifier' ? env.get(resolveId(node.left, ctx.scopeInfo)) : TaintSet.empty();
        if (leftEnvTaint.tainted) { finalTaint = leftEnvTaint.clone().merge(rhsTaint); }
        else {
          // Check if the left variable was initialized to a non-nullish constant
          const _lcAV = resolveAbstract(node.left, env, ctx);
          if (_lcAV.concrete && _lcAV.value !== undefined && _lcAV.value !== null) {
            // Left is a known non-nullish constant → short-circuits
            finalTaint = leftTaint.clone();
          } else {
            finalTaint = leftTaint.clone().merge(rhsTaint);
          }
        }
      }
    } else if (node.operator === '||=') {
      // x ||= rhs: only assigns if x is falsy
      // If left is a known truthy constant, short-circuit (keep left)
      const _lcAV2 = resolveAbstract(node.left, env, ctx);
      if (_lcAV2.concrete && _lcAV2.value) {
        finalTaint = leftTaint.clone();
      } else if (leftTaint.tainted) {
        // Left is tainted (source strings are always truthy) → short-circuit, keep left
        finalTaint = leftTaint.clone();
      } else {
        finalTaint = leftTaint.clone().merge(rhsTaint);
      }
    } else if (node.operator === '&&=') {
      // x &&= rhs: only assigns if x is truthy → result is rhs
      // If left is a known falsy constant, skip assignment (result is left)
      const _lcAV3 = resolveAbstract(node.left, env, ctx);
      if (_lcAV3.concrete && !_lcAV3.value) {
        // Left is falsy → short-circuit, keep left taint
        finalTaint = leftTaint.clone();
      } else if (_lcAV3.concrete && _lcAV3.value) {
        // Left is truthy constant → result is RHS value
        finalTaint = rhsTaint.clone();
      } else if (leftTaint.tainted) {
        // Left is tainted (source strings are always truthy non-empty strings)
        // → result is RHS value
        finalTaint = rhsTaint.clone();
      } else {
        // Unknown → conservative merge
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
    // Annotate store stateStep for multi-step PoC when taint is stored under a branch condition inside a handler
    if (ctx._handlerContext && ctx._currentBranchCondition && finalTaint.tainted &&
        node.left.type === 'MemberExpression') {
      const cond = extractConditionInfo(ctx._currentBranchCondition.node, ctx._currentBranchCondition.polarity, ctx);
      if (cond) {
        finalTaint = finalTaint.withStateStep({
          action: 'store',
          variable: _scopeQualifyMemberExpr(node.left, ctx) || '',
          condition: cond,
          handler: ctx._handlerContext.type,
        });
      }
    }
    assignToPattern(node.left, finalTaint, env, ctx);
    // Propagate per-property entries from RHS to LHS for assignments like e = arguments[s]
    // This copies funcMap entries and per-property taints so for-in enumeration finds them
    if (node.operator === '=' && node.left.type === 'Identifier') {
      const _assignTargetKey = resolveId(node.left, ctx.scopeInfo);
      propagatePerPropertyEntries(node.right, _assignTargetKey, env, ctx, node.left);
    }
    if (node.operator === '=' && node.left.type === 'Identifier') {
      const key = resolveId(node.left, ctx.scopeInfo);
      env.markDefinite(key);
      env.markDefinite(`global:${node.left.name}`);
    }
  }
  registerReturnedFunctions(node.left, ctx, env);

  // Copy funcMap entry from RHS to LHS for assignments.
  // Handles: w.extend = w.fn.extend (MemberExpression RHS)
  //          w.extend = w.fn.extend = function(){} (chained AssignmentExpression RHS)
  if (node.operator === '=') {
    let _rhsEffective = node.right;
    // Unwrap chained assignment: a = b = expr → effective RHS is b (the inner LHS)
    if (_rhsEffective.type === 'AssignmentExpression' && _rhsEffective.operator === '=') {
      _rhsEffective = _rhsEffective.left;
    }
    if (_rhsEffective.type === 'MemberExpression' || _rhsEffective.type === 'Identifier') {
      let rhsFuncKey = _scopeQualifyMemberExpr(_rhsEffective, ctx);
      // Computed member RHS: e[t] where t resolves to a string → look up e.resolvedKey
      if (!rhsFuncKey && _rhsEffective.type === 'MemberExpression' && _rhsEffective.computed) {
        const _srcObj = _resolveObjKey(_rhsEffective.object, ctx);
        const _srcKeyAV = resolveAbstract(_rhsEffective.property, env, ctx);
        if (_srcObj && _srcKeyAV.concrete && typeof _srcKeyAV.value === 'string') {
          const _srcKey = _srcKeyAV.value;
          rhsFuncKey = `${_srcObj}.${_srcKey}`;
        }
      }
      const rhsFunc = rhsFuncKey && ctx.funcMap.get(rhsFuncKey);
      if (rhsFunc) {
        const lhsFuncKey = _scopeQualifyMemberExpr(node.left, ctx);
        if (lhsFuncKey && lhsFuncKey !== rhsFuncKey) {
          ctx.funcMap.set(lhsFuncKey, rhsFunc);
        }
        // Also set for computed LHS: a[t] = e[t] where a resolves via alias
        if (!lhsFuncKey && node.left.type === 'MemberExpression' && node.left.computed) {
          const _lhsObj = _resolveObjKey(node.left.object, ctx);
          const _lhsKeyAV = resolveAbstract(node.left.property, env, ctx);
          if (_lhsObj && _lhsKeyAV.concrete && typeof _lhsKeyAV.value === 'string') {
            const _lhsKey = _lhsKeyAV.value;
            ctx.funcMap.set(`${_lhsObj}.${_lhsKey}`, rhsFunc);
            // If the LHS object is aliased (e.g., a = this), also register under the alias
            if (node.left.object.type === 'Identifier') {
              const _lhsScopeKey = resolveId(node.left.object, ctx.scopeInfo);
              const _lhsAlias = env.getAlias ? env.getAlias(_lhsScopeKey) : env.aliases?.get(_lhsScopeKey);
              if (_lhsAlias && _lhsAlias !== _lhsObj) {
                ctx.funcMap.set(`${_lhsAlias}.${_lhsKey}`, rhsFunc);
              }
            }
          }
        }
      }
    }
  }

  // Propagate element type / DOM attachment from RHS to LHS
  if (node.operator === '=') {
    const rhsKey = _scopeQualifyMemberExpr(node.right, ctx);
    if (rhsKey) {
      const lhsKey = node.left.type === 'Identifier' ? resolveId(node.left, ctx.scopeInfo)
        : _scopeQualifyMemberExpr(node.left, ctx);
      if (lhsKey) {
        let tag = ctx.elementTypes.get(rhsKey);
        // Resolve DOM-producing properties via IDL: rhs = document.body → lhs is DOM-attached
        if (!tag && node.right.type === 'MemberExpression' && !node.right.computed) {
          const objNode = node.right.object;
          const objKey2 = objNode.type === 'Identifier' ? resolveId(objNode, ctx.scopeInfo) : null;
          if (objKey2) {
            const objType = ctx.variableTypes.get(objKey2) || _resolveInterfaceName(_stripScopePrefix(objKey2));
            if (objType) {
              const propName = node.right.property?.name;
              if (propName) {
                const domPropInfo = getDOMPropertyInfo(objType, propName);
                if (domPropInfo) {
                  ctx.domAttached.add(lhsKey);
                  if (domPropInfo.tag) {
                    tag = domPropInfo.tag;
                  }
                }
              }
            }
          }
        }
        if (tag) ctx.elementTypes.set(lhsKey, tag);
        if (ctx.domAttached.has(rhsKey)) ctx.domAttached.add(lhsKey);
        if (ctx.scriptElements.has(rhsKey)) ctx.scriptElements.add(lhsKey);
        // Propagate variable types
        const rhsType = ctx.variableTypes.get(rhsKey);
        if (rhsType) ctx.variableTypes.set(lhsKey, rhsType);
      }
    }
  }

  // Level 3b: Register builtin alias from interprocedural return (assignment)
  // Same as Level 3 in processVarDeclarator but for assignments: Ai = IIFE()
  if (ctx._returnedBuiltinAlias && node.left.type === 'Identifier') {
    env.aliases.set(resolveId(node.left, ctx.scopeInfo), ctx._returnedBuiltinAlias);
    if (globalThis._TAINT_DEBUG) console.log(`[ALIAS-BUILTIN-L3b] ${resolveId(node.left, ctx.scopeInfo)} → ${ctx._returnedBuiltinAlias} (from call return, assignment)`);
    ctx._returnedBuiltinAlias = null;
  }

  // Apply returned aliases for assignment: mn = rt.defaults(...) → mn.Object → Object
  if (ctx._returnedAliases && node.left.type === 'Identifier') {
    const _lhsKey = resolveId(node.left, ctx.scopeInfo);
    for (const [suffix, aliasValue] of ctx._returnedAliases) {
      env.aliases.set(`${_lhsKey}.${suffix}`, aliasValue);
    }
    ctx._returnedAliases = null;
  }

  // Constant tracking for assignments is handled above (line ~4210) with env for alias resolution.
  // A duplicate block here without env fails to resolve aliased calls (Li → Math.max)
  // and would erroneously delete valid constants set by the first block.

  // Propagate per-property taints from source to target on assignment
  if (node.operator === '=' && node.left.type === 'Identifier' &&
      node.right.type !== 'ObjectExpression' && node.right.type !== 'ArrayExpression') {
    propagatePerPropertyEntries(node.right, resolveId(node.left, ctx.scopeInfo), env, ctx, node.left);
  }

  // Track CustomEvent type: var ev = new CustomEvent('type', ...) → map ev → type
  if (ctx._pendingCustomEventType) {
    const evName = _scopeQualifyMemberExpr(node.left, ctx);
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
    node.right._closureFuncMap = ctx.funcMap;
    if (node.left.type === 'MemberExpression') {
      // Scope-qualified: obj.method → scopeKey.method
      // Scope-qualify the deepest Identifier object in the MemberExpression chain
      const leftKey = _scopeQualifyMemberExpr(node.left, ctx);
      if (leftKey) ctx.funcMap.set(leftKey, node.right);
      // If the object is aliased to a global (window/self/globalThis), also register
      // under global: prefix and bare property name for cross-scope resolution
      if (node.left.object?.type === 'Identifier' && !node.left.computed && node.left.property?.name) {
        const _leftObjKey = resolveId(node.left.object, ctx.scopeInfo);
        const objAlias = (env?.getAlias ? env.getAlias(_leftObjKey) : env?.aliases?.get(_leftObjKey)) || node.left.object.name;
        const _GS = new Set(['window', 'self', 'globalThis', 'global']);
        if (_GS.has(objAlias)) {
          const propName = node.left.property.name;
          ctx.funcMap.set(`global:${propName}`, node.right);
          ctx.funcMap.set(propName, node.right);
        }
      }
      // Register prototype methods
      if (!node.left.computed &&
          node.left.object?.type === 'MemberExpression' && !node.left.object.computed &&
          node.left.object.property?.name === 'prototype' &&
          node.left.object.object?.type === 'Identifier') {
        const className = resolveId(node.left.object.object, ctx.scopeInfo);
        const methodName = node.left.property.name;
        if (ctx.protoMethodMap && !ctx.protoMethodMap.has(className)) ctx.protoMethodMap.set(className, []);
        ctx.protoMethodMap.get(className).push({ methodName, funcNode: node.right });
        // Also register as ClassName#methodName for new Foo().method() resolution
        ctx.funcMap.set(`${className}#${methodName}`, node.right);
      }
    } else if (node.left.type === 'Identifier') {
      const key = resolveId(node.left, ctx.scopeInfo);
      ctx.funcMap.set(key, node.right);
    }
    // Computed member: obj[key] = function(){} → register as obj[] for dynamic dispatch
    if (node.left.type === 'MemberExpression' && node.left.computed) {
      const objKey = _scopeQualifyMemberExpr(node.left.object, ctx);
      if (objKey) {
        ctx.funcMap.set(`${objKey}[]`, node.right);
      }
    }
  }

  // Register function-valued properties from object literal assigned to a named target:
  // X.prototype = { render: function(){} }   → register X.prototype.render in funcMap
  // X.fn = { html: function(){} }            → register X.fn.html in funcMap
  // Also handles chained assignment: X.fn = X.prototype = { ... }
  if (node.operator === '=') {
    // Determine the scope-qualified prefix for method registration
    // Pass env for alias resolution: $n._ where $n→self resolves to self._
    const leftStr = _scopeQualifyMemberExpr(node.left, ctx, env);
    if (leftStr) {
      // Find the ultimate ObjectExpression RHS (unwrap assignment chains)
      let rhsObj = node.right;
      while (rhsObj && rhsObj.type === 'AssignmentExpression') rhsObj = rhsObj.right;
      if (rhsObj && rhsObj.type === 'ObjectExpression') {
        // Compute stripped prefix for global window/self/globalThis assignments:
        // leftStr is already alias-resolved via resolveId(env):
        // $n._ where $n→self produces leftStr="self._", stripped to "global:_"
        let strippedPrefix = null;
        const _barePfx = _stripScopePrefix(leftStr);
        const _globalPrefixes = ['window.', 'self.', 'globalThis.'];
        for (const gp of _globalPrefixes) {
          if (_barePfx.startsWith(gp)) {
            strippedPrefix = `global:${_barePfx.slice(gp.length)}`;
            break;
          }
        }
        const romStack = [{objExpr: rhsObj, prefix: leftStr}];
        while (romStack.length > 0) {
          const {objExpr, prefix} = romStack.pop();
          for (const prop of objExpr.properties) {
            if (isObjectProp(prop) && prop.key) {
              let propName;
              if (prop.computed) {
                const _av = resolveAbstract(prop.key, env, ctx);
                if (_av.concrete && typeof _av.value === 'string') propName = _av.value;
              }
              if (!propName) propName = propKeyName(prop.key);
              const val = prop.value;
              if (propName && val && (val.type === 'FunctionExpression' || val.type === 'ArrowFunctionExpression')) {
                val._closureEnv = env;
                val._closureFuncMap = ctx.funcMap;
                ctx.funcMap.set(`${prefix}.${propName}`, val);
                // Also register under stripped prefix for global window.X exports
                if (strippedPrefix) {
                  const sp = prefix === leftStr ? strippedPrefix : prefix.replace(leftStr, strippedPrefix);
                  ctx.funcMap.set(`${sp}.${propName}`, val);
                }
              }
              if (propName && val && val.type === 'Identifier') {
                const refFunc = ctx.funcMap.get(resolveId(val, ctx.scopeInfo));
                if (refFunc) {
                  ctx.funcMap.set(`${prefix}.${propName}`, refFunc);
                  if (strippedPrefix) {
                    const sp = prefix === leftStr ? strippedPrefix : prefix.replace(leftStr, strippedPrefix);
                    ctx.funcMap.set(`${sp}.${propName}`, refFunc);
                  }
                }
              }
              if (propName && val && val.type === 'ObjectExpression') {
                romStack.push({objExpr: val, prefix: `${prefix}.${propName}`});
              }
            }
            if (prop.type === 'ObjectMethod' && prop.key) {
              let propName;
              if (prop.computed) {
                const _av = resolveAbstract(prop.key, env, ctx);
                if (_av.concrete && typeof _av.value === 'string') propName = _av.value;
              }
              if (!propName) propName = propKeyName(prop.key);
              if (propName) {
                prop._closureEnv = env;
                prop._closureFuncMap = ctx.funcMap;
                const accessorPrefix = prop.kind === 'get' ? 'getter:' : (prop.kind === 'set' ? 'setter:' : '');
                ctx.funcMap.set(`${accessorPrefix}${prefix}.${propName}`, prop);
                if (accessorPrefix) {
                  ctx.funcMap.set(`${prefix}.${propName}`, prop);
                }
              }
            }
          }
        }
        // Also store per-property taints for the object
        storeObjectPropertyTaints(leftStr, rhsObj, env, ctx);
      }
    }
  }

  // X.prototype = Y (non-ObjectExpression) → copy Y's methods to X prototype
  // Handles: ce.fn.init.prototype = ce.fn (jQuery pattern)
  // Also registers a prototype LINKAGE so methods added to Y later are automatically
  // propagated to X#method (reactive propagation for sequential code).
  if (node.operator === '=' &&
      node.left.type === 'MemberExpression' && !node.left.computed &&
      node.left.property?.name === 'prototype') {
    let rhsRef = node.right;
    while (rhsRef.type === 'AssignmentExpression') rhsRef = rhsRef.right;
    if (rhsRef.type !== 'ObjectExpression') {
      const rhsKey = rhsRef.type === 'Identifier' ? resolveId(rhsRef, ctx.scopeInfo)
        : _scopeQualifyMemberExpr(rhsRef, ctx);
      // lhsBase: the constructor whose prototype is being set.
      // Handles: (ce.fn.init = function(){...}).prototype = ce.fn
      // where node.left.object is an AssignmentExpression — extract the LHS of the inner assignment
      let _protoTarget = node.left.object;
      if (_protoTarget.type === 'AssignmentExpression' && _protoTarget.operator === '=') {
        _protoTarget = _protoTarget.left; // ce.fn.init
      }
      if (_protoTarget.type === 'ParenthesizedExpression') {
        _protoTarget = _protoTarget.expression;
        if (_protoTarget.type === 'AssignmentExpression' && _protoTarget.operator === '=') {
          _protoTarget = _protoTarget.left;
        }
      }
      const lhsBase = _scopeQualifyMemberExpr(_protoTarget, ctx);
      if (rhsKey && lhsBase) {
        // Copy existing methods from Y to X#method
        const rhsPrefix = rhsKey + '.';
        for (const [fk, fv] of ctx.funcMap) {
          if (fk.startsWith(rhsPrefix)) {
            const methodName = fk.slice(rhsPrefix.length);
            if (methodName && !methodName.includes('.')) {
              ctx.funcMap.set(`${lhsBase}#${methodName}`, fv);
              if (!ctx.protoMethodMap.has(lhsBase)) ctx.protoMethodMap.set(lhsBase, []);
              ctx.protoMethodMap.get(lhsBase).push({ methodName, funcNode: fv });
            }
          }
        }
        // Register prototype linkage for reactive propagation:
        // When Y.newMethod is later added, automatically create X#newMethod.
        if (!ctx._prototypeLinkages.has(rhsKey)) ctx._prototypeLinkages.set(rhsKey, []);
        ctx._prototypeLinkages.get(rhsKey).push(lhsBase);
      }
    }
  }

  // Child.prototype = Object.create(Base.prototype) → link Child to Base in prototype chain
  if (node.operator === '=' &&
      node.left.type === 'MemberExpression' && !node.left.computed &&
      node.left.property?.name === 'prototype' &&
      node.left.object?.type === 'Identifier' &&
      node.right.type === 'CallExpression' &&
      isCalleeMatch(node.right, 'Object', 'create', env, ctx) &&
      node.right.arguments[0]?.type === 'MemberExpression' && !node.right.arguments[0].computed &&
      node.right.arguments[0].property?.name === 'prototype' &&
      node.right.arguments[0].object?.type === 'Identifier') {
    const childName = resolveId(node.left.object, ctx.scopeInfo);
    const parentName = resolveId(node.right.arguments[0].object, ctx.scopeInfo);
    ctx.superClassMap.set(childName, parentName);
    _inheritClassMethods(parentName, childName, ctx);
  }

  // Identifier assignment of function ref: handler = existingFunc
  if (node.operator === '=' && node.right.type === 'Identifier' && node.left.type === 'Identifier') {
    const refFunc = ctx.funcMap.get(resolveId(node.right, ctx.scopeInfo));
    if (refFunc) {
      const leftKey = resolveId(node.left, ctx.scopeInfo);
      ctx.funcMap.set(leftKey, refFunc);
    }
    // Update alias on reassignment: fn = parseInt (clear previous eval alias)
    const ALIASABLE_GLOBALS = new Set(['location', 'document', 'window', 'self', 'globalThis', 'navigator', 'top', 'parent',
      'eval', 'setTimeout', 'setInterval', 'Function', 'fetch', 'atob', 'decodeURIComponent', 'decodeURI',
      'encodeURIComponent', 'encodeURI', 'parseInt', 'parseFloat', 'Number', 'Boolean', 'String', 'JSON', 'Math',
      'DOMPurify', 'structuredClone', 'queueMicrotask', 'requestAnimationFrame']);
    const rhsKey = resolveId(node.right, ctx.scopeInfo);
    const rhsAlias = env.aliases.get(rhsKey) || node.right.name;
    const lhsKey = resolveId(node.left, ctx.scopeInfo);
    if (ALIASABLE_GLOBALS.has(rhsAlias)) {
      env.aliases.set(lhsKey, rhsAlias);
    } else if (env.aliases.has(lhsKey)) {
      // Reassigned to non-global — clear the alias
      env.aliases.delete(lhsKey);
    }
  }

  // MemberExpression assignment of function ref: window.getConfig = createConfig, obj.handler = existingFunc
  // Also handles chained: window.jQuery = window.$ = jQuery (unwrap AssignmentExpression chain)
  if (node.operator === '=' &&
      (node.left.type === 'MemberExpression' || node.left.type === 'OptionalMemberExpression') && !node.left.computed) {
    let _rhsForFunc = node.right;
    while (_rhsForFunc.type === 'AssignmentExpression') _rhsForFunc = _rhsForFunc.right;
    const refFunc = _rhsForFunc.type === 'Identifier' ? ctx.funcMap.get(resolveId(_rhsForFunc, ctx.scopeInfo)) : null;
    if (refFunc) {
      _registerMethod(ctx.funcMap, node.left.object, node.left.property?.name, refFunc, ctx);
      // window.X = func → also register global:X and bare X
      if (node.left.object?.type === 'Identifier' && node.left.property?.name) {
        const _objKey2 = resolveId(node.left.object, ctx.scopeInfo);
        const _objAlias2 = (env?.getAlias ? env.getAlias(_objKey2) : null) || node.left.object.name;
        const _GS2 = new Set(['window', 'self', 'globalThis', 'global']);
        if (_GS2.has(_objAlias2)) {
          const pName = node.left.property.name;
          ctx.funcMap.set(`global:${pName}`, refFunc);
          ctx.funcMap.set(pName, refFunc);
        }
      }
    }
    // Global alias export: $n.X = someObj → copy someObj.* funcMap entries to X.*
    // Only fires when LHS root is aliased to a global prefix (window/self/globalThis/global)
    if (node.left.object?.type === 'Identifier') {
      const _GS = new Set(['window', 'self', 'globalThis', 'global']);
      const _gaKey = resolveId(node.left.object, ctx.scopeInfo, env);
      // _gaKey is already alias-resolved via resolveId(env) — if $n→self, _gaKey = 'self'
      const _GS_check = _GLOBAL_SCOPE_OBJECTS.has(_gaKey) ||
        _GLOBAL_SCOPE_OBJECTS.has((env?.getAlias ? env.getAlias(_gaKey) : env.aliases?.get(_gaKey)) || node.left.object.name);
      if (_GS_check) {
        const targetName = node.left.property?.name;
        let _rhsUnwrapped = node.right;
        while (_rhsUnwrapped.type === 'AssignmentExpression') _rhsUnwrapped = _rhsUnwrapped.right;
        const rhsSrcName = _rhsUnwrapped.type === 'Identifier' ? _rhsUnwrapped.name : null;
        const rhsSrcKey = _rhsUnwrapped.type === 'Identifier' ? resolveId(_rhsUnwrapped, ctx.scopeInfo) : null;
        if (targetName) {
          const srcPrefixes = [rhsSrcName + '.'];
          if (rhsSrcKey !== rhsSrcName) srcPrefixes.push(rhsSrcKey + '.');
          for (const [key, val] of ctx.funcMap) {
            for (const sp of srcPrefixes) {
              if (key.startsWith(sp)) {
                const suffix = key.slice(sp.length);
                // Register under bare name and global: prefix since this is a global export
                ctx.funcMap.set(`${targetName}.${suffix}`, val);
                ctx.funcMap.set(`global:${targetName}.${suffix}`, val);
                // Also register under the full scope-qualified LHS path
                const _lhsKey = _scopeQualifyMemberExpr(node.left, ctx, env);
                if (_lhsKey) ctx.funcMap.set(`${_lhsKey}.${suffix}`, val);
                break;
              }
            }
          }
        }
      }
    }
    // Track global function alias: obj.fn = eval → env.aliases.set('obj.fn', 'eval')
    const _rhsKey = resolveId(node.right, ctx.scopeInfo);
    const _rhsAlias = env.aliases.get(_rhsKey) || node.right.name;
    const SINK_GLOBALS = new Set(['eval', 'setTimeout', 'setInterval', 'Function']);
    if (SINK_GLOBALS.has(_rhsAlias)) {
      const leftStr = _scopeQualifyMemberExpr(node.left, ctx);
      if (leftStr) env.aliases.set(leftStr, _rhsAlias);
    }
  }

  // Computed member assignment of function ref: obj[key] = existingFunc or obj[key] = source[key]
  if (node.operator === '=' && node.left.type === 'MemberExpression' && node.left.computed) {
    let refFunc = null;
    if (node.right.type === 'Identifier') {
      refFunc = ctx.funcMap.get(resolveId(node.right, ctx.scopeInfo));
    } else if (node.right.type === 'MemberExpression' && node.right.computed) {
      // source[key] — resolve key to find the specific funcMap entry
      const srcObj = _resolveObjKey(node.right.object, ctx);
      const _srcKeyAV2 = resolveAbstract(node.right.property, env, ctx);
      if (srcObj && _srcKeyAV2.concrete) {
        refFunc = ctx.funcMap.get(`${srcObj}.${_srcKeyAV2.value}`);
      }
    } else if (node.right.type === 'MemberExpression' && !node.right.computed) {
      const srcPath = _scopeQualifyMemberExpr(node.right, ctx);
      if (srcPath) refFunc = ctx.funcMap.get(srcPath);
    }
    if (refFunc) {
      const objKey = _resolveObjKey(node.left.object, ctx);
      if (objKey) {
        ctx.funcMap.set(`${objKey}[]`, refFunc);
        let resolved;
        if (isStringLiteral(node.left.property)) {
          resolved = stringLiteralValue(node.left.property);
        } else {
          const _av = resolveAbstract(node.left.property, env, ctx);
          if (_av.concrete) resolved = _av.value;
        }
        if (typeof resolved === 'string') {
          ctx.funcMap.set(`${objKey}.${resolved}`, refFunc);
        }
      }
    }
  }

  // Computed bulk copy alias propagation: target[k] = source[k]
  // When both sides use the same computed key and source has an alias,
  // target inherits the source's identity for property resolution
  if (node.operator === '=' &&
      node.left.type === 'MemberExpression' && node.left.computed &&
      node.right.type === 'MemberExpression' && node.right.computed) {
    const lhsKeyStr = _scopeQualifyMemberExpr(node.left.property, ctx);
    const rhsKeyStr = _scopeQualifyMemberExpr(node.right.property, ctx);
    if (lhsKeyStr && rhsKeyStr && lhsKeyStr === rhsKeyStr) {
      const lhsObjKey = _scopeQualifyMemberExpr(node.left.object, ctx);
      const rhsObjKey = _scopeQualifyMemberExpr(node.right.object, ctx);
      if (lhsObjKey && rhsObjKey && lhsObjKey !== rhsObjKey) {
        const rhsAlias = env.getAlias ? env.getAlias(rhsObjKey) : env.aliases?.get(rhsObjKey);
        if (rhsAlias && !env.aliases.has(lhsObjKey)) {
          env.aliases.set(lhsObjKey, rhsAlias);
        }
      }
    }
  }

  // Register object literal methods: obj = { render: function(){} } or window.Mod = { get: function(){} }
  if (node.operator === '=' && node.right.type === 'ObjectExpression') {
    const leftStr = _scopeQualifyMemberExpr(node.left, ctx);
    if (leftStr) {
      // Resolve global alias: if root is aliased to window/self/globalThis, compute stripped path
      // e.g., $n._ = { merge: fn } where $n→window → strippedLeft="_"
      const _GLOBAL_SET = new Set(['window', 'self', 'globalThis', 'global']);
      let strippedLeft = null;
      const resolvedLeft = resolveAliasedPath(leftStr, env);
      const resolvedRoot = resolvedLeft.split('.')[0];
      if (_GLOBAL_SET.has(resolvedRoot) && resolvedLeft.indexOf('.') !== -1) {
        strippedLeft = resolvedLeft.slice(resolvedRoot.length + 1);
      } else if (_GLOBAL_SET.has(leftStr.split('.')[0]) && leftStr.indexOf('.') !== -1) {
        strippedLeft = leftStr.slice(leftStr.indexOf('.') + 1);
      }
      for (const prop of node.right.properties) {
        if (isObjectProp(prop) && prop.key) {
          const propName = propKeyName(prop.key);
          const val = prop.value;
          if (propName && val && (val.type === 'FunctionExpression' || val.type === 'ArrowFunctionExpression')) {
            val._closureEnv = env;
            _registerMethod(ctx.funcMap, node.left.object || leftStr, propName, val, ctx);
            if (strippedLeft) ctx.funcMap.set(`global:${strippedLeft}.${propName}`, val);
          }
        }
        if (prop.type === 'ObjectMethod' && prop.key) {
          const propName = propKeyName(prop.key);
          if (propName) {
            prop._closureEnv = env;
            _registerMethod(ctx.funcMap, node.left.object || leftStr, propName, prop, ctx);
            if (strippedLeft) ctx.funcMap.set(`global:${strippedLeft}.${propName}`, prop);
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
      handler = ctx.funcMap.get(resolveId(handler, ctx.scopeInfo)) || handler;
    }
    if (handler.type === 'ArrowFunctionExpression' || handler.type === 'FunctionExpression' ||
        handler.type === 'FunctionDeclaration') {
      const childEnv = env.child();
      if (handler.body.type === 'BlockStatement') {
        analyzeInlineFunction(handler, childEnv, ctx);
      } else {
        evaluateExpr(handler.body, childEnv, ctx);
      }
    } else {
      // Tainted string assigned to event handler property: el.onclick = taintedStr
      // This is equivalent to setAttribute("onclick", taintedStr) — XSS sink
      const rhsTaint = evaluateExpr(node.right, env, ctx);
      if (rhsTaint.tainted) {
        const propName = node.left.property.name;
        const loc = getNodeLoc(node);
        pushFinding(ctx, {
          type: 'XSS',
          severity: 'high',
          title: `XSS: tainted data assigned to event handler property .${propName}`,
          sink: makeSinkInfo(`.${propName}`, ctx, loc),
          source: formatSources(annotateSinkSteps(rhsTaint, ctx, env)),
          path: buildTaintPath(rhsTaint, `.${propName}`),
        });
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
        const refKey = resolveId(handler, ctx.scopeInfo);
        handler = ctx.funcMap.get(refKey) || handler;
      }
      if (handler.type === 'ArrowFunctionExpression' || handler.type === 'FunctionExpression' ||
          handler.type === 'FunctionDeclaration') {
        const originCheck = callbackChecksOrigin(handler.body, ctx);
        if (originCheck !== 'strong' && handler.params[0]) {
          const paramName = handler.params[0].type === 'Identifier' ? handler.params[0].name : null;
          if (paramName) {
            const childEnv = env.child();
            const loc = getNodeLoc(handler);
            const desc = originCheck === 'weak'
              ? `${paramName}.data (weak origin check)`
              : `${paramName}.data (no origin check)`;
            const label = new TaintLabel('postMessage.data', ctx.file, loc.line || 0, loc.column || 0, desc);
            label.structural = true; // attacker controls the message data shape
            assignToPattern(handler.params[0], TaintSet.from(label), childEnv, ctx);
            childEnv.set(`${paramName}.data`, TaintSet.from(label));
            const prevHandler = ctx._handlerContext;
            ctx._handlerContext = { type: 'message', param: paramName };
            handler._isEventHandler = true;
            if (!handler._closureEnv) handler._closureEnv = env;
            if (handler.body.type === 'BlockStatement') {
              analyzeInlineFunction(handler, childEnv, ctx);
            } else {
              evaluateExpr(handler.body, childEnv, ctx);
            }
            ctx._handlerContext = prevHandler;
          }
        }
      }
    }
  }

  // window.onhashchange = function(e) { ... }
  // Analyze the handler body with tainted event param, same as addEventListener('hashchange', fn)
  if (node.operator === '=') {
    const isOnhashchange = (node.left.type === 'Identifier' && node.left.name === 'onhashchange') ||
      (node.left.type === 'MemberExpression' && !node.left.computed &&
       node.left.property?.name === 'onhashchange' &&
       node.left.object?.type === 'Identifier' &&
       (node.left.object.name === 'window' || node.left.object.name === 'self' || node.left.object.name === 'globalThis'));
    if (isOnhashchange) {
      let handler = node.right;
      if (handler.type === 'Identifier') {
        const refKey = resolveId(handler, ctx.scopeInfo);
        handler = ctx.funcMap.get(refKey) || handler;
      }
      if (handler.type === 'ArrowFunctionExpression' || handler.type === 'FunctionExpression' ||
          handler.type === 'FunctionDeclaration') {
        if (handler.params[0]) {
          const paramName = handler.params[0].type === 'Identifier' ? handler.params[0].name : null;
          if (paramName) {
            const evtSource = EVENT_SOURCES['hashchange'];
            if (evtSource) {
              const childEnv = env.child();
              const loc = getNodeLoc(handler);
              const label = new TaintLabel(evtSource.label, ctx.file, loc.line || 0, loc.column || 0, `${paramName}.${evtSource.property}`);
              childEnv.set(`${paramName}.${evtSource.property}`, TaintSet.from(label));
              assignToPattern(handler.params[0], TaintSet.from(label), childEnv, ctx);
              const prevHandler = ctx._handlerContext;
              ctx._handlerContext = { type: 'hashchange', param: paramName };
              handler._isEventHandler = true;
              if (!handler._closureEnv) handler._closureEnv = env;
              if (handler.body.type === 'BlockStatement') {
                analyzeInlineFunction(handler, childEnv, ctx);
              } else {
                evaluateExpr(handler.body, childEnv, ctx);
              }
              ctx._handlerContext = prevHandler;
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
        const key = resolveId(pattern, ctx.scopeInfo);
        if (globalThis._TAINT_DEBUG && taint.tainted) console.log(`[ASSIGN-ID] ${pattern.name} key=${key} tainted=${taint.tainted} loc=${pattern.loc?.start?.line}:${pattern.loc?.start?.column}`);
        env.set(key, taint);
        // Skip global:X for inner-scope variables — they're function-local, not globals.
        // Uses Babel's scope UID via isProgramScope to correctly identify program scope
        // regardless of Babel's global UID counter.
        const isProgScope = key === `global:${pattern.name}` ||
          ctx.scopeInfo.isProgramScope(key);
        const skipGlobal = !isProgScope || (ctx._blockScopedDecl &&
          key !== `global:${pattern.name}` && key !== pattern.name);
        if (!skipGlobal) {
          env.set(`global:${pattern.name}`, taint);
        }
        break;
      }

      case 'MemberExpression':
      case 'OptionalMemberExpression': {
        const str = _scopeQualifyMemberExpr(pattern, ctx);
        if (str) env.set(str, taint);
        if (!pattern.computed && pattern.property?.name) {
          const objStr = _resolveObjKey(pattern.object, ctx);
          if (objStr) env.set(`${objStr}.${pattern.property.name}`, taint);
          const GLOBAL_PREFIXES = new Set(['window', 'self', 'globalThis', 'global']);
          if (pattern.object.type === 'Identifier') {
            const _apKey = resolveId(pattern.object, ctx.scopeInfo);
            const objName = (env?.getAlias ? env.getAlias(_apKey) : env.aliases?.get(_apKey)) || pattern.object.name;
            if (GLOBAL_PREFIXES.has(objName)) {
              const propName = pattern.property.name;
              env.set(propName, taint);
              env.set(`global:${propName}`, taint);
            }
          }
        }
        if (pattern.computed) {
          const objStr = _resolveObjKey(pattern.object, ctx);
          if (objStr) {
            const _av = resolveAbstract(pattern.property, null, ctx);
            if (globalThis._TAINT_DEBUG) console.log('[ASSIGN-COMPUTED] ' + objStr + '[' + (_scopeQualifyMemberExpr(pattern.property, ctx)||'?') + '] resolved=' + String(_av.value) + ' tainted=' + taint.tainted);
            if (_av.concrete) {
              const resolved = _av.value;
              env.set(`${objStr}.${resolved}`, taint);
              if (/^\d+$/.test(String(resolved))) {
                env.set(`${objStr}.#idx_${resolved}`, taint);
                // An array containing tainted elements is itself tainted — propagate to
                // the base variable so taintBits includes it when passed as a function arg.
                // Without this, calls like apply(func, this, arr) have taintBits=0 and
                // hit cached untainted results from definition-time analysis.
                if (taint.tainted) {
                  env.set(objStr, env.get(objStr).clone().merge(taint));
                  if (pattern.object.type === 'Identifier') {
                    const scopeKey = resolveId(pattern.object, ctx.scopeInfo);
                    if (scopeKey !== objStr) {
                      env.set(scopeKey, env.get(scopeKey).clone().merge(taint));
                    }
                  }
                }
                // When assigning an array-like value (with per-element taints) to an
                // array slot, propagate nested per-index taints. E.g., arr[1] = restArray
                // where restArray has per-index taints → arr.#idx_1.#idx_0, arr.#idx_1.#idx_1, etc.
                if (ctx.returnElementTaints) {
                  const retElems = ctx.returnElementTaints;
                  for (let ri = 0; ri < retElems.length; ri++) {
                    if (retElems[ri]) {
                      env.set(`${objStr}.#idx_${resolved}.#idx_${ri}`, retElems[ri]);
                      env.set(`${objStr}.#idx_${resolved}.${ri}`, retElems[ri]);
                    }
                  }
                }
              }
            } else {
              // Computed key couldn't be resolved → taint the base object
              if (globalThis._TAINT_DEBUG && taint.tainted) console.log(`[ASSIGN-COMPUTED-FALLBACK] ${objStr}[?] → tainting base object '${objStr}'`);
              if (taint.tainted) {
                env.set(objStr, env.get(objStr).clone().merge(taint));
                // Also taint scope-resolved keys so outer lookups find it
                if (pattern.object.type === 'Identifier') {
                  const scopeKey = resolveId(pattern.object, ctx.scopeInfo);
                  if (scopeKey !== objStr) {
                    env.set(scopeKey, env.get(scopeKey).clone().merge(taint));
                  }
                  env.set(`global:${pattern.object.name}`, env.get(`global:${pattern.object.name}`).clone().merge(taint));
                }
              }
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
function registerReturnedFunctions(target, ctx, env) {
  if (!target) return;

  // Direct function return: var fn = factory()
  if (ctx.returnedFuncNode && target.type === 'Identifier') {
    const key = resolveId(target, ctx.scopeInfo);
    const retFunc = ctx.returnedFuncNode;
    if (globalThis._TAINT_DEBUG) console.log(`[REG-RET] ${target.name} → ${retFunc.type}/${retFunc.id?.name||'anon'} params=${retFunc.params?.length}`);
    ctx.funcMap.set(key, retFunc);
    // Copy returned function's sub-entries to target: if factory returns An,
    // copy An.merge → rt.merge so later assignments like $n._ = rt can propagate
    const retName = retFunc.id?.name;
    if (retName) {
      const retPrefix = retName + '.';
      for (const [fk, fv] of ctx.funcMap) {
        if (fk.startsWith(retPrefix)) {
          const suffix = fk.slice(retPrefix.length);
          _registerMethod(ctx.funcMap, target, suffix, fv, ctx);
        }
      }
    }
    ctx.returnedFuncNode = null;
  }

  // Object with methods: var obj = factory() where factory returns { render: function(){} }
  if (ctx.returnedMethods && target.type === 'MemberExpression') {
    trace('RET-METHODS', { target: _scopeQualifyMemberExpr(target, ctx) || target.property?.name, count: Object.keys(ctx.returnedMethods).length, hasTemplate: 'template' in ctx.returnedMethods });
  }
  if (ctx.returnedMethods) {
    let varName = null;
    if (target.type === 'Identifier') {
      varName = target.name;
    } else if (target.type === 'MemberExpression' && !target.computed && target.property?.name) {
      // obj.prop = factory() — register methods under prop.method
      // Handles UMD: window._ = factory() → registers _.template etc.
      varName = target.property.name;
    }
    if (varName) {
      const _rmNode = target.type === 'Identifier' ? target : (target.type === 'MemberExpression' ? target : null);
      for (const [methodName, funcNode] of Object.entries(ctx.returnedMethods)) {
        _registerMethod(ctx.funcMap, _rmNode || varName, methodName, funcNode, ctx);
      }
      // For global alias exports: n._ = factory() where n→window → also register _.method globally
      if (target.type === 'MemberExpression' && target.object?.type === 'Identifier') {
        const _tgtObjKey = resolveId(target.object, ctx.scopeInfo);
        const objAlias = (env?.getAlias ? env.getAlias(_tgtObjKey) : env?.aliases?.get(_tgtObjKey)) || target.object.name;
        const _GS = new Set(['window', 'self', 'globalThis', 'global']);
        if (_GS.has(objAlias)) {
          for (const [methodName, funcNode] of Object.entries(ctx.returnedMethods)) {
            ctx.funcMap.set(`global:${varName}.${methodName}`, funcNode);
            ctx.funcMap.set(`${varName}.${methodName}`, funcNode);
          }
          if (ctx.returnedFuncNode) {
            ctx.funcMap.set(`global:${varName}`, ctx.returnedFuncNode);
          }
        }
      }
    }
    ctx.returnedMethods = null;
  }

  // Also handle: obj.prop = factory()
  if (ctx.returnedFuncNode && (target.type === 'MemberExpression' || target.type === 'OptionalMemberExpression')) {
    const qualKey = _scopeQualifyMemberExpr(target, ctx);
    if (qualKey) ctx.funcMap.set(qualKey, ctx.returnedFuncNode);
    ctx.returnedFuncNode = null;
  }
}

// ── Propagate this.* taint from constructor to instance.* ──
// After `var w = new Widget(tainted)`, copies this.html → w.html
function propagateThisToInstance(instanceName, env, ctx) {
  const toSet = [];
  for (const [key, taint] of env.entries()) {
    if (key.startsWith('this.')) {
      const propName = key.slice(5); // "this.html" → "html"
      if (propName) toSet.push([`${instanceName}.${propName}`, taint]);
    }
  }
  for (const [k, t] of toSet) env.set(k, t);

  // Propagate element types / DOM attachment from this.* to instance.*
  for (const thisKey of ctx.elementTypes.keys()) {
    if (thisKey.startsWith('this.')) {
      const propName = thisKey.slice(5);
      if (propName) {
        ctx.elementTypes.set(`${instanceName}.${propName}`, ctx.elementTypes.get(thisKey));
      }
    }
  }
  for (const thisKey of ctx.domAttached) {
    if (thisKey.startsWith('this.')) {
      const propName = thisKey.slice(5);
      if (propName) ctx.domAttached.add(`${instanceName}.${propName}`);
    }
  }
  for (const thisKey of ctx.scriptElements) {
    if (thisKey.startsWith('this.')) {
      const propName = thisKey.slice(5);
      if (propName) ctx.scriptElements.add(`${instanceName}.${propName}`);
    }
  }

  // Also register prototype methods for the constructor under instance.methodName
  const constructorFuncs = [];
  // Look up prototype methods from protoMethodMap by class name
  const ctorCalleeForProto = ctx._lastNewCallee;
  if (ctorCalleeForProto && ctx.protoMethodMap.has(ctorCalleeForProto)) {
    for (const { methodName, funcNode } of ctx.protoMethodMap.get(ctorCalleeForProto)) {
      constructorFuncs.push([`${instanceName}.${methodName}`, funcNode]);
    }
  }
  // For class methods: if the constructor was registered as className (from ClassDeclaration),
  // find all class methods and register them under instance.methodName
  // Class methods are registered by plain name in funcMap during ClassDeclaration processing
  const ctorCallee = ctx._lastNewCallee;
  if (ctorCallee) {
    // Copy all inherited methods (ClassName#method) to instance.method
    // Uses the already-inherited funcMap entries from _inheritClassMethods
    // Also checks getter:/setter: prefixed entries
    for (const prefix of ['', 'getter:', 'setter:']) {
      const classKey = prefix + ctorCallee + '#';
      for (const [k, v] of ctx.funcMap) {
        if (k.startsWith(classKey)) {
          const methodPart = k.slice(classKey.length);
          if (methodPart) {
            constructorFuncs.push([`${prefix}${instanceName}.${methodPart}`, v]);
            if (prefix) constructorFuncs.push([`${instanceName}.${methodPart}`, v]);
          }
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
const C_TAGGED_TEMPLATE = 13; // Pop N expression taints, run tagged template logic
const C_MEMBER_EXPR = 14;     // Pop sub-expression taint(s), apply member chain logic
const C_CALL_ARGS = 15;       // Pop N arg taints, run call expression body
const C_NEW_ARGS = 16;        // Pop N arg taints, run new expression body
const C_BUILTIN_OBJ = 17;     // Pop callee object taint, run handleBuiltinMethod

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

/** When && LHS is a proto-guard comparison (e.g., "__proto__" !== key), mark key as proto-guarded
 *  so that PP checks in the RHS are suppressed. */
// Apply exclusion constraint from a logical && guard: "x" !== key && ...
// When LHS of && is truthy, RHS executes with the guarantee that key !== "x".
function _applyLogicalExclusionGuard(node, env) {
  if (node.type !== 'BinaryExpression') return;
  if (node.operator !== '!==' && node.operator !== '!=') return;
  let varName = null, strVal = null;
  if (node.left.type === 'Identifier' && isStringLiteral(node.right)) {
    varName = node.left.name; strVal = stringLiteralValue(node.right);
  } else if (node.right.type === 'Identifier' && isStringLiteral(node.left)) {
    varName = node.right.name; strVal = stringLiteralValue(node.left);
  }
  if (varName && typeof strVal === 'string') {
    _addConstraintToVar(env, varName, { variable: varName, op: '!==', value: strVal });
  }
}

/** Push work for the next step of a LogicalExpression chain, or finalize. */
function logicalStep(accum, parts, index, ln, env, ctx, W, V) {
  // While loop to handle short-circuit skips without recursion
  while (index >= 0) {
    const { op, right } = parts[index];
    if (op === '&&') {
      const constLeft = isConstantBool(ln, ctx, env);
      if (constLeft === false) { V.push(TaintSet.empty()); return; }
      // When LHS of && is truthy (or unknown), apply branch condition:
      // The RHS only executes when LHS is truthy, so LHS-is-truthy constraint applies.
      // This handles proto-guards: "__proto__" !== key && recurse() → key !== "__proto__" on RHS path.
      _applyLogicalExclusionGuard(ln, env);
      // Also apply full branch condition from LHS to narrow types/constraints
      if (ctx) applyBranchCondition(ln, true, env, ctx);
      if (constLeft === true || accum.tainted) {
        // Left is known truthy (constant true OR tainted source string = always truthy)
        // Result is RHS only — push RHS with empty accum so merge doesn't carry LHS
        W.push({ kind: W_CONTINUATION, label: C_LOGICAL_NEXT, accum: TaintSet.empty(), parts, index, ln: right, env, ctx });
        W.push({ kind: W_EVAL_EXPR, node: right, env, ctx });
        return;
      }
      // Unknown LHS truthiness: RHS only executes if LHS is truthy.
      // Branch condition already applied above. Evaluate RHS in this constrained env.
      W.push({ kind: W_CONTINUATION, label: C_LOGICAL_NEXT, accum, parts, index, ln: right, env, ctx });
      W.push({ kind: W_EVAL_EXPR, node: right, env, ctx });
      return;
    } else if (op === '||') {
      const constLeft = isConstantBool(ln, ctx, env);
      if (constLeft === true || accum.tainted) {
        // short-circuit: left is truthy (constant true OR tainted source = always truthy)
        // → entire chain result is the left value
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
      // Check if left is a known non-nullish constant (including via variable resolution)
      // Note: isConstantBool returns false for null (falsy), so we can't use it directly.
      // Instead, resolve identifiers through scope and check the resolved node.
      let resolvedLn = ln;
      if (ln.type === 'Identifier' && ln.name !== 'undefined') {
        const _init = resolveInitFromScope(ln, ctx);
        if (_init) resolvedLn = _init;
      }
      const isNonNullishConst = (resolvedLn.type === 'StringLiteral') ||
        (resolvedLn.type === 'NumericLiteral') || (resolvedLn.type === 'BooleanLiteral') ||
        (resolvedLn.type === 'Literal' && resolvedLn.value !== null && resolvedLn.value !== undefined) ||
        (resolvedLn.type === 'ObjectExpression') || (resolvedLn.type === 'ArrayExpression');
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
    if (ctx._ipSuspended) { V.push(TaintSet.empty()); break; }
    const item = W.pop();

    switch (item.kind) {
      case W_EVAL_EXPR: {
        if (!item.node) { V.push(TaintSet.empty()); break; }
        const _n = item.node, _e = item.env, _c = item.ctx;
        switch (_n.type) {
          // ── Stage 1: Leaf nodes (no sub-expression evaluation) ──
          case 'Identifier': {
            const key = resolveId(_n, _c.scopeInfo);
            const taint = _e.get(key);
            if (taint.tainted) {
              if (globalThis._TAINT_DEBUG) console.log(`[EVAL-ID] ${_n.name} key=${key} → TAINTED (direct) loc=${_n.loc?.start?.line}:${_n.loc?.start?.column}`);
              V.push(taint.clone()); break;
            }
            // Check per-index taints: when array elements are individually tainted
            // but the whole variable isn't (e.g., f[0] = tainted via loop assignment),
            // merge per-index taints so the variable evaluates as tainted when passed
            // to functions like identity(f) or applyHelper(t, this, o).
            const _perIdxKey = (key !== _n.name && _e.has(key)) ? key : _n.name;
            const _perIdx = _e.getTaintedWithPrefix(`${_perIdxKey}.#idx_`);
            if (_perIdx.length > 0) {
              const merged = TaintSet.empty();
              for (const [, t] of _perIdx) merged.merge(t);
              if (globalThis._TAINT_DEBUG) console.log(`[EVAL-ID] ${_n.name} key=${key} → TAINTED (per-idx, ${_perIdx.length} entries)`);
              V.push(merged);
              break;
            }
            if (key !== _n.name && _e.has(key)) {
              if (globalThis._TAINT_DEBUG && (_n.name === 'o' || _n.name === 'f' || _n.name === 'u' || _n.name === 'arguments')) console.log(`[EVAL-ID] ${_n.name} key=${key} → EMPTY (scope-resolved, exists but empty)`);
              V.push(TaintSet.empty()); break;
            }
            const globalTaint = _e.get(`global:${_n.name}`);
            if (globalTaint.tainted) {
              V.push(globalTaint.clone()); break;
            }
            // DOM clobbering: bare identifier matching a DOM catalog element ID
            // with no JS declaration → attacker-controlled if they can inject HTML
            if (_c.domCatalog?.elements?.has(_n.name) && !_e.has(key)) {
              const loc = getNodeLoc(_n);
              const clobberLabel = new TaintLabel('dom-clobbering', _c.file,
                loc?.line || 0, loc?.col || 0,
                `DOM element #${_n.name} (${_c.domCatalog.elements.get(_n.name)}) used as value`);
              const ts = new TaintSet();
              ts.add(clobberLabel);
              V.push(ts);
              break;
            }
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
            // Route through processAssignment: i++ → i = i + 1
            // processAssignment tracks the new value in env.constants so
            // subsequent resolveToConstant(i) returns the correct value.
            if (_n.argument?.type === 'Identifier') {
              if (!_c._mutatedVars) _c._mutatedVars = new Set();
              _c._mutatedVars.add(_n.argument.name);
              processAssignment({
                type: 'AssignmentExpression', operator: '=',
                left: _n.argument,
                right: { type: 'BinaryExpression', operator: _n.operator === '++' ? '+' : '-',
                  left: _n.argument, right: { type: 'NumericLiteral', value: 1 } },
                loc: _n.loc,
              }, _e, _c);
            }
            V.push(TaintSet.empty());
            break;
          case 'ArrowFunctionExpression':
          case 'FunctionExpression':
            _n._closureEnv = _e;
            _n._closureScopeInfo = _c.scopeInfo;
            V.push(TaintSet.empty());
            break;
          // ── Stage 6: MemberExpression (iterative chain walk) ──
          case 'MemberExpression':
          case 'OptionalMemberExpression': {
            // arguments.callee — always safe
            const _mFullPath = _scopeQualifyMemberExpr(_n, _c);
            if (_mFullPath && (_mFullPath === 'arguments.callee' || _mFullPath.startsWith('arguments.callee.'))) {
              V.push(TaintSet.empty());
              break;
            }
            let _mCur = _n;
            const _mOuterProps = [];
            let _mResolved = false;

            while (_mCur.type === 'MemberExpression' || _mCur.type === 'OptionalMemberExpression') {
              let _mSourceLabel = checkMemberSource(_mCur);
              if (!_mSourceLabel && _mCur.computed && _mCur.property) {
                const _mResAV = resolveAbstract(_mCur.property, _e, _c);
                if (_mResAV.concrete && typeof _mResAV.value === 'string') {
                  const _mResConst = _mResAV.value;
                  const _mObjStr = _scopeQualifyMemberExpr(_mCur.object, _c);
                  if (_mObjStr) {
                    const _mSynthPath = `${_mObjStr}.${_mResConst}`;
                    if (MEMBER_SOURCES[_mSynthPath]) _mSourceLabel = MEMBER_SOURCES[_mSynthPath];
                  }
                }
              }
              if (_mSourceLabel) {
                const _mLoc = getNodeLoc(_mCur);
                const _mLabel = new TaintLabel(_mSourceLabel, _c.file, _mLoc.line || 0, _mLoc.column || 0, _scopeQualifyMemberExpr(_mCur, _c) || '');
                V.push(_applyOuterProps(TaintSet.from(_mLabel), _mOuterProps));
                _mResolved = true;
                break;
              }

              // Build scope-qualified path by resolving the deepest Identifier object
              let _mFullStr;
              if (_mCur.object?.type === 'Identifier') {
                _mFullStr = `${resolveId(_mCur.object, _c.scopeInfo)}.${_mCur.property?.name || _mCur.property?.value || _mCur.property?.value || ''}`;
              } else {
                // Multi-level: walk to find the root Identifier and scope-qualify it
                let _mRoot = _mCur;
                const _mParts = [];
                while (_mRoot.type === 'MemberExpression' || _mRoot.type === 'OptionalMemberExpression') {
                  _mParts.unshift(_mRoot.property?.name || _mRoot.property?.value || _mRoot.property?.value || '');
                  _mRoot = _mRoot.object;
                }
                if (_mRoot.type === 'Identifier') {
                  _mFullStr = `${resolveId(_mRoot, _c.scopeInfo)}.${_mParts.join('.')}`;
                } else {
                  _mFullStr = _scopeQualifyMemberExpr(_mCur, _c);
                }
              }
              if (_mFullStr) {
                const _mResolvedStr = resolveAliasedPath(_mFullStr, _e);
                if (_mResolvedStr !== _mFullStr && MEMBER_SOURCES[_mResolvedStr]) {
                  const _mLoc = getNodeLoc(_mCur);
                  V.push(_applyOuterProps(TaintSet.from(new TaintLabel(MEMBER_SOURCES[_mResolvedStr], _c.file, _mLoc.line || 0, _mLoc.column || 0, _mResolvedStr)), _mOuterProps));
                  _mResolved = true;
                  break;
                }
              }
              if (!_mCur.computed && _mCur.object?.type === 'Identifier') {
                const _mAlias = _e.getAlias(resolveId(_mCur.object, _c.scopeInfo));
                if (_mAlias && _mCur.property) {
                  const _mPropName = _mCur.property.name || _mCur.property.value;
                  // Global scope objects: window.X === X, self.X === X
                  let _mDeepPath = `${_mAlias}.${_mPropName}`;
                  if (_GLOBAL_SCOPE_OBJECTS.has(_mAlias) && _mOuterProps.length > 0) {
                    // Re-evaluate as global: w.location.hash → location.hash
                    const _mGlobalPath = `${_mPropName}.${_mOuterProps.map(p => p.name || p.value).join('.')}`;
                    if (MEMBER_SOURCES[_mGlobalPath]) {
                      const _mLoc = getNodeLoc(_mCur);
                      V.push(TaintSet.from(new TaintLabel(MEMBER_SOURCES[_mGlobalPath], _c.file, _mLoc.line || 0, _mLoc.column || 0, _mGlobalPath)));
                      _mResolved = true;
                      break;
                    }
                  }
                  if (MEMBER_SOURCES[_mDeepPath]) {
                    const _mLoc = getNodeLoc(_mCur);
                    V.push(_applyOuterProps(TaintSet.from(new TaintLabel(MEMBER_SOURCES[_mDeepPath], _c.file, _mLoc.line || 0, _mLoc.column || 0, _mDeepPath)), _mOuterProps));
                    _mResolved = true;
                    break;
                  }
                }
              }

              const _mFP = _mFullStr;
              // Scope-qualified path for env and funcMap lookups
              let _mScopedPath = _mFP;
              if (!_mCur.computed && _mCur.object?.type === 'Identifier' && _mCur.property) {
                const _mResolvedObjKey = resolveId(_mCur.object, _c.scopeInfo);
                const _mMemberProp = _mCur.property.name || _mCur.property.value;
                if (_mMemberProp) _mScopedPath = `${_mResolvedObjKey}.${_mMemberProp}`;
              }
              if (_mScopedPath) {
                if (_e.has(_mScopedPath)) { V.push(_applyOuterProps(_e.get(_mScopedPath).clone(), _mOuterProps)); _mResolved = true; break; }
              }
              if (_mScopedPath) {
                const _mGetterFunc = _c.funcMap.get(`getter:${_mScopedPath}`);
                if (_mGetterFunc && _mGetterFunc.body) {
                  const _mChildEnv = (_mGetterFunc._closureEnv || _e).child();
                  // Copy obj.* funcMap entries to this.* so getter body can call this.method()
                  const _mGetterObjKey = _mScopedPath.slice(0, _mScopedPath.lastIndexOf('.'));
                  if (_mGetterObjKey) {
                    const _mObjPrefix = _mGetterObjKey + '.';
                    for (const [fk, fv] of _c.funcMap) {
                      if (fk.startsWith(_mObjPrefix)) {
                        _c.funcMap.set(`this.${fk.slice(_mObjPrefix.length)}`, fv);
                      }
                    }
                  }
                  const _mGetterTaint = analyzeInlineFunction(_mGetterFunc, _mChildEnv, _c);
                  if (_mGetterTaint.tainted) { V.push(_applyOuterProps(_mGetterTaint, _mOuterProps)); _mResolved = true; break; }
                }
              }

              const _mPropName = !_mCur.computed && _mCur.property ? (_mCur.property.name || _mCur.property.value) : null;
              if (_mPropName && (NUMERIC_PROPS.has(_mPropName) || _mPropName === 'constructor' || _mPropName === 'prototype')) {
                // If the object might have side effects (assignment), evaluate it first
                if (_mCur.object && (_mCur.object.type === 'AssignmentExpression' ||
                    (_mCur.object.type === 'ParenthesizedExpression' && _mCur.object.expression?.type === 'AssignmentExpression'))) {
                  W.push({ kind: W_CONTINUATION, label: C_MEMBER_EXPR, subtype: 'root', outerProps: [], env: _e, ctx: _c });
                  W.push({ kind: W_EVAL_EXPR, node: _mCur.object, env: _e, ctx: _c });
                } else {
                  V.push(TaintSet.empty());
                }
                _mResolved = true;
                break;
              }

              // Computed access: push continuation to evaluate object + property via W/V
              if (_mCur.computed) {
                W.push({ kind: W_CONTINUATION, label: C_MEMBER_EXPR, subtype: 'computed', node: _mCur, outerProps: _mOuterProps.slice(), env: _e, ctx: _c });
                W.push({ kind: W_EVAL_EXPR, node: _mCur.property, env: _e, ctx: _c });
                W.push({ kind: W_EVAL_EXPR, node: _mCur.object, env: _e, ctx: _c });
                _mResolved = true;
                break;
              }

              if (_mPropName) _mOuterProps.push(_mPropName);
              _mCur = _mCur.object;
            }

            if (!_mResolved) {
              // Root non-MemberExpression — evaluate via W/V
              W.push({ kind: W_CONTINUATION, label: C_MEMBER_EXPR, subtype: 'root', outerProps: _mOuterProps.slice(), env: _e, ctx: _c });
              W.push({ kind: W_EVAL_EXPR, node: _mCur, env: _e, ctx: _c });
            }
            break;
          }
          // ── Stage 7: CallExpression (iterative arg + callee evaluation) ──
          case 'CallExpression':
          case 'OptionalCallExpression': {
            // Handle import() with 'Import' callee type (Babel legacy)
            if (_n.callee.type === 'Import' && _n.arguments.length > 0) {
              W.push({ kind: W_CONTINUATION, label: C_IMPORT_EXPR, node: _n, ctx: _c });
              W.push({ kind: W_EVAL_EXPR, node: _n.arguments[0], env: _e, ctx: _c });
              break;
            }

            // Pre-compute calleeStr & methodName (scope-qualified)
            let _cCalleeStr = null;
            let _cMethodName = '';
            if (_n.callee.type === 'Identifier') {
              _cCalleeStr = resolveId(_n.callee, _c.scopeInfo);
            } else if (_n.callee.type === 'MemberExpression' || _n.callee.type === 'OptionalMemberExpression') {
              if (_n.callee.computed) {
                const _cmAV = resolveAbstract(_n.callee.property, _e, _c);
                if (_cmAV.concrete && _cmAV.value) _cMethodName = _cmAV.value;
              } else {
                _cMethodName = _n.callee.property?.name || '';
              }
              // Scope-qualify the object part
              if (_n.callee.object?.type === 'Identifier' && _cMethodName) {
                const objKey = _resolveObjKey(_n.callee.object, _c);
                _cCalleeStr = `${objKey}.${_cMethodName}`;
              } else {
                _cCalleeStr = _scopeQualifyMemberExpr(_n.callee, _c);
              }
            } else {
              _cCalleeStr = _scopeQualifyMemberExpr(_n.callee, _c);
            }
            if (_cCalleeStr && _n.callee.type === 'Identifier') {
              const _calleeScopeKey = resolveId(_n.callee, _c.scopeInfo);
              const alias = _e.getAlias(_calleeScopeKey);
              if (alias) _cCalleeStr = alias;
              // Resolve through parameter→arg name mapping (e.g., fn param received eval)
              if (_c._paramArgNames) {
                const paramArg = _c._paramArgNames.get(_n.callee.name);
                if (paramArg) _cCalleeStr = paramArg;
              }
              // Deep resolution: follow scope/init chains to resolve aliased builtins
              // e.g., Qu = mn.Object → "Object" when mn resolves to window/self/globalThis
              if (!_e.getAlias(_cCalleeStr) && !_c.funcMap.has(_cCalleeStr)) {
                const identity = resolveCalleeIdentity(_n.callee, _e, _c);
                if (identity) _cCalleeStr = identity;
              }
            }
            if (_cCalleeStr && (_n.callee.type === 'MemberExpression' || _n.callee.type === 'OptionalMemberExpression')) {
              const _memberScopeKey = _scopeQualifyMemberExpr(_n.callee, _c);
              const memberAlias = _memberScopeKey && _e.getAlias(_memberScopeKey);
              if (memberAlias) _cCalleeStr = memberAlias;
            }
            if (!_cCalleeStr && _n.callee.type === 'SequenceExpression') {
              const last = _n.callee.expressions[_n.callee.expressions.length - 1];
              if (last) { const lastStr = _scopeQualifyMemberExpr(last, _c); if (lastStr) _cCalleeStr = lastStr; }
            }
            if (!_cCalleeStr && _n.callee.type === 'LogicalExpression') {
              const leftStr = _scopeQualifyMemberExpr(_n.callee.left, _c);
              const rightStr = _scopeQualifyMemberExpr(_n.callee.right, _c);
              const _lcAV = resolveAbstract(_n.callee.left, _e, _c);
              if (_n.callee.operator === '??') {
                if (!_lcAV.concrete || _lcAV.value === null || _lcAV.value === undefined) _cCalleeStr = rightStr;
                else _cCalleeStr = leftStr;
              } else if (_n.callee.operator === '||') {
                if (_lcAV.concrete && !_lcAV.value) _cCalleeStr = rightStr;
                else if (_lcAV.concrete && _lcAV.value) _cCalleeStr = leftStr;
                else _cCalleeStr = rightStr || leftStr;
              } else if (_n.callee.operator === '&&') {
                if (_lcAV.concrete && _lcAV.value) _cCalleeStr = rightStr;
                else if (_lcAV.concrete && !_lcAV.value) _cCalleeStr = leftStr;
                else _cCalleeStr = rightStr || leftStr;
              }
              if (_cCalleeStr) {
                const parts = _cCalleeStr.split('.');
                _cMethodName = parts[parts.length - 1];
              }
            }

            // Determine if callee needs W/V evaluation for side effects
            const _cNeedCalleeEval = _n.callee.type === 'CallExpression' ||
                                     _n.callee.type === 'OptionalCallExpression' ||
                                     _n.callee.type === 'NewExpression' ||
                                     _n.callee.type === 'ConditionalExpression';
            // Determine if callee.object needs W/V evaluation (for handleBuiltinMethod objTaint)
            const _cHasObjEval = !!(_n.callee?.object &&
              (_n.callee.type === 'MemberExpression' || _n.callee.type === 'OptionalMemberExpression'));

            // Push continuation (processed last)
            // V pop order: args (N), then objTaint (if hasObjEval), then calleeResult (if hasCalleeEval)
            W.push({ kind: W_CONTINUATION, label: C_CALL_ARGS,
                     node: _n, calleeStr: _cCalleeStr, methodName: _cMethodName,
                     argCount: _n.arguments.length,
                     hasCalleeEval: _cNeedCalleeEval,
                     hasObjEval: _cHasObjEval,
                     env: _e, ctx: _c });
            // Push args in reverse (last pushed = first evaluated)
            for (let i = _n.arguments.length - 1; i >= 0; i--) {
              W.push({ kind: W_EVAL_EXPR, node: _n.arguments[i], env: _e, ctx: _c });
            }
            // Push callee.object eval (processed before args, after callee)
            if (_cHasObjEval) {
              W.push({ kind: W_EVAL_EXPR, node: _n.callee.object, env: _e, ctx: _c });
            }
            // Push callee eval if needed (processed first, before everything)
            if (_cNeedCalleeEval) {
              W.push({ kind: W_EVAL_EXPR, node: _n.callee, env: _e, ctx: _c });
            }
            break;
          }
          case 'NewExpression': {
            // Pre-compute constructorName (scope-qualified)
            let _nCtorName = _n.callee.type === 'Identifier' ? resolveId(_n.callee, _c.scopeInfo)
              : (_scopeQualifyMemberExpr(_n.callee, _c));
            if (_nCtorName && _n.callee.type === 'Identifier') {
              const alias = _e.getAlias ? _e.getAlias(_nCtorName) : _e.aliases.get(_nCtorName);
              if (alias) _nCtorName = alias;
            }
            // Push continuation + args via W/V
            W.push({ kind: W_CONTINUATION, label: C_NEW_ARGS,
                     node: _n, constructorName: _nCtorName,
                     argCount: _n.arguments.length,
                     env: _e, ctx: _c });
            for (let i = _n.arguments.length - 1; i >= 0; i--) {
              W.push({ kind: W_EVAL_EXPR, node: _n.arguments[i], env: _e, ctx: _c });
            }
            break;
          }
          case 'TaggedTemplateExpression': {
            const exprs = _n.quasi.expressions;
            W.push({ kind: W_CONTINUATION, label: C_TAGGED_TEMPLATE, count: exprs.length, node: _n, env: _e, ctx: _c });
            for (let i = exprs.length - 1; i >= 0; i--) {
              W.push({ kind: W_EVAL_EXPR, node: exprs[i], env: _e, ctx: _c });
            }
            if (exprs.length === 0) V.push(TaintSet.empty()); // sentinel for 0-expr case
            break;
          }
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
              else if (isObjectProp(prop))
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
              const loc = getNodeLoc(item.node);
              pushFinding(item.ctx, {
                type: 'XSS',
                severity: 'critical',
                title: 'XSS: tainted data flows to dynamic import()',
                sink: makeSinkInfo('import()', item.ctx, loc, 'TrustedScriptURL'),
                source: formatSources(specifierTaint),
                path: buildTaintPath(specifierTaint, 'import()'),
              });
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
                  const objKey = resolveId(operand, item.ctx.scopeInfo);
                  for (const methodName of ['toString', 'valueOf']) {
                    // Scope-aware coercion lookup: prefer scope-qualified key.
                    // Fall back to bare name ONLY if the scope-qualified key doesn't
                    // exist in funcMap at all (meaning the method was registered before
                    // scope-qualified registration was available). If the scope-qualified
                    // key was registered (possibly as null/undefined), the bare name
                    // might be from a DIFFERENT scope — skip to prevent cross-scope collision.
                    const coercionFunc = item.ctx.funcMap.get(`${objKey}.${methodName}`);
                    if (coercionFunc && coercionFunc.body) {
                      const synthCall = { type: 'CallExpression', callee: operand, arguments: [], loc: operand.loc };
                      const coercionTaint = analyzeCalledFunction(synthCall, `${objKey}.${methodName}`, [], item.env, item.ctx);
                      result = result.merge(coercionTaint);
                    }
                  }
                  // Check Symbol.toPrimitive: obj[Symbol.toPrimitive] = fn → registered as obj[] in funcMap
                  if (!result.tainted) {
                    const toPrimFunc = item.ctx.funcMap.get(`${objKey}[]`);
                    if (toPrimFunc && toPrimFunc.body) {
                      const synthCall = { type: 'CallExpression', callee: operand, arguments: [], loc: operand.loc };
                      const coercionTaint = analyzeCalledFunction(synthCall, `${objKey}[]`, [], item.env, item.ctx);
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
            const constCond = isConstantBool(cn.test, item.ctx);
            if (constCond === true) {
              // Definite true: evaluate consequent as final result
              W.push({ kind: W_CONTINUATION, label: C_COND_FINAL, accum: TaintSet.empty(), ctx: item.ctx, node: cn.consequent });
              W.push({ kind: W_EVAL_EXPR, node: cn.consequent, env: item.env, ctx: item.ctx });
            } else if (constCond === false) {
              // Definite false: skip to alternate
              conditionalStep(item.accum, cn.alternate, item.env, item.ctx, W, V);
            } else {
              // Unknown: evaluate consequent, then continue to alternate
              const checkedVar = extractSchemeCheck(cn.test, true, item.ctx);
              W.push({ kind: W_CONTINUATION, label: C_COND_BRANCH, accum: item.accum, cn, env: item.env, ctx: item.ctx, checkedVar, hadCheck: checkedVar && item.env.schemeCheckedVars.has(checkedVar) });
              if (checkedVar && !item.env.schemeCheckedVars.has(checkedVar)) item.env.schemeCheckedVars.add(checkedVar);
              W.push({ kind: W_EVAL_EXPR, node: cn.consequent, env: item.env, ctx: item.ctx });
            }
            break;
          }
          case C_COND_BRANCH: {
            let consequentTaint = V.pop();
            const cn = item.cn;
            if (item.checkedVar && !item.hadCheck) item.env.schemeCheckedVars.delete(item.checkedVar);
            // Annotate consequent taint with positive branch constraints.
            // The consequent only executes when the condition is true, so constraints
            // from the true branch apply to these taint labels. Uses a temp env to
            // extract constraints without modifying the real env (avoids side-effect breakage).
            if (consequentTaint.tainted) {
              const _tmp = new TaintEnv();
              _tmp._branchConstraints = [];
              applyBranchCondition(cn.test, true, _tmp, item.ctx);
              for (const _c of _tmp._branchConstraints) {
                consequentTaint = consequentTaint.withConstraint(_c);
              }
            }
            let accum = item.accum.merge(consequentTaint);
            if (!item.ctx.returnedFuncNode && cn.consequent.type === 'Identifier') {
              const refKey = resolveId(cn.consequent, item.ctx.scopeInfo);
              const funcRef = item.ctx.funcMap.get(refKey);
              if (funcRef) item.ctx.returnedFuncNode = funcRef;
            }
            // Apply negated branch constraint to alternate env — the false branch
            // only executes when the condition is false, so any condition checks
            // (e.g., key === "__proto__") are negated on this path.
            const altEnv = item.env.clone();
            applyBranchCondition(cn.test, false, altEnv, item.ctx);
            conditionalStep(accum, cn.alternate, altEnv, item.ctx, W, V);
            break;
          }
          case C_COND_FINAL: {
            const taint = V.pop();
            const result = item.accum.merge(taint);
            // Check for returnedFuncNode on the final node (passed via item.node if set)
            if (item.node && !item.ctx.returnedFuncNode && item.node.type === 'Identifier') {
              const refKey = resolveId(item.node, item.ctx.scopeInfo);
              const funcRef = item.ctx.funcMap.get(refKey);
              if (funcRef) item.ctx.returnedFuncNode = funcRef;
            }
            V.push(result);
            break;
          }
          case C_TAGGED_TEMPLATE: {
            const exprTaints = [];
            if (item.count === 0) {
              V.pop(); // pop sentinel
            } else {
              for (let i = 0; i < item.count; i++) exprTaints.push(V.pop());
              exprTaints.reverse();
            }
            V.push(_evaluateTaggedTemplateBody(item.node, exprTaints, item.env, item.ctx));
            break;
          }
          case C_MEMBER_EXPR: {
            if (item.subtype === 'root') {
              const rootTaint = V.pop();
              V.push(_applyOuterProps(rootTaint, item.outerProps));
            } else if (item.subtype === 'computed') {
              // W push order: continuation, property, object → object eval first, property second
              // V pop order: keyTaint (top, last pushed), objTaint (below)
              const keyTaint = V.pop();
              const objTaint = V.pop();
              V.push(_applyOuterProps(_evaluateComputedMemberBody(item.node, objTaint, keyTaint, item.env, item.ctx), item.outerProps));
            }
            break;
          }
          case C_CALL_ARGS: {
            // Pop arg taints: last pushed = on top, so pop in reverse then reverse array
            const argTaints = [];
            for (let i = 0; i < item.argCount; i++) argTaints.push(V.pop());
            argTaints.reverse();
            const objTaint = item.hasObjEval ? V.pop() : TaintSet.empty();
            if (item.hasCalleeEval) V.pop(); // discard callee result (side effects already done)
            V.push(_evaluateCallExprBody(item.node, item.calleeStr, item.methodName, argTaints, objTaint, item.env, item.ctx));
            break;
          }
          case C_NEW_ARGS: {
            const argTaints = [];
            for (let i = 0; i < item.argCount; i++) argTaints.push(V.pop());
            argTaints.reverse();
            V.push(_evaluateNewExprBody(item.node, item.constructorName, argTaints, item.env, item.ctx));
            break;
          }
        }
        break;
      }
    }
  }

  return V.pop() || TaintSet.empty();
}

// ── Tagged template body (called from C_TAGGED_TEMPLATE continuation) ──
function _evaluateTaggedTemplateBody(node, exprTaints, env, ctx) {
  const stringsArg = TaintSet.empty();
  const allArgTaints = [stringsArg, ...exprTaints];
  const tagCallee = node.tag;
  let funcNode = null;
  if (tagCallee.type === 'Identifier') {
    funcNode = ctx.funcMap.get(resolveId(tagCallee, ctx.scopeInfo));
  } else if (tagCallee.type === 'MemberExpression') {
    const tagStr = _scopeQualifyMemberExpr(tagCallee, ctx);
    if (tagStr) funcNode = ctx.funcMap.get(tagStr);
  }
  // Check sanitizer BEFORE attempting function analysis or fallback merge
  const tagCalleeStr = _scopeQualifyMemberExpr(tagCallee, ctx);
  const tagMethodName = tagCallee.type === 'MemberExpression' ? (tagCallee.property?.name || '') : '';
  if (isSanitizer(tagCalleeStr, tagMethodName)) return TaintSet.empty();

  if (funcNode && funcNode.body) {
    const synthCall = { type: 'CallExpression', callee: tagCallee, arguments: [{ type: 'ArrayExpression', elements: [] }, ...node.quasi.expressions] };
    return analyzeCalledFunction(synthCall, tagCalleeStr, allArgTaints, env, ctx);
  }
  const t = TaintSet.empty();
  for (const et of exprTaints) t.merge(et);
  return t;
}

// Standalone helper: apply accumulated outer-property transforms to a taint result
function _applyOuterProps(taint, outerProps) {
  if (!taint.tainted || outerProps.length === 0) return taint;
  let result = taint;
  for (let i = outerProps.length - 1; i >= 0; i--) {
    result = result.withTransform({ op: 'property', args: [outerProps[i]] });
  }
  return result;
}

// Body of computed member evaluation — keyTaint is pre-computed by W/V stack
function _evaluateComputedMemberBody(node, objTaint, keyTaint, env, ctx) {
    // For computed access with a constant key (obj['key'], arr[0], obj[constVar]),
    // do per-property lookup — precise, not overapproximated
    let litKey = null;
    if (isStringLiteral(node.property)) {
      litKey = stringLiteralValue(node.property);
    } else if (isNumericLit(node.property)) {
      litKey = String(node.property.value);
    } else {
      // Try to resolve identifier to constant: obj[key] where key = 'prop'
      const _av = resolveAbstract(node.property, env, ctx);
      if (_av.concrete) litKey = String(_av.value);
    }
    // Only trust resolved key when it came directly from a literal (not a variable that might change)
    const isDirectLiteral = isStringLiteral(node.property) ||
      node.property.type === 'NumericLiteral' ||
      (node.property.type === 'Literal' && (typeof node.property.value === 'string' || typeof node.property.value === 'number'));
    if (litKey !== null && isDirectLiteral) {
      const objStr = _scopeQualifyMemberExpr(node.object, ctx);
      if (objStr) {
        if (env.has(`${objStr}.${litKey}`)) {
          const t = env.get(`${objStr}.${litKey}`).clone();
          return t.tainted && /^\d+$/.test(litKey) ? t.withTransform({ op: 'index', args: [Number(litKey)] }) : t;
        }
        if (/^\d+$/.test(litKey) && env.has(`${objStr}.#idx_${litKey}`)) {
          const t = env.get(`${objStr}.#idx_${litKey}`).clone();
          return t.tainted ? t.withTransform({ op: 'index', args: [Number(litKey)] }) : t;
        }
      }
      if (node.object?.type === 'Identifier') {
        const resolvedKey = resolveId(node.object, ctx.scopeInfo);
        if (env.has(`${resolvedKey}.${litKey}`)) {
          const t = env.get(`${resolvedKey}.${litKey}`).clone();
          return t.tainted && /^\d+$/.test(litKey) ? t.withTransform({ op: 'index', args: [Number(litKey)] }) : t;
        }
        if (/^\d+$/.test(litKey) && env.has(`${resolvedKey}.#idx_${litKey}`)) {
          const t = env.get(`${resolvedKey}.#idx_${litKey}`).clone();
          return t.tainted ? t.withTransform({ op: 'index', args: [Number(litKey)] }) : t;
        }
      }
    }
    // For variable-resolved keys (obj[key] where key='prop'), do per-property lookup
    // but also fall through to prefix check to handle mutable variables (loop counters)
    if (litKey !== null && !isDirectLiteral) {
      const objStr = _scopeQualifyMemberExpr(node.object, ctx);
      if (objStr) {
        if (env.has(`${objStr}.${litKey}`)) {
          return env.get(`${objStr}.${litKey}`).clone();
        }
        // Check #idx_ prefix for per-index entries (arguments.#idx_N)
        if (/^\d+$/.test(litKey) && env.has(`${objStr}.#idx_${litKey}`)) {
          const t = env.get(`${objStr}.#idx_${litKey}`).clone();
          return t.tainted ? t.withTransform({ op: 'index', args: [Number(litKey)] }) : t;
        }
      }
      if (node.object?.type === 'Identifier') {
        const resolvedKey = resolveId(node.object, ctx.scopeInfo);
        if (env.has(`${resolvedKey}.${litKey}`)) {
          return env.get(`${resolvedKey}.${litKey}`).clone();
        }
        if (/^\d+$/.test(litKey) && env.has(`${resolvedKey}.#idx_${litKey}`)) {
          const t = env.get(`${resolvedKey}.#idx_${litKey}`).clone();
          return t.tainted ? t.withTransform({ op: 'index', args: [Number(litKey)] }) : t;
        }
      }
      // Fall through to prefix check for overapproximation (variable might hold different values)
    }
    // For dynamic computed access obj[key], check if any obj.* properties are tainted
    // When the key is tainted, the attacker controls which property is selected,
    // but the VALUE read carries its own taint — don't propagate key taint as value taint.
    const objStr = _scopeQualifyMemberExpr(node.object, ctx);
    if (globalThis._TAINT_DEBUG) console.log('[ECM-DYN] objStr=' + objStr + ' litKey=' + litKey + ' objTainted=' + objTaint.tainted);
    if (objStr) {
      const taintedProps = env.getTaintedWithPrefix(objStr + '.');
      if (taintedProps.size > 0) {
        const merged = TaintSet.empty();
        for (const [, taint] of taintedProps) merged.merge(taint);
        return merged;
      }
    }
    if (node.object?.type === 'Identifier') {
      const resolvedKey = resolveId(node.object, ctx.scopeInfo);
      if (resolvedKey !== objStr) {
        const resolvedProps = env.getTaintedWithPrefix(`${resolvedKey}.`);
        if (resolvedProps.size > 0) {
          const merged = TaintSet.empty();
          for (const [, taint] of resolvedProps) merged.merge(taint);
          return merged;
        }
      }
    }
    // If the object itself is tainted (e.g. from JSON.parse), reading any property is tainted.
    // But prefer per-property taint (from overapproximation above) when available,
    // as it carries more specific source labels than the base taint.
    if (objTaint.tainted) {
      // Check if there are per-property entries with proper source labels first
      const _objStr2 = objStr || (node.object?.type === 'Identifier' ? resolveId(node.object, ctx.scopeInfo) : null);
      if (_objStr2) {
        const _perPropTaint = env.getTaintedWithPrefix(_objStr2 + '.');
        if (_perPropTaint.size > 0) {
          const merged = TaintSet.empty();
          for (const [, taint] of _perPropTaint) merged.merge(taint);
          if (merged.tainted) return merged;
        }
      }
      const propName = !node.computed && node.property ? (node.property.name || node.property.value) : litKey;
      return propName ? objTaint.withTransform({ op: 'property', args: [propName] }) : objTaint.clone();
    }

    // Level 1: Track builtin member access through parameters
    // When n[t] where n resolves to a builtin object (Object, Array, etc.) and t resolves to a method name,
    // set _returnedBuiltinAlias so the caller knows this expression yields a builtin reference.
    // This enables: Be(Object, "defineProperty") → returns Object.defineProperty → tracked through chain.
    if (litKey && node.object?.type === 'Identifier') {
      const _BUILTIN_OBJS = ['Object', 'Array', 'Reflect', 'JSON', 'Math', 'Number', 'String', 'Boolean', 'Promise', 'Symbol'];
      const objName = node.object.name;
      const objScopeKey = resolveId(node.object, ctx.scopeInfo);
      // Resolve object name: through _paramArgNames (fn param), env.getAlias (walks parent chain)
      let resolvedObjName = ctx._paramArgNames?.get(objName) || objName;
      const _getAlias = (n) => env.getAlias ? env.getAlias(n) : env.aliases?.get(n);
      resolvedObjName = _getAlias(objScopeKey) || resolvedObjName;
      // Also check if objName itself has a direct alias
      if (!_BUILTIN_OBJS.includes(resolvedObjName)) {
        const directAlias = _getAlias(objScopeKey);
        if (directAlias) resolvedObjName = directAlias;
      }
      if (_BUILTIN_OBJS.includes(resolvedObjName)) {
        ctx._returnedBuiltinAlias = `${resolvedObjName}.${litKey}`;
        if (globalThis._TAINT_DEBUG) console.log(`[BUILTIN-MEMBER-L1] ${objName}[${litKey}] → ${ctx._returnedBuiltinAlias} (objName=${objName} resolved=${resolvedObjName})`);
      }
    }

    // If key is tainted but object has no tainted values, the read value is safe
  return objTaint;
}

// ── AST-based callee matching ──
// Verifies a CallExpression callee matches a specific Object.method pattern
// by walking the AST structure directly, not converting to string.
// Handles aliasing: if `Array` is shadowed, `isCalleeMatch` returns false.
function isCalleeMatch(node, objectName, methodName, env, ctx) {
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
      const alias = env?.getAlias ? env.getAlias(resolveId(callee.object, ctx.scopeInfo)) : env?.aliases?.get(resolveId(callee.object, ctx.scopeInfo));
      if (alias === objectName) return true;
    }
  }
  // Aliased builtin: var Ai = Object.defineProperty; Ai(...) matches Object.defineProperty
  if (callee.type === 'Identifier' && env?.getAlias) {
    const alias = env.getAlias(ctx.scopeInfo ? (ctx.scopeInfo.resolve(callee) || callee.name) : callee.name);
    if (globalThis._TAINT_DEBUG && methodName === 'defineProperty') {
      // Verbose: trace the parent chain to find where alias might be
      let depth = 0;
      let cur = env;
      let chain = '';
      while (cur && depth < 10) {
        const _dbgKey = ctx.scopeInfo ? (ctx.scopeInfo.resolve(callee) || callee.name) : callee.name;
        const a = cur.aliases?.get(_dbgKey);
        chain += `[d${depth}:${a||'-'}] `;
        cur = cur.parent;
        depth++;
      }
      console.log(`[isCalleeMatch] callee=${callee.name} want=${objectName}.${methodName} alias=${alias} chain=${chain}`);
    }
    if (alias === `${objectName}.${methodName}`) return true;
  }
  return false;
}
// Match bare function name (e.g., eval, setTimeout) by AST Identifier type
function isCalleeIdentifier(node, name, env, ctx) {
  const callee = node.callee;
  if (!callee || callee.type !== 'Identifier') return false;
  if (callee.name === name) return true;
  const _ciKey = ctx.scopeInfo ? (ctx.scopeInfo.resolve(callee) || callee.name) : callee.name;
  const alias = env?.getAlias ? env.getAlias(_ciKey) : env?.aliases?.get(_ciKey);
  return alias === name;
}

// Check if a node refers to a well-known global by AST structure.
// Matches: bare Identifier (e.g., localStorage), or window.localStorage, self.localStorage, globalThis.localStorage
// Also resolves aliases via env.
function isGlobalRef(node, globalName, env, ctx) {
  if (!node) return false;
  if (node.type === 'Identifier') {
    if (node.name === globalName) return true;
    const _grKey = resolveId(node, ctx.scopeInfo);
    const alias = env?.getAlias ? env.getAlias(_grKey) : env?.aliases?.get(_grKey);
    if (alias === globalName) return true;
    return false;
  }
  if (node.type === 'MemberExpression' && !node.computed) {
    if (node.property?.name !== globalName) return false;
    if (node.object?.type === 'Identifier') {
      const objName = node.object.name;
      if (objName === 'window' || objName === 'self' || objName === 'globalThis') return true;
      const _grObjKey = ctx.scopeInfo ? (ctx.scopeInfo.resolve(node.object) || objName) : objName;
      const alias = env?.getAlias ? env.getAlias(_grObjKey) : env?.aliases?.get(_grObjKey);
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
// Body of call expression evaluation — calleeStr, methodName, argTaints, objTaint pre-computed by W/V
function _evaluateCallExprBody(node, calleeStr, methodName, argTaints, objTaint, env, ctx) {
  // Strip scope prefix for sink/source/sanitizer matching (these use bare names like "eval", "JSON.parse")
  // calleeStr is scope-qualified for funcMap lookups, bareCallee for external API matching
  const bareCallee = _stripScopePrefix(calleeStr);

  if (isSanitizer(bareCallee, methodName)) return TaintSet.empty();

  const sinkInfo = checkCallSink(bareCallee, methodName);
  if (sinkInfo) checkSinkCall(node, sinkInfo, argTaints, bareCallee || methodName, env, ctx);

  // Function(bodyStr) — parse constant string body into a real function AST
  if (bareCallee === 'Function' || bareCallee === 'window.Function' ||
      bareCallee === 'self.Function' || bareCallee === 'globalThis.Function') {
    const parsedFunc = parseFunctionConstructor(node.arguments);
    if (parsedFunc) ctx.returnedFuncNode = parsedFunc;
  }

  // DOM attachment tracking: parent.appendChild(child), parent.append(child), etc.
  // Child becomes attached only if parent is attached
  if (methodName === 'appendChild' || methodName === 'append' || methodName === 'prepend' ||
      methodName === 'insertBefore' || methodName === 'replaceChild' || methodName === 'insertAdjacentElement' ||
      methodName === 'after' || methodName === 'before' || methodName === 'replaceWith') {
    // Check if the parent (callee object) is DOM-attached
    const parentNode = node.callee?.object;
    let parentAttached = false;
    if (parentNode) {
      const parentKey = parentNode.type === 'Identifier' ? resolveId(parentNode, ctx.scopeInfo) : _scopeQualifyMemberExpr(parentNode, ctx);
      if (parentKey) {
        parentAttached = ctx.domAttached.has(parentKey);
        // Also check if parent is a known DOM access (document.body, etc.)
        if (!parentAttached) {
          const stripped = _stripScopePrefix(parentKey);
          parentAttached = stripped.startsWith('document.') || stripped === 'document';
          // Check variableTypes for DOM types
          if (!parentAttached && ctx.variableTypes.has(parentKey)) parentAttached = true;
        }
      }
    }
    if (parentAttached) {
      for (const arg of (node.arguments || [])) {
        if (arg.type === 'Identifier') {
          const key = resolveId(arg, ctx.scopeInfo);
          ctx.domAttached.add(key);
          // Flush deferred element property taints — these were set before attachment
          if (ctx._deferredElementTaints) {
            const deferred = ctx._deferredElementTaints.get(key);
            if (deferred) {
              ctx._deferredElementTaints.delete(key);
              const tag = ctx.elementTypes.get(key);
              if (tag) {
                for (const d of deferred) {
                  // Re-run sink check now that element is attached
                  checkElementPropertySink(d.leftNode, d.rhsTaint, d.rhsNode, d.env, ctx);
                }
              }
            }
          }
        }
      }
    }
  }

  // .constructor.constructor(code) — resolves to Function(code), equivalent to eval
  // Works with any base: x.constructor.constructor, "".constructor.constructor, [].constructor.constructor
  if (methodName === 'constructor') {
    const callee = node.callee;
    let isDoubleConstructor = false;
    if (bareCallee && bareCallee.endsWith('.constructor.constructor')) {
      isDoubleConstructor = true;
    } else if (callee.type === 'MemberExpression' && !callee.computed &&
               callee.property?.name === 'constructor' &&
               callee.object?.type === 'MemberExpression' && !callee.object.computed &&
               callee.object.property?.name === 'constructor') {
      // AST check: callee is X.constructor.constructor where X can be any expression (literal, etc.)
      isDoubleConstructor = true;
    }
    if (isDoubleConstructor) {
      const allArgIndices = argTaints.map((_, i) => i);
      checkSinkCall(node, { type: 'XSS', taintedArgs: allArgIndices }, argTaints, 'Function()', env, ctx);
    }
  }

  // Script element: el.setAttribute('src', tainted)
  if (methodName === 'setAttribute' && node.arguments.length >= 2) {
    const attrArg = node.arguments[0];
    let attrName = null;
    if (attrArg && isStringLiteral(attrArg)) {
      attrName = stringLiteralValue(attrArg).toLowerCase();
    } else if (attrArg) {
      const _av = resolveAbstract(attrArg, env, ctx);
      if (_av.concrete && typeof _av.value === 'string') attrName = _av.value.toLowerCase();
    }
    // Tainted attribute NAME (arg 0) — attacker can set onclick/onfocus/etc.
    const attrNameTaint = argTaints[0];
    if (attrNameTaint && attrNameTaint.tainted && node.callee?.object) {
      const objName = _scopeQualifyMemberExpr(node.callee.object, ctx);
      const loc = getNodeLoc(node);
      pushFinding(ctx, {
        type: 'XSS',
        severity: 'high',
        title: 'XSS: attacker-controlled attribute name in setAttribute',
        sink: makeSinkInfo(`${objName || 'element'}.setAttribute(tainted, ...)`, ctx, loc),
        source: formatSources(attrNameTaint),
        path: buildTaintPath(attrNameTaint, `${objName || 'element'}.setAttribute(tainted, ...)`),
      });
    }
    if (attrName) {
      const srcTaint = argTaints[1];
      if (srcTaint && srcTaint.tainted && node.callee?.object) {
        const objKey = _scopeQualifyMemberExpr(node.callee.object, ctx);
        const objName = _stripScopePrefix(objKey) || 'element';
        // Script element src
        if (attrName === 'src' && objKey && ctx.scriptElements.has(objKey)) {
          const loc = getNodeLoc(node);
          pushFinding(ctx, {
            type: 'XSS',
            severity: 'critical',
            title: 'XSS: tainted data flows to script element src',
            sink: makeSinkInfo(`${objName}.setAttribute('src')`, ctx, loc),
            source: formatSources(srcTaint),
            path: buildTaintPath(srcTaint, `${objName}.setAttribute('src')`),
          });
        }
        // Dangerous attributes: event handlers, href, action, srcdoc, formaction
        const DANGEROUS_ATTRS = new Set(['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onblur',
          'onchange', 'oninput', 'onsubmit', 'onkeydown', 'onkeyup', 'onkeypress',
          'href', 'action', 'formaction', 'srcdoc', 'src', 'data', 'style']);
        // Skip 'src'/'data' on safe elements (img, video, audio, source, picture)
        let skipAttr = false;
        if ((attrName === 'src' || attrName === 'data') && objName) {
          const tag = ctx.elementTypes.get(objKey) || ctx.elementTypes.get(objName);
          const SAFE_SRC_TAGS = new Set(['img', 'video', 'audio', 'source', 'picture', 'track']);
          if (tag && SAFE_SRC_TAGS.has(tag)) skipAttr = true;
        }
        // setAttribute sinks require DOM-attached elements — detached elements can't execute
        // javascript: URIs or event handlers. Apply same logic as innerHTML sinks:
        // only report if element is known DOM-attached, or is a direct document.X access
        if (!skipAttr && objKey) {
          const _bareObjName = _stripScopePrefix(objName);
          const isDomAccess = _bareObjName.startsWith('document.') || _bareObjName.includes('.document.');
          const isAttached = ctx.domAttached.has(objKey);
          const isTypedDom = ctx.variableTypes.has(objKey);
          // If element is tracked as createElement result but NOT attached → skip
          if (ctx.elementTypes.has(objKey) && !isAttached) skipAttr = true;
          // For href/action/formaction: require DOM attachment proof (same as innerHTML)
          const NEEDS_DOM = new Set(['href', 'action', 'formaction', 'srcdoc']);
          if (NEEDS_DOM.has(attrName) && !isAttached && !isDomAccess && !isTypedDom) skipAttr = true;
        }
        if (DANGEROUS_ATTRS.has(attrName) && !skipAttr) {
          const isEventHandler = EVENT_HANDLER_ATTRS.has(attrName);
          const isCss = attrName === 'style';
          const type = isCss ? 'CSS Injection' : 'XSS';
          const loc = getNodeLoc(node);
          pushFinding(ctx, {
            type,
            severity: isCss ? 'high' : (isEventHandler ? 'critical' : 'high'),
            title: `${type}: tainted data flows to setAttribute('${attrName}')`,
            sink: makeSinkInfo(`${objName || 'element'}.setAttribute('${attrName}')`, ctx, loc),
            source: formatSources(srcTaint),
            path: buildTaintPath(srcTaint, `${objName || 'element'}.setAttribute('${attrName}')`),
          });
        }
      }
    }
  }

  // setTimeout/setInterval/queueMicrotask/requestAnimationFrame with function callback:
  // analyze body for closure taint reaching sinks
  if ((isCalleeIdentifier(node, 'setTimeout', env, ctx) || isCalleeIdentifier(node, 'setInterval', env, ctx) ||
       isCalleeIdentifier(node, 'queueMicrotask', env, ctx) || isCalleeIdentifier(node, 'requestAnimationFrame', env, ctx)) && node.arguments[0]) {
    let callback = node.arguments[0];
    if (callback.type === 'Identifier') {
      const refKey = resolveId(callback, ctx.scopeInfo);
      callback = ctx.funcMap.get(refKey) || callback;
    }
    if (callback.type === 'ArrowFunctionExpression' || callback.type === 'FunctionExpression' ||
        callback.type === 'FunctionDeclaration') {
      const childEnv = (callback._closureEnv || env).child();
      const prevHandler = ctx._handlerContext;
      const _timerAV = node.arguments[1] ? resolveAbstract(node.arguments[1], env, ctx) : AV_UNKNOWN;
      ctx._handlerContext = { type: 'timer', delay: (_timerAV.concrete && typeof _timerAV.value === 'number') ? _timerAV.value : 0 };
      if (callback.body.type === 'BlockStatement') {
        analyzeInlineFunction(callback, childEnv, ctx);
      } else {
        evaluateExpr(callback.body, childEnv, ctx);
      }
      ctx._handlerContext = prevHandler;
    }
  }

  // Array.from(iterable) / Array.of(...items) — propagate taint from args
  if (isCalleeMatch(node, 'Array', 'from', env, ctx) || isCalleeMatch(node, 'Array', 'of', env, ctx)) {
    const merged = TaintSet.empty();
    for (const t of argTaints) merged.merge(t);
    return merged;
  }

  // Object.setPrototypeOf(obj, proto) — detect prototype pollution when proto is tainted
  if (isCalleeMatch(node, 'Object', 'setPrototypeOf', env, ctx) && node.arguments.length >= 2) {
    const protoTaint = argTaints[1];
    if (protoTaint && protoTaint.tainted) {
      const loc = getNodeLoc(node);
      pushFinding(ctx, {
        type: 'Prototype Pollution',
        severity: 'critical',
        title: 'Prototype Pollution: tainted data passed to Object.setPrototypeOf',
        sink: makeSinkInfo('Object.setPrototypeOf()', ctx, loc),
        source: formatSources(protoTaint),
        path: buildTaintPath(protoTaint, 'Object.setPrototypeOf()'),
      });
    }
    return TaintSet.empty();
  }

  // Object.fromEntries — propagate taint from entries (array of [key, value] pairs)
  if (isCalleeMatch(node, 'Object', 'fromEntries', env, ctx)) {
    return argTaints[0]?.clone() || TaintSet.empty();
  }

  // Reflect.get(obj, prop) → equivalent to obj[prop]
  if (isCalleeMatch(node, 'Reflect', 'get', env, ctx) && node.arguments.length >= 2) {
    const objNode = node.arguments[0];
    const propNode = node.arguments[1];
    const objScopeKey = _scopeQualifyMemberExpr(objNode, ctx);
    const objBareStr = _stripScopePrefix(_scopeQualifyMemberExpr(objNode, ctx) || '');
    if (isStringLiteral(propNode)) {
      const propName = stringLiteralValue(propNode);
      // Check if this resolves to a known taint source (e.g., Reflect.get(location, "hash"))
      if (objBareStr) {
        const sourceLabel = MEMBER_SOURCES[`${objBareStr}.${propName}`];
        if (sourceLabel) {
          const taint = new TaintSet();
          taint.add(new TaintLabel(sourceLabel, ctx.file, node.loc?.start?.line || 0, `${objBareStr}.${propName}`));
          return taint;
        }
      }
      // Per-property lookup using scope-qualified key
      if (objScopeKey && env.has(`${objScopeKey}.${propName}`)) return env.get(`${objScopeKey}.${propName}`).clone();
      if (objNode.type === 'Identifier') {
        const key = resolveId(objNode, ctx.scopeInfo);
        if (env.has(`${key}.${propName}`)) return env.get(`${key}.${propName}`).clone();
      }
    }
    // Fall back: if object itself is tainted, reading any property is tainted
    return argTaints[0]?.clone() || TaintSet.empty();
  }

  // Object.defineProperty(obj, prop, descriptor) — propagate taint from descriptor.value or getter
  if (isCalleeMatch(node, 'Object', 'defineProperty', env, ctx) && node.arguments.length >= 3) {
    const objNode = node.arguments[0];
    const propNode = node.arguments[1];
    const descNode = node.arguments[2];
    // Object.defineProperty sets OWN properties by JS spec — it never traverses the
    // prototype chain. PP only occurs when the TARGET is itself a prototype object.
    // Evaluate the target AST to determine if it's a prototype reference.
    const propKeyTaint = evaluateExpr(propNode, env, ctx);
    if (propKeyTaint.tainted && _isPrototypeNode(objNode)) {
      const loc = getNodeLoc(node);
      const objStr = _scopeQualifyMemberExpr(objNode, ctx) || 'obj';
      pushFinding(ctx, {
        type: 'Prototype Pollution',
        severity: 'critical',
        title: `Prototype Pollution: attacker controls property key on prototype via Object.defineProperty`,
        sink: makeSinkInfo(`Object.defineProperty(${objStr}, taintedKey)`, ctx, loc),
        source: formatSources(propKeyTaint),
        path: buildTaintPath(propKeyTaint, `Object.defineProperty(${objStr}, taintedKey)`),
      });
    }
    if (objNode && propNode && descNode && descNode.type === 'ObjectExpression') {
      const objKey = _scopeQualifyMemberExpr(objNode, ctx);
      const propName = isStringLiteral(propNode) ? stringLiteralValue(propNode) : null;
      for (const prop of descNode.properties) {
        if (isObjectProp(prop) && prop.key) {
          const descPropName = propKeyName(prop.key);
          if (descPropName === 'value') {
            const valTaint = evaluateExpr(prop.value, env, ctx);
            if (valTaint.tainted && objKey && propName) {
              env.set(`${objKey}.${propName}`, valTaint);
              // Detect Object.defineProperty(obj, '__proto__', {value: tainted}) as Prototype Pollution
              if (propName === '__proto__' || propName === 'prototype') {
                const loc = getNodeLoc(node);
                pushFinding(ctx, {
                  type: 'Prototype Pollution',
                  severity: 'critical',
                  title: `Prototype Pollution: tainted data set via Object.defineProperty on ${propName}`,
                  sink: makeSinkInfo(`Object.defineProperty(${objKey}, "${propName}")`, ctx, loc),
                  source: formatSources(valTaint),
                  path: buildTaintPath(valTaint, `Object.defineProperty(${objKey}, "${propName}")`),
                });
              }
            }
          }
          // Register getter function: Object.defineProperty(obj, 'prop', {get: function(){...}})
          if (descPropName === 'get' && propName) {
            const getterFunc = prop.value;
            if (getterFunc && (getterFunc.type === 'FunctionExpression' || getterFunc.type === 'ArrowFunctionExpression')) {
              getterFunc._closureEnv = env;
              const objKey = _resolveObjKey(objNode, ctx);
              if (objKey) ctx.funcMap.set(`getter:${objKey}.${propName}`, getterFunc);
            }
          }
          if (descPropName === 'set' && propName) {
            const setterFunc = prop.value;
            if (setterFunc && (setterFunc.type === 'FunctionExpression' || setterFunc.type === 'ArrowFunctionExpression')) {
              setterFunc._closureEnv = env;
              const objKey = _resolveObjKey(objNode, ctx);
              if (objKey) ctx.funcMap.set(`setter:${objKey}.${propName}`, setterFunc);
            }
          }
        }
      }
    }
    // Object.defineProperty returns its first argument — propagate callability
    if (objNode) {
      if (objNode.type === 'Identifier') {
        const key = resolveId(objNode, ctx.scopeInfo);
        const funcNode = ctx.funcMap.get(key);
        if (funcNode) ctx.returnedFuncNode = funcNode;
        if (globalThis._TAINT_DEBUG) console.log(`[ODP-RET] objNode=${objNode.name} key=${key} funcNode=${funcNode?.type}/${funcNode?.id?.name||'anon'} params=${funcNode?.params?.length} byKey=${!!ctx.funcMap.get(key)}`);
      } else if (isFuncExpr(objNode)) {
        ctx.returnedFuncNode = objNode;
      }
    }
    return argTaints[0]?.clone() || TaintSet.empty();
  }

  // Object.getOwnPropertyDescriptor(obj, prop) — return descriptor with getter/setter refs
  // When `var desc = Object.getOwnPropertyDescriptor(obj, "x")`, make desc.get resolve to the getter
  if (isCalleeMatch(node, 'Object', 'getOwnPropertyDescriptor', env, ctx) && node.arguments.length >= 2) {
    const objNode = node.arguments[0];
    const propNode = node.arguments[1];
    const objStr = _resolveObjKey(objNode, ctx);
    const propName = isStringLiteral(propNode) ? stringLiteralValue(propNode) : null;
    if (objStr && propName) {
      // Look up the getter registered for this property
      const getterFunc = ctx.funcMap.get(`getter:${objStr}.${propName}`);
      if (getterFunc) {
        // Store it so that when assigned to `var desc = ...`, desc.get resolves in funcMap
        // We use ctx._pendingDescriptorGetter which processAssignment will pick up
        ctx._pendingDescriptorGetter = { getter: getterFunc, propName };
      }
      // Return the taint of the property value itself
      const valTaint = env.get(`${objStr}.${propName}`);
      if (valTaint.tainted) return valTaint;
    }
    return TaintSet.empty();
  }

  // Object.create(proto, propertyDescriptors) — extract taint from descriptor values
  if (isCalleeMatch(node, 'Object', 'create', env, ctx) && node.arguments.length >= 2) {
    const descMapNode = node.arguments[1];
    if (descMapNode && descMapNode.type === 'ObjectExpression') {
      const resultTaint = TaintSet.empty();
      for (const prop of descMapNode.properties) {
        if (isObjectProp(prop) && prop.key && prop.value) {
          const propName = propKeyName(prop.key);
          if (propName && prop.value.type === 'ObjectExpression') {
            // Extract value from property descriptor: {value: ..., writable: ...}
            for (const descProp of prop.value.properties) {
              if (isObjectProp(descProp) &&
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
  if (isCalleeMatch(node, 'Reflect', 'apply', env, ctx) && node.arguments.length >= 3) {
    const fnNode = node.arguments[0];
    const argsArrayNode = node.arguments[2];
    // Extract individual arg taints from the array expression
    let spreadArgTaints = [];
    if (argsArrayNode && argsArrayNode.type === 'ArrayExpression' && argsArrayNode.elements) {
      spreadArgTaints = argsArrayNode.elements.map(el => el ? evaluateExpr(el, env, ctx) : TaintSet.empty());
    } else {
      const argsArrayTaint = argTaints[2] || TaintSet.empty();
      spreadArgTaints = [argsArrayTaint];
    }
    const funcName = _scopeQualifyMemberExpr(fnNode, ctx);
    const funcRef = funcName && ctx.funcMap.get(funcName);
    if (funcRef && funcRef.body) {
      const synthArgs = argsArrayNode?.type === 'ArrayExpression' ? argsArrayNode.elements.filter(Boolean) : [];
      const synthCall = { ...node, callee: fnNode, arguments: synthArgs };
      return analyzeCalledFunction(synthCall, funcName, spreadArgTaints, env, ctx);
    }
    // Check if target is a known call sink (e.g. eval, document.write)
    if (funcName) {
      const bareFuncName = _stripScopePrefix(funcName);
      const fnParts = bareFuncName.split('.');
      const fnMethodName = fnParts[fnParts.length - 1];
      const sinkInfo = checkCallSink(bareFuncName, fnMethodName);
      if (sinkInfo) {
        const synthArgs = argsArrayNode?.type === 'ArrayExpression' ? argsArrayNode.elements.filter(Boolean) : [];
        const synthCall = { ...node, callee: fnNode, arguments: synthArgs };
        checkSinkCall(synthCall, sinkInfo, spreadArgTaints, bareFuncName, env, ctx);
      }
    }
    return spreadArgTaints[0]?.clone() || TaintSet.empty();
  }

  // Reflect.construct(Target, args) — equivalent to new Target(...args)
  if (isCalleeMatch(node, 'Reflect', 'construct', env, ctx) && node.arguments.length >= 2) {
    const targetNode = node.arguments[0];
    const argsNode = node.arguments[1];
    // Synthesize a NewExpression and delegate to _evaluateNewExprBody
    const synthArgs = argsNode.type === 'ArrayExpression' ? argsNode.elements.filter(Boolean) : [];
    const synthNew = { ...node, type: 'NewExpression', callee: targetNode, arguments: synthArgs };
    let rCtorName = _scopeQualifyMemberExpr(targetNode, ctx);
    if (rCtorName && targetNode.type === 'Identifier') {
      const alias = env.aliases.get(rCtorName);
      if (alias) rCtorName = alias;
    }
    const rArgTaints = synthArgs.map(a => evaluateExpr(a, env, ctx));
    return _evaluateNewExprBody(synthNew, rCtorName, rArgTaints, env, ctx);
  }

  // Reflect.set(obj, prop, value) — detect __proto__ as Prototype Pollution
  if (isCalleeMatch(node, 'Reflect', 'set', env, ctx) && node.arguments.length >= 3) {
    const propNode = node.arguments[1];
    const valTaint = argTaints[2] || TaintSet.empty();
    const _propAV = resolveAbstract(propNode, env, ctx);
    if (_propAV.concrete && typeof _propAV.value === 'string' && (_propAV.value === '__proto__' || _propAV.value === 'prototype')) {
      const propResolved = _propAV.value;
      if (valTaint.tainted) {
        const loc = getNodeLoc(node);
        const objStr = _scopeQualifyMemberExpr(node.arguments[0], ctx) || 'obj';
        pushFinding(ctx, {
          type: 'Prototype Pollution',
          severity: 'critical',
          title: `Prototype Pollution: tainted data set via Reflect.set on ${propResolved}`,
          sink: makeSinkInfo(`Reflect.set(${objStr}, "${propResolved}")`, ctx, loc),
          source: formatSources(valTaint),
          path: buildTaintPath(valTaint, `Reflect.set(${objStr}, "${propResolved}")`),
        });
      }
    }
    // Tainted property key is also PP
    const propTaint = argTaints[1] || TaintSet.empty();
    if (propTaint.tainted) {
      const loc = getNodeLoc(node);
      const objStr = _scopeQualifyMemberExpr(node.arguments[0], ctx) || 'obj';
      pushFinding(ctx, {
        type: 'Prototype Pollution',
        severity: 'critical',
        title: 'Prototype Pollution: attacker controls property key in Reflect.set',
        sink: makeSinkInfo(`Reflect.set(${objStr}, taintedKey)`, ctx, loc),
        source: formatSources(propTaint),
        path: buildTaintPath(propTaint, `Reflect.set(${objStr}, taintedKey)`),
      });
    }
  }

  // Reflect.defineProperty(obj, taintedKey, descriptor) — sets own properties.
  // Only PP when target is a prototype object (same as Object.defineProperty).
  if (isCalleeMatch(node, 'Reflect', 'defineProperty', env, ctx) && node.arguments.length >= 2) {
    const propTaint = argTaints[1] || TaintSet.empty();
    if (propTaint.tainted && _isPrototypeNode(node.arguments[0])) {
      const loc = getNodeLoc(node);
      const objStr = _scopeQualifyMemberExpr(node.arguments[0], ctx) || 'obj';
      pushFinding(ctx, {
        type: 'Prototype Pollution',
        severity: 'critical',
        title: 'Prototype Pollution: attacker controls property key in Reflect.defineProperty',
        sink: makeSinkInfo(`Reflect.defineProperty(${objStr}, taintedKey)`, ctx, loc),
        source: formatSources(propTaint),
        path: buildTaintPath(propTaint, `Reflect.defineProperty(${objStr}, taintedKey)`),
      });
    }
  }

  // Object.freeze/seal/preventExtensions — return the same object, propagate taint
  if (isCalleeMatch(node, 'Object', 'freeze', env, ctx) || isCalleeMatch(node, 'Object', 'seal', env, ctx) || isCalleeMatch(node, 'Object', 'preventExtensions', env, ctx)) {
    return argTaints[0]?.clone() || TaintSet.empty();
  }

  // Object.values/keys/entries — propagate taint from object properties
  // Object.keys: keys of a known-structure object (object literal, variable assigned
  // from literal) are safe string literals. But when the object was produced by a
  // fully-tainted expression (JSON.parse, function return, etc.), attacker may control
  // property names, so propagate taint.
  if (isCalleeMatch(node, 'Object', 'keys', env, ctx) && node.arguments?.length >= 1) {
    const argNode = node.arguments[0];
    const argTaint = argTaints[0] || TaintSet.empty();

    // Discover known property names from the argument for iteration resolution
    const objKey = _scopeQualifyMemberExpr(argNode, ctx);
    if (objKey) {
      const knownProps = new Set();
      const prefix = `${objKey}.`;
      for (const [key] of env.entries()) {
        if (key.startsWith(prefix)) {
          const propName = key.slice(prefix.length);
          if (propName && !propName.startsWith('#') && !propName.includes('.')) knownProps.add(propName);
        }
      }
      for (const [key] of ctx.funcMap) {
        if (key.startsWith(prefix)) {
          const propName = key.slice(prefix.length);
          if (propName && !propName.startsWith('#') && !propName.includes('.')) knownProps.add(propName);
        }
      }
      if (knownProps.size > 0) {
        node._objectKeysResult = [...knownProps];
        node._objectKeysSource = objKey;
      }
    }

    // Taint classification: Object.keys() returns the PROPERTY NAMES of the object.
    // These are safe (programmer-defined) unless the object has structural taint
    // (attacker controls the object's shape via JSON.parse, postMessage, etc.).
    if (argNode) {
      if (argNode.type === 'ObjectExpression') return TaintSet.empty();
      if (argNode.type === 'Identifier') {
        const initNode = resolveInitFromScope(argNode, ctx);
        if (initNode && initNode.type === 'ObjectExpression') return TaintSet.empty();
      }
    }
    // Non-structural taint: the object's VALUES are tainted but its KEYS are programmer-defined.
    // Object.keys() returns safe strings in this case.
    if (argTaint.tainted && !argTaint.toArray().some(label => label.structural)) {
      return TaintSet.empty();
    }
    if (argTaint.tainted) return argTaint.clone();
    return TaintSet.empty();
  }

  if (isCalleeMatch(node, 'Object', 'values', env, ctx) || isCalleeMatch(node, 'Object', 'entries', env, ctx)) {
    const argTaint = argTaints[0] || TaintSet.empty();
    if (argTaint.tainted) return argTaint.clone();
    // Also check if any properties of the argument are tainted
    const argNode = node.arguments[0];
    if (argNode) {
      const argKey = _scopeQualifyMemberExpr(argNode, ctx);
      if (argKey) {
        const propTaints = env.getTaintedWithPrefix(`${argKey}.`);
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
  if (isCalleeMatch(node, 'Object', 'assign', env, ctx) && node.arguments.length >= 2) {
    // PP check: Object.assign(Object.prototype, tainted) or Object.assign(X.prototype, tainted)
    const targetNode = node.arguments[0];
    const targetStr = targetNode ? _scopeQualifyMemberExpr(targetNode, ctx) : null;
    if (targetStr && (targetStr.endsWith('.prototype') || targetStr === 'Object.prototype')) {
      // Check if any source argument is tainted
      for (let si = 1; si < node.arguments.length; si++) {
        const srcTaint = argTaints[si] || TaintSet.empty();
        if (srcTaint.tainted) {
          const loc = getNodeLoc(node);
          pushFinding(ctx, {
            type: 'Prototype Pollution',
            severity: 'critical',
            title: `Prototype Pollution: Object.assign to ${targetStr} with tainted source`,
            sink: makeSinkInfo(`Object.assign(${targetStr}, ...)`, ctx, loc),
            source: formatSources(srcTaint),
            path: buildTaintPath(srcTaint, `Object.assign(${targetStr}, ...)`),
          });
          break;
        }
      }
    }

    // If target is an identifier or member, update its taint in env
    // Collect per-property taints from all sources in order (later sources override earlier)
    const propTaints = new Map();
    let overallTaint = TaintSet.empty();

    const targetKey = targetNode?.type === 'Identifier' ? resolveId(targetNode, ctx.scopeInfo) : null;

    for (let si = 1; si < node.arguments.length; si++) {
      const srcNode = node.arguments[si];
      const srcTaint = argTaints[si] || TaintSet.empty();
      overallTaint = overallTaint.merge(srcTaint);
      if (srcNode.type === 'ObjectExpression') {
        for (const prop of srcNode.properties) {
          if (prop.type === 'SpreadElement') continue;
          if (isObjectProp(prop) && prop.key) {
            const propName = propKeyName(prop.key);
            if (propName) {
              const pTaint = evaluateExpr(prop.value, env, ctx);
              propTaints.set(propName, pTaint);
            }
          }
        }
      } else {
        const srcStr = _scopeQualifyMemberExpr(srcNode, ctx);
        if (srcStr) {
          // Copy per-property taints from source identifier
          for (const [key, taint] of env.getTaintedWithPrefix(`${srcStr}.`)) {
            const propName = key.slice(srcStr.length + 1);
            if (propName && !propName.startsWith('#')) {
              propTaints.set(propName, taint);
            }
          }
          // Also check if source has safe overrides for properties already in propTaints or target
          // This handles Object.assign(taintedTarget, safeSource) where safeSource.prop overrides taintedTarget.prop
          const keysToCheck = new Set([...propTaints.keys()]);
          if (targetStr) {
            for (const [key] of env.getTaintedWithPrefix(`${targetStr}.`)) {
              const propName = key.slice(targetStr.length + 1);
              if (propName && !propName.startsWith('#')) keysToCheck.add(propName);
            }
            if (targetKey) {
              for (const [key] of env.getTaintedWithPrefix(`${targetKey}.`)) {
                const propName = key.slice(targetKey.length + 1);
                if (propName && !propName.startsWith('#')) keysToCheck.add(propName);
              }
            }
          }
          for (const propName of keysToCheck) {
            const _srcPropKey = `${srcStr}.${propName}`;
            const srcPropTaint = env.get(_srcPropKey);
            if (!srcPropTaint.tainted && env.has(_srcPropKey)) {
              propTaints.set(propName, srcPropTaint);
            }
          }
        }
      }
    }

    // Compute actual return taint: only tainted if at least one property is still tainted
    // after later sources may have overridden earlier ones with safe values
    let resultTaint = TaintSet.empty();
    for (const [, pTaint] of propTaints) {
      if (pTaint.tainted) resultTaint = resultTaint.merge(pTaint);
    }
    // If no per-property info was collected, fall back to overall merge
    if (propTaints.size === 0) resultTaint = overallTaint;

    if (targetStr) {
      env.set(targetStr, env.get(targetStr).clone().merge(resultTaint));
      if (targetKey) env.set(targetKey, env.get(targetKey).clone().merge(resultTaint));
      for (const [propName, pTaint] of propTaints) {
        env.set(`${targetStr}.${propName}`, pTaint);
        if (targetKey) env.set(`${targetKey}.${propName}`, pTaint);
      }
      // Copy funcMap entries from source to target (Object.assign copies methods too)
      for (let si = 1; si < node.arguments.length; si++) {
        const srcNode = node.arguments[si];
        const srcKey = _scopeQualifyMemberExpr(srcNode, ctx);
        if (srcKey) {
          const srcPrefix = srcKey + '.';
          for (const [fk, fv] of ctx.funcMap) {
            if (fk.startsWith(srcPrefix)) {
              const methodName = fk.slice(srcPrefix.length);
              if (methodName && !methodName.includes('.')) {
                if (targetKey) ctx.funcMap.set(`${targetKey}.${methodName}`, fv);
                ctx.funcMap.set(`${targetStr}.${methodName}`, fv);
              }
            }
          }
        }
      }
    }
    // Store per-property taints for the result variable assignment (when target is {})
    if (propTaints.size > 0) {
      node._assignPerPropertyTaints = propTaints;
    }
    return resultTaint;
  }

  if (bareCallee && CALL_SOURCES[bareCallee] && CALL_SOURCES[bareCallee] !== 'passthrough') {
    const loc = getNodeLoc(node);
    const _firstArgAV = node.arguments?.[0] ? resolveAbstract(node.arguments[0], env, ctx) : AV_UNKNOWN;
    const firstArg = _firstArgAV.concrete ? _firstArgAV.value : undefined;
    const label = new TaintLabel(CALL_SOURCES[bareCallee], ctx.file, loc.line || 0, loc.column || 0,
      firstArg !== undefined ? `${bareCallee}(${JSON.stringify(firstArg)})` : bareCallee + '()');
    if (typeof firstArg === 'string') label.sourceKey = firstArg;
    return TaintSet.from(label);
  }

  if (bareCallee && isPassthrough(bareCallee)) {
    const base = argTaints[0]?.clone() || TaintSet.empty();
    return base.tainted ? base.withTransform({ op: bareCallee }) : base;
  }

  // Check if there's a user-defined function for this exact callee path before deferring to builtins.
  // Only match full dot-path (e.g., "s.get") — prevents Map.get from intercepting class method s.get().
  if (methodName && (node.callee?.type === 'MemberExpression' || node.callee?.type === 'OptionalMemberExpression')) {
    const fullPath = _scopeQualifyMemberExpr(node.callee, ctx);
    if (fullPath && ctx.funcMap.has(fullPath)) {
      return analyzeCalledFunction(node, calleeStr, argTaints, env, ctx);
    }
  }

  const propagated = handleBuiltinMethod(methodName, node, argTaints, objTaint, env, ctx);
  if (propagated !== null) return propagated;

  // Chained method on returned object: factory().method() or new Foo().method()
  if (methodName && ctx.returnedMethods && ctx.returnedMethods[methodName] &&
      (node.callee?.type === 'MemberExpression' || node.callee?.type === 'OptionalMemberExpression') &&
      (node.callee.object?.type === 'CallExpression' || node.callee.object?.type === 'OptionalCallExpression' || node.callee.object?.type === 'NewExpression')) {
    const retFunc = ctx.returnedMethods[methodName];
    const allReturnedMethods = ctx.returnedMethods;
    ctx.returnedMethods = null;
    // Store in funcMap and ensure analyzeCalledFunction can find it
    const retCalleeStr = calleeStr || `__returned__.${methodName}`;
    ctx.funcMap.set(retCalleeStr, retFunc);
    // Register all sibling methods as this.* so return this can carry them forward
    for (const [mName, mFunc] of Object.entries(allReturnedMethods)) {
      if (!ctx.funcMap.has(`this.${mName}`)) ctx.funcMap.set(`this.${mName}`, mFunc);
    }
    return analyzeCalledFunction(node, retCalleeStr, argTaints, env, ctx);
  }

  // Fallback: resolve method on chained call via constructor's class methods
  // e.g., new Builder().set().build() → walk chain to find NewExpression constructor → Builder#build
  if (!calleeStr && methodName &&
      (node.callee?.type === 'MemberExpression' || node.callee?.type === 'OptionalMemberExpression')) {
    let chainObj = node.callee.object;
    while (chainObj && (chainObj.type === 'CallExpression' || chainObj.type === 'OptionalCallExpression')) {
      chainObj = chainObj.callee?.object || chainObj.callee;
    }
    if (chainObj?.type === 'NewExpression' && chainObj.callee) {
      const ctorName = _scopeQualifyMemberExpr(chainObj.callee, ctx);
      if (ctorName) {
        const classMethodKey = `${ctorName}#${methodName}`;
        const classFunc = ctx.funcMap.get(classMethodKey);
        if (classFunc) {
          calleeStr = classMethodKey;
          ctx.funcMap.set(classMethodKey, classFunc);
        }
      }
    }
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
// Body of new expression evaluation — constructorName, argTaints pre-computed by W/V
function _evaluateNewExprBody(node, constructorName, argTaints, env, ctx) {

  // Handle ClassExpression as callee: new (class { constructor() {...} })()
  if (node.callee.type === 'ClassExpression' && node.callee.body?.body) {
    const synthName = `__classExpr_${node.loc?.start?.line || 0}_${node.loc?.start?.column || 0}`;
    const classBody = node.callee.body.body;
    for (const member of classBody) {
      if (member.type !== 'ClassMethod' && member.type !== 'MethodDefinition') continue;
      const mname = propKeyName(member.key);
      if (!mname) continue;
      if (mname === 'constructor') {
        ctx.classBodyMap.set(synthName, classBody);
        ctx.funcMap.set(synthName, member);
      } else {
        const getterPrefix = member.kind === 'get' ? 'getter:' : (member.kind === 'set' ? 'setter:' : '');
        ctx.funcMap.set(`${getterPrefix}${synthName}#${mname}`, member);
        if (getterPrefix) {
          ctx.funcMap.set(`${synthName}#${mname}`, member);
        }
      }
    }
    constructorName = synthName;
  }

  const bareCtorName = _stripScopePrefix(constructorName);
  if (bareCtorName && CONSTRUCTOR_SOURCES[bareCtorName]) {
    const argTaint = argTaints.reduce((acc, t) => acc.merge(t), TaintSet.empty());
    if (argTaint.tainted) return argTaint;
    const loc = getNodeLoc(node);
    return TaintSet.from(new TaintLabel(CONSTRUCTOR_SOURCES[bareCtorName], ctx.file, loc.line || 0, loc.column || 0, `new ${bareCtorName}()`));
  }

  if (isGlobalRef(node.callee, 'Function', env, ctx)) {
    // new Function(body) or new Function(arg1, ..., body) — any tainted arg is code injection
    const allArgIndices = argTaints.map((_, i) => i);
    checkSinkCall(node, { type: 'XSS', taintedArgs: allArgIndices }, argTaints, 'new Function()', env, ctx);
    // Parse constant string body into a real function AST for interprocedural analysis
    const parsedFunc = parseFunctionConstructor(node.arguments);
    if (parsedFunc) {
      ctx.returnedFuncNode = parsedFunc;
    }
  }

  // new WebSocket(url) — tainted URL is injection risk (attacker-controlled endpoint)
  if (isGlobalRef(node.callee, 'WebSocket', env, ctx)) {
    checkSinkCall(node, { type: 'XSS', taintedArgs: [0] }, argTaints, 'new WebSocket()', env, ctx);
  }

  // new Worker(url) / new SharedWorker(url) — tainted URL is script injection
  if ((isGlobalRef(node.callee, 'Worker', env, ctx) || isGlobalRef(node.callee, 'SharedWorker', env, ctx)) && argTaints[0]) {
    const ctorName = isGlobalRef(node.callee, 'Worker', env, ctx) ? 'Worker' : 'SharedWorker';
    checkSinkCall(node, { type: 'XSS', taintedArgs: [0] }, argTaints, `new ${ctorName}()`, env, ctx);
  }

  // new Blob([content], ...) — propagate taint from array content
  if (isGlobalRef(node.callee, 'Blob', env, ctx) && argTaints[0]) {
    return argTaints[0].clone();
  }

  // new Promise(function(resolve, reject) { resolve(tainted) }) → taint propagates to .then()
  if (isGlobalRef(node.callee, 'Promise', env, ctx) && node.arguments[0]) {
    let callback = node.arguments[0];
    if (isFuncExpr(callback)) {
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
  if (isGlobalRef(node.callee, 'CustomEvent', env, ctx) && node.arguments.length >= 2) {
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
        if (isObjectProp(prop) && prop.key) {
          const pname = propKeyName(prop.key);
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

  // Proxy: new Proxy(target, handler) — analyze handler.get/apply return taint
  if (bareCtorName === 'Proxy' && node.arguments.length >= 2) {
    const handlerNode = node.arguments[1];
    // If handler has an 'apply' trap, the proxy is callable — register target as the callable
    const targetNode = node.arguments[0];
    if (handlerNode.type === 'ObjectExpression') {
      for (const prop of handlerNode.properties) {
        if ((isObjectProp(prop) || prop.type === 'ObjectMethod') && prop.key) {
          const pname = propKeyName(prop.key);
          if (pname === 'apply') {
            // Proxy with apply trap: handler.apply(target, thisArg, argumentsList)
            // Register the apply trap itself so calls to proxy invoke it
            const applyFunc = prop.type === 'ObjectMethod' ? prop : prop.value;
            if (applyFunc && (applyFunc.type === 'FunctionExpression' || applyFunc.type === 'ArrowFunctionExpression' || applyFunc.type === 'ObjectMethod')) {
              applyFunc._isProxyApplyTrap = true;
              applyFunc._closureEnv = env;
              // Bind the target function to the 1st param so t() resolves inside the trap
              if (targetNode) {
                const targetFunc = targetNode.type === 'Identifier'
                  ? ctx.funcMap.get(resolveId(targetNode, ctx.scopeInfo))
                  : (targetNode.type === 'FunctionExpression' || targetNode.type === 'ArrowFunctionExpression' ? targetNode : null);
                if (targetFunc && applyFunc.params?.length >= 1 && applyFunc.params[0].type === 'Identifier') {
                  applyFunc._proxyTargetParam = applyFunc.params[0].name;
                  applyFunc._proxyTargetFunc = targetFunc;
                }
              }
              ctx.returnedFuncNode = applyFunc;
            } else {
              // Fallback: resolve target function for callability
              if (targetNode?.type === 'Identifier') {
                const targetFunc = ctx.funcMap.get(resolveId(targetNode, ctx.scopeInfo));
                if (targetFunc) ctx.returnedFuncNode = targetFunc;
              }
              if (targetNode?.type === 'FunctionExpression' || targetNode?.type === 'ArrowFunctionExpression') {
                ctx.returnedFuncNode = targetNode;
              }
            }
          }
          if (pname === 'construct') {
            // Proxy with construct trap: new P(args) calls handler.construct(target, args, newTarget)
            // Store the construct handler so it can be invoked when new P(...) is called later
            const constructFunc = prop.type === 'ObjectMethod' ? prop : prop.value;
            if (constructFunc && (constructFunc.type === 'FunctionExpression' || constructFunc.type === 'ArrowFunctionExpression' || constructFunc.type === 'ObjectMethod')) {
              constructFunc._closureEnv = env;
              constructFunc._isProxyConstructTrap = true;
              ctx.returnedFuncNode = constructFunc;
            }
          }
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
    // If handler is an identifier, try to resolve its methods via funcMap
    if (handlerNode.type === 'Identifier') {
      const handlerName = handlerNode.name;
      const resolvedName = resolveId(handlerNode, ctx.scopeInfo);
      // Resolve construct trap: handler.construct → store as returnedFuncNode
      const constructFunc = ctx.funcMap.get(`${resolvedName}.construct`);
      if (constructFunc && (constructFunc.type === 'FunctionExpression' || constructFunc.type === 'ArrowFunctionExpression' || constructFunc.type === 'FunctionDeclaration')) {
        constructFunc._closureEnv = env;
        constructFunc._isProxyConstructTrap = true;
        ctx.returnedFuncNode = constructFunc;
      }
      // Resolve apply trap
      if (!ctx.returnedFuncNode) {
        const applyFunc = ctx.funcMap.get(`${resolvedName}.apply`);
        if (applyFunc && (applyFunc.type === 'FunctionExpression' || applyFunc.type === 'ArrowFunctionExpression' || applyFunc.type === 'FunctionDeclaration' || applyFunc.type === 'ObjectMethod')) {
          applyFunc._isProxyApplyTrap = true;
          applyFunc._closureEnv = env;
          // Bind the target function to the 1st param so target() resolves inside the trap
          if (targetNode) {
            const targetFunc = targetNode.type === 'Identifier'
              ? ctx.funcMap.get(resolveId(targetNode, ctx.scopeInfo))
              : (targetNode.type === 'FunctionExpression' || targetNode.type === 'ArrowFunctionExpression' ? targetNode : null);
            if (targetFunc && applyFunc.params?.length >= 1 && applyFunc.params[0].type === 'Identifier') {
              applyFunc._proxyTargetParam = applyFunc.params[0].name;
              applyFunc._proxyTargetFunc = targetFunc;
            }
          }
          ctx.returnedFuncNode = applyFunc;
        }
      }
      // Resolve get trap
      const getFunc = ctx.funcMap.get(`${resolvedName}.get`);
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
      // Always populate returnedMethods from prototype chain — needed for chained
      // method calls (new X().method()) regardless of cache hit.
      {
        const _ctorMethods = {};
        // Class instance methods
        const _classBody = ctx.classBodyMap.get(constructorName) || funcNode?._classBody;
        if (_classBody) {
          for (const member of _classBody) {
            if (member.type !== 'ClassMethod' && member.type !== 'MethodDefinition') continue;
            const mname = propKeyName(member.key);
            if (mname && mname !== 'constructor' && !member.static) _ctorMethods[mname] = member;
          }
        }
        // Prototype methods (Constructor#method entries from X.prototype = Y)
        const _protoPrefix = constructorName + '#';
        for (const [fk, fv] of ctx.funcMap) {
          if (fk.startsWith(_protoPrefix)) {
            const mname = fk.slice(_protoPrefix.length);
            if (mname && !mname.includes('.')) _ctorMethods[mname] = fv;
          }
        }
        if (Object.keys(_ctorMethods).length > 0) ctx.returnedMethods = _ctorMethods;
      }
      // Don't cache constructor results in analyzedCalls — let analyzeInlineFunction's
      // own _inlineResults cache handle it. This ensures IP-suspended constructor analysis
      // returns the REAL result on resume (from _inlineResults), not a pre-seeded placeholder.
      {
        const childEnv = (funcNode._closureEnv || env).child();
        // Set up 'this' as empty so this.* assignments are tracked
        childEnv.set('this', TaintSet.empty());
        if (funcNode._isProxyConstructTrap) {
          // Proxy construct trap signature: (target, argumentsList, newTarget)
          // Map call args to the 2nd parameter (argumentsList)
          if (funcNode.params.length >= 1) {
            assignToPattern(funcNode.params[0], TaintSet.empty(), childEnv, ctx); // target = empty
          }
          if (funcNode.params.length >= 2 && funcNode.params[1].type === 'Identifier') {
            const argsParam = funcNode.params[1].name;
            const argsKey = resolveId(funcNode.params[1], ctx.scopeInfo);
            const argsMerged = argTaints.reduce((acc, t) => acc.merge(t), TaintSet.empty());
            childEnv.set(argsParam, argsMerged);
            childEnv.set(argsKey, argsMerged);
            for (let ai = 0; ai < argTaints.length; ai++) {
              childEnv.set(`${argsParam}.#idx_${ai}`, argTaints[ai] || TaintSet.empty());
              childEnv.set(`${argsKey}.#idx_${ai}`, argTaints[ai] || TaintSet.empty());
            }
          }
        } else {
          for (let i = 0; i < funcNode.params.length; i++) {
            assignToPattern(funcNode.params[i], argTaints[i] || TaintSet.empty(), childEnv, ctx);
          }
        }
        // Propagate element types from constructor arguments to parameters
        if (node.arguments) {
          for (let i = 0; i < funcNode.params.length && i < node.arguments.length; i++) {
            const param = funcNode.params[i];
            if (param.type !== 'Identifier') continue;
            const argNode = node.arguments[i];
            const argKey = _scopeQualifyMemberExpr(argNode, ctx);
            const paramKey = resolveId(param, ctx.scopeInfo);
            if (argKey) {
              const tag = ctx.elementTypes.get(argKey);
              if (tag) ctx.elementTypes.set(paramKey, tag);
              if (ctx.domAttached.has(argKey)) ctx.domAttached.add(paramKey);
              if (ctx.scriptElements.has(argKey)) ctx.scriptElements.add(paramKey);
            }
            // Direct DOM access args: document.body, document.getElementById(...)
            if (argNode.type === 'MemberExpression') {
              const argStr = _stripScopePrefix(_scopeQualifyMemberExpr(argNode, ctx) || '');
              if (argStr && (argStr.startsWith('document.') || argStr.includes('.document.'))) {
                ctx.domAttached.add(paramKey);
              }
            }
            // DOM query calls: document.getElementById(), document.querySelector() etc.
            if (argNode.type === 'CallExpression') {
              const domInfo = getDOMQueryInfo(argNode, env, ctx);
              if (domInfo) {
                ctx.domAttached.add(paramKey);
                if (domInfo.tag) ctx.elementTypes.set(paramKey, domInfo.tag);
              }
            }
          }
        }
        // Process class field initializations BEFORE constructor body
        // (fields are initialized before constructor runs in JS semantics)
        const classBody = ctx.classBodyMap.get(constructorName) || funcNode?._classBody;
        if (classBody) {
          for (const member of classBody) {
            if ((member.type === 'ClassProperty' || member.type === 'PropertyDefinition') && member.value && member.key) {
              const fieldName = propKeyName(member.key);
              if (fieldName && !member.static) {
                const fieldTaint = evaluateExpr(member.value, childEnv, ctx);
                childEnv.set(`this.${fieldName}`, fieldTaint);
              }
            }
          }
        }

        const body = funcNode.body.type === 'BlockStatement' ? funcNode.body
          : { type: 'BlockStatement', body: [{ type: 'ReturnStatement', argument: funcNode.body }] };
        const retTaint = analyzeInlineFunction({ ...funcNode, body }, childEnv, ctx, env);

        // Propagate this.* bindings to the parent env for instance resolution
        // (also handled by postProcess in callerEnv mode for frame-based path)
        // Includes clean bindings so sanitized properties are tracked accurately
        const thisTaint = TaintSet.empty();
        for (const [key, taint] of childEnv.entries()) {
          if (key.startsWith('this.') && key.length > 5) {
            env.set(key, taint);
            if (taint.tainted) thisTaint.merge(taint);
          }
        }
        if (thisTaint.tainted) return thisTaint;
        // If the function has explicit return statements (e.g., Proxy construct trap
        // or factory function), use the return value instead of arg-merge fallback.
        // Regular constructors don't return explicitly — they return `this`.
        const hasExplicitReturn = funcNode.body?.type === 'BlockStatement' &&
          funcNode.body.body.some(s => s.type === 'ReturnStatement' && s.argument);
        if (hasExplicitReturn) {
          ctx.analyzedCalls.set(callSig, retTaint || TaintSet.empty());
          return retTaint || TaintSet.empty();
        }

        // Populate returnedMethods with class instance methods so chained calls
        // like new Foo().method() can resolve via _evaluateCallExprBody
        const classBodyForMethods = ctx.classBodyMap.get(constructorName) || funcNode?._classBody;
        const methods = {};
        if (classBodyForMethods) {
          for (const member of classBodyForMethods) {
            if (member.type !== 'ClassMethod' && member.type !== 'MethodDefinition') continue;
            const mname = propKeyName(member.key);
            if (mname && mname !== 'constructor' && !member.static) {
              methods[mname] = member;
            }
          }
        }
        // Also include prototype methods for non-class constructors
        if (constructorName && ctx.protoMethodMap.has(constructorName)) {
          for (const { methodName, funcNode: mfn } of ctx.protoMethodMap.get(constructorName)) {
            if (!methods[methodName]) methods[methodName] = mfn;
          }
        }
        if (Object.keys(methods).length > 0) {
          ctx.returnedMethods = methods;
        }
      }
    }
    // Populate returnedMethods for chained calls (even on cache hit)
    // This uses class/prototype structure, not analysis results
    if (!ctx.returnedMethods) {
      const classBodyForChain = ctx.classBodyMap.get(constructorName) || ctx.funcMap.get(constructorName)?._classBody;
      const chainMethods = {};
      if (classBodyForChain) {
        for (const member of classBodyForChain) {
          if (member.type !== 'ClassMethod' && member.type !== 'MethodDefinition') continue;
          const mname = propKeyName(member.key);
          if (mname && mname !== 'constructor' && !member.static) chainMethods[mname] = member;
        }
      }
      if (ctx.protoMethodMap.has(constructorName)) {
        for (const { methodName, funcNode: mfn } of ctx.protoMethodMap.get(constructorName)) {
          if (!chainMethods[methodName]) chainMethods[methodName] = mfn;
        }
      }
      if (Object.keys(chainMethods).length > 0) ctx.returnedMethods = chainMethods;
    }
  }

  return argTaints.reduce((acc, t) => acc.merge(t), TaintSet.empty());
}

// ── Built-in method taint propagation ──
function handleBuiltinMethod(methodName, node, argTaints, objTaint, env, ctx) {

  switch (methodName) {
    case 'slice': case 'substring': case 'substr': case 'trim': case 'trimStart':
    case 'trimEnd': case 'toLowerCase': case 'toUpperCase': case 'normalize':
    case 'repeat': case 'at': case 'charAt':
    case 'valueOf': case 'toString': {
      if (!objTaint.tainted) return objTaint.clone();
      const cArgs = resolveConstantArgs(node.arguments, env, ctx);
      return objTaint.withTransform({ op: methodName, args: cArgs });
    }

    case 'padStart': case 'padEnd':
      // padStart/padEnd(targetLength, padString) — result includes both obj and pad string
      return objTaint.clone().merge(argTaints[1] || TaintSet.empty());

    case 'match': case 'matchAll':
      // Returns array of matches — preserve taint from the source string
      return objTaint.tainted ? objTaint.withTransform({ op: methodName }) : objTaint.clone();

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
        let funcRef = callee.type === 'Identifier'
          ? ctx.funcMap.get(resolveId(callee, ctx.scopeInfo))
          : null;
        // For built-in Identifier callees (eval, setTimeout, etc.): store as alias
        if (!funcRef && callee.type === 'Identifier') {
          ctx._boundCalleeStr = callee.name;
        }
        // Also check MemberExpression callees: document.write.bind(document) → resolve document.write
        if (!funcRef && (callee.type === 'MemberExpression' || callee.type === 'OptionalMemberExpression')) {
          const scopedCalleeStr = _scopeQualifyMemberExpr(callee, ctx);
          if (scopedCalleeStr) {
            funcRef = ctx.funcMap.get(scopedCalleeStr);
            // For built-in sinks (eval, document.write, etc.), store bare callee string as alias
            if (!funcRef) {
              ctx._boundCalleeStr = _stripScopePrefix(scopedCalleeStr);
            }
          }
        }
        if (funcRef) {
          // Store the thisArg node so analyzeCalledFunction can bind this.* properties
          const thisArgNode = node.arguments?.[0];
          if (thisArgNode) funcRef._boundThisArg = _scopeQualifyMemberExpr(thisArgNode, ctx);
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

    case 'replace': case 'replaceAll': {
      // When arg 1 is a callback function, analyze it with proper parameter scope.
      // Callback params: (fullMatch, group1, ..., offset, sourceString) — all derived
      // from the SOURCE STRING (the object), not from the pattern (arg 0).
      // This prevents FPs where a tainted regex pattern causes callback params
      // to inherit taint when the source string is safe.
      const replCb = node.arguments?.[1];
      // When arg 1 is a callback function, analyze it with proper parameter scope.
      // Callback params: (fullMatch, group1, ..., offset, sourceString) — all derived
      // from the SOURCE STRING (the object), not from the pattern (arg 0).
      if (replCb && (replCb.type === 'FunctionExpression' || replCb.type === 'ArrowFunctionExpression') &&
          replCb.params?.length > 0) {
        const cbEnv = env.child();
        for (const p of replCb.params) {
          assignToPattern(p, objTaint.clone(), cbEnv, ctx);
        }
        // Don't override _closureEnv — the callback's closure was set during definition-time.
        const cbResult = analyzeInlineFunction(replCb, cbEnv, ctx);
        const result = objTaint.clone().merge(cbResult || TaintSet.empty());
        if (!result.tainted) return result;
        const cArgs = resolveConstantArgs(node.arguments, env, ctx);
        return result.withTransform({ op: methodName, args: cArgs });
      }
      const result = objTaint.clone().merge(argTaints[1] || TaintSet.empty());
      if (!result.tainted) return result;
      const cArgs = resolveConstantArgs(node.arguments, env, ctx);
      return result.withTransform({ op: methodName, args: cArgs });
    }

    case 'split': {
      if (!objTaint.tainted) return objTaint.clone();
      const cArgs = resolveConstantArgs(node.arguments, env, ctx);
      return objTaint.withTransform({ op: 'split', args: cArgs });
    }

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
        const iterObjStr = _scopeQualifyMemberExpr(node.callee.object, ctx);
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

    case 'findIndex':
      // findIndex takes a callback — analyze it for sinks, returns number
      analyzeArrayCallback(node, argTaints, objTaint, env, ctx);
      return TaintSet.empty();

    case 'indexOf': case 'lastIndexOf':
      // These take a VALUE (not a callback) — returns number, kill taint
      return TaintSet.empty();

    case 'some': case 'every':
      // These return a boolean — kill taint, but analyze callback for sinks
      analyzeArrayCallback(node, argTaints, objTaint, env, ctx);
      return TaintSet.empty();

    case 'includes':
      // includes takes a VALUE (not a callback) — returns boolean, kill taint
      return TaintSet.empty();

    case 'reduce': case 'reduceRight': {
      // Analyze the callback: (accumulator, element, index, array) => ...
      // The accumulator starts with initial value (argTaints[1]) and merges with array elements
      const cbReduce = node.arguments[0];
      if (cbReduce && isFuncExpr(cbReduce)) {
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
        const objStr = _scopeQualifyMemberExpr(node.callee.object, ctx);
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
        const objStr = _scopeQualifyMemberExpr(node.callee.object, ctx);
        const mapKey = node.arguments[0];
        const keyStr = mapKey && (mapKey.type === 'StringLiteral' || mapKey.type === 'Literal')
          ? (mapKey.value ?? mapKey.raw) : null;
        if (objStr && keyStr != null) {
          // Per-key taint: store as "map.#key_<keyStr>"
          const perKeyPath = `${objStr}.#key_${keyStr}`;
          env.set(perKeyPath, valueTaint.clone());
          if (node.callee.object.type === 'Identifier') {
            const scopedKey = resolveId(node.callee.object, ctx.scopeInfo);
            env.set(`${scopedKey}.#key_${keyStr}`, valueTaint.clone());
          }
          // Track nested Map aliases: map.set('key', otherMap) → alias for per-key chaining
          const valueArg = node.arguments[1];
          if (valueArg?.type === 'Identifier') {
            const valueId = resolveId(valueArg, ctx.scopeInfo);
            env.aliases.set(perKeyPath, valueId);
            if (node.callee.object.type === 'Identifier') {
              const scopedKey = resolveId(node.callee.object, ctx.scopeInfo);
              env.aliases.set(`${scopedKey}.#key_${keyStr}`, valueId);
            }
          }
        } else if (objStr && valueTaint.tainted) {
          // Dynamic key: fall back to tainting the whole Map
          env.set(objStr, env.get(objStr).clone().merge(valueTaint));
          if (node.callee.object.type === 'Identifier') {
            const key = resolveId(node.callee.object, ctx.scopeInfo);
            env.set(key, env.get(key).clone().merge(valueTaint));
          }
        }
      }
      // If the callee resolves to a user-defined function, let analyzeCalledFunction handle it
      const setCalleeStr = _scopeQualifyMemberExpr(node.callee, ctx);
      if (setCalleeStr && ctx.funcMap.has(setCalleeStr)) return null;
      return objTaint.clone(); // Map.set returns the Map itself
    }

    case 'add': {
      // Set.add(value) — taint the Set if value is tainted
      const valueTaint = argTaints[0] || TaintSet.empty();
      if (valueTaint.tainted && node.callee?.object) {
        const objEnvKey = _scopeQualifyMemberExpr(node.callee.object, ctx);
        if (objEnvKey) env.set(objEnvKey, env.get(objEnvKey).clone().merge(valueTaint));
      }
      return objTaint.clone();
    }

    case 'push': case 'unshift':
      if (node.callee?.object) {
        const scopedObjStr = _scopeQualifyMemberExpr(node.callee.object, ctx);
        if (scopedObjStr) {
          const merged = env.get(scopedObjStr).clone();
          for (const t of argTaints) merged.merge(t);
          env.set(scopedObjStr, merged);
        }
        // When arr.push(forInVar) and forInVar is a for-in key variable,
        // the array inherits the source object's property enumeration.
        // This enables: var keys = []; for(var k in obj) keys.push(k); → keys has obj's property names
        if (ctx._forInEnumeration) {
          for (const arg of node.arguments) {
            if (arg.type === 'Identifier') {
              if (!ctx._ctxId) ctx._ctxId = Math.random().toString(36).slice(2,6);
              trace('PUSH-ENUM', { arg: arg.name, ctxId: ctx._ctxId, has: ctx._forInEnumeration.has(resolveId(arg, ctx.scopeInfo)) });
              const enumInfo = ctx._forInEnumeration.get(resolveId(arg, ctx.scopeInfo));
              if (enumInfo && scopedObjStr) {
                if (!ctx._objectKeysVars) ctx._objectKeysVars = new Map();
                const arrName = node.callee.object.type === 'Identifier' ? node.callee.object.name : null;
                ctx._objectKeysVars.set(scopedObjStr, { sourceName: enumInfo.sourceName, properties: enumInfo.properties });
                if (arrName) ctx._objectKeysVars.set(arrName, { sourceName: enumInfo.sourceName, properties: enumInfo.properties });
                // Also tag for return value propagation: if this array is returned,
                // the caller gets the known property names
                node.callee.object._objectKeysSource = enumInfo.sourceName;
                node.callee.object._objectKeysProperties = enumInfo.properties;
              }
            }
          }
        }
        // Register function arguments pushed to arrays so computed calls (arr[0]()) can resolve them
        for (const arg of node.arguments) {
          if (arg.type === 'FunctionExpression' || arg.type === 'ArrowFunctionExpression') {
            arg._closureEnv = env;
            if (scopedObjStr) ctx.funcMap.set(`${scopedObjStr}[]`, arg);
          }
          // Resolve identifier references to known functions
          if (arg.type === 'Identifier') {
            const refKey = resolveId(arg, ctx.scopeInfo);
            const refFunc = ctx.funcMap.get(refKey);
            if (refFunc) {
              if (scopedObjStr) ctx.funcMap.set(`${scopedObjStr}[]`, refFunc);
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
                if (scopedObjStr) ctx.funcMap.set(`${scopedObjStr}[]`, retFunc);
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
      const scopedProtoMethod = calleeObj ? _scopeQualifyMemberExpr(calleeObj, ctx) : null;
      const bareProtoMethod = scopedProtoMethod ? _stripScopePrefix(scopedProtoMethod) : null;

      // Handle Function.prototype.call.call(targetFn, thisArg, ...args) first
      // This is .call() called on .call itself: 1st arg is the target function
      if (bareProtoMethod && /\.call$/.test(bareProtoMethod) && node.arguments?.length >= 1) {
        const targetArg = node.arguments[0];
        if (targetArg.type === 'Identifier') {
          const targetName = targetArg.name;
          const aliasedName = env.aliases?.get(targetName) || targetName;
          const sinkArgTaints = argTaints.slice(2);
          // Check if target is a sink (eval, setTimeout, etc.)
          const sinkInfo = checkCallSink(aliasedName, aliasedName);
          if (sinkInfo) {
            const sinkCall = { ...node, callee: targetArg, arguments: node.arguments.slice(2) };
            checkSinkCall(sinkCall, sinkInfo, sinkArgTaints, aliasedName, env, ctx);
          }
          // Also try interprocedural
          const targetFunc = ctx.funcMap.get(resolveId(targetArg, ctx.scopeInfo));
          if (targetFunc && targetFunc.body) {
            const synthCall2 = { ...node, callee: targetArg, arguments: node.arguments.slice(2) };
            return analyzeCalledFunction(synthCall2, targetName, sinkArgTaints, env, ctx);
          }
          return sinkArgTaints.reduce((a, t) => a.merge(t), TaintSet.empty());
        }
      }

      if (scopedProtoMethod) {
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
        // Try builtin method first — thisArgTaint serves as objTaint for re-dispatched call
        const result = handleBuiltinMethod(method, {
          ...node,
          callee: { ...node.callee, object: node.arguments?.[0] || node.callee.object },
        }, restArgTaints, thisArgTaint, env, ctx);
        if (result !== null) return thisArgTaint.clone().merge(result);
      }
      // Try interprocedural: fn.call(thisArg, arg1, ...) → analyze fn with args
      {
        // Resolve callee name through _paramArgNames (parameter→arg mapping from call site)
        // Bare version for sink matching, scoped version for funcMap
        const scopedResolvedCallName = calleeObj?.type === 'Identifier'
          ? (ctx._paramArgNames?.get(calleeObj.name) || resolveId(calleeObj, ctx.scopeInfo))
          : scopedProtoMethod;
        const resolvedCallName = scopedResolvedCallName ? _stripScopePrefix(scopedResolvedCallName) : null;

        // Check if resolved callee is a known sink (bare name for external API matching)
        if (resolvedCallName) {
          const sinkInfo = checkCallSink(resolvedCallName, resolvedCallName);
          if (sinkInfo) {
            const sinkCall = { ...node, callee: calleeObj, arguments: node.arguments?.slice(1) || [] };
            checkSinkCall(sinkCall, sinkInfo, restArgTaints, resolvedCallName, env, ctx);
          }
        }

        // Try interprocedural with funcMap resolution (scope-qualified keys)
        let funcRef = calleeObj?.type === 'Identifier'
          ? ctx.funcMap.get(resolveId(calleeObj, ctx.scopeInfo))
          : (scopedProtoMethod && ctx.funcMap.get(scopedProtoMethod));
        if (!funcRef && scopedResolvedCallName !== scopedProtoMethod && scopedResolvedCallName) {
          funcRef = ctx.funcMap.get(scopedResolvedCallName);
        }
        // IIFE .call(this): (function(){...}).call(thisArg) — callee object is a FunctionExpression
        if (!funcRef && calleeObj && (calleeObj.type === 'FunctionExpression' || calleeObj.type === 'ArrowFunctionExpression')) {
          funcRef = calleeObj;
        }
        if (funcRef && funcRef.body) {
          const thisArgNode = node.arguments?.[0];
          const thisArgName = thisArgNode ? _scopeQualifyMemberExpr(thisArgNode, ctx) : null;
          if (thisArgName) {
            funcRef._boundThisArg = thisArgName;
          } else if (thisArgNode && thisArgNode.type === 'ObjectExpression') {
            funcRef._boundThisNode = thisArgNode;
          }
          const synthCall = { ...node, callee: calleeObj, arguments: node.arguments.slice(1) };
          return analyzeCalledFunction(synthCall, scopedResolvedCallName || scopedProtoMethod, restArgTaints, env, ctx);
        }
      }
      return thisArgTaint.clone().merge(restArgTaints.reduce((a, t) => a.merge(t), TaintSet.empty()));
    }

    case 'apply': {
      // Function.prototype.apply(thisArg, argsArray) — similar to call but args in array
      const thisArgTaint = argTaints[0] || TaintSet.empty();
      const argsArrayTaint = argTaints[1] || TaintSet.empty();
      const applyObj = node.callee?.object;
      if (applyObj) {
        // Resolve callee name: scope-qualified for funcMap, bare for sink matching
        // Identifier → resolveId (scoped); MemberExpression → _scopeQualifyMemberExpr (scoped)
        let funcName = _scopeQualifyMemberExpr(applyObj, ctx);
        const resolvedName = (applyObj.type === 'Identifier' && ctx._paramArgNames?.get(applyObj.name))
          || funcName;

        // Resolve funcRef early so we can use param count for taint unpacking
        let funcRef = funcName && ctx.funcMap.get(funcName);
        if (!funcRef && resolvedName !== funcName && resolvedName) {
          funcRef = ctx.funcMap.get(resolvedName);
        }
        // IIFE .apply(this, args): (function(){...}).apply(thisArg, argsArray)
        if (!funcRef && (applyObj.type === 'FunctionExpression' || applyObj.type === 'ArrowFunctionExpression')) {
          funcRef = applyObj;
        }
        if (globalThis._TAINT_DEBUG) {
          const _scopedKey = applyObj.type === 'Identifier' ? resolveId(applyObj, ctx.scopeInfo) : 'N/A';
          const _callerArg0 = ctx._callerArgNodes?.[0];
          const _callerArg0Ret = _callerArg0?._returnedFuncNode;
          console.log(`[APPLY] ${funcName}.apply() resolved=${resolvedName} funcRef=${funcRef?.type||'null'}/${funcRef?.id?.name||'anon'} params=${funcRef?.params?.length} hasBody=${!!funcRef?.body} scopeKey=${_scopedKey} hasClosure=${!!funcRef?._closureEnv} callerRetFunc=${!!ctx._callerReturnedFuncNode} retFunc=${!!ctx.returnedFuncNode} callerArg0RetFunc=${_callerArg0Ret?.type||'none'}/${_callerArg0Ret?.params?.length}`);
        }
        // Unpack per-index argument taints from the args array
        const argsNode = node.arguments?.[1];
        let unpackedArgTaints;
        if (argsNode?.type === 'Identifier') {
          const argsKey = resolveId(argsNode, ctx.scopeInfo);
          // Collect all per-index entries from the args variable (scope-qualified).
          // Use getAllWithPrefix to find the highest index, then fill in gaps with empty taints.
          const allIdx = env.getAllWithPrefix(`${argsKey}.#idx_`);
          let maxIdx = -1;
          const idxMap = new Map();
          for (const [key, taint] of allIdx) {
            const m = key.match(/\.#idx_(\d+)$/);
            if (m) {
              const idx = parseInt(m[1]);
              idxMap.set(idx, taint);
              if (idx > maxIdx) maxIdx = idx;
            }
          }
          const perIdx = [];
          for (let ai = 0; ai <= maxIdx; ai++) {
            perIdx.push(idxMap.get(ai) || TaintSet.empty());
          }
          if (perIdx.length > 0) {
            // Pad per-index array to cover all callee params — if the array was
            // populated via a dynamic-index loop (o[i] = args[i]), some indices
            // may be missing. Use the overall array taint for missing slots.
            const paramCount = funcRef?.params?.length || perIdx.length;
            while (perIdx.length < paramCount && argsArrayTaint.tainted) {
              perIdx.push(argsArrayTaint.clone());
            }
            unpackedArgTaints = perIdx;
          } else if (argsArrayTaint.tainted) {
            // No per-index entries but the array variable itself is tainted (e.g., from
            // a loop like `while(++i<N) arr[i] = args[i]` where indices couldn't be resolved).
            // Spread the base taint across all params so each param gets tainted.
            const paramCount = funcRef?.params?.length || 1;
            unpackedArgTaints = Array.from({ length: Math.max(paramCount, 1) }, () => argsArrayTaint.clone());
          } else {
            unpackedArgTaints = [argsArrayTaint];
          }
        } else if (argsNode?.type === 'ArrayExpression') {
          unpackedArgTaints = argsNode.elements.map(el => el ? evaluateExpr(el, env, ctx) : TaintSet.empty());
        } else {
          unpackedArgTaints = [argsArrayTaint];
        }

        // Check if resolved callee is a known sink (eval, document.write, etc.)
        if (resolvedName) {
          const bareResolvedName = _stripScopePrefix(resolvedName);
          const sinkInfo = checkCallSink(bareResolvedName, bareResolvedName);
          if (sinkInfo) {
            const synthArgs = argsNode?.type === 'ArrayExpression' ? argsNode.elements : [];
            const sinkCall = { ...node, callee: applyObj, arguments: synthArgs };
            checkSinkCall(sinkCall, sinkInfo, unpackedArgTaints, bareResolvedName, env, ctx);
          }
        }
        if (funcRef && funcRef.body) {
          const thisArgNode = node.arguments?.[0];
          if (thisArgNode) {
            const thisArgNameApply = _scopeQualifyMemberExpr(thisArgNode, ctx);
            if (thisArgNameApply) funcRef._boundThisArg = thisArgNameApply;
          }
          // Construct synthCall with proper argument AST nodes (not the argsArray wrapper).
          // This enables function node registration (e.g., param→FunctionExpression mapping)
          // inside the callee when functions are passed through .apply().
          let synthArgs;
          if (argsNode?.type === 'ArrayExpression') {
            synthArgs = argsNode.elements;
          } else if (argsNode?.type === 'Identifier' && argsNode.name === 'arguments' && ctx._callerArgNodes) {
            synthArgs = ctx._callerArgNodes;
            // Propagate returnedFuncNode from the outer call site so that param→funcNode
            // registration works (e.g., Ce wrapper forwarding Ue result via arguments to ao)
            if (ctx._callerReturnedFuncNode && !ctx.returnedFuncNode) {
              ctx.returnedFuncNode = ctx._callerReturnedFuncNode;
            }
          } else {
            synthArgs = node.arguments?.slice(1) || [];
          }
          const synthCall = { ...node, callee: applyObj, arguments: synthArgs };
          // When args came from a variable (not inline array/arguments), store the variable
          // name so analyzeCalledFunction can propagate nested per-index taints
          // (e.g., argsVar.#idx_1.#idx_0 → param_r.#idx_0)
          if (argsNode?.type === 'Identifier' && argsNode.name !== 'arguments') {
            synthCall._applyArgsVarName = argsNode.name;
          }
          const applyResult = analyzeCalledFunction(synthCall, resolvedName || funcName, unpackedArgTaints, env, ctx);
          return applyResult;
        }
      }
      return thisArgTaint.clone().merge(argsArrayTaint);
    }

    case 'get': case 'getAll': {
      // Check per-key Map taint first
      const getObjStr = _scopeQualifyMemberExpr(node.callee?.object, ctx);
      const getKeyArg = node.arguments?.[0];
      const getKeyStr = getKeyArg && (getKeyArg.type === 'StringLiteral' || getKeyArg.type === 'Literal')
        ? (getKeyArg.value ?? getKeyArg.raw) : null;
      if (getObjStr && getKeyStr != null) {
        const perKeyPath = `${getObjStr}.#key_${getKeyStr}`;
        const perKeyTaint = env.get(perKeyPath);
        if (perKeyTaint.tainted) return perKeyTaint.clone();
        // Also check scope-resolved key
        if (node.callee?.object?.type === 'Identifier') {
          const scopedKey = resolveId(node.callee.object, ctx.scopeInfo);
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
          const innerObjStr = _scopeQualifyMemberExpr(innerCallee.object, ctx);
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
              const scopedInner = resolveId(innerCallee.object, ctx.scopeInfo);
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
      if (objTaint.tainted) {
        // Track .get('key') as a transform so PoC knows the parameter name
        if (getKeyStr != null) {
          return objTaint.withTransform({ op: 'get', args: [getKeyStr] });
        }
        return objTaint.clone();
      }
      // Storage API: localStorage.get() / sessionStorage.get()
      if (node.callee?.object) {
        const storageObj = node.callee.object;
        if (isGlobalRef(storageObj, 'localStorage', env, ctx)) {
          const loc = getNodeLoc(node);
          return TaintSet.from(new TaintLabel('storage.local', ctx.file, loc.line || 0, loc.column || 0, 'localStorage.getItem()'));
        }
        if (isGlobalRef(storageObj, 'sessionStorage', env, ctx)) {
          const loc = getNodeLoc(node);
          return TaintSet.from(new TaintLabel('storage.session', ctx.file, loc.line || 0, loc.column || 0, 'sessionStorage.getItem()'));
        }
      }
      // If the callee resolves to a user-defined function, let analyzeCalledFunction handle it
      const getCalleeStr = _scopeQualifyMemberExpr(node.callee, ctx);
      if (getCalleeStr && ctx.funcMap.has(getCalleeStr)) return null;
      return TaintSet.empty();
    }

    case 'getItem': {
      // Storage API: localStorage.getItem() / sessionStorage.getItem()
      if (node.callee?.object) {
        const storageObj = node.callee.object;
        if (isGlobalRef(storageObj, 'localStorage', env, ctx)) {
          const loc = getNodeLoc(node);
          return TaintSet.from(new TaintLabel('storage.local', ctx.file, loc.line || 0, loc.column || 0, 'localStorage.getItem()'));
        }
        if (isGlobalRef(storageObj, 'sessionStorage', env, ctx)) {
          const loc = getNodeLoc(node);
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
        const eventStr = _scopeQualifyMemberExpr(eventArg, ctx);
        let eventType = eventStr && ctx._customEventTypes?.get(eventStr);
        if (!eventType && eventArg.type === 'Identifier') {
          const resolvedKey = resolveId(eventArg, ctx.scopeInfo);
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
    const refKey = resolveId(callback, ctx.scopeInfo);
    const refFunc = ctx.funcMap.get(refKey);
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
      const loc = getNodeLoc(callback);
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
        const loc = getNodeLoc(callback);
        const desc = originCheck === 'weak'
          ? `${paramName}.data (weak origin check)`
          : `${paramName}.data (no origin check)`;
        const label = new TaintLabel('postMessage.data', ctx.file, loc.line || 0, loc.column || 0, desc);
        label.structural = true; // attacker controls the message data shape
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

  const prevHandler = ctx._handlerContext;
  ctx._handlerContext = { type: eventName || 'event', param: callback.params[0]?.name || null };
  callback._isEventHandler = true;
  if (!callback._closureEnv) callback._closureEnv = env;
  let result;
  if (callback.body.type === 'BlockStatement') {
    result = analyzeInlineFunction(callback, childEnv, ctx);
  } else {
    result = evaluateExpr(callback.body, childEnv, ctx);
  }
  ctx._handlerContext = prevHandler;
  return result;
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
          const regexNode = node.callee.object;
          const pattern = regexNode?.regex?.pattern || regexNode?.pattern || '';
          const flags = regexNode?.regex?.flags || regexNode?.flags || '';
          checks.push(classifyOriginRegex(pattern, flags));
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
            const key = resolveId(node.callee, ctx.scopeInfo);
            funcNode = ctx.funcMap.get(key);
          } else if (node.callee.type === 'MemberExpression' && node.callee.object?.type === 'Identifier' && node.callee.property?.name) {
            const calleeName = `${_resolveObjKey(node.callee.object, ctx)}.${node.callee.property.name}`;
            funcNode = ctx.funcMap.get(calleeName);
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
function classifyOriginRegex(pattern, flags) {
  if (!pattern) return 'weak';
  // Use the JS runtime's own regex engine to evaluate safety.
  // An origin check is "strong" only if it rejects all attacker-controlled origins.
  try {
    const re = new RegExp(pattern, flags || '');
    // Test known bypass patterns — if ANY match, the check is bypassable
    const bypasses = [
      'https://evil.com',
      'https://attacker.example.com',
      'https://evil-trusted.com',
      'null',
    ];
    for (const bypass of bypasses) {
      if (re.test(bypass)) return 'weak';
    }
    return 'strong';
  } catch {
    return 'weak';
  }
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
    const refKey = resolveId(callback, ctx.scopeInfo);
    const refFunc = ctx.funcMap.get(refKey);
    if (refFunc) callback = refFunc;
    else return TaintSet.empty();
  }
  if (callback.type !== 'ArrowFunctionExpression' && callback.type !== 'FunctionExpression' &&
      callback.type !== 'FunctionDeclaration') return TaintSet.empty();

  const childEnv = env.child();
  if (callback.params[0]) assignToPattern(callback.params[0], objTaint, childEnv, ctx);
  if (callback.params[1]) assignToPattern(callback.params[1], TaintSet.empty(), childEnv, ctx);

  // Set closure env so closure mutation propagation works (line ~5570)
  // This allows forEach/map callbacks to propagate outer variable mutations
  if (!callback._closureEnv) callback._closureEnv = env;

  let result;
  if (callback.body.type === 'BlockStatement') {
    result = analyzeInlineFunction(callback, childEnv, ctx);
  } else {
    result = evaluateExpr(callback.body, childEnv, ctx);
  }

  // Propagate closure mutations from callback back to outer env
  // This handles patterns like: arr.forEach(function(x) { outerVar = x; })
  for (const [key, taint] of childEnv.entries()) {
    // Skip callback params and internal keys
    if (callback.params[0]?.type === 'Identifier' && key === callback.params[0].name) continue;
    if (callback.params[1]?.type === 'Identifier' && key === callback.params[1].name) continue;
    if (key.startsWith('this.') || key === 'this') continue;
    // Propagate tainted entries to outer env (for captured variables and property writes)
    if (taint.tainted) {
      env.set(key, env.get(key).clone().merge(taint));
    }
  }

  return result;
}

// ── Promise callback ──
function analyzePromiseCallback(node, argTaints, objTaint, env, ctx) {
  const methodName = node.callee?.property?.name || '';
  const callback = node.arguments[0];

  // .finally() does not receive the resolved value; it passes through the original taint
  if (methodName === 'finally') {
    if (callback && isFuncExpr(callback)) {
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

  // Propagate resolved value's funcMap entries and per-property taints to callback param
  // Promise.resolve(obj).then(m => m.method()) → m inherits obj's funcMap entries
  if (callback.params[0]?.type === 'Identifier') {
    const paramKey = resolveId(callback.params[0], ctx.scopeInfo);
    // Find the resolved value source: walk up .then().then() chains to find the Promise.resolve(x) arg
    let resolvedSrcNode = null;
    let chainObj = node.callee?.object;
    while (chainObj) {
      if (chainObj.type === 'CallExpression' && isCalleeMatch(chainObj, 'Promise', 'resolve', env, ctx) && chainObj.arguments?.[0]) {
        resolvedSrcNode = chainObj.arguments[0];
        break;
      }
      chainObj = chainObj.callee?.object || null;
    }
    if (resolvedSrcNode) {
      const srcKey = _scopeQualifyMemberExpr(resolvedSrcNode, ctx);
      if (srcKey) {
        const srcPrefix = srcKey + '.';
        for (const [fk, fv] of ctx.funcMap) {
          if (fk.startsWith(srcPrefix)) {
            const methodName = fk.slice(srcPrefix.length);
            if (methodName && !methodName.includes('.')) ctx.funcMap.set(`${paramKey}.${methodName}`, fv);
          }
        }
        for (const [ek, ev] of env.entries()) {
          if (ek.startsWith(srcPrefix)) {
            const propName = ek.slice(srcPrefix.length);
            if (propName && !propName.startsWith('#')) childEnv.set(`${paramKey}.${propName}`, ev);
          }
        }
      }
    }
  }

  // If a previous promise callback returned a function node, register it under the
  // current callback's parameter name so fn() calls inside this callback resolve correctly
  if (ctx.returnedFuncNode && callback.params[0]?.type === 'Identifier') {
    ctx.funcMap.set(resolveId(callback.params[0], ctx.scopeInfo), ctx.returnedFuncNode);
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

// ── Shared frame finalization ──
// Propagates results (exit state, returnedFuncNode, funcMap entries) from child to caller.

let _wrapperIdCounter = 0;
function _finalizeFrame(frame) {
  const { innerCtx, callerCtx, env, cfg, blockEnvs } = frame;

  // Merge exit state back to the frame's env
  const exitState = blockEnvs.get(cfg.exit.id);
  if (globalThis._TAINT_TRACE) {
    if (exitState) {
      for (const [k, v] of exitState.entries()) {
        if (k.includes('obj') && k.includes('.')) trace('EXIT-STATE', { key: k, tainted: v.tainted, calleeStr: frame.calleeStr });
      }
    }
    for (const [k, v] of env.entries()) {
      if (k.includes('obj') && k.includes('.')) trace('CHILD-BEFORE', { key: k, tainted: v.tainted, calleeStr: frame.calleeStr });
    }
  }
  if (exitState) env.mergeFrom(exitState);
  for (const pred of cfg.exit.predecessors) {
    const state = blockEnvs.get(pred.id);
    if (state) {
      if (globalThis._TAINT_TRACE) {
        for (const [k, v] of state.entries()) {
          if (k.includes('obj') && k.includes('.')) trace('PRED-STATE', { predId: pred.id, key: k, tainted: v.tainted, calleeStr: frame.calleeStr });
        }
      }
      env.mergeFrom(state);
    }
  }
  if (globalThis._TAINT_TRACE) {
    for (const [k, v] of env.entries()) {
      if (k.includes('obj') && k.includes('.')) trace('FINALIZE-ENV', { key: k, tainted: v.tainted, calleeStr: frame.calleeStr });
    }
  }

  // Propagate returned function/method info to the caller context
  if (innerCtx.returnedFuncNode) {
    if (globalThis._TAINT_DEBUG) console.log(`[FINALIZE] callee=${frame.calleeStr||'?'} retFunc=${innerCtx.returnedFuncNode.type}/${innerCtx.returnedFuncNode.id?.name||'anon'} params=${innerCtx.returnedFuncNode.params?.length} prevRetFunc=${callerCtx.returnedFuncNode?.type||'none'}/${callerCtx.returnedFuncNode?.id?.name||'anon'} prevParams=${callerCtx.returnedFuncNode?.params?.length||'?'}`);
    callerCtx.returnedFuncNode = innerCtx.returnedFuncNode;
    if (frame.callNode) {
      frame.callNode._returnedFuncNode = callerCtx.returnedFuncNode;
    }
  }
  if (innerCtx.returnedMethods) callerCtx.returnedMethods = innerCtx.returnedMethods;
  // Resolve _returnedObjectKeysData: the return handler may have run before the push handler
  // (worklist processes return block before loop body). Resolve now using the saved key.
  if (!innerCtx._returnedObjectKeysData && innerCtx._returnedVarKey && innerCtx._objectKeysVars) {
    const keysData = innerCtx._objectKeysVars.get(innerCtx._returnedVarKey);
    trace('DEFERRED-KEYS', { retVarKey: innerCtx._returnedVarKey, keysVarsSize: innerCtx._objectKeysVars.size, found: !!keysData, calleeStr: frame.calleeStr });
    if (keysData) {
      innerCtx._returnedObjectKeysData = keysData;
      callerCtx._returnedObjectKeysData = keysData;
    }
  }
  if (innerCtx._returnedObjectKeysData) callerCtx._returnedObjectKeysData = innerCtx._returnedObjectKeysData;
  if (innerCtx.returnElementTaints) callerCtx.returnElementTaints = innerCtx.returnElementTaints;
  if (innerCtx.returnPropertyTaints) callerCtx.returnPropertyTaints = innerCtx.returnPropertyTaints;

  // Level 2: Propagate _returnedBuiltinAlias through interprocedural call chain
  // When a callee returns a builtin reference (e.g., Be(Object,"defineProperty") → Object.defineProperty),
  // propagate the alias to the caller so var assignments can register it.
  if (innerCtx._returnedBuiltinAlias) {
    if (globalThis._TAINT_DEBUG) console.log(`[FINALIZE-BUILTIN-L2] callee=${frame.calleeStr||'?'} alias=${innerCtx._returnedBuiltinAlias}`);
    callerCtx._returnedBuiltinAlias = innerCtx._returnedBuiltinAlias;
  }

  // Propagate env aliases from inner to caller (for IIFEs especially)
  // This allows aliases set inside an IIFE body to be visible in the caller scope
  if (frame._isIIFE && innerCtx._iifePropagatedAliases) {
    for (const [k, v] of innerCtx._iifePropagatedAliases) {
      if (!env.aliases.has(k)) env.aliases.set(k, v);
    }
  }

  // Propagate funcMap entries from inner function to caller.
  // With scope-qualified keys, cross-scope collisions are impossible by construction —
  // inner function's "5:o.toString" can never match caller's "3:o.toString" lookup.
  // So we propagate everything: the scope UID IS the isolation mechanism.
  const newFuncEntries = innerCtx.funcMap.newEntries ? innerCtx.funcMap.newEntries() : innerCtx.funcMap;
  for (const [key, val] of newFuncEntries) {
    if (!callerCtx.funcMap.has(key)) {
      callerCtx.funcMap.set(key, val);
    }
  }
}

// ── Analyze inline function body ──
// Fully iterative via the IP frame stack. Pushes a frame onto _ipStack when
// available; otherwise runs _runIPLoop directly. Uses per-block counter-based
// caching so re-processed blocks get cached results.
function analyzeInlineFunction(funcNode, env, ctx, callerEnv) {
  // Re-entrancy guard: prevent infinite recursion when a callback references itself
  // (e.g., function retry() { setTimeout(retry, 100); addEventListener("load", retry); })
  // Uses a stack-based check so the same function CAN be re-analyzed with different
  // taint inputs (e.g., CustomEvent dispatch), just not recursively.
  const loc = funcNode.loc?.start;
  const aifKey = loc ? `aif:${loc.line}:${loc.column}` : null;
  if (!ctx._aifStack) ctx._aifStack = new Set();
  if (aifKey && ctx._aifStack.has(aifKey)) return TaintSet.empty();
  if (aifKey) ctx._aifStack.add(aifKey);
  const innerCfg = buildCFG(funcNode.body);
  // Event handlers can be invoked multiple times — add a back-edge from exit to entry
  // so the worklist's fixed-point iteration models state accumulation across invocations.
  if (funcNode._isEventHandler && innerCfg.exit && innerCfg.entry) {
    innerCfg.exit.connect(innerCfg.entry);
  }
  const innerCtx = new AnalysisContext(
    ctx.file, ctx.funcMap.fork ? ctx.funcMap.fork() : new FuncMap(ctx.funcMap), ctx.findings,
    ctx.globalEnv, ctx.scopeInfo, ctx.analyzedCalls
  );
  innerCtx._aifStack = ctx._aifStack; // propagate re-entrancy guard to nested calls
  if (ctx._isRecursiveCall) innerCtx._isRecursiveCall = true; // propagate to callees
  // Track source file for correct finding attribution in multi-file analysis.
  // If the function was parsed from a different file, use that file for sink info.
  innerCtx._sinkFile = funcNode._sourceFile || ctx._sinkFile || ctx.file;
  innerCtx.classBodyMap = ctx.classBodyMap;
  innerCtx.superClassMap = ctx.superClassMap;
  innerCtx.protoMethodMap = ctx.protoMethodMap;
  innerCtx.elementTypes = ctx.elementTypes;
  innerCtx.domAttached = ctx.domAttached;
  innerCtx.scriptElements = ctx.scriptElements;
  innerCtx._prototypeLinkages = ctx._prototypeLinkages;
  if (ctx._paramConstants) innerCtx._paramConstants = ctx._paramConstants;
  if (ctx._localConstants?.size > 0) {
    if (!innerCtx._localConstants) innerCtx._localConstants = new Map(ctx._localConstants);
    else for (const [k, v] of ctx._localConstants) innerCtx._localConstants.set(k, v);
  }
  if (funcNode._superClass) innerCtx._currentSuperClass = funcNode._superClass;
  if (ctx._handlerContext) innerCtx._handlerContext = ctx._handlerContext;

  const frame = {
    cfg: innerCfg,
    worklist: [innerCfg.entry],
    blockEnvs: new Map([[innerCfg.entry.id, env.clone()]]),
    inWorklist: new Set([innerCfg.entry.id]),
    innerCtx,
    callerCtx: ctx,
    env,
    postProcess: null,
  };

  // If caller provides callerEnv, set up postProcess to propagate this.* bindings
  // (used by constructor analysis to propagate instance properties)
  if (callerEnv) {
    const _childEnv = env;
    frame.postProcess = (result) => {
      for (const [key, taint] of _childEnv.entries()) {
        if (key.startsWith('this.') && key.length > 5) {
          callerEnv.set(key, taint);
        }
      }
    };
  }

  if (ctx._ipStack) {
    // Check inline result cache (keyed by block + call index within that block)
    const callIdx = ctx._inlineCallIdx++;
    const cacheKey = `${ctx._currentBlockId}:${callIdx}`;
    if (!ctx._inlineResults) ctx._inlineResults = new Map();
    if (ctx._inlineResults.has(cacheKey)) {
      const cached = ctx._inlineResults.get(cacheKey);
      if (cached._returnedFuncNode) ctx.returnedFuncNode = cached._returnedFuncNode;
      if (cached._returnedMethods) ctx.returnedMethods = cached._returnedMethods;
      if (cached._returnElementTaints) ctx.returnElementTaints = cached._returnElementTaints;
      if (cached._returnPropertyTaints) ctx.returnPropertyTaints = cached._returnPropertyTaints;
      return cached.clone();
    }
    frame._inlineCacheKey = cacheKey;
    frame._parentInlineResults = ctx._inlineResults;
    // Clean up re-entrancy guard when frame eventually completes (via postProcess)
    // Also propagate closure variable mutations back to _closureEnv
    const _origPostProcess = frame.postProcess;
    const _aifCleanupKey = aifKey;
    const _aifCleanupStack = ctx._aifStack;
    const _closureEnv = funcNode._closureEnv;
    const _frameEnv = env;
    const _funcParams = funcNode.params || [];
    const _analyzedCalls = ctx.analyzedCalls;
    frame.postProcess = (result) => {
      if (_origPostProcess) _origPostProcess(result);
      if (_aifCleanupKey) _aifCleanupStack.delete(_aifCleanupKey);
      // Update the constructor callSig in analyzedCalls with the real result.
      // _evaluateNewExprBody pre-seeds with callSig; this updates it with the actual taint.
      if (frame._ctorCallSig && _analyzedCalls) {
        _analyzedCalls.set(frame._ctorCallSig, result || TaintSet.empty());
      }
      // Propagate tainted closure mutations back to outer env
      if (_closureEnv) {
        const paramNames = new Set();
        for (const p of _funcParams) {
          if (p.type === 'Identifier') paramNames.add(p.name);
          else if (p.type === 'RestElement' && p.argument?.type === 'Identifier') paramNames.add(p.argument.name);
        }
        _propagateClosureMutations(_frameEnv, _closureEnv, paramNames);
      }
      // Propagate global-scoped side effects (window.X, bare globals)
      for (const [key, taint] of _frameEnv.entries()) {
        if (taint.tainted && key.indexOf('.') !== -1 &&
            key.slice(0, 5) !== 'this.' && key.slice(0, 7) !== 'global:' &&
            !(key[0] >= '0' && key[0] <= '9')) {
          env.set(key, taint);
        }
      }
    };
    ctx._ipStack.push(frame);
    ctx._ipSuspended = true;
    return TaintSet.empty();
  }

  const _result = _runIPLoop([frame]);
  if (aifKey) ctx._aifStack.delete(aifKey);
  // Propagate closure mutations back to outer env (for non-IP-stack path)
  if (funcNode._closureEnv) {
    const paramNames = new Set();
    for (const p of (funcNode.params || [])) {
      if (p.type === 'Identifier') paramNames.add(p.name);
      else if (p.type === 'RestElement' && p.argument?.type === 'Identifier') paramNames.add(p.argument.name);
    }
    _propagateClosureMutations(env, funcNode._closureEnv, paramNames);
  }
  return _result;
}

// Compute reverse postorder numbering for CFG blocks.
// RPO ensures loop bodies are processed before loop exits in forward dataflow analysis.
function _computeRPO(cfg) {
  const rpo = new Map();
  const visited = new Set();
  let order = 0;
  const postOrder = [];
  const stack = [{ block: cfg.entry, childIdx: 0 }];
  while (stack.length > 0) {
    const frame = stack[stack.length - 1];
    const block = frame.block;
    if (!visited.has(block.id)) visited.add(block.id);
    if (frame.childIdx < block.successors.length) {
      const succ = block.successors[frame.childIdx++];
      if (!visited.has(succ.id)) {
        stack.push({ block: succ, childIdx: 0 });
      }
    } else {
      stack.pop();
      postOrder.push(block);
    }
  }
  for (let i = postOrder.length - 1; i >= 0; i--) {
    rpo.set(postOrder[i].id, order++);
  }
  return rpo;
}

// ── Interprocedural frame loop driver ──
// Processes frames from the stack until all complete. Each frame is a function body
// being analyzed via its CFG worklist. When a nested call is encountered, a child
// frame is pushed; when it completes, the parent re-processes the suspended block.
function _runIPLoop(ipStack) {
  let finalResult = TaintSet.empty();

  while (ipStack.length > 0) {
    const frame = ipStack[ipStack.length - 1];
    const { worklist, blockEnvs, inWorklist, innerCtx } = frame;

    // Attach the stack to the context so nested calls can push frames
    innerCtx._ipStack = ipStack;

    let suspended = false;

    while (worklist.length > 0) {
      const block = worklist.shift();
      inWorklist.delete(block.id);
      const entryEnv = blockEnvs.get(block.id);
      if (!entryEnv) continue;

      // Resume from checkpoint if available, otherwise fresh processing
      innerCtx._currentBlockId = block.id;
      let processEnv;
      if (frame._checkpoint && frame._checkpoint.blockId === block.id) {
        processEnv = frame._checkpoint.env;
        innerCtx._resumeNodeIdx = frame._checkpoint.nodeIdx;
        innerCtx._inlineCallIdx = frame._checkpoint.inlineCallIdx;
        innerCtx._resumeEvaluator = frame._checkpoint.evaluator;
        frame._checkpoint = null;
      } else {
        processEnv = entryEnv.clone();
        innerCtx._inlineCallIdx = 0;
        // Inject deferred per-property/per-index entries into the processing env.
        // These are stored on the frame to avoid polluting blockEnvs (which would
        // re-introduce stale values during _finalizeFrame's predecessor merge).
        if (frame._deferredPropEntries && block.id === frame.cfg.entry.id) {
          for (const [key, taint] of frame._deferredPropEntries) {
            processEnv.set(key, taint);
          }
        }
      }

      if (!frame._wlGen) frame._wlGen = 1;
      processEnv._generation = frame._wlGen++;
      const exitEnv = processBlock(block, processEnv, innerCtx);

      if (innerCtx._ipSuspended) {
        // A child frame was pushed during processBlock.
        // Save checkpoint so we can resume at the suspended node instead of
        // re-processing the entire block from scratch.
        innerCtx._ipSuspended = false;
        frame._checkpoint = {
          blockId: block.id,
          env: exitEnv,
          nodeIdx: innerCtx._suspendedNodeIdx,
          inlineCallIdx: innerCtx._suspendedInlineIdx,
        };
        // Re-queue suspended block at correct RPO position (not just front)
        const _suspRpo = frame.rpo?.get(block.id) ?? block.id;
        let _suspIdx = 0;
        for (let wi = 0; wi < worklist.length; wi++) {
          const wiRpo = frame.rpo?.get(worklist[wi].id) ?? worklist[wi].id;
          if (_suspRpo < wiRpo) { _suspIdx = wi; break; } else { _suspIdx = wi + 1; }
        }
        worklist.splice(_suspIdx, 0, block);
        inWorklist.add(block.id);
        suspended = true;
        break;
      }

      // Propagate to successors
      for (const succ of block.successors) {
        // Branch fold: skip unreachable branches.
        // Pass innerCtx for scope-aware resolution (typeof on undeclared identifiers).
        // For recursive functions, strip _paramConstants to avoid folding branches
        // that depend on parameters which change across recursive calls.
        if (succ.branchCondition) {
          let _branchCtx = innerCtx;
          if (innerCtx._isRecursiveCall && innerCtx._paramConstants) {
            _branchCtx = Object.create(innerCtx);
            _branchCtx._paramConstants = null;
          }
          const _foldVal = isConstantBool(succ.branchCondition, _branchCtx, exitEnv);
          if (_foldVal !== null) {
            if (_foldVal === false && succ.branchPolarity === true) continue;
            if (_foldVal === true && succ.branchPolarity === false) continue;
          }
        }
        const existing = blockEnvs.get(succ.id);
        if (!existing) {
          blockEnvs.set(succ.id, exitEnv.clone());
          if (!inWorklist.has(succ.id)) {
            // Insert in RPO order: find the correct position to maintain RPO ordering.
            // This ensures loop bodies are processed before loop exits.
            const succRpo = frame.rpo?.get(succ.id) ?? succ.id;
            let insertIdx = worklist.length;
            for (let wi = 0; wi < worklist.length; wi++) {
              const wiRpo = frame.rpo?.get(worklist[wi].id) ?? worklist[wi].id;
              if (succRpo < wiRpo) { insertIdx = wi; break; }
            }
            worklist.splice(insertIdx, 0, succ);
            inWorklist.add(succ.id);
          }
        } else {
          const _changed = existing.mergeFrom(exitEnv);
          let _forceRequeue = false;
          if (innerCtx._forLoopCounterActive && innerCtx._forLoopRequeueRemaining) {
            for (const [lk, rem] of innerCtx._forLoopRequeueRemaining) {
              if (rem > 0) { _forceRequeue = true; innerCtx._forLoopRequeueRemaining.set(lk, rem - 1); break; }
            }
            if (!_forceRequeue) innerCtx._forLoopCounterActive = false;
          }
          if ((_changed || _forceRequeue) && !inWorklist.has(succ.id)) {
            const succRpo = frame.rpo?.get(succ.id) ?? succ.id;
            let insertIdx = worklist.length;
            for (let wi = 0; wi < worklist.length; wi++) {
              const wiRpo = frame.rpo?.get(worklist[wi].id) ?? worklist[wi].id;
              if (succRpo < wiRpo) { insertIdx = wi; break; }
            }
            worklist.splice(insertIdx, 0, succ);
            inWorklist.add(succ.id);
          }
        }
      }
    }

    if (suspended) continue; // process the child frame next

    // Frame's worklist is empty — finalize it
    innerCtx._ipStack = null;

    _finalizeFrame(frame);

    const returnTaint = innerCtx.returnTaint;

    // Run call-level post-processing (env propagation, funcMap propagation, caching)
    if (frame.postProcess) {
      frame.postProcess(returnTaint);
    }

    // Cache inline frame results for block re-processing
    if (frame._inlineCacheKey && frame._parentInlineResults) {
      const cached = returnTaint.clone();
      if (innerCtx.returnedFuncNode) cached._returnedFuncNode = innerCtx.returnedFuncNode;
      if (innerCtx.returnedMethods) cached._returnedMethods = innerCtx.returnedMethods;
      if (innerCtx.returnElementTaints) cached._returnElementTaints = innerCtx.returnElementTaints;
      if (innerCtx.returnPropertyTaints) cached._returnPropertyTaints = innerCtx.returnPropertyTaints;
      frame._parentInlineResults.set(frame._inlineCacheKey, cached);
    }

    ipStack.pop();

    if (ipStack.length > 0) {
      // Parent resumes from checkpoint on next iteration.
    } else {
      finalResult = returnTaint;
    }
  }

  return finalResult;
}

// ── Interprocedural: analyze a called function ──
// Fully iterative via explicit frame stack — no JS recursion.
function analyzeCalledFunction(callNode, calleeStr, argTaints, env, ctx) {
  let funcNode = null;

  // Resolve via scope-aware binding key
  if (callNode.callee?.type === 'Identifier') {
    const key = resolveId(callNode.callee, ctx.scopeInfo);
    if (ctx.funcMap.has(key)) funcNode = ctx.funcMap.get(key);
  }

  // Look up by calleeStr (scope-qualified path or dotted member path)
  if (!funcNode && calleeStr && ctx.funcMap.has(calleeStr)) {
    funcNode = ctx.funcMap.get(calleeStr);
  }

  // Cross-file / hoisted: try global: prefix for unresolved identifiers
  if (!funcNode && callNode.callee?.type === 'Identifier') {
    const globalKey = `global:${callNode.callee.name}`;
    if (ctx.funcMap.has(globalKey)) funcNode = ctx.funcMap.get(globalKey);
  }

  // super() call — resolve to parent class constructor via _superClass or superClassMap
  if (!funcNode && callNode.callee?.type === 'Super') {
    const currentSuper = ctx._currentSuperClass;
    if (currentSuper) {
      const parentCtor = ctx.funcMap.get(currentSuper);
      if (parentCtor) funcNode = parentCtor;
    }
    if (!funcNode) {
      for (const [, parentClass] of ctx.superClassMap) {
        const parentCtor = ctx.funcMap.get(parentClass);
        if (parentCtor) { funcNode = parentCtor; break; }
      }
    }
  }

  // Inline function expression / arrow
  if (!funcNode && callNode.callee) {
    let effectiveCallee = callNode.callee;
    // Unwrap unary operators: !function(){}(), void function(){}(), ~function(){}()
    // These are common IIFE patterns in minified code (UMD wrappers)
    if (effectiveCallee.type === 'UnaryExpression' && effectiveCallee.argument) {
      effectiveCallee = effectiveCallee.argument;
    }
    // Unwrap parenthesized: (function(){})()
    if (effectiveCallee.type === 'ParenthesizedExpression' && effectiveCallee.expression) {
      effectiveCallee = effectiveCallee.expression;
    }
    if (effectiveCallee.type === 'ArrowFunctionExpression' ||
        effectiveCallee.type === 'FunctionExpression') {
      funcNode = effectiveCallee;
    }
    // Immediately-invoked return: factory()(arg) — callee is a CallExpression
    if (!funcNode && (callNode.callee.type === 'CallExpression' || callNode.callee.type === 'OptionalCallExpression')) {
      if (ctx.returnedFuncNode) {
        funcNode = ctx.returnedFuncNode;
        ctx.returnedFuncNode = null;
      }
    }
    // Ternary callee: (cond ? fnA : fnB)(args) — resolve the selected branch
    if (!funcNode && callNode.callee.type === 'ConditionalExpression') {
      const resolveTernaryBranches = (condNode) => {
        const result = [];
        const rtbStack = [condNode];
        while (rtbStack.length > 0) {
          const cur = rtbStack.pop();
          if (cur.type !== 'ConditionalExpression') { result.push(cur); continue; }
          const condConst = isConstantBool(cur.test);
          if (condConst === true) rtbStack.push(cur.consequent);
          else if (condConst === false) rtbStack.push(cur.alternate);
          else { rtbStack.push(cur.alternate); rtbStack.push(cur.consequent); }
        }
        return result;
      };
      const leafBranches = resolveTernaryBranches(callNode.callee);
      for (const branch of leafBranches) {
        if (branch.type === 'Identifier') {
          const ref = ctx.funcMap.get(resolveId(branch, ctx.scopeInfo));
          if (ref) { funcNode = ref; break; }
        }
        if (isFuncExpr(branch)) {
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
        if ((isObjectProp(prop) || prop.type === 'ObjectMethod') && prop.key) {
          const pName = propKeyName(prop.key);
          if (pName === methodName) {
            funcNode = prop.type === 'ObjectMethod' ? prop : prop.value;
            break;
          }
        }
      }
    }
  }

  // Method call: try scope-qualified dot-path first, then bare dot-path
  if (!funcNode && (callNode.callee?.type === 'MemberExpression' || callNode.callee?.type === 'OptionalMemberExpression')) {
    // Scope-qualify the object part
    if (callNode.callee.object?.type === 'Identifier' && callNode.callee.property?.name && !callNode.callee.computed) {
      const scopedPath = `${_resolveObjKey(callNode.callee.object, ctx)}.${callNode.callee.property.name}`;
      if (ctx.funcMap.has(scopedPath)) funcNode = ctx.funcMap.get(scopedPath);
    }
    if (!funcNode) {
      const fullPath = _scopeQualifyMemberExpr(callNode.callee, ctx);
      if (fullPath && ctx.funcMap.has(fullPath)) funcNode = ctx.funcMap.get(fullPath);
    }
    // Try global: prefix for cross-scope/closure resolution
    if (!funcNode && callNode.callee.object?.type === 'Identifier' && callNode.callee.property?.name && !callNode.callee.computed) {
      const globalPath = `global:${callNode.callee.object.name}.${callNode.callee.property.name}`;
      if (ctx.funcMap.has(globalPath)) funcNode = ctx.funcMap.get(globalPath);
    }
    if (!funcNode) {
      const methodName = callNode.callee.property?.name;
      if (methodName) {
        if (ctx.funcMap.has(`this.${methodName}`)) funcNode = ctx.funcMap.get(`this.${methodName}`);
      }
    }
    // Computed member call: obj[method](args) — resolve method name to dot-path
    if (!funcNode && callNode.callee.computed) {
      const objKey = _resolveObjKey(callNode.callee.object, ctx);
      if (objKey) {
        const _rmAV = resolveAbstract(callNode.callee.property, env, ctx);
        if (_rmAV.concrete && typeof _rmAV.value === 'string') {
          const resolvedMethod = _rmAV.value;
          const dotPath = `${objKey}.${resolvedMethod}`;
          if (ctx.funcMap.has(dotPath)) funcNode = ctx.funcMap.get(dotPath);
        }
        if (!funcNode) {
          const arrFunc = ctx.funcMap.get(`${objKey}[]`);
          if (arrFunc) funcNode = arrFunc;
        }
      }
    }
  }

  if (!funcNode || !funcNode.body) {
    trace('ACF-MISS', { calleeStr, calleeType: callNode.callee?.type, calleeName: callNode.callee?.name || _scopeQualifyMemberExpr(callNode.callee, ctx) || '', file: ctx.file, line: callNode.loc?.start?.line });
    if (globalThis._TAINT_DEBUG) {
      const _aliasInfo = callNode.callee?.type === 'Identifier' && env?.getAlias ? env.getAlias(resolveId(callNode.callee, ctx.scopeInfo)) : undefined;
      console.log(`[ACF] NO funcNode for '${calleeStr}' callee=${callNode.callee?.type}/${callNode.callee?.name||''} alias=${_aliasInfo||'none'} key=${callNode.callee?.type === 'Identifier' ? resolveId(callNode.callee, ctx.scopeInfo) : 'N/A'}`);
    }
    return TaintSet.empty();
  }

  // Include the resolved super class in the signature so different super() calls in an inheritance chain aren't deduplicated
  const superSuffix = callNode.callee?.type === 'Super' && ctx._currentSuperClass ? `:super=${ctx._currentSuperClass}` : '';
  // For inline function expressions (IIFEs), use source location to disambiguate since they all resolve to 'anon'
  const locSuffix = (!calleeStr && funcNode.loc) ? `:${funcNode.loc.start.line}:${funcNode.loc.start.column}` : '';
  // Include funcNode source location to disambiguate different function definitions
  // that share the same calleeStr. This prevents cache collisions when e.g. nested wrappers
  // both use "func" as parameter name — func(t,r) (callback) vs func(n,t) (outerFunc)
  // resolve to different AST nodes but would otherwise share the same callSig.
  let wrapperSuffix = '';
  if (funcNode.loc && calleeStr &&
      calleeStr.indexOf('.') === -1 && calleeStr.indexOf(':') === -1) {
    wrapperSuffix = `:fl${funcNode.loc.start.line}:${funcNode.loc.start.column}`;
  }
  let taintBits = 0;
  for (let i = 0; i < argTaints.length; i++) if (argTaints[i].tainted) taintBits |= (1 << i);
  // When arguments include ObjectExpressions, include property names in signature
  // so that calls like extend({html: fn}) and extend({data: fn}) are analyzed separately
  let objArgSuffix = '';
  if (callNode.arguments) {
    for (let i = 0; i < callNode.arguments.length; i++) {
      const arg = callNode.arguments[i];
      if (arg && arg.type === 'ObjectExpression' && arg.properties && arg.properties.length > 0) {
        const keys = [];
        for (let j = 0; j < arg.properties.length && j < 8; j++) {
          const p = arg.properties[j];
          if (p.key) keys.push(p.key.name || p.key.value || '');
        }
        if (keys.length) objArgSuffix += `:obj${i}=${keys.join(',')}`;
      }
    }
  }
  // When arguments include FunctionExpressions and taint is flowing (taintBits > 0),
  // include source locations in signature so decorator calls with different inner functions
  // are analyzed separately (different taint paths through different function bodies).
  // When taintBits === 0 (definition time), skip this — structural result is identical,
  // only returnedFuncNode differs, which we handle via wrapper creation on cache hit.
  // When arguments include inline FunctionExpressions, include source locations so that
  // calls like wrapper(function A(){...}) and wrapper(function B(){...}) are analyzed separately.
  // Only include for INLINE function expressions — NOT for Identifier refs or CallExpression results,
  // as those cause explosive cache growth in large libs (jQuery/lodash have 100s of internal wrapper calls).
  let funcArgSuffix = '';
  if (callNode.arguments) {
    for (let i = 0; i < callNode.arguments.length; i++) {
      const arg = callNode.arguments[i];
      if (arg && (arg.type === 'FunctionExpression' || arg.type === 'ArrowFunctionExpression') && arg.loc) {
        funcArgSuffix += `:fn${i}=${arg.loc.start.line}:${arg.loc.start.column}`;
      } else if (arg && arg.type === 'ObjectExpression' && arg.loc &&
                 arg.properties.some(p => p.value && (p.value.type === 'FunctionExpression' || p.value.type === 'ArrowFunctionExpression'))) {
        // ObjectExpression with function properties — unique per call site
        funcArgSuffix += `:obj${i}=${arg.loc.start.line}:${arg.loc.start.column}`;
      } else if (arg && arg.type === 'Identifier') {
        // When an Identifier arg resolves to a function in funcMap, include its identity
        // in the sig. Without this, higher-order functions like apply(func, this, args)
        // return cached results from a DIFFERENT function when called with the same taintBits
        // but different closure-captured function references (e.g., lodash's minified wrapper
        // chain where `n(t, this, o)` is called with different callbacks bound to `t`).
        const resolvedKey = resolveId(arg, ctx.scopeInfo);
        const refFunc = ctx.funcMap.get(resolvedKey);
        if (refFunc) {
          if (refFunc.loc) funcArgSuffix += `:fn${i}=${refFunc.loc.start.line}:${refFunc.loc.start.column}`;
          else if (refFunc._wrapperId) funcArgSuffix += `:fn${i}=w${refFunc._wrapperId}`;
        }
      } else if (arg && (arg.type === 'CallExpression' || arg.type === 'OptionalCallExpression')) {
        // When a CallExpression arg produced a returnedFuncNode (wrapper), include its
        // identity so passthrough functions like setToString(overRest(...), str) don't
        // collapse all calls into one cached result with the wrong returned function.
        const retFunc = arg._returnedFuncNode;
        if (retFunc) {
          if (retFunc.loc) funcArgSuffix += `:fn${i}=${retFunc.loc.start.line}:${retFunc.loc.start.column}`;
          else if (retFunc._wrapperId) funcArgSuffix += `:fn${i}=w${retFunc._wrapperId}`;
        }
      }
      // Include enumeration context in sig so calls with different enum data aren't cached together
      if (arg?.type === 'Identifier') {
        const argKey = resolveId(arg, ctx.scopeInfo);
        if (ctx._objectKeysVars) {
          if (ctx._objectKeysVars.has(argKey)) {
            funcArgSuffix += `:keys${i}`;
          }
        }
        if (ctx._forInEnumeration) {
          if (ctx._forInEnumeration.has(argKey)) {
            funcArgSuffix += `:enum${i}`;
          }
        }
      } else if (arg?.type === 'MemberExpression' && arg.computed && arg.object?.type === 'Identifier') {
        if (ctx._objectKeysVars) {
          const arrKey = resolveId(arg.object, ctx.scopeInfo);
          if (ctx._objectKeysVars.has(arrKey)) {
            funcArgSuffix += `:keys${i}`;
          }
        }
      }
    }
  }
  const callSig = `${calleeStr || 'anon'}:${taintBits}${superSuffix}${locSuffix}${wrapperSuffix}${objArgSuffix}${funcArgSuffix}`;
  trace('ACF-ENTER', { calleeStr, sig: callSig, taintBits, params: funcNode.params?.length, cached: ctx.analyzedCalls.has(callSig), file: ctx.file, line: callNode.loc?.start?.line });
  if (calleeStr === '312:n') trace('ACF-312N', { funcName: funcNode.id?.name || 'anon', funcParams: funcNode.params?.map(p=>p.name||p.type).join(','), funcLoc: funcNode.loc?.start?.line + ':' + funcNode.loc?.start?.column, wid: funcNode._wrapperId || 'ast' });
  _traceDepth++;
  if (globalThis._TAINT_DEBUG) {
    console.log('[ACF] ENTER ' + JSON.stringify(calleeStr) + ' fn=' + (funcNode.id?.name||'anon') + ' params=' + funcNode.params?.length + ' taintBits=' + taintBits + ' sig=' + callSig + ' cached=' + ctx.analyzedCalls.has(callSig));
    if (funcNode.params?.length === 0 && taintBits > 0 && funcNode._closureFuncMap) {
      const entries = [];
      for (const [k, v] of funcNode._closureFuncMap) {
        entries.push(`${k}→${v?.id?.name||v?.type||'?'}(${v?.params?.length||'?'})`);
      }
      console.log(`[ACF-0PARAM-CLOSURE] wrapperId=${funcNode._wrapperId||'none'} ownKeys=[${funcNode._closureFuncMap._own ? [...funcNode._closureFuncMap._own.keys()].filter(k=>k==='t'||k==='n'||k.endsWith(':t')||k.endsWith(':n')).join(',') : 'N/A'}] entries: ${entries.slice(0,20).join(', ')}`);
    }
  }
  if (ctx.analyzedCalls.has(callSig)) {
    const cached = ctx.analyzedCalls.get(callSig);
    // For definition-time calls (taintBits=0) with function args, reuse cached structural
    // result but create a fresh wrapper for returnedFuncNode with current closure bindings.
    // This avoids re-analyzing the same wrapper body N times (e.g., lodash's baseRest(fn) x100).
    if (cached && cached._returnedFuncNode && taintBits === 0) {
      // For functions with 0 params (passthrough/shortOut pattern using 'arguments'):
      // arg evaluation may have already set ctx.returnedFuncNode to the correct wrapper
      // (e.g., xo(Ue(...), str) where Ue(...) produces the returned function).
      // Since there are no named params, the wrapper path can't bind any closure entries.
      // Preserve the arg-eval returnedFuncNode if set; otherwise fall back to cached.
      if (!funcNode.params || funcNode.params.length === 0) {
        if (!ctx.returnedFuncNode) {
          ctx.returnedFuncNode = cached._returnedFuncNode;
        }
        if (cached._returnedMethods) ctx.returnedMethods = cached._returnedMethods;
        if (globalThis._TAINT_DEBUG) console.log(`[ACF] CACHE-HIT(0-param) '${calleeStr}' → tainted=${cached.tainted} retFunc=${ctx.returnedFuncNode?.type}/${ctx.returnedFuncNode?.id?.name||'anon'}`);
        return cached.clone();
      }
      // Get the underlying AST node. If cached is an Object.create wrapper (_wrapperId),
      // unwrap one level to the prototype (the real AST node). If it's already a real AST
      // node (no _wrapperId), use it directly — its prototype is Node.prototype, not an AST node.
      const rfn = cached._returnedFuncNode;
      const astNode = rfn._wrapperId ? (Object.getPrototypeOf(rfn) || rfn) : rfn;
      const newWrapper = Object.create(astNode);
      // Build closure bindings: bind function's params → current call's args
      // so the wrapper's body can resolve parameter references (e.g., func → innerWrapper)
      const closureEnv = (funcNode._closureEnv || env).child();
      const closureFuncMap = ctx.funcMap.fork ? ctx.funcMap.fork() : new FuncMap(ctx.funcMap);
      if (funcNode._closureFuncMap) {
        // Closure entries take priority over caller-inherited entries
        for (const [k, v] of funcNode._closureFuncMap) {
          closureFuncMap.set(k, v);
        }
        // Add caller entries that aren't in the closure
        for (const [k, v] of ctx.funcMap) {
          if (!closureFuncMap.has(k)) closureFuncMap.set(k, v);
        }
      }
      // When the returned function already has its own closureFuncMap (e.g., a wrapper
      // from overRest with closure binding t→callback), merge those bindings with highest
      // priority. Without this, passthrough wrappers like setToString(overRest(...))
      // would lose the inner function's closure bindings and replace them with the
      // outer caller's entries (e.g., t → outer function declaration).
      if (rfn._closureFuncMap) {
        for (const [k, v] of rfn._closureFuncMap) {
          closureFuncMap.set(k, v);
        }
      }
      // Resolve scope-qualified param keys using the callee's scope info so that
      // body references (which resolve via scopeInfo) find the correct bindings.
      const wrapperScopeInfo = funcNode._closureScopeInfo || ctx.scopeInfo;
      for (let pi = 0; pi < funcNode.params.length && pi < callNode.arguments.length; pi++) {
        const param = funcNode.params[pi];
        if (param.type !== 'Identifier') continue;
        const argNode = callNode.arguments[pi];
        let boundFunc = null;
        if (argNode.type === 'FunctionExpression' || argNode.type === 'ArrowFunctionExpression') {
          const argWrapper = Object.create(argNode);
          argWrapper._closureEnv = env;
          argWrapper._closureFuncMap = ctx.funcMap;
          argWrapper._wrapperId = ++_wrapperIdCounter;
          boundFunc = argWrapper;
        } else if (argNode.type === 'Identifier') {
          const refFunc = ctx.funcMap.get(resolveId(argNode, ctx.scopeInfo));
          if (refFunc) boundFunc = refFunc;
        }
        // CallExpression arg that produced a returnedFuncNode (per-node or volatile ctx)
        if (argNode.type === 'CallExpression' || argNode.type === 'OptionalCallExpression') {
          const retFunc = argNode._returnedFuncNode || ctx.returnedFuncNode;
          if (retFunc) boundFunc = retFunc;
        }
        if (boundFunc) {
          const paramKey = wrapperScopeInfo?.resolve(param) || param.name;
          closureFuncMap.set(paramKey, boundFunc);
        }
        if (argTaints[pi]) {
          const paramKey = wrapperScopeInfo?.resolve(param) || param.name;
          closureEnv.set(paramKey, argTaints[pi]);
        }
      }
      // Apply closure→param mapping: rebind inner closure keys to current call's
      // argument functions. This handles multi-level wrapper chains where the
      // returned function's closure uses a different variable name than the callee's
      // param (e.g., fr(callback) returns Ue wrapper with closure key 't' → callback,
      // so on cache hit we need to bind 't' to the new call's arg).
      if (cached._closureParamMapping) {
        for (const [closureKey, paramIdx] of Object.entries(cached._closureParamMapping)) {
          if (paramIdx < callNode.arguments.length) {
            const argNode = callNode.arguments[paramIdx];
            let resolvedFunc = null;
            // Reuse the wrapper already bound for this param
            const paramName = funcNode.params[paramIdx]?.name;
            if (paramName) resolvedFunc = closureFuncMap.get(paramName);
            if (!resolvedFunc) {
              if (argNode.type === 'FunctionExpression' || argNode.type === 'ArrowFunctionExpression') {
                const w = Object.create(argNode);
                w._closureEnv = env; w._closureFuncMap = ctx.funcMap;
                w._wrapperId = ++_wrapperIdCounter;
                resolvedFunc = w;
              } else if (argNode.type === 'Identifier') {
                resolvedFunc = ctx.funcMap.get(resolveId(argNode, ctx.scopeInfo));
              } else if (argNode.type === 'CallExpression' || argNode.type === 'OptionalCallExpression') {
                resolvedFunc = argNode._returnedFuncNode || ctx.returnedFuncNode;
              }
            }
            if (resolvedFunc) {
              closureFuncMap.set(closureKey, resolvedFunc);
              if (globalThis._TAINT_DEBUG) console.log(`[FIX-C] closureKey=${closureKey} paramIdx=${paramIdx} → ${resolvedFunc.id?.name||resolvedFunc.type}(${resolvedFunc.params?.length})`);
            }
          }
        }
      }
      newWrapper._closureEnv = closureEnv;
      newWrapper._closureFuncMap = closureFuncMap;
      newWrapper._wrapperId = ++_wrapperIdCounter;
      if (ctx._paramArgNames) newWrapper._closureParamArgNames = ctx._paramArgNames;
      // Propagate closure local constants from the cached wrapper's prototype chain.
      // Without this, constants like r=1 (computed during the original analysis) are lost
      // when the cache hit creates a fresh wrapper for a new call site.
      {
        let _p = newWrapper;
        while (_p && _p !== Object.prototype) {
          if (_p._closureLocalConstants) {
            if (!newWrapper._closureLocalConstants) newWrapper._closureLocalConstants = new Map(_p._closureLocalConstants);
            else for (const [k, v] of _p._closureLocalConstants) { if (!newWrapper._closureLocalConstants.has(k)) newWrapper._closureLocalConstants.set(k, v); }
            break; // Found the closest, stop
          }
          _p = Object.getPrototypeOf(_p);
        }
      }
      ctx.returnedFuncNode = newWrapper;
      if (cached._returnedMethods) ctx.returnedMethods = cached._returnedMethods;
      if (globalThis._TAINT_DEBUG) {
        console.log(`[ACF] CACHE-HIT(wrapper) '${calleeStr}' wrapperId=${newWrapper._wrapperId} → tainted=${cached.tainted} retFunc=${newWrapper.type}/${newWrapper.id?.name||'anon'} params=${newWrapper.params?.length}`);
        if (newWrapper.params?.length === 0) {
          const te = closureFuncMap.get('t'), ne = closureFuncMap.get('n');
          console.log(`[ACF] CACHE-HIT(0param) t=${te?.id?.name||te?.type||'?'}(${te?.params?.length||'?'}) n=${ne?.id?.name||ne?.type||'?'}(${ne?.params?.length||'?'})`);
        }
      }
      return cached.clone();
    }
    if (cached && cached._returnedFuncNode) {
      ctx.returnedFuncNode = cached._returnedFuncNode;
    }
    if (cached && cached._returnedMethods) ctx.returnedMethods = cached._returnedMethods;
    // If cache entry was pre-seeded (analysis still in progress) and the call has
    // tainted arguments, this is a recursive call. Return the merged argument taint
    // as a conservative approximation: tainted input → tainted output.
    // This enables recursive merge functions to propagate taint through recursion.
    if (cached?._preSeeded && taintBits > 0) {
      // Mark the current analysis context as recursive — the function calls itself.
      // This enables PP Pattern 5 to expand the danger set (e.g., constructor path).
      ctx._isRecursiveCall = true;
      const mergedArgTaint = TaintSet.empty();
      for (const at of argTaints) if (at.tainted) mergedArgTaint.merge(at.clone());
      if (mergedArgTaint.tainted) {
        if (globalThis._TAINT_DEBUG) console.log(`[ACF] RECURSIVE-APPROX '${calleeStr}' → propagating arg taint as return`);
        return mergedArgTaint;
      }
    }
    if (cached?._returnedFuncNode) ctx.returnedFuncNode = cached._returnedFuncNode;
    if (cached?._returnedMethods) ctx.returnedMethods = cached._returnedMethods;
    if (cached?._returnPropertyTaints) ctx.returnPropertyTaints = cached._returnPropertyTaints;
    if (cached?._returnElementTaints) ctx.returnElementTaints = cached._returnElementTaints;
    if (cached?._returnedObjectKeysData) ctx._returnedObjectKeysData = cached._returnedObjectKeysData;
    trace('ACF-CACHE', { calleeStr, sig: callSig, tainted: cached?.tainted, retFunc: cached?._returnedFuncNode?.id?.name || 'none' });
    _traceDepth--;
    if (globalThis._TAINT_DEBUG) console.log(`[ACF] CACHE-HIT '${calleeStr}' → tainted=${cached?.tainted} retFunc=${cached?._returnedFuncNode?.id?.name||'none'}`);
    return cached?.clone() || TaintSet.empty();
  }
  const _preSeeded = TaintSet.empty();
  _preSeeded._preSeeded = true;
  ctx.analyzedCalls.set(callSig, _preSeeded);

  // Detect recursion: if the same function is already on the IP call stack,
  // mark the context so PP Pattern 5 can expand the danger set.
  // Compare calleeStr (exact match) and funcNode identity (for aliased recursion
  // like global:jQuery.extend calling 3:w.extend — same function, different keys).
  if (calleeStr && ctx._ipStack) {
    for (const frame of ctx._ipStack) {
      if (frame.calleeStr === calleeStr) {
        ctx._isRecursiveCall = true;
        break;
      }
      // Aliased recursion: different calleeStr but same funcNode.
      // Only when taint is flowing (taintBits > 0) — definition-time calls
      // (taintBits = 0) sharing a function aren't recursive deep merges.
      if (taintBits > 0 && frame.funcNode === funcNode) {
        ctx._isRecursiveCall = true;
        break;
      }
    }
  }

  // Pre-check: does the function body contain a self-call? If so, mark as recursive
  // so branch folding doesn't eliminate branches that depend on changing parameters.
  if (calleeStr && funcNode.body && !ctx._isRecursiveCall) {
    // Use the function's OWN scope info for resolving callee identity inside its body.
    // The function body's AST nodes are scoped to the definition file, not the caller's file.
    const _selfScopeInfo = funcNode._closureScopeInfo || ctx.scopeInfo;
    // Also check by function's own name (for HOF patterns where the function is called
    // via a parameter name like 'n' but the body uses its definition name like 'Yt')
    const _selfName = funcNode.id?.name;
    const _selfKey = _selfName ? resolveId(funcNode.id, _selfScopeInfo) : null;
    const _checkSelfCall = (node) => {
      if (!node || typeof node !== 'object') return false;
      if (node.type === 'CallExpression') {
        if (node.callee?.type === 'Identifier') {
          const _callKey = resolveId(node.callee, _selfScopeInfo);
          if (_callKey === calleeStr || _callKey === _selfKey) return true;
        }
        // MemberExpression callee: w.extend(l, o, r) — resolve scope-qualified path
        if (node.callee?.type === 'MemberExpression' || node.callee?.type === 'OptionalMemberExpression') {
          const _callPath = _scopeQualifyMemberExpr(node.callee, { scopeInfo: _selfScopeInfo, file: ctx.file });
          if (_callPath && (_callPath === calleeStr || _callPath === _selfKey)) return true;
          // Also check via funcMap / closureFuncMap — the callee might resolve to the same funcNode
          const _callFn = ctx.funcMap?.get(_callPath) || funcNode._closureFuncMap?.get(_callPath);
          if (_callFn && _callFn === funcNode) return true;
        }
      }
      // Walk INTO nested function expressions — recursion through callbacks
      // (e.g., merge calls iterateKeys with callback that calls merge again)
      // must be detected for PP Pattern 5's recursive context check.
      for (const key of Object.keys(node)) {
        if (key === 'loc' || key === 'start' || key === 'end' || key === '_closureEnv') continue;
        const child = node[key];
        if (Array.isArray(child)) { for (const c of child) if (c && typeof c === 'object' && c.type && _checkSelfCall(c)) return true; }
        else if (child && typeof child === 'object' && child.type && _checkSelfCall(child)) return true;
      }
      return false;
    };
    if (_checkSelfCall(funcNode.body)) ctx._isRecursiveCall = true;
  }

  const closureEnv = funcNode._closureEnv || env;
  const childEnv = closureEnv.child();
  // Flatten aliases from the entire parent chain into childEnv.aliases.
  // clone() doesn't preserve the parent chain — it copies only this.aliases.
  // Without flattening, aliases like Li→Math.max (defined in outer scopes) are lost
  // in processing envs, breaking constant folding for loop bounds, array indices, etc.
  {
    let cur = closureEnv;
    while (cur) {
      for (const [k, v] of cur.aliases) {
        if (!childEnv.aliases.has(k)) childEnv.aliases.set(k, v);
      }
      cur = cur.parent;
    }
  }

  // For wrapper functions (created via Object.create in returnedFuncNode handling):
  // Walk the prototype chain to find inner function's closure env bindings that may
  // have been lost through wrapper stacking. Each wrapper level overwrites _closureEnv
  // with the outer function's env, losing inner closure variables (e.g., Ue's param 'r'
  // gets lost when xo wraps the result). Copy missing bindings into childEnv so the
  // body can access closure variables from the inner function's definition context.
  let proto = Object.getPrototypeOf(funcNode);
  while (proto && proto !== Object.prototype) {
    if (proto._closureEnv && proto._closureEnv !== closureEnv) {
      for (const [key, val] of proto._closureEnv.entries()) {
        if (!childEnv.has(key)) childEnv.set(key, val);
      }
      // Propagate constants from inner closure envs (e.g., r=1 from Ue's body)
      if (proto._closureEnv.constants) {
        if (!childEnv.constants) childEnv.constants = new Map();
        for (const [k, v] of proto._closureEnv.constants) {
          if (!childEnv.constants.has(k)) childEnv.constants.set(k, v);
        }
      }
      // Propagate aliases from inner closure envs
      for (const [k, v] of proto._closureEnv.aliases) {
        if (!childEnv.aliases.has(k)) childEnv.aliases.set(k, v);
      }
    }
    proto = Object.getPrototypeOf(proto);
  }

  // For method calls (obj.method()), bind 'this' to the receiver object
  // Propagate obj.* taint as this.* so this.prop lookups resolve correctly
  let _methodObjName = null;
  if (callNode.callee?.type === 'MemberExpression' || callNode.callee?.type === 'OptionalMemberExpression') {
    let objName = _scopeQualifyMemberExpr(callNode.callee.object, ctx);
    if (!objName && callNode.callee.object) {
      let receiver = callNode.callee.object;
      while (receiver && (receiver.type === 'CallExpression' || receiver.type === 'OptionalCallExpression')) {
        if (receiver.callee?.type === 'MemberExpression' || receiver.callee?.type === 'OptionalMemberExpression') {
          receiver = receiver.callee.object;
        } else break;
      }
      if (receiver) objName = _scopeQualifyMemberExpr(receiver, ctx);
    }
    if (objName) {
      _methodObjName = objName;
      const objTaint = evaluateExpr(callNode.callee.object, env, ctx);
      childEnv.set('this', objTaint);
      const objBindings = env.getTaintedWithPrefix(`${objName}.`);
      for (const [key, taint] of objBindings) {
        const propName = key.slice(objName.length + 1);
        childEnv.set(`this.${propName}`, taint);
      }
      // Propagate element types from obj.* to this.* for method bodies
      for (const [etKey, etTag] of ctx.elementTypes) {
        if (etKey.startsWith(`${objName}.`)) {
          const propName = etKey.slice(objName.length + 1);
          ctx.elementTypes.set(`this.${propName}`, etTag);
        }
      }
      for (const daKey of ctx.domAttached) {
        if (daKey.startsWith(`${objName}.`)) {
          const propName = daKey.slice(objName.length + 1);
          ctx.domAttached.add(`this.${propName}`);
        }
      }
      for (const seKey of ctx.scriptElements) {
        if (seKey.startsWith(`${objName}.`)) {
          const propName = seKey.slice(objName.length + 1);
          ctx.scriptElements.add(`this.${propName}`);
        }
      }
    } else {
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
  if (funcNode._boundThisNode) {
    const objNode = funcNode._boundThisNode;
    for (const prop of objNode.properties || []) {
      if (isObjectProp(prop) && prop.key) {
        const propName = propKeyName(prop.key);
        if (propName && prop.value) {
          const propTaint = evaluateExpr(prop.value, env, ctx);
          childEnv.set(`this.${propName}`, propTaint);
        }
      }
    }
    funcNode._boundThisNode = null;
  }

  // Handle pre-filled arguments from fn.bind(thisArg, arg1, arg2)
  if (funcNode._boundArgs) {
    const boundArgNodes = funcNode._boundArgs;
    const boundArgTaints = boundArgNodes.map(a => evaluateExpr(a, env, ctx));
    argTaints = [...boundArgTaints, ...argTaints];
    callNode = { ...callNode, arguments: [...boundArgNodes, ...(callNode.arguments || [])] };
    funcNode._boundArgs = null;
  }

  // Proxy apply trap: handler(target, thisArg, argumentsList)
  // Remap call args → 3rd parameter (argumentsList array)
  if (funcNode._isProxyApplyTrap) {
    const originalArgTaints = argTaints;
    argTaints = [TaintSet.empty(), TaintSet.empty()]; // target, thisArg
    const mergedArgs = originalArgTaints.reduce((acc, t) => acc.merge(t), TaintSet.empty());
    argTaints.push(mergedArgs); // argumentsList
    // Synthesize call arguments to match params count
    const synthArgs = [
      { type: 'NullLiteral' },
      { type: 'NullLiteral' },
      { type: 'ArrayExpression', elements: callNode.arguments || [] },
    ];
    callNode = { ...callNode, arguments: synthArgs };
    // Set per-index taints for argumentsList so args[0], args[1] resolve
    funcNode._proxyApplyArgTaints = originalArgTaints;
  }

  // Store function expression arguments in funcMap so they can be called inside the body
  // Build innerFuncMap with correct lexical scoping:
  // 1. Start from closure scope (where the function was defined) — these represent
  //    the function's free variable bindings and should take priority.
  // 2. Add caller's entries that aren't in the closure scope — these represent
  //    functions/variables discovered after the closure was created.
  // 3. Parameter bindings (set below at ~line 6835) override everything.
  let innerFuncMap;
  if (funcNode._closureFuncMap) {
    // Start from closure funcMap as the base
    innerFuncMap = funcNode._closureFuncMap.fork ? funcNode._closureFuncMap.fork() : new FuncMap(funcNode._closureFuncMap);
    // Add caller entries that aren't in the closure (don't override closure bindings)
    for (const [key, val] of ctx.funcMap) {
      if (!innerFuncMap.has(key)) innerFuncMap.set(key, val);
    }
  } else {
    innerFuncMap = ctx.funcMap.fork ? ctx.funcMap.fork() : new FuncMap(ctx.funcMap);
  }
  // Proxy apply trap: bind target function to 1st param name so t() resolves inside trap body
  if (funcNode._isProxyApplyTrap && funcNode._proxyTargetFunc && funcNode._proxyTargetParam) {
    innerFuncMap.set(funcNode._proxyTargetParam, funcNode._proxyTargetFunc);
    // Also set scope-qualified key so resolveId lookups find it
    const innerScopeInfo2 = funcNode._closureScopeInfo || ctx.scopeInfo;
    if (innerScopeInfo2 && funcNode.params?.[0]) {
      const scopedParam = innerScopeInfo2.resolve(funcNode.params[0]);
      if (scopedParam) innerFuncMap.set(scopedParam, funcNode._proxyTargetFunc);
    }
  }

  // Copy obj.* funcMap entries to this.* so method bodies can resolve this.prop functions
  if (_methodObjName) {
    const objPrefix = `${_methodObjName}.`;
    for (const [key, val] of ctx.funcMap) {
      if (key.startsWith(objPrefix)) {
        innerFuncMap.set(`this.${key.slice(objPrefix.length)}`, val);
      }
    }
  }

  // Compute the callee's scopeInfo early so param assignment uses the same scoped keys
  // as the body. Without this, cross-file calls (app.js → lodash.js) resolve param nodes
  // using the caller's scopeInfo, producing different keys than the body's scopeInfo,
  // causing closure variable lookups to fall through to polluted global:name entries.
  const innerScopeInfo = funcNode._closureScopeInfo || ctx.scopeInfo;
  // Create a lightweight ctx proxy for param assignment that uses callee's scopeInfo
  const paramCtx = innerScopeInfo !== ctx.scopeInfo ? Object.create(ctx, {
    scopeInfo: { value: innerScopeInfo, writable: false }
  }) : ctx;

  let _pendingForInEnum = null;
  for (let i = 0; i < funcNode.params.length; i++) {
    const param = funcNode.params[i];
    if (param.type === 'Identifier' && callNode.arguments[i]) {
      const argNode = callNode.arguments[i];
      if (argNode.type === 'FunctionExpression' || argNode.type === 'ArrowFunctionExpression') {
        const argWrapper = Object.create(argNode);
        argWrapper._closureEnv = env;
        argWrapper._closureFuncMap = ctx.funcMap;
        argWrapper._wrapperId = ++_wrapperIdCounter;
        const paramKey = resolveId(param, paramCtx.scopeInfo);
        innerFuncMap.set(paramKey, argWrapper);
      } else if (argNode._returnedFuncNode) {
        // CallExpression result with a known returned function (from HOF passthrough)
        const paramKey = resolveId(param, paramCtx.scopeInfo);
        innerFuncMap.set(paramKey, argNode._returnedFuncNode);
      }
      if (argNode.type === 'Identifier') {
        const refKey = resolveId(argNode, ctx.scopeInfo);
        // Only register as function reference if the argument isn't a tainted value
        // (a tainted variable like `data = location.hash` should pass taint, not register as function)
        const argTaintCheck = argTaints[i];
        if (!argTaintCheck || !argTaintCheck.tainted) {
          const refFunc = ctx.funcMap.get(refKey);
          if (refFunc) {
            const paramKey = resolveId(param, paramCtx.scopeInfo);
            innerFuncMap.set(paramKey, refFunc);
            if (globalThis._TAINT_DEBUG) console.log(`[ACF-PARAM-BIND] param=${param.name} paramKey=${paramKey} arg=${argNode.name} refKey=${refKey} → ${refFunc.id?.name||refFunc.type}(${refFunc.params?.length})`);
          }
        }
      }
      if (argNode.type === 'ObjectExpression') {
        const paramKey = resolveId(param, paramCtx.scopeInfo);
        for (const prop of argNode.properties) {
          if (isObjectProp(prop) && prop.key) {
            const pName = propKeyName(prop.key);
            const val = prop.value;
            if (pName && val && (val.type === 'FunctionExpression' || val.type === 'ArrowFunctionExpression')) {
              const valWrapper = Object.create(val);
              valWrapper._closureEnv = env;
              valWrapper._closureFuncMap = ctx.funcMap;
              valWrapper._wrapperId = ++_wrapperIdCounter;
              innerFuncMap.set(`${paramKey}.${pName}`, valWrapper);
              const _objParamKey = resolveId(param, paramCtx.scopeInfo);
              innerFuncMap.set(`${_objParamKey}.${pName}`, valWrapper);
            }
          }
        }
      }
      // CallExpression arg that produced a returnedFuncNode (factory/decorator result):
      // Register the returned function under the parameter name so the callee body
      // can resolve it (e.g., shortOut(overRest(...)) → func.apply() resolves func).
      // Must overwrite any inherited entry (e.g., outer scope's 'func' from baseRest).
      // Use per-call-site _returnedFuncNode (tagged on AST node in _finalizeFrame) first,
      // falling back to the volatile ctx.returnedFuncNode. Per-call-site is immune to
      // overwrites by sibling argument evaluations (e.g., xo(Ue(...), n+"")).
      if (argNode.type === 'CallExpression' || argNode.type === 'OptionalCallExpression') {
        const retFunc = argNode._returnedFuncNode || ctx.returnedFuncNode;
        if (retFunc) {
          const paramKey = resolveId(param, paramCtx.scopeInfo);
          innerFuncMap.set(paramKey, retFunc);
          if (globalThis._TAINT_DEBUG) console.log(`[ACF-RETFUNC] param=${param.name} paramKey=${paramKey} retFunc=${retFunc.type}/${retFunc.id?.name||'anon'} params=${retFunc.params?.length} source=${argNode._returnedFuncNode ? 'per-node' : 'ctx'}`);
        }
        // Propagate keys data: fn(Object.keys(obj), callback) or fn(customKeys(obj), callback)
        const _argKeysData = (argNode._objectKeysResult
          ? { sourceName: argNode._objectKeysSource, properties: argNode._objectKeysResult }
          : ctx._returnedObjectKeysData) || null;
        if (_argKeysData) {
          if (!_pendingForInEnum) _pendingForInEnum = [];
          _pendingForInEnum.push({ paramName: param.name, paramKey: resolveId(param, paramCtx.scopeInfo),
            keysData: _argKeysData, isArrayParam: true });
          if (argNode._objectKeysResult) { argNode._objectKeysResult = null; argNode._objectKeysSource = null; }
          else ctx._returnedObjectKeysData = null;
        }
      }
    }
    // Propagate enumeration data through function arguments
    if (param.type === 'Identifier' && callNode.arguments[i]) {
      const argNode = callNode.arguments[i];

      // 1. Identifier arg that IS a for-in variable → propagate _forInEnumeration to param
      if (argNode.type === 'Identifier' && ctx._forInEnumeration) {
        const enumInfo = ctx._forInEnumeration.get(resolveId(argNode, ctx.scopeInfo));
        if (enumInfo) {
          if (!_pendingForInEnum) _pendingForInEnum = [];
          _pendingForInEnum.push({ paramName: param.name, paramKey: resolveId(param, paramCtx.scopeInfo), keysData: enumInfo });
        }
      }

      // 2. Identifier arg that is a known-keys array → propagate _objectKeysVars to param
      if (argNode.type === 'Identifier' && ctx._objectKeysVars) {
        const argKey = resolveId(argNode, ctx.scopeInfo);
        const keysData = ctx._objectKeysVars.get(argKey);
        if (keysData) {
          if (!_pendingForInEnum) _pendingForInEnum = [];
          _pendingForInEnum.push({ paramName: param.name, paramKey: resolveId(param, paramCtx.scopeInfo),
            keysData, isArrayParam: true });
        }
      }

      // 3. arr[i] arg where arr has _objectKeysVars → element is a key → _forInEnumeration on param
      if (argNode.type === 'MemberExpression' && argNode.computed &&
          argNode.object?.type === 'Identifier' && ctx._objectKeysVars) {
        const arrKey = resolveId(argNode.object, ctx.scopeInfo);
        const keysData = ctx._objectKeysVars.get(arrKey);
        if (keysData) {
          if (!_pendingForInEnum) _pendingForInEnum = [];
          _pendingForInEnum.push({ paramName: param.name, paramKey: resolveId(param, paramCtx.scopeInfo), keysData });
        }
      }
    }
    if (param.type === 'RestElement') {
      const restTaint = TaintSet.empty();
      for (let j = i; j < argTaints.length; j++) restTaint.merge(argTaints[j]);
      assignToPattern(param.argument, restTaint, childEnv, paramCtx);
    } else {
      if (param.type === 'AssignmentPattern' && i < callNode.arguments.length) {
        const argNode = callNode.arguments[i];
        const isUndefined = argNode && argNode.type === 'Identifier' && argNode.name === 'undefined';
        if (isUndefined) {
          assignToPattern(param, argTaints[i] || TaintSet.empty(), childEnv, paramCtx);
        } else {
          assignToPattern(param.left, argTaints[i] || TaintSet.empty(), childEnv, paramCtx);
        }
      } else {
        if (param.type === 'ObjectPattern' && callNode.arguments[i]) {
          const argNode = callNode.arguments[i];
          const argStr = _scopeQualifyMemberExpr(argNode, ctx);
          if (argStr) {
            assignObjectPatternFromSource(param, argStr, argTaints[i] || TaintSet.empty(), childEnv, paramCtx);
          } else if (argNode.type === 'ObjectExpression') {
            const literalProps = new Map();
            for (const prop of argNode.properties) {
              if (isObjectProp(prop) && prop.key) {
                const pName = propKeyName(prop.key);
                if (pName) literalProps.set(pName, evaluateExpr(prop.value, childEnv, paramCtx));
              }
              if (prop.type === 'SpreadElement' || prop.type === 'RestElement') {
                const spreadTaint = evaluateExpr(prop.argument || prop, childEnv, paramCtx);
                if (spreadTaint.tainted) {
                  for (const pp of param.properties) {
                    if (pp.type !== 'RestElement') {
                      const ppName = propKeyName(pp.key);
                      if (ppName && !literalProps.has(ppName)) literalProps.set(ppName, spreadTaint);
                    }
                  }
                }
              }
            }
            for (const prop of param.properties) {
              if (prop.type === 'RestElement') {
                assignToPattern(prop.argument, argTaints[i] || TaintSet.empty(), childEnv, paramCtx);
                continue;
              }
              const keyName = propKeyName(prop.key);
              const target = prop.value || prop.key;
              if (keyName && literalProps.has(keyName)) {
                if (target.type === 'AssignmentPattern') {
                  assignToPattern(target.left, literalProps.get(keyName), childEnv, paramCtx);
                } else {
                  assignToPattern(target, literalProps.get(keyName), childEnv, paramCtx);
                }
              } else {
                assignToPattern(target, TaintSet.empty(), childEnv, paramCtx);
              }
            }
          } else {
            assignToPattern(param, argTaints[i] || TaintSet.empty(), childEnv, paramCtx);
          }
        } else {
          assignToPattern(param, argTaints[i] || TaintSet.empty(), childEnv, paramCtx);
        }
      }
    }
  }

  // Propagate element types / DOM attachment / script element tracking from arguments to parameters.
  // When g(document.body) is called, the param inherits document.body's element type.
  if (callNode.arguments) {
    for (let i = 0; i < funcNode.params.length && i < callNode.arguments.length; i++) {
      const param = funcNode.params[i];
      if (param.type !== 'Identifier') continue;
      const argNode = callNode.arguments[i];
      const argKey = _scopeQualifyMemberExpr(argNode, ctx);
      if (argKey) {
        const paramKey = resolveId(param, paramCtx.scopeInfo);
        // Element type
        const tag = ctx.elementTypes.get(argKey);
        if (tag) {
          ctx.elementTypes.set(paramKey, tag);
        }
        if (ctx.domAttached.has(argKey)) {
          ctx.domAttached.add(paramKey);
        }
        if (ctx.scriptElements.has(argKey)) {
          ctx.scriptElements.add(paramKey);
        }
      }
      // Direct DOM access: document.body, document.getElementById(...) — always DOM-attached
      if (argNode.type === 'MemberExpression' && !argNode.computed) {
        const argStr = _stripScopePrefix(_scopeQualifyMemberExpr(argNode, ctx) || '');
        if (argStr && (argStr.startsWith('document.') || argStr.includes('.document.'))) {
          const paramKey = resolveId(param, paramCtx.scopeInfo);
          ctx.domAttached.add(paramKey);
        }
      }
    }
  }

  // Per-property/per-index propagation is deferred until after the frame is created.
  // This prevents mergeFrom collision in _finalizeFrame: initial tainted per-property
  // values in childEnv would persist even when the body overwrites them with safe values.
  // By storing on the entry block env directly (after clone), childEnv stays clean.
  // See _deferredPropPropagation below.

  // Proxy apply trap: set per-index taints on the argumentsList param
  if (funcNode._isProxyApplyTrap && funcNode._proxyApplyArgTaints) {
    const argsParam = funcNode.params.length >= 3 && funcNode.params[2].type === 'Identifier'
      ? resolveId(funcNode.params[2], paramCtx.scopeInfo) : null;
    if (argsParam) {
      const proxyArgTaints = funcNode._proxyApplyArgTaints;
      for (let ai = 0; ai < proxyArgTaints.length; ai++) {
        childEnv.set(`${argsParam}.#idx_${ai}`, proxyArgTaints[ai] || TaintSet.empty());
      }
    }
    funcNode._proxyApplyArgTaints = null;
  }

  // Bind `arguments` object — merge all arg taints so arguments[n] resolves
  const argsMerged = TaintSet.empty();
  for (const t of argTaints) argsMerged.merge(t);
  if (argsMerged.tainted) {
    childEnv.set('arguments', argsMerged);
    childEnv.set('global:arguments', argsMerged);
  }
  // Per-index arguments tracking: arguments.#idx_0, arguments.#idx_1, etc.
  // Enables arguments[n] to resolve individual arg taints and per-property taints
  for (let ai = 0; ai < argTaints.length; ai++) {
    childEnv.set(`arguments.#idx_${ai}`, argTaints[ai]);
  }
  // Store arguments count for later — innerCtx doesn't exist yet
  const _argsCount = argTaints.length;
  // For ObjectExpression arguments, propagate per-property taints and funcMap entries
  // so that code like `options = arguments[0]; for (k in options) { this[k] = options[k] }` works
  for (let ai = 0; ai < callNode.arguments.length; ai++) {
    const argNode = callNode.arguments[ai];
    if (argNode.type === 'ObjectExpression') {
      const argPrefix = `arguments.#idx_${ai}`;
      // Store per-property taints in childEnv (evaluate in caller's env context)
      for (const prop of argNode.properties) {
        if (prop.type === 'SpreadElement') continue;
        if ((isObjectProp(prop) || prop.type === 'ObjectMethod') && prop.key) {
          let propName;
          if (prop.computed) {
            const _av = resolveAbstract(prop.key, env, ctx);
            if (_av.concrete && typeof _av.value === 'string') propName = _av.value;
          }
          if (!propName) propName = propKeyName(prop.key);
          if (propName) {
            const val = prop.type === 'ObjectMethod' ? prop : prop.value;
            if (val && (val.type === 'FunctionExpression' || val.type === 'ArrowFunctionExpression')) {
              val._closureEnv = env;
              val._closureFuncMap = ctx.funcMap;
              innerFuncMap.set(`${argPrefix}.${propName}`, val);
            } else if (val && val.type === 'Identifier') {
              const refFunc = ctx.funcMap.get(resolveId(val, ctx.scopeInfo));
              if (refFunc) innerFuncMap.set(`${argPrefix}.${propName}`, refFunc);
            }
            // Evaluate prop value taint in caller context
            const propTaint = evaluateExpr(val || prop.key, env, ctx);
            childEnv.set(`${argPrefix}.${propName}`, propTaint);
          }
        }
      }
    }
  }

  const savedFuncMap = ctx.funcMap;
  ctx.funcMap = innerFuncMap;

  // Collect parameter names to distinguish locals from closure vars
  const paramNames = new Set();
  for (const param of funcNode.params) {
    if (param.type === 'Identifier') paramNames.add(param.name);
    else if (param.type === 'RestElement' && param.argument?.type === 'Identifier') paramNames.add(param.argument.name);
  }

  // Build a map of parameter → constant argument value for resolveToConstant
  const savedParamConstants = ctx._paramConstants;
  const paramConstants = new Map();
  // Build a map of parameter → original argument Identifier name for callee resolution
  // e.g., wrapper(eval, args) → fn→"eval" so fn.apply() resolves correctly
  const paramArgNames = new Map();
  for (let i = 0; i < funcNode.params.length; i++) {
    const param = funcNode.params[i];
    if (param.type === 'Identifier') {
      const argNode = i < callNode.arguments.length ? callNode.arguments[i] : null;
      const _paramScopedKey = resolveId(param, paramCtx.scopeInfo);
      if (argNode) {
        const _constAV = resolveAbstract(argNode, env, ctx);
        if (_constAV.concrete) {
          paramConstants.set(param.name, _constAV.value);
          paramConstants.set(_paramScopedKey, _constAV.value);
        }
      }
      // Param not passed at call site → track as undefined for typeof/=== comparisons
      if (!argNode) {
        paramConstants.set(param.name, undefined);
        paramConstants.set(_paramScopedKey, undefined);
      }
      // Track Identifier arg names for callee resolution in .call()/.apply()
      // Resolve through aliases and parent _paramArgNames for multi-level wrappers
      const _paramKey = resolveId(param, paramCtx.scopeInfo);
      if (!argNode) continue; // missing param — already tracked in _undefinedParams
      if (argNode.type === 'Identifier') {
        const _argKey = resolveId(argNode, ctx.scopeInfo);
        const resolvedArgName = ctx._paramArgNames?.get(argNode.name)
          || env.aliases?.get(_argKey) || argNode.name;
        paramArgNames.set(param.name, resolvedArgName);
        paramArgNames.set(_paramScopedKey, resolvedArgName);
        // Set env alias so property assignments (root.x = fn) resolve through aliases
        const GLOBAL_NAMES = new Set(['window', 'self', 'globalThis', 'global', 'this']);
        if (GLOBAL_NAMES.has(resolvedArgName)) {
          childEnv.aliases.set(_paramKey, resolvedArgName);
        }
      } else if (argNode.type === 'ThisExpression') {
        // this as arg → param aliases to window (top-level this is the global object)
        paramArgNames.set(param.name, 'window');
        childEnv.aliases.set(_paramKey, 'window');
      } else if (argNode.type === 'LogicalExpression') {
        // this||self pattern: resolve to window
        const identity = resolveCalleeIdentity(argNode, env, ctx);
        if (identity) {
          paramArgNames.set(param.name, identity);
          const GLOBAL_NAMES = new Set(['window', 'self', 'globalThis', 'global']);
          if (GLOBAL_NAMES.has(identity)) childEnv.aliases.set(_paramKey, identity);
        }
      } else if (argNode.type === 'MemberExpression' || argNode.type === 'OptionalMemberExpression') {
        const argPath = _scopeQualifyMemberExpr(argNode, ctx);
        if (argPath) paramArgNames.set(param.name, argPath);
      }
    }
  }
  if (paramConstants.size > 0) ctx._paramConstants = paramConstants;

  // Propagate caller's aliases to function parameters
  // When defaults(target, src) is called with src=xn and xn has alias 'self',
  // the parameter 'src' inside the function should carry alias 'self'
  for (let i = 0; i < funcNode.params.length && i < callNode.arguments.length; i++) {
    const param = funcNode.params[i];
    if (param.type !== 'Identifier') continue;
    const argNode = callNode.arguments[i];
    // Resolve the arg to an identity (handles Identifier, ConditionalExpression, LogicalExpression, etc.)
    let _resolvedArgIdentity = null;
    if (argNode.type === 'Identifier') {
      const _argKey2 = resolveId(argNode, ctx.scopeInfo);
      const argAlias = env.getAlias ? env.getAlias(_argKey2) : env.aliases?.get(_argKey2);
      _resolvedArgIdentity = argAlias || null;
      // Also propagate per-property aliases: if caller has xn.X → Y, set src.X → Y
      if (_resolvedArgIdentity) {
        const prefix = _argKey2 + '.';
        for (const [aliasKey, aliasValue] of env.aliases) {
          if (aliasKey.startsWith(prefix)) {
            const _paramKey3 = resolveId(param, paramCtx.scopeInfo);
            const suffix = aliasKey.slice(_argKey2.length);
            childEnv.aliases.set(`${_paramKey3}${suffix}`, aliasValue);
          }
        }
      }
    }
    if (!_resolvedArgIdentity) {
      // Try resolveCalleeIdentity for complex expressions (ternary, logical, etc.)
      _resolvedArgIdentity = resolveCalleeIdentity(argNode, env, ctx);
    }
    if (_resolvedArgIdentity) {
      const _paramKey2 = resolveId(param, paramCtx.scopeInfo);
      const GLOBAL_NAMES = new Set(['window', 'self', 'globalThis', 'global']);
      if (GLOBAL_NAMES.has(_resolvedArgIdentity)) {
        childEnv.aliases.set(_paramKey2, _resolvedArgIdentity);
      }
    }
  }

  const body = funcNode.body.type === 'BlockStatement'
    ? funcNode.body
    : { type: 'BlockStatement', body: [{ type: 'ReturnStatement', argument: funcNode.body }] };

  // Build the CFG and inner context for the function body
  const innerCfg = buildCFG(body);
  // innerScopeInfo already computed above (before param assignment) to ensure consistent
  // scope key resolution between param assignment and body analysis.
  const innerCtx = new AnalysisContext(
    ctx.file, innerFuncMap.fork ? innerFuncMap.fork() : new FuncMap(innerFuncMap), ctx.findings,
    ctx.globalEnv, innerScopeInfo, ctx.analyzedCalls
  );
  if (!globalThis._acfIdCounter) globalThis._acfIdCounter = 0;
  innerCtx._acfId = ++globalThis._acfIdCounter;
  innerCtx._sinkFile = funcNode._sourceFile || ctx._sinkFile || ctx.file;
  if (ctx._isRecursiveCall) innerCtx._isRecursiveCall = true;
  innerCtx.classBodyMap = ctx.classBodyMap;
  innerCtx.superClassMap = ctx.superClassMap;
  innerCtx.protoMethodMap = ctx.protoMethodMap;
  innerCtx.elementTypes = ctx.elementTypes;
  innerCtx.domAttached = ctx.domAttached;
  innerCtx.scriptElements = ctx.scriptElements;
  innerCtx._prototypeLinkages = ctx._prototypeLinkages;
  if (ctx._paramConstants) innerCtx._paramConstants = ctx._paramConstants;
  // Propagate local constants and array index constants to callee
  if (ctx._localConstants?.size > 0) {
    if (!innerCtx._localConstants) innerCtx._localConstants = new Map(ctx._localConstants);
    else for (const [k, v] of ctx._localConstants) innerCtx._localConstants.set(k, v);
  }
  // Set arguments.length as a local constant for deterministic loop bound resolution
  if (!innerCtx._localConstants) innerCtx._localConstants = new Map();
  innerCtx._localConstants.set('arguments.length', _argsCount);
  // Track per-index argument constants for arguments[i] access in variadic functions.
  // This enables typeof folding (e.g., typeof arguments[0] === "boolean") and
  // constant resolution through arguments object in 0-param functions like jQuery.extend.
  for (let ai = 0; ai < _argsCount; ai++) {
    const argNode = callNode.arguments[ai];
    if (argNode) {
      const _argConstAV = resolveAbstract(argNode, env, ctx);
      if (_argConstAV.concrete) {
        innerCtx._localConstants.set('arguments.' + ai, _argConstAV.value);
      }
    }
  }
  if (ctx._arrayIndexConstants?.size > 0) {
    if (!innerCtx._arrayIndexConstants) innerCtx._arrayIndexConstants = new Map(ctx._arrayIndexConstants);
    else for (const [k, v] of ctx._arrayIndexConstants) innerCtx._arrayIndexConstants.set(k, v);
  }
  if (ctx._objectKeysVars?.size > 0) {
    if (!innerCtx._objectKeysVars) innerCtx._objectKeysVars = new Map(ctx._objectKeysVars);
    else for (const [k, v] of ctx._objectKeysVars) innerCtx._objectKeysVars.set(k, v);
  }
  // Apply pending enumeration data (must be after innerCtx creation)
  if (_pendingForInEnum) {
    // Re-resolve param keys using innerScopeInfo — the body uses inner scope UIDs
    // but param binding used paramCtx (which may have a different scopeInfo)
    for (const entry of _pendingForInEnum) {
      // Find the matching param AST node to re-resolve with inner scope
      let innerKey = entry.paramKey;
      for (const p of funcNode.params) {
        if (p.type === 'Identifier' && p.name === entry.paramName) {
          innerKey = innerScopeInfo?.resolve(p) || entry.paramKey;
          break;
        }
      }
      if (entry.isArrayParam) {
        if (!innerCtx._objectKeysVars) innerCtx._objectKeysVars = new Map();
        innerCtx._objectKeysVars.set(innerKey, entry.keysData);
      } else {
        if (!innerCtx._forInEnumeration) innerCtx._forInEnumeration = new Map();
        innerCtx._forInEnumeration.set(innerKey, entry.keysData);
      }
    }
  }
  if (innerCtx._localConstants) {
    // Remove entries that conflict with function parameter names — params shadow
    // outer constants (e.g., outer `var mn = "..."` shadowed by param `mn`)
    if (funcNode.params) {
      for (const param of funcNode.params) {
        if (param.type === 'Identifier') {
          // Remove by inner scope key
          const _pKey = innerScopeInfo?.resolve(param) || param.name;
          if (innerCtx._localConstants.has(_pKey)) innerCtx._localConstants.delete(_pKey);
        }
      }
    }
  }
  if (paramArgNames.size > 0) innerCtx._paramArgNames = paramArgNames;
  if (funcNode._superClass) innerCtx._currentSuperClass = funcNode._superClass;
  if (ctx._handlerContext) innerCtx._handlerContext = ctx._handlerContext;

  // Store caller's argument AST nodes so that `arguments` inside the body can resolve
  // to the actual call-site nodes (needed for func.apply(this, arguments) wrappers)
  if (callNode.arguments) {
    innerCtx._callerArgNodes = callNode.arguments;
    // Also store the returnedFuncNode from the call site so that func.apply(T, arguments)
    // can propagate it into the callee's param registration (e.g., Ce wrapper forwarding
    // the Ue wrapper result to ao via arguments object)
    if (ctx.returnedFuncNode) innerCtx._callerReturnedFuncNode = ctx.returnedFuncNode;
  }
  // Propagate closure-captured param→arg names from factory patterns
  if (funcNode._closureParamArgNames) {
    if (!innerCtx._paramArgNames) innerCtx._paramArgNames = new Map(funcNode._closureParamArgNames);
    else for (const [k, v] of funcNode._closureParamArgNames) innerCtx._paramArgNames.set(k, v);
  }
  // Propagate closure-captured local constants (walk prototype chain for re-wrapped functions)
  {
    let _fn = funcNode;
    while (_fn && _fn !== Object.prototype) {
      if (_fn.hasOwnProperty('_closureLocalConstants') && _fn._closureLocalConstants) {
        if (!innerCtx._localConstants) innerCtx._localConstants = new Map(_fn._closureLocalConstants);
        else for (const [k, v] of _fn._closureLocalConstants) {
          if (!innerCtx._localConstants.has(k)) innerCtx._localConstants.set(k, v);
        }
      }
      _fn = Object.getPrototypeOf(_fn);
    }
  }

  // Capture all state needed for post-processing in a closure
  const _callNode = callNode, _callSig = callSig, _childEnv = childEnv,
        _funcNode = funcNode, _methodObjName2 = _methodObjName, _paramNames = paramNames,
        _savedFuncMap = savedFuncMap, _savedParamConstants = savedParamConstants,
        _innerFuncMap = innerFuncMap, _callerEnv = env, _callerCtx = ctx;

  // Post-processing runs after the function body analysis completes
  const postProcess = (result) => {
    _callerCtx._paramConstants = _savedParamConstants;
    _callerCtx.funcMap = _savedFuncMap;

    // Propagate new funcMap entries discovered during the call (COW: only overlay)
    // Skip scope-qualified keys (e.g., "6:t") — these are parameter bindings local to the
    // callee's scope and must not leak to the caller. Without this filter, a higher-order
    // function like Ue(callback) leaks "6:t → callback" to the caller, polluting subsequent
    // calls with stale bindings (e.g., lodash's wrapper cache resolves to wrong callback).
    const _newFuncEntries = _innerFuncMap.newEntries ? _innerFuncMap.newEntries() : _innerFuncMap;
    for (const [key, val] of _newFuncEntries) {
      if (key.charCodeAt(0) >= 48 && key.charCodeAt(0) <= 57) continue;
      if (!_savedFuncMap.has(key)) _savedFuncMap.set(key, val);
    }

    // super() call: propagate this.* from parent constructor
    if (_callNode.callee?.type === 'Super') {
      for (const [key, taint] of _childEnv.entries()) {
        if (key.startsWith('this.') && taint.tainted) {
          _callerEnv.set(key, taint);
        }
      }
    }

    // Propagate this.* side effects back to the receiver object
    if (_callNode.callee?.type === 'MemberExpression' || _callNode.callee?.type === 'OptionalMemberExpression') {
      const objName = _scopeQualifyMemberExpr(_callNode.callee.object, ctx);
      for (const [key, taint] of _childEnv.entries()) {
        if (key.startsWith('this.') && taint.tainted) {
          const propName = key.slice(5);
          if (objName) _callerEnv.set(`${objName}.${propName}`, taint);
          _callerEnv.set(key, taint);
        }
      }
      if (objName) {
        const _newFuncEntries2 = _innerFuncMap.newEntries ? _innerFuncMap.newEntries() : _innerFuncMap;
        for (const [key, val] of _newFuncEntries2) {
          if (key.startsWith('this.')) {
            const propName = key.slice(5);
            _savedFuncMap.set(`${objName}.${propName}`, val);
          }
        }
      }
    }

    // Propagate param.* entries as global exports when param is aliased to window/self.
    // Handles: factory(window) → e.jQuery = w → global:jQuery = w
    for (let _pi = 0; _pi < _funcNode.params.length && _pi < _callNode.arguments.length; _pi++) {
      const _p = _funcNode.params[_pi];
      if (_p.type !== 'Identifier') continue;
      const _pKey = innerCtx.scopeInfo ? (innerCtx.scopeInfo.resolve(_p) || _p.name) : _p.name;
      const _pAlias = _childEnv.getAlias ? _childEnv.getAlias(_pKey) : _childEnv.aliases?.get(_pKey);
      if (_pAlias && new Set(['window', 'self', 'globalThis']).has(_pAlias)) {
        const _pPrefix = `${_pKey}.`;
        for (const [key, taint] of _childEnv.entries()) {
          if (key.startsWith(_pPrefix)) {
            const propName = key.slice(_pPrefix.length);
            if (propName && !propName.includes('#')) {
              _callerEnv.set(propName, taint);
              _callerEnv.set(`global:${propName}`, taint);
            }
          }
        }
      }
    }
    // IIFE .call(this) at global scope: propagate this.* as global exports
    // e.g., (function(){ this._ = lodash; }).call(this) → window._ = lodash
    if (_funcNode._boundThisArg === 'this') {
      for (const [key, taint] of _childEnv.entries()) {
        if (key.startsWith('this.')) {
          const propName = key.slice(5);
          _callerEnv.set(propName, taint);
          _callerEnv.set(`global:${propName}`, taint);
          _callerEnv.set(`window.${propName}`, taint);
        }
      }
      // Also propagate funcMap entries: this.methodName → global methodName
      // this._ → global:_, _.merge → global:_.merge, window._ etc.
      const _newFuncEntries3 = _innerFuncMap.newEntries ? _innerFuncMap.newEntries() : _innerFuncMap;
      for (const [key, val] of _newFuncEntries3) {
        if (key.startsWith('this.')) {
          const propName = key.slice(5);
          _savedFuncMap.set(propName, val);
          _savedFuncMap.set(`global:${propName}`, val);
          _savedFuncMap.set(`window.${propName}`, val);
          _savedFuncMap.set(`global:window.${propName}`, val);
        }
      }
      // Second pass: propagate dotted entries like _.merge whose base was exported as this.*
      // These were created by the global alias export handler during the IIFE analysis
      const _exportedBases = new Set();
      for (const [key] of _newFuncEntries3) {
        if (key.startsWith('this.') && !key.slice(5).includes('.') && !key.slice(5).includes('#')) {
          _exportedBases.add(key.slice(5));
        }
      }
      if (_exportedBases.size > 0) {
        for (const [key, val] of _newFuncEntries3) {
          if (!key.startsWith('this.') && !key.startsWith('global:')) {
            const dotIdx = key.indexOf('.');
            const hashIdx = key.indexOf('#');
            const sepIdx = dotIdx === -1 ? hashIdx : (hashIdx === -1 ? dotIdx : Math.min(dotIdx, hashIdx));
            if (sepIdx > 0) {
              const base = key.slice(0, sepIdx);
              if (_exportedBases.has(base)) {
                _savedFuncMap.set(`global:${key}`, val);
              }
            }
          }
        }
      }
    }

    // Propagate closure variable mutations back to the closure env
    if (_funcNode._closureEnv) {
      _propagateClosureMutations(_childEnv, _funcNode._closureEnv, _paramNames);
    } else {
      // No explicit closure env — propagate to caller env directly
      // (handles static methods, functions without _closureEnv)
      _propagateClosureMutations(_childEnv, _callerEnv, _paramNames);
    }

    // Propagate closure variable mutations back to the caller's env
    for (const [key, taint] of _childEnv.entries()) {
      if (key.startsWith('this.') || key === 'this' || key.startsWith('global:') ||
          _paramNames.has(key) || key.indexOf('.') !== -1) continue;
      if (_callerEnv.has(key)) {
        _callerEnv.set(key, taint);
      }
    }

    // Propagate global-scoped side effects
    for (const [key, taint] of _childEnv.entries()) {
      if (taint.tainted && key.indexOf('.') !== -1 &&
          key.slice(0, 5) !== 'this.' && key.slice(0, 7) !== 'global:' &&
          !(key[0] >= '0' && key[0] <= '9')) {
        _callerEnv.set(key, taint);
      }
      // Propagate global: entries created by window.X/self.X assignments (true globals)
      // Skip entries from var declarations (function-local) by checking for window.X companion
      if (taint.tainted && key.startsWith('global:')) {
        const bareName = key.slice(7);
        // window.X assignments create global:window.X → the bareName includes 'window.'
        const isWindowProp = bareName.startsWith('window.') || bareName.startsWith('self.') ||
          bareName.startsWith('globalThis.');
        // Direct global: bare variable → check if window.X companion exists
        const isWindowAssign = !bareName.includes('.') &&
          _childEnv.get(`global:window.${bareName}`).tainted;
        if (isWindowProp || isWindowAssign || _callerEnv.has(key)) {
          _callerEnv.set(key, taint);
          if (!bareName.includes('.')) {
            _callerEnv.set(`0:${bareName}`, taint);
          }
        }
      }
    }

    // Propagate global exports from IIFEs (global:X entries and their bare forms)
    // IIFEs are scope wrappers — their window.X assignments should be visible in the outer scope
    if (_callNode.callee && (_callNode.callee.type === 'FunctionExpression' ||
        _callNode.callee.type === 'ArrowFunctionExpression')) {
      for (const [key, taint] of _childEnv.entries()) {
        if (key.startsWith('global:') && key.length > 7) {
          _callerEnv.set(key, taint);
          const bare = key.slice(7);
          _callerEnv.set(bare, taint);
        }
      }
    }

    // Propagate parameter property mutations back to caller argument names
    for (let i = 0; i < _funcNode.params.length && i < _callNode.arguments.length; i++) {
      const param = _funcNode.params[i];
      if (param.type !== 'Identifier') continue;
      const argNode = _callNode.arguments[i];
      const argStr = _scopeQualifyMemberExpr(argNode, _callerCtx);
      if (!argStr) continue;
      // Resolve param name in the inner function's scope
      const pKey = innerCtx.scopeInfo ? (innerCtx.scopeInfo.resolve(param) || param.name) : param.name;
      if (pKey === argStr) continue;
      if (globalThis._TAINT_TRACE) {
        const _allEntries = [];
        for (const [key, taint] of _childEnv.entries()) {
          if (key.includes('obj') || key.includes('html')) _allEntries.push(`${key}=${taint.tainted?'T':'S'}`);
        }
        trace('PROP-SCAN', { pKey, argStr, envEntries: _allEntries.join(', ') || 'none' });
      }
      for (const [key, taint] of _childEnv.entries()) {
        if (key.startsWith(pKey + '.')) {
          const suffix = key.slice(pKey.length);
          trace('PROP-BACK', { from: key, to: `${argStr}${suffix}`, tainted: taint.tainted, calleeStr });
          _callerEnv.set(`${argStr}${suffix}`, taint);
        }
      }
    }

    // Propagate thrown taint from callee back to caller (for interprocedural try/catch)
    if (innerCtx.thrownTaint.tainted) {
      _callerCtx.thrownTaint.merge(innerCtx.thrownTaint);
    }
    if (innerCtx._thrownProperties) {
      if (!_callerCtx._thrownProperties) _callerCtx._thrownProperties = new Map();
      for (const [suffix, propTaint] of innerCtx._thrownProperties) {
        _callerCtx._thrownProperties.set(suffix, propTaint);
      }
    }

    // Propagate returnedFuncNode/Methods to caller context so the call site can use them
    if (innerCtx.returnedFuncNode) _callerCtx.returnedFuncNode = innerCtx.returnedFuncNode;
    if (innerCtx.returnedMethods) _callerCtx.returnedMethods = innerCtx.returnedMethods;
    if (innerCtx._returnedObjectKeysData) _callerCtx._returnedObjectKeysData = innerCtx._returnedObjectKeysData;

    // Propagate funcMap entries from inner to caller (same as _finalizeFrame)
    const _ppFuncEntries = innerCtx.funcMap.newEntries ? innerCtx.funcMap.newEntries() : innerCtx.funcMap;
    for (const [key, val] of _ppFuncEntries) {
      if (!_callerCtx.funcMap.has(key)) {
        _callerCtx.funcMap.set(key, val);
      }
    }
    // Translate this.* funcMap entries to obj.* for method calls.
    // When obj.method() sets this.html = fn, the caller's funcMap needs obj.html = fn.
    if (_callNode.callee?.type === 'MemberExpression' || _callNode.callee?.type === 'OptionalMemberExpression') {
      const _ppObjKey = _scopeQualifyMemberExpr(_callNode.callee.object, _callerCtx);
      if (_ppObjKey) {
        for (const [key, val] of _ppFuncEntries) {
          if (key.startsWith('this.') && key.length > 5) {
            const propName = key.slice(5);
            const objPropKey = `${_ppObjKey}.${propName}`;
            _callerCtx.funcMap.set(objPropKey, val);
            // Reactive prototype propagation: if obj has prototype linkages
            // (from X.prototype = obj), propagate the new method to X#method.
            // This handles: ce.fn.init.prototype = ce.fn, then ce.fn.extend({html: fn})
            // → ce.fn.html is added → automatically create ce.fn.init#html
            if (_callerCtx._prototypeLinkages?.has(_ppObjKey)) {
              for (const linkedBase of _callerCtx._prototypeLinkages.get(_ppObjKey)) {
                _callerCtx.funcMap.set(`${linkedBase}#${propName}`, val);
              }
            }
          }
        }
      }
    }

    // Propagate returned aliases (property aliases from the returned variable)
    if (innerCtx._returnedAliases) _callerCtx._returnedAliases = innerCtx._returnedAliases;

    // Propagate parameter property aliases back to caller argument names
    // Mirrors the parameter property taint propagation pattern above
    for (let i = 0; i < _funcNode.params.length && i < _callNode.arguments.length; i++) {
      const param = _funcNode.params[i];
      if (param.type !== 'Identifier') continue;
      const argNode = _callNode.arguments[i];
      const argStr = _scopeQualifyMemberExpr(argNode, _callerCtx);
      if (!argStr) continue;
      const pKey = innerCtx.scopeInfo ? (innerCtx.scopeInfo.resolve(param) || param.name) : param.name;
      if (pKey === argStr) continue;
      const prefix = pKey + '.';
      for (const [aliasKey, aliasValue] of _childEnv.aliases) {
        if (aliasKey.startsWith(prefix)) {
          const suffix = aliasKey.slice(pKey.length);
          _callerEnv.aliases.set(`${argStr}${suffix}`, aliasValue);
        }
      }
    }

    // Cache the result (include returnedFuncNode/Methods so cache hits restore them)
    const cachedResult = result.tainted ? result : TaintSet.empty();
    if (innerCtx.returnedFuncNode) cachedResult._returnedFuncNode = innerCtx.returnedFuncNode;
    if (innerCtx.returnedMethods) cachedResult._returnedMethods = innerCtx.returnedMethods;
    if (_callerCtx._returnedObjectKeysData) cachedResult._returnedObjectKeysData = _callerCtx._returnedObjectKeysData;

    // Store closure→param mapping: when the returned function's closureFuncMap entries
    // match callee param bindings by identity, record which closure key came from which
    // param index. Cache-hit wrapper path uses this to rebind inner closure keys to
    // current call's argument functions (multi-level wrapper propagation).
    if (innerCtx.returnedFuncNode && innerCtx.returnedFuncNode._closureFuncMap) {
      const mapping = {};
      for (const [key, val] of innerCtx.returnedFuncNode._closureFuncMap) {
        for (let pi = 0; pi < _funcNode.params.length; pi++) {
          if (_funcNode.params[pi].type !== 'Identifier') continue;
          const _paramScopeKey = innerScopeInfo?.resolve(_funcNode.params[pi]) || _funcNode.params[pi].name;
          const paramFunc = _innerFuncMap.get(_paramScopeKey) || _innerFuncMap.get(_funcNode.params[pi].name);
          if (paramFunc && paramFunc === val) {
            mapping[key] = pi;
            break;
          }
        }
      }
      if (Object.keys(mapping).length > 0) {
        cachedResult._closureParamMapping = mapping;
        if (globalThis._TAINT_DEBUG) console.log(`[FIX-B] sig=${_callSig} mapping=${JSON.stringify(mapping)}`);
      }
    }
    _callerCtx.analyzedCalls.set(_callSig, cachedResult);
    trace('ACF-EXIT', { calleeStr: calleeStr, sig: _callSig, tainted: cachedResult?.tainted, retFunc: innerCtx.returnedFuncNode?.id?.name || 'none', file: _callerCtx.file });
    _traceDepth = Math.max(0, _traceDepth - 1);
  };

  // Build the frame
  const _rpo = _computeRPO(innerCfg);
  const frame = {
    cfg: innerCfg,
    worklist: [innerCfg.entry],
    blockEnvs: new Map([[innerCfg.entry.id, childEnv.clone()]]),
    inWorklist: new Set([innerCfg.entry.id]),
    rpo: _rpo,
    innerCtx,
    callerCtx: ctx,
    env: childEnv,
    postProcess,
    calleeStr,
    callNode,  // for tagging returnedFuncNode per call site
    funcNode,  // for aliased recursion detection (same function, different calleeStr)
  };
  // _deferredPropEntries: per-property/per-index entries stored on the frame, injected
  // into the processing env by _runIPLoop after the entryEnv.clone(). This prevents
  // _finalizeFrame's predecessor merge from re-introducing stale tainted values when
  // the function body overwrites them (the processing clone has the override, but the
  // original blockEnvs entry does not — _finalizeFrame merges from the original).
  {
    const _deferred = [];
    if (callNode.arguments) {
      for (let i = 0; i < funcNode.params.length && i < callNode.arguments.length; i++) {
        const param = funcNode.params[i];
        if (param.type !== 'Identifier') continue;
        const argNode = callNode.arguments[i];
        const paramKey = resolveId(param, paramCtx.scopeInfo);
        let argKey = null;
        if (argNode?.type === 'Identifier') {
          argKey = resolveId(argNode, ctx.scopeInfo);
        } else if (argNode?.type === 'MemberExpression' || argNode?.type === 'OptionalMemberExpression') {
          argKey = _scopeQualifyMemberExpr(argNode, ctx);
        }
        if (argKey) {
          const argPrefix = `${argKey}.`;
          for (const [key, taint] of env.entries()) {
            if (key.startsWith(argPrefix)) {
              const suffix = key.slice(argKey.length);
              _deferred.push([`${paramKey}${suffix}`, taint]);
            }
          }
          // Propagate funcMap entries: argKey.method → paramKey.method
          // Use savedFuncMap (caller's funcMap) as source since argKey is in caller's scope.
          // Set on innerCtx.funcMap (the forked copy) since it was created before this code runs.
          for (const [key, val] of savedFuncMap) {
            if (key.startsWith(argPrefix)) {
              const suffix = key.slice(argKey.length);
              innerCtx.funcMap.set(`${paramKey}${suffix}`, val);
            }
          }
          // Set param.length from known per-index count
          let _maxArgIdx = -1;
          const _idxPrefix = `${argKey}.#idx_`;
          for (const [key] of env.entries()) {
            if (key.startsWith(_idxPrefix)) {
              const idx = parseInt(key.slice(_idxPrefix.length));
              if (idx > _maxArgIdx) _maxArgIdx = idx;
            }
          }
          if (_maxArgIdx >= 0) {
            if (!ctx._localConstants) ctx._localConstants = new Map();
            ctx._localConstants.set(`${paramKey}.length`, _maxArgIdx + 1);
          }
        } else if (argNode?.type === 'ArrayExpression') {
          for (let ai = 0; ai < argNode.elements.length; ai++) {
            const el = argNode.elements[ai];
            if (el) {
              _deferred.push([`${paramKey}.#idx_${ai}`, evaluateExpr(el, env, ctx)]);
            }
          }
          if (!ctx._localConstants) ctx._localConstants = new Map();
          ctx._localConstants.set(`${paramKey}.length`, argNode.elements.length);
        }
      }
    }
    // .apply() nested per-index propagation
    if (callNode._applyArgsVarName && funcNode.params) {
      const argsVarName = callNode._applyArgsVarName;
      for (let i = 0; i < funcNode.params.length; i++) {
        const param = funcNode.params[i];
        if (param.type !== 'Identifier') continue;
        const paramKey = resolveId(param, paramCtx.scopeInfo);
        const prefix = `${argsVarName}.#idx_${i}.`;
        const nested = env.getTaintedWithPrefix(prefix);
        for (const [key, taint] of nested) {
          const suffix = key.slice(prefix.length - 1);
          _deferred.push([`${paramKey}${suffix}`, taint]);
        }
      }
    }
    if (_deferred.length > 0) frame._deferredPropEntries = _deferred;
  }
  // Mark IIFE frames: callee is an inline FunctionExpression (not resolved from funcMap)
  // IIFEs are scope wrappers — their globals/funcMap entries should propagate to the caller
  {
    let iifeCallee = callNode.callee;
    // Unwrap unary: !function(){}(), void function(){}()
    if (iifeCallee?.type === 'UnaryExpression') iifeCallee = iifeCallee.argument;
    if (iifeCallee?.type === 'ParenthesizedExpression') iifeCallee = iifeCallee.expression;
    if (iifeCallee && (iifeCallee.type === 'FunctionExpression' ||
        iifeCallee.type === 'ArrowFunctionExpression')) {
      frame._isIIFE = true;
    }
  }

  // If we're inside the IP loop, push a frame and signal suspension
  if (ctx._ipStack) {
    ctx._ipStack.push(frame);
    ctx._ipSuspended = true;
    // Restore caller state immediately (postProcess will do it again, but we need
    // the caller's ctx to be in a consistent state during re-processing)
    ctx._paramConstants = savedParamConstants;
    ctx.funcMap = savedFuncMap;
    return TaintSet.empty(); // placeholder
  }

  // Top-level call: run the IP loop
  return _runIPLoop([frame]);
}

// ── For-in/of binding ──
function processForBinding(node, env, ctx) {
  // For-in yields string property keys — safe for known-structure objects,
  // but tainted when the iterable itself is attacker-controlled (e.g., JSON.parse(tainted))
  if (node._isForIn) {
    let keyTaint = TaintSet.empty();
    const iterableTaint = evaluateExpr(node.right, env, ctx);
    // For-in key taint: the keys are attacker-controlled ONLY if the object ITSELF is the
    // attacker's value (not just containing tainted property values).
    // { a: tainted } → keys are programmer-defined ("a"), safe
    // JSON.parse(tainted) → keys are attacker-defined, tainted
    // The distinction: if the taint is on the object binding itself (top-level), the attacker
    // controls the object structure including keys. If taint is only on nested properties
    // (obj.prop is tainted but obj itself isn't), the keys are safe.
    if (iterableTaint.tainted) {
      // For-in key taint: check if the attacker controls the object's STRUCTURE (keys).
      // TaintLabel.structural tracks this through the data flow:
      //   JSON.parse(tainted) → structural=true → keys tainted
      //   postMessage.data → structural=true → keys tainted
      //   {url: location.href} → structural=false → keys safe (programmer-defined)
      //
      // For Identifier iterables, also check if the init is a literal ObjectExpression
      // (programmer-defined keys regardless of value taint).
      let taintKeys = false;
      if (iterableTaint.toArray().some(label => label.structural)) {
        taintKeys = true;
      } else if (node.right.type === 'Identifier') {
        const iterKey = resolveId(node.right, ctx.scopeInfo);
        const iterOwnTaint = env.get(iterKey);
        if (iterOwnTaint.tainted) {
          const valueNode = env.getValueNode(iterKey);
          const isLiteralObject = valueNode?.type === 'ObjectExpression' || valueNode?.type === 'ArrayExpression';
          if (!isLiteralObject) {
            // Non-literal, non-structural: check if ANY label has structural control
            taintKeys = iterOwnTaint.toArray().some(label => label.structural);
          }
        }
      }
      if (taintKeys) keyTaint = iterableTaint;
    }
    // Extract loop variable name
    let forInVarName = null;
    if (node.left.type === 'VariableDeclaration' && node.left.declarations[0]?.id?.type === 'Identifier') {
      forInVarName = resolveId(node.left.declarations[0].id, ctx.scopeInfo);
    } else if (node.left.type === 'Identifier') {
      forInVarName = resolveId(node.left, ctx.scopeInfo);
    }

    // Static property enumeration: if the iterable has known per-property entries or funcMap entries,
    // record the known properties so computed assignments target[key]=source[key] can be resolved
    if (forInVarName) {
      const iterStr = _scopeQualifyMemberExpr(node.right, ctx) || _resolveObjKey(node.right, ctx);
      if (iterStr) {
        const knownProps = new Set();
        // Collect properties from the iterable's direct entries
        const _collectProps = (prefix) => {
          for (const [key] of env.getAllWithPrefix(`${prefix}.`)) {
            const propName = key.slice(prefix.length + 1);
            if (propName && !propName.startsWith('#')) knownProps.add(propName);
          }
          for (const [key] of ctx.funcMap) {
            if (key.startsWith(`${prefix}.`) && key.length > prefix.length + 1) {
              const propName = key.slice(prefix.length + 1);
              if (propName && !propName.includes('.')) knownProps.add(propName);
            }
          }
        };
        _collectProps(iterStr);
        // Also check init chain: if e = arguments[s], trace to arguments.#idx_N.*
        if (knownProps.size === 0 && node.right.type === 'Identifier') {
          const _iterInit = resolveInitFromScope(node.right, ctx);
          if (_iterInit) {
            if (_iterInit.type === 'MemberExpression' && _iterInit.computed &&
                _iterInit.object?.type === 'Identifier' && _iterInit.object.name === 'arguments') {
              const _argIdxAV = resolveAbstract(_iterInit.property, env, ctx);
              if (_argIdxAV.concrete) {
                _collectProps(`arguments.#idx_${_argIdxAV.value}`);
              }
              // Also merge all arguments.#idx_N.* when index is unknown
              if (!_argIdxAV.concrete || knownProps.size === 0) {
                for (const [key] of ctx.funcMap) {
                  const m = key.match(/^arguments\.#idx_\d+\.([^.]+)$/);
                  if (m) knownProps.add(m[1]);
                }
              }
            } else if (_iterInit.type === 'Identifier') {
              const _initKey = resolveId(_iterInit, ctx.scopeInfo);
              _collectProps(_initKey);
            }
          }
        }
        if (knownProps.size > 0) {
          if (!ctx._forInEnumeration) ctx._forInEnumeration = new Map();
          const props = [...knownProps];
          ctx._forInEnumeration.set(forInVarName, { sourceName: iterStr, properties: props });
          // Bulk method copy: scan body for target[iterVar] = source[iterVar] patterns
          // and copy all known properties eagerly (both taint and funcMap).
          // This handles jQuery's extend: for(t in e) { ... a[t] = e[t] | r=e[t]; a[t]=r }
          if (node._body) {
            const iterVarName = node.left.type === 'VariableDeclaration'
              ? node.left.declarations[0]?.id?.name : node.left.name;
            const _bulkTargets = new Set();
            // Walk body AST to find target[iterVar] = ... patterns
            const _walkBulk = (n) => {
              if (!n || typeof n !== 'object') return;
              if (n.type === 'AssignmentExpression' && n.operator === '=' &&
                  n.left.type === 'MemberExpression' && n.left.computed &&
                  n.left.property?.type === 'Identifier' && n.left.property.name === iterVarName &&
                  n.left.object?.type === 'Identifier') {
                _bulkTargets.add(n.left.object.name);
              }
              for (const key of Object.keys(n)) {
                if (key === 'loc' || key === 'start' || key === 'end') continue;
                const child = n[key];
                if (Array.isArray(child)) { for (const c of child) if (c?.type) _walkBulk(c); }
                else if (child?.type) _walkBulk(child);
              }
            };
            _walkBulk(node._body);
            // For each target[iterVar] = ..., copy all source properties to target.
            // Try multiple source prefixes: direct iterable, then arguments.#idx_N
            const _srcPrefixes = [iterStr];
            if (node.right.type === 'Identifier') {
              const _srcInit = resolveInitFromScope(node.right, ctx);
              if (_srcInit?.type === 'MemberExpression' && _srcInit.computed &&
                  _srcInit.object?.name === 'arguments') {
                const _sIdxAV = resolveAbstract(_srcInit.property, env, ctx);
                if (_sIdxAV.concrete) _srcPrefixes.push(`arguments.#idx_${_sIdxAV.value}`);
                // Also try all argument indices
                for (let _ai = 0; _ai < 10; _ai++) {
                  const _aiPrefix = `arguments.#idx_${_ai}`;
                  if (!_srcPrefixes.includes(_aiPrefix)) {
                    let _hasEntries = false;
                    for (const [k] of ctx.funcMap) { if (k.startsWith(_aiPrefix + '.')) { _hasEntries = true; break; } }
                    if (_hasEntries) _srcPrefixes.push(_aiPrefix);
                  }
                }
              }
            }
            for (const targetName of _bulkTargets) {
              const targetKey = resolveId({ type: 'Identifier', name: targetName }, ctx.scopeInfo);
              const isThisAlias = ctx._thisAliases?.has(targetKey);
              for (const propName of props) {
                for (const srcPrefix of _srcPrefixes) {
                  const srcFunc = ctx.funcMap.get(`${srcPrefix}.${propName}`);
                  if (srcFunc) {
                    ctx.funcMap.set(`${targetKey}.${propName}`, srcFunc);
                    if (isThisAlias) ctx.funcMap.set(`this.${propName}`, srcFunc);
                    break; // found source, no need to check other prefixes
                  }
                }
                for (const srcPrefix of _srcPrefixes) {
                  const srcTaint = env.get(`${srcPrefix}.${propName}`);
                  if (srcTaint?.tainted) {
                    env.set(`${targetKey}.${propName}`, srcTaint);
                    if (isThisAlias) env.set(`this.${propName}`, srcTaint);
                    break;
                  }
                }
              }
            }
          }
          // Set up per-key iteration: on each worklist pass, advance to the next key.
          // The body processes once per key, with _localConstants[name] = currentKey.
          // _forLoopCounterActive forces re-processing until all keys are iterated.
          const _enumKey = `${forInVarName}@forin`;
          if (!ctx._forLoopCounters) ctx._forLoopCounters = new Map();
          let enumIdx = ctx._forLoopCounters.get(_enumKey);
          if (enumIdx === undefined) enumIdx = 0;
          if (enumIdx < props.length) {
            if (!ctx._localConstants) ctx._localConstants = new Map();
            ctx._localConstants.set(forInVarName, props[enumIdx]);
            ctx._forLoopCounters.set(_enumKey, enumIdx + 1);
            ctx._forLoopCounterActive = true;
          } else {
            ctx._forLoopCounterActive = false;
          }
        }
      }
    }

    if (node.left.type === 'VariableDeclaration') {
      for (const decl of node.left.declarations) assignToPattern(decl.id, keyTaint, env, ctx);
    } else {
      assignToPattern(node.left, keyTaint, env, ctx);
    }
    return;
  }
  let iterableTaint = evaluateExpr(node.right, env, ctx);
  // For Maps/objects with per-key taint, merge per-key entries into iterable taint
  const iterStr = _scopeQualifyMemberExpr(node.right, ctx) || _resolveObjKey(node.right, ctx);
  if (iterStr) {
    const perKeyTaints = env.getTaintedWithPrefix(`${iterStr}.#key_`);
    if (perKeyTaints.size > 0) {
      iterableTaint = iterableTaint.clone();
      for (const [, taint] of perKeyTaints) iterableTaint.merge(taint);
    }
    const perIdxTaints = env.getTaintedWithPrefix(`${iterStr}.#idx_`);
    if (perIdxTaints.size > 0) {
      iterableTaint = iterableTaint.clone();
      for (const [, taint] of perIdxTaints) iterableTaint.merge(taint);
    }
  }

  // Custom iterable: if the object has a function assigned via computed property (Symbol.iterator)
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
      const _ccKey = resolveId(node, ctx.scopeInfo);
      const t = env.get(_ccKey);
      if (t.tainted) taintOut.merge(t);
      const perIdx = env.getTaintedWithPrefix(`${_ccKey}.#idx_`);
      for (const [, pt] of perIdx) taintOut.merge(pt);
      const perKey = env.getTaintedWithPrefix(`${_ccKey}.#key_`);
      for (const [, pt] of perKey) taintOut.merge(pt);
      continue;
    }
    if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
      const str = _scopeQualifyMemberExpr(node, ctx);
      if (str) {
        const t = env.get(str);
        if (t.tainted) { taintOut.merge(t); continue; }
        // Also check if this member expression is a taint source (e.g., location.hash)
        const sourceLabel = checkMemberSource(node);
        if (sourceLabel) {
          const loc = getNodeLoc(node);
          taintOut.merge(TaintSet.from(new TaintLabel(sourceLabel, ctx.file, loc.line || 0, loc.column || 0, str)));
          continue;
        }
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
    const varName = _scopeQualifyMemberExpr(rhsNode, ctx);
    if (varName && env.schemeCheckedVars.has(varName)) return 'Open Redirect';
    // Also check for URL object patterns: if url is scheme-checked, url.href inherits it
    if (rhsNode.type === 'MemberExpression' || rhsNode.type === 'OptionalMemberExpression') {
      const objName = _scopeQualifyMemberExpr(rhsNode.object, ctx);
      if (objName && env.schemeCheckedVars.has(objName)) return 'Open Redirect';
    }
    // Check if the variable references a new URL() result — new URL() with validated protocol
    if (rhsNode.type === 'Identifier') {
      const resolvedKey = resolveId(rhsNode, ctx.scopeInfo);
      if (env.schemeCheckedVars.has(resolvedKey)) return 'Open Redirect';
    }
  }

  // Check if RHS is a concatenation with a safe URL scheme prefix literal
  // e.g., "https://safe.com/" + tainted → Open Redirect (not XSS)
  if (rhsNode) {
    let exprToCheck = rhsNode;
    // Resolve Identifier to its initializer expression for prefix checking
    if (exprToCheck.type === 'Identifier' && ctx) {
      const init = resolveInitFromScope(exprToCheck, ctx);
      if (init) exprToCheck = init;
    }
    const leftmostLiteral = getLeftmostStringLiteral(exprToCheck);
    if (leftmostLiteral !== null && /^https?:\/\//i.test(leftmostLiteral)) {
      return 'Open Redirect';
    }
  }

  return sinkInfo.type; // default: XSS
}

// Walk leftward through BinaryExpression(+) / TemplateLiteral to find the leftmost string literal
function getLeftmostStringLiteral(node) {
  if (!node) return null;
  if (node.type === 'StringLiteral' || (node.type === 'Literal' && typeof node.value === 'string')) {
    return node.value;
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return getLeftmostStringLiteral(node.left);
  }
  if (node.type === 'TemplateLiteral' && node.quasis.length > 0 && node.quasis[0].value) {
    return node.quasis[0].value.raw || node.quasis[0].value.cooked || '';
  }
  return null;
}

// ── Element-type-aware property sink: el.src/textContent/text/data = tainted ──
// Different element types have different security implications for .src:
//   script.src → Script Injection (loads and executes JS)
//   iframe.src → XSS with navigation (javascript: URI, about:, loads arbitrary content)
//   embed.src / object.data → XSS with navigation (plugin content, javascript: URI)
//   img.src, video.src, audio.src → safe (media elements, no code execution)
// Elements with navigation: true get scheme-check classification (XSS vs Open Redirect)
// Elements whose src/href/action attributes can navigate to attacker URLs
const NAVIGABLE_ELEMENTS = new Set(['iframe', 'embed', 'object', 'frame', 'a', 'area', 'form', 'base']);

function checkElementPropertySink(leftNode, rhsTaint, rhsNode, env, ctx) {
  if (!rhsTaint.tainted) return;
  if (leftNode.type !== 'MemberExpression' && leftNode.type !== 'OptionalMemberExpression') return;
  let propName = null;
  if (leftNode.computed) {
    // Resolve computed property: el[prop] where prop = 'innerHTML'
    const _av = resolveAbstract(leftNode.property, env, ctx);
    if (_av.concrete && typeof _av.value === 'string') propName = _av.value;
  } else {
    propName = leftNode.property?.name;
  }
  if (!propName) return;
  const objKey = _scopeQualifyMemberExpr(leftNode.object, ctx);
  if (!objKey) return;
  const tag = ctx.elementTypes.get(objKey);
  if (!tag) return;

  // If element is not DOM-attached, store the tainted property for deferred check at attachment time
  if (!ctx.domAttached.has(objKey)) {
    if (!ctx._deferredElementTaints) ctx._deferredElementTaints = new Map();
    let props = ctx._deferredElementTaints.get(objKey);
    if (!props) { props = []; ctx._deferredElementTaints.set(objKey, props); }
    props.push({ propName, rhsTaint, rhsNode, env: env.clone(), leftNode });
    return;
  }

  // Query IDL + Chromium data: is this property a sink on this element tag?
  const sinkInfo = isElementPropertySink(tag, propName);
  if (!sinkInfo) return;

  const loc = getNodeLoc(leftNode);
  const sinkExpr = `${_stripScopePrefix(objKey)}.${propName}`;
  const tt = sinkInfo.type; // "TrustedHTML" | "TrustedScript" | "TrustedScriptURL" | "navigation"
  const behavior = sinkInfo.behavior; // "injection" | "navigation" | "script"

  if (tt === 'TrustedScriptURL' || behavior === 'script') {
    // Script loading sink — check scheme
    const navInfo = { navigation: true, type: 'XSS' };
    const type = classifyNavigationType(navInfo, env, rhsNode, ctx);
    const finalType = type === 'Open Redirect' ? 'Script Injection' : type;
    pushFinding(ctx, {
      type: finalType,
      severity: finalType === 'Script Injection' ? 'critical' : getSeverity(finalType),
      title: `${finalType}: tainted data flows to ${tag} element ${propName}`,
      sink: makeSinkInfo(sinkExpr, ctx, loc, tt),
      source: formatSources(annotateSinkSteps(rhsTaint, ctx, env)),
      path: buildTaintPath(rhsTaint, sinkExpr),
    });
  } else if (behavior === 'navigation') {
    const navInfo = { navigation: true, type: 'XSS' };
    const type = classifyNavigationType(navInfo, env, rhsNode, ctx);
    pushFinding(ctx, {
      type,
      severity: getSeverity(type),
      title: `${type}: tainted data flows to ${tag} element ${propName}`,
      sink: makeSinkInfo(sinkExpr, ctx, loc, 'navigation'),
      source: formatSources(annotateSinkSteps(rhsTaint, ctx, env)),
      path: buildTaintPath(rhsTaint, sinkExpr),
    });
  } else if (tt === 'TrustedHTML' || tt === 'TrustedScript') {
    // HTML/script injection sink — the generator already filters context-dependent sinks
    // (textContent/innerText only on script/style, innerHTML/outerHTML on all elements)
    pushFinding(ctx, {
      type: 'XSS',
      severity: tag === 'script' ? 'critical' : 'high',
      title: `XSS: tainted data flows to ${tag} element ${propName}`,
      sink: makeSinkInfo(sinkExpr, ctx, loc, tt),
      source: formatSources(annotateSinkSteps(rhsTaint, ctx, env)),
      path: buildTaintPath(rhsTaint, sinkExpr),
    });
  }
}

function checkSinkAssignment(leftNode, rhsTaint, rhsNode, env, ctx) {
  if (!rhsTaint.tainted) return;

  // el.style.* = tainted → CSS Injection
  if (leftNode.type === 'MemberExpression' && !leftNode.computed &&
      leftNode.object?.type === 'MemberExpression' && !leftNode.object.computed &&
      leftNode.object.property?.name === 'style') {
    const loc = getNodeLoc(leftNode);
    const leftStr = _scopeQualifyMemberExpr(leftNode, ctx) || '';
    pushFinding(ctx, {
      type: 'CSS Injection',
      severity: 'high',
      title: `CSS Injection: tainted data flows to ${leftStr || 'element.style'}`,
      sink: makeSinkInfo(leftStr || 'element.style', ctx, loc),
      source: formatSources(annotateSinkSteps(rhsTaint, ctx, env)),
      path: buildTaintPath(rhsTaint, leftStr || 'element.style'),
    });
    return;
  }

  const leftStr = _scopeQualifyMemberExpr(leftNode, ctx);
  let propName = null;
  if (leftNode.type === 'MemberExpression' || leftNode.type === 'OptionalMemberExpression') {
    if (leftNode.computed) {
      // Computed: obj['innerHTML'] or obj[prop] where prop = 'innerHTML'
      const prop = leftNode.property;
      if (prop && (prop.type === 'StringLiteral' || (prop.type === 'Literal' && typeof prop.value === 'string'))) {
        propName = prop.value;
      } else if (prop) {
        const _av = resolveAbstract(prop, env, ctx);
        if (_av.concrete && typeof _av.value === 'string') {
          propName = _av.value;
        } else {
          // Conservative: resolve through scope to find the init expression
          // If it's a ternary, check if either branch is a sink name
          let initNode = resolveInitFromScope(prop, ctx) || prop;
          if (initNode.type === 'ConditionalExpression') {
            const _consAV = resolveAbstract(initNode.consequent, env, ctx);
            const _altAV = resolveAbstract(initNode.alternate, env, ctx);
            if (_consAV.concrete && typeof _consAV.value === 'string' && checkAssignmentSink(null, _consAV.value)) propName = _consAV.value;
            else if (_altAV.concrete && typeof _altAV.value === 'string' && checkAssignmentSink(null, _altAV.value)) propName = _altAV.value;
          }
        }
      }
    } else {
      // Non-computed: obj.innerHTML
      propName = leftNode.property?.name;
    }
  }
  const sinkInfo = checkAssignmentSink(_stripScopePrefix(leftStr), propName);
  if (!sinkInfo) return;

  // Full-path sinks (location.href, document.domain, etc.) are always real — skip element check
  const matchedByFullPath = leftStr && checkAssignmentSink(_stripScopePrefix(leftStr), null);

  // Element property sinks (innerHTML, outerHTML, srcdoc, href, cssText) are only real sinks
  // when the target is a known DOM element — not a plain JS object with the same property name.
  if (!matchedByFullPath && propName && (leftNode.type === 'MemberExpression' || leftNode.type === 'OptionalMemberExpression')) {
    const ELEMENT_ONLY_PROPS = new Set(['innerHTML', 'outerHTML', 'srcdoc', 'href', 'cssText']);
    if (ELEMENT_ONLY_PROPS.has(propName)) {
      const objNode = leftNode.object;
      const objKey = _scopeQualifyMemberExpr(objNode, ctx);
      if (objKey) {
        const tag = ctx.elementTypes.get(objKey);
        const isDomAttached = ctx.domAttached.has(objKey);
        const _bareLeftStr = _stripScopePrefix(leftStr);
        const isDirectDomAccess = _bareLeftStr && (_bareLeftStr.startsWith('document.') || _bareLeftStr.includes('.document.'));

        // Check if object resolves to a DOM type via variableTypes
        // e.g., var doc = document; doc.body.innerHTML → doc has type Document → DOM access
        let isDomTyped = false;
        if (!isDomAttached && !isDirectDomAccess) {
          // Walk up the object chain to check variableTypes
          let checkNode = leftNode.object;
          while (checkNode) {
            const checkKey = checkNode.type === 'Identifier' ? resolveId(checkNode, ctx.scopeInfo) : _scopeQualifyMemberExpr(checkNode, ctx);
            if (checkKey) {
              if (ctx.domAttached.has(checkKey) || ctx.variableTypes.has(checkKey)) {
                isDomTyped = true;
                break;
              }
            }
            checkNode = checkNode.type === 'MemberExpression' ? checkNode.object : null;
          }
        }

        // If element type is tracked, checkElementPropertySink handles it with precise tag-aware logic
        if (tag) return;

        // For unknown variables: only report if the object is known to be DOM-attached,
        // is a direct DOM access, or resolves to a DOM type via variableTypes
        if (!isDomAttached && !isDirectDomAccess && !isDomTyped) return;
      }
    }
  }

  // Skip self-redirect: top.location.href = self.location.href
  if (sinkInfo.navigation && isSelfRedirect(sinkInfo, rhsNode, ctx)) return;

  const type = classifyNavigationType(sinkInfo, env, rhsNode, ctx);
  const severity = getSeverity(type);
  const loc = getNodeLoc(leftNode);
  // Derive sinkClass from assignment sink classification:
  // navigation: true → 'navigation' (location.href, window.open)
  // propName 'innerHTML'/'outerHTML'/'srcdoc' → 'TrustedHTML'
  // propName 'cssText' → CSS (no sinkClass needed — type is CSS Injection)
  const _assignSinkClass = sinkInfo.navigation ? 'navigation'
    : (propName === 'innerHTML' || propName === 'outerHTML' || propName === 'srcdoc') ? 'TrustedHTML'
    : null;
  pushFinding(ctx, {
    type,
    severity,
    title: `${type}: tainted data flows to ${leftStr || propName}`,
    sink: makeSinkInfo(leftStr || propName, ctx, loc, _assignSinkClass),
    source: formatSources(annotateSinkSteps(rhsTaint, ctx, env)),
    path: buildTaintPath(rhsTaint, leftStr || propName),
  });
}

function isSelfRedirect(sinkInfo, argNode, ctx) {
  // Suppress location.replace(location.href) / location.assign(self.location.href) etc.
  // These are frame-busting or same-page reloads, not exploitable
  if (!sinkInfo.navigation || !argNode) return false;
  const argStr = _stripScopePrefix(_scopeQualifyMemberExpr(argNode, ctx) || '');
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
      if (isFuncExpr(argNode)) continue;
    }

    // Skip self-redirect patterns: location.replace(self.location.href)
    if (isSelfRedirect(sinkInfo, callNode.arguments[argIdx], ctx)) continue;

    const type = classifyNavigationType(sinkInfo, env, callNode.arguments[argIdx], ctx);
    const severity = getSeverity(type);
    const loc = getNodeLoc(callNode);
    // sinkClass from CALL_SINKS entry or IDL classification.
    const sinkClass = sinkInfo.sinkClass || (sinkInfo.navigation ? 'navigation'
      : sinkInfo.type === 'Script Injection' ? 'TrustedScriptURL' : 'TrustedScript');
    pushFinding(ctx, {
      type,
      severity,
      title: `${type}: tainted data flows to ${calleeStr}()`,
      sink: makeSinkInfo(`${calleeStr}(arg${argIdx})`, ctx, loc, sinkClass),
      source: formatSources(annotateSinkSteps(argTaint, ctx, env)),
      path: buildTaintPath(argTaint, calleeStr),
    });
  }
}

// ── Prototype pollution ──
// All taint values are pre-computed by the caller (processAssignment) in the iterative engine.
// rhsTaint: taint of the RHS value, keyTaint: taint of the innermost computed key,
// outerKeyTaint: taint of the outer computed key in obj[k1][k2] patterns.
export function checkPrototypePollution(node, _env, ctx, rhsTaint, keyTaint, outerKeyTaint) {
  if (node.type !== 'AssignmentExpression') return;
  const left = node.left;
  if (left.type !== 'MemberExpression') return;
  if (globalThis._TAINT_DEBUG && (rhsTaint.tainted || keyTaint.tainted)) {
    const keyTransforms = keyTaint.tainted ? keyTaint.toArray().map(l => (l.transforms||[]).map(t=>t.op).join(',')).join(';') : '';
    const rhsTransforms = rhsTaint.tainted ? rhsTaint.toArray().map(l => (l.transforms||[]).map(t=>t.op).join(',')).join(';') : '';
    console.log(`[PP-CHECK] ${_scopeQualifyMemberExpr(left, ctx)||left.type} computed=${left.computed} rhsTainted=${rhsTaint.tainted} keyTainted=${keyTaint.tainted} outerKeyTainted=${outerKeyTaint.tainted} file=${ctx.file} keyTransforms=[${keyTransforms}] rhsTransforms=[${rhsTransforms}] loc=${node.loc?.start?.line}:${node.loc?.start?.column}`);
  }

  // Pattern 1: obj[key1][key2] = tainted (both keys tainted)
  if (left.computed && left.object.type === 'MemberExpression' && left.object.computed) {
    if (outerKeyTaint.tainted && keyTaint.tainted) {
      const loc = getNodeLoc(node);
      pushFinding(ctx, {
        type: 'Prototype Pollution',
        severity: 'critical',
        title: 'Prototype Pollution: attacker controls nested property keys',
        sink: makeSinkInfo(_scopeQualifyMemberExpr(left, ctx) || 'obj[key1][key2]', ctx, loc),
        source: formatSources(outerKeyTaint.clone().merge(keyTaint)),
        path: buildTaintPath(outerKeyTaint.clone().merge(keyTaint), 'obj[key1][key2]'),
        sinkModel: { dangerousValues: [..._PROTO_SETTER_KEYS, 'constructor'], constraintSource: outerKeyTaint },
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

      const combinedTaint = rhsTaint.tainted ? rhsTaint : keyTaint;
      if (combinedTaint.tainted) {
        const loc = getNodeLoc(node);
        const expr = _scopeQualifyMemberExpr(left, ctx) || `obj.${objProp}.prop`;
        const title = keyTaint.tainted
          ? `Prototype Pollution: attacker controls property key on ${objProp}`
          : `Prototype Pollution: tainted data assigned to ${objProp}`;
        pushFinding(ctx, {
          type: 'Prototype Pollution',
          severity: 'critical',
          title,
          sink: makeSinkInfo(expr, ctx, loc),
          source: formatSources(combinedTaint),
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
    if (keyTaint.tainted) {
      const loc = getNodeLoc(node);
      const expr = _scopeQualifyMemberExpr(left, ctx) || 'obj.constructor.prototype[key]';
      pushFinding(ctx, {
        type: 'Prototype Pollution',
        severity: 'critical',
        title: 'Prototype Pollution: attacker controls property key on constructor.prototype',
        sink: makeSinkInfo(expr, ctx, loc),
        source: formatSources(keyTaint),
        path: buildTaintPath(keyTaint, expr),
      });
    }
  }

  // Pattern 4: obj.__proto__ = tainted (direct prototype replacement)
  if (!left.computed && left.property?.name === '__proto__') {
    if (rhsTaint.tainted) {
      const loc = getNodeLoc(node);
      const expr = _scopeQualifyMemberExpr(left, ctx) || 'obj.__proto__';
      pushFinding(ctx, {
        type: 'Prototype Pollution',
        severity: 'critical',
        title: 'Prototype Pollution: tainted data assigned to __proto__',
        sink: makeSinkInfo(expr, ctx, loc),
        source: formatSources(annotateSinkSteps(rhsTaint, ctx, _env)),
        path: buildTaintPath(rhsTaint, expr),
      });
    }
  }

  // Pattern 5: obj[taintedKey] = taintedValue — attacker controls both key and value.
  // For single-level assignment (obj[key] = val), PP only occurs if:
  // (a) the target IS a prototype (Object.prototype[key] = val), OR
  // (b) the function is recursive (deep merge traverses constructor.prototype path), OR
  // (c) the target is accessed via a prototype chain (obj.constructor.prototype[key] = val — handled by Pattern 1)
  // Single-level obj["__proto__"] = val on a local object changes obj's prototype but does NOT pollute Object.prototype.
  if (left.computed && !(left.object.type === 'MemberExpression' && left.object.computed)) {
    const _pp5Target = left.object;
    const _pp5IsProto = _isPrototypeNode(_pp5Target);
    const _pp5IsRecursive = !!ctx._isRecursiveCall;
    // Single-level obj[key] = val does NOT pollute Object.prototype — it only changes obj's
    // prototype chain via the __proto__ setter. PoC confirms: ({}).polluted remains undefined.
    // PP requires: (a) target IS a prototype object, or (b) recursive deep merge that traverses
    // constructor.prototype path across multiple levels.
    // Type-based suppression: if the RHS value is known to be a non-object primitive type,
    // obj["__proto__"] = primitive cannot pollute Object.prototype (no nested properties to traverse).
    // This handles ternary else branches like: D(p) ? recurse : a[m]=p where p is primitive on else path.
    let _pp5ValueIsObject = true;
    if (_pp5IsRecursive && node.right?.type === 'Identifier') {
      const rhsKey = resolveId(node.right, ctx.scopeInfo);
      const rhsTypes = _env.knownTypes.get(rhsKey);
      if (rhsTypes && rhsTypes.size > 0) {
        // If ALL known types are non-object primitives, the value can't carry nested PP
        const objectTypes = new Set(['object', 'function']);
        _pp5ValueIsObject = [...rhsTypes].some(t => objectTypes.has(t));
      }
    }
    if (left.computed && (keyTaint.tainted || rhsTaint.tainted)) {
      trace('PP5-CHECK', { keyT: keyTaint.tainted, rhsT: rhsTaint.tainted, recursive: _pp5IsRecursive, isProto: _pp5IsProto, valIsObj: _pp5ValueIsObject, file: ctx.file, line: node.loc?.start?.line });
    }
    if (keyTaint.tainted && rhsTaint.tainted && (_pp5IsProto || (_pp5IsRecursive && _pp5ValueIsObject))) {
      trace('PP5-WILL-FIRE', { file: ctx.file, line: node.loc?.start?.line });
      if (globalThis._TAINT_DEBUG) {
        const keyNode = left.property;
        const keyName = keyNode?.type === 'Identifier' ? keyNode.name : (_scopeQualifyMemberExpr(keyNode, ctx) || '');
        const objStr2 = _scopeQualifyMemberExpr(left.object, ctx);
        console.log(`[PP5-FIRE] ${objStr2}[${keyName}] loc=${node.loc?.start?.line}:${node.loc?.start?.column} recursive=${!!ctx._isRecursiveCall} keyLabels=${keyTaint.toArray().map(l=>l.description).join(';')}`);
      }
      const loc = getNodeLoc(node);
      const objStr = _stripScopePrefix(_scopeQualifyMemberExpr(left.object, ctx) || 'obj');
      pushFinding(ctx, {
        type: 'Prototype Pollution',
        severity: 'high',
        title: 'Prototype Pollution: attacker controls property key and value in assignment',
        sink: makeSinkInfo(`${objStr}[taintedKey]`, ctx, loc),
        source: formatSources(keyTaint.clone().merge(rhsTaint)),
        path: buildTaintPath(keyTaint, `${objStr}[taintedKey]`),
        // When inside a recursive function (e.g., deep merge), the attacker's value
        // gets recursively processed. This enables 2-step PP via constructor.prototype.
        // Expand danger set to include 'constructor' when recursion is detected.
        // Check constraints from BOTH key and value — the value's constraints
        // (from safeGet conditional returns) also restrict which keys are viable.
        sinkModel: (() => {
          // In recursive functions, check if the value went through a conditional
          // return (has constraints). If so, the attacker's structured data gets
          // recursively processed, enabling constructor.prototype PP.
          const rhsHasConstraints = ctx._isRecursiveCall && rhsTaint.tainted &&
            rhsTaint.toArray().some(l => l.constraints && l.constraints.length > 0);
          return {
            dangerousValues: rhsHasConstraints
              ? [..._PROTO_SETTER_KEYS, 'constructor']
              : _PROTO_SETTER_KEYS,
            constraintSource: keyTaint,
            valueConstraintSource: rhsHasConstraints ? rhsTaint : null,
          };
        })(),
      });
    }
  }
}


// Check if a TaintSet carries structured data — the attacker controls nested properties.
// Structured sources: JSON.parse output, postMessage data, parsed URL params.
// When structured, obj[key] = val allows the attacker to set nested objects,
// enabling multi-level PP (e.g., constructor.prototype).
function buildTaintPath(taintSet, sinkExpr) {
  return taintSet.toArray().map(label => `${label.description} (${label.file}:${label.line}) → ${sinkExpr}`);
}

// ── PoC generation from data flow transforms ──

// Determine the base payload a sink needs to demonstrate exploitation
// Derive the concrete exploit payload from the finding's data flow classification.
// The payload is what must arrive at the SINK to demonstrate exploitation.
// Classification is derived from the finding's type and sink expression — both come
// from the AST-level sink analysis, not from string patterns.
function sinkPayload(finding, cleanedConstraints) {
  const type = finding.type;
  const sinkModel = finding.sinkModel;

  if (type === 'Prototype Pollution') {
    const dangerKeys = sinkModel?.dangerousValues || ['__proto__'];
    const blockedKeys = new Set();
    const constraints = cleanedConstraints || finding.source?.[0]?.constraints || [];
    for (const c of constraints) {
      if (c.op === '!==' || c.op === '!=') blockedKeys.add(c.value);
    }
    // Prefer constructor.prototype traversal — it works universally across
    // JS engines and environments. __proto__ traversal depends on the __proto__
    // setter behavior which varies between engines and merge implementations.
    let traversalKey = null;
    const preferredOrder = dangerKeys.includes('constructor')
      ? ['constructor', ...dangerKeys.filter(k => k !== 'constructor')]
      : dangerKeys;
    for (const key of preferredOrder) {
      if (!blockedKeys.has(key)) { traversalKey = key; break; }
    }
    if (traversalKey === 'constructor') {
      return '{"constructor":{"prototype":{"polluted":true}}}';
    }
    return '{"__proto__":{"polluted":true}}';
  }

  if (type === 'CSS Injection') return 'color:red;background:url(//attacker.com/steal)';
  if (type === 'Open Redirect') return 'https://evil.com/phish';
  if (type === 'Script Injection') return 'data:text/javascript,alert(origin)';

  // For XSS: the sink's TrustedType class determines the payload format.
  // This classification flows from the IDL data / CALL_SINKS / ASSIGNMENT_SINKS
  // through makeSinkInfo into the finding's sink.sinkClass field.
  const sinkClass = finding.sink?.sinkClass;
  if (sinkClass === 'TrustedScript') return 'alert(origin)';
  if (sinkClass === 'TrustedScriptURL') return 'data:text/javascript,alert(origin)';
  if (sinkClass === 'navigation') return 'javascript:alert(origin)';
  // TrustedHTML or unclassified: HTML injection
  return '<img src=x onerror=alert(origin)>';
}

// Reverse-apply transforms to work out what the source input must contain.
// Walks the transform chain backwards from the sink payload.
function reverseTransforms(payload, transforms) {
  const steps = [];
  let value = payload;
  for (let i = transforms.length - 1; i >= 0; i--) {
    const t = transforms[i];
    switch (t.op) {
      case 'slice': case 'substring': case 'substr': {
        const start = typeof t.args[0] === 'number' ? t.args[0] : 0;
        if (start > 0) {
          const pad = '_'.repeat(start);
          value = pad + value;
          steps.unshift(`.${t.op}(${t.args.map(a => JSON.stringify(a)).join(', ')}) strips first ${start} char(s)`);
        }
        break;
      }
      case 'split': {
        const sep = typeof t.args[0] === 'string' ? t.args[0] : null;
        // Look for a following index/property transform (property with numeric key = array index)
        const nextT = i + 1 < transforms.length ? transforms[i + 1] : null;
        const isNextIndex = nextT && (nextT.op === 'index' || (nextT.op === 'property' && /^\d+$/.test(nextT.args[0])));
        if (sep !== null && isNextIndex) {
          // Handled by the index/property case — just skip the split step here
          // to avoid duplicate steps
        } else if (sep !== null) {
          steps.unshift(`.split(${JSON.stringify(sep)}) splits on ${JSON.stringify(sep)}`);
        }
        break;
      }
      case 'index': {
        // Handled by split lookahead above; standalone index just selects an element
        if (i === 0 || transforms[i - 1].op !== 'split') {
          steps.unshift(`[${t.args[0]}] selects element at index ${t.args[0]}`);
        }
        break;
      }
      case 'replace': case 'replaceAll': {
        const pattern = t.args[0];
        const replacement = t.args[1];
        if (typeof pattern === 'string' && typeof replacement === 'string') {
          // If the code removes something from the input (replaces with ''), our payload just shouldn't contain that pattern
          // If the code replaces pattern→replacement, and replacement is in our payload, swap back
          if (replacement === '' && !value.includes(pattern)) {
            steps.unshift(`.${t.op}(${JSON.stringify(pattern)}, '') removes ${JSON.stringify(pattern)} (payload unaffected)`);
          } else if (replacement !== '' && value.includes(replacement)) {
            value = value.replace(replacement, pattern);
            steps.unshift(`.${t.op}(${JSON.stringify(pattern)}, ${JSON.stringify(replacement)}) substitutes text`);
          }
        }
        break;
      }
      case 'decodeURIComponent': case 'decodeURI':
        // Input is URL-encoded; our payload can stay decoded (browser sends it encoded)
        steps.unshift(`${t.op}() decodes URL-encoded input`);
        break;
      case 'atob':
        // Input is base64-encoded
        try { value = btoa(value); } catch { /* leave as-is */ }
        steps.unshift('atob() decodes base64 — payload must be base64-encoded');
        break;
      case 'btoa':
        steps.unshift('btoa() encodes to base64 (taint carries through)');
        break;
      case 'JSON.parse':
        // The code does JSON.parse(input). The input must be a valid JSON string.
        // If the current value is already a valid JSON string (from a PP payload
        // or nested object construction), keep it as-is. Otherwise stringify.
        if (typeof value === 'string') {
          try { JSON.parse(value); /* already valid JSON */ } catch {
            value = JSON.stringify(value);
          }
        } else {
          value = JSON.stringify(value);
        }
        steps.unshift('JSON.parse() parses JSON — payload must be valid JSON string');
        break;
      case 'property': {
        const prop = t.args[0];
        // Numeric property after split acts as array index
        if (prop && /^\d+$/.test(prop)) {
          const prev = i > 0 ? transforms[i - 1] : null;
          if (prev && prev.op === 'split') {
            const sep = typeof prev.args[0] === 'string' ? prev.args[0] : null;
            const idx = Number(prop);
            if (sep !== null) {
              if (idx > 0) {
                const prefix = ('x' + sep).repeat(idx);
                value = prefix + value;
              }
              steps.unshift(`.split(${JSON.stringify(sep)})[${idx}] takes segment at index ${idx}`);
              break;
            }
          }
          steps.unshift(`[${prop}] selects element at index ${prop}`);
        } else if (prop) {
          // Collect consecutive property transforms and check if preceded by JSON.parse.
          // E.g., JSON.parse(x).config.template → wrap in {config:{template: value}}
          // Look backwards through consecutive properties to find a JSON.parse predecessor.
          let jsonParseIdx = -1;
          let scanIdx = i;
          const propChain = [prop];
          while (scanIdx > 0) {
            const prevScan = transforms[scanIdx - 1];
            if (prevScan.op === 'property' && typeof prevScan.args[0] === 'string' && !/^\d+$/.test(prevScan.args[0])) {
              propChain.push(prevScan.args[0]);
              scanIdx--;
            } else if (prevScan.op === 'JSON.parse') {
              jsonParseIdx = scanIdx - 1;
              break;
            } else {
              break;
            }
          }
          if (jsonParseIdx >= 0) {
            // Wrap value in nested object matching the property chain
            let wrapped = value;
            for (const p of propChain) {
              wrapped = JSON.stringify({ [p]: wrapped });
              // Unwrap inner stringify for nesting: {"key":"val"} not {"key":"\"val\""}
              // Re-parse and re-stringify to get correct nesting
            }
            // Actually build properly with real objects
            let obj = value;
            for (const p of propChain) {
              obj = { [p]: obj };
            }
            value = JSON.stringify(obj);
            const keyList = [...propChain].reverse().map(p => JSON.stringify(p)).join('.');
            steps.unshift(`.${[...propChain].reverse().join('.')} reads from parsed JSON — payload must include ${keyList} path`);
            i = jsonParseIdx; // skip past JSON.parse and consumed property transforms
          } else {
            steps.unshift(`.${prop} reads property "${prop}" from tainted object`);
          }
        }
        break;
      }
      case 'get': {
        // .get(key) on URLSearchParams/Map — the key name is used in delivery
        const getKey = t.args[0];
        if (getKey != null) {
          steps.unshift(`.get(${JSON.stringify(getKey)}) reads parameter ${JSON.stringify(getKey)}`);
        }
        break;
      }
      case 'toLowerCase': case 'toUpperCase':
        steps.unshift(`.${t.op}() changes case (payload unaffected)`);
        break;
      case 'trim': case 'trimStart': case 'trimEnd':
        steps.unshift(`.${t.op}() trims whitespace (payload unaffected)`);
        break;
      case 'match': case 'matchAll':
        steps.unshift(`.${t.op}() extracts regex matches from tainted string`);
        break;
      case 'charAt': case 'at': {
        const idx = typeof t.args[0] === 'number' ? t.args[0] : 0;
        steps.unshift(`.${t.op}(${idx}) extracts single character (limited exploitation)`);
        break;
      }
      default:
        if (t.op) steps.unshift(`${t.op}() transforms the data`);
        break;
    }
  }
  return { value, steps };
}

// Build a nested object literal from property transforms.
// E.g. transforms [{op:'property',args:['data']},{op:'property',args:['html']}] + value
// → { data: { html: value } }
function buildNestedObject(propChain, value) {
  let result = value;
  for (let i = propChain.length - 1; i >= 0; i--) {
    result = `{${JSON.stringify(propChain[i])}: ${typeof result === 'string' && result.startsWith('{') ? result : JSON.stringify(result)}}`;
  }
  return result;
}

// Wrap the reverse-transformed payload in the appropriate delivery for the source type
function wrapDelivery(sourceType, value, pageUrl, sourceKey, propertyChain) {
  const page = pageUrl || 'https://victim.com/page';
  // URL-delivered values are URL-encoded by the browser. The payload must be
  // encodeURIComponent'd so the browser delivers the exact bytes after decoding.
  const urlValue = encodeURIComponent(value);
  switch (sourceType) {
    case 'url.location.hash':
      return { vector: `${page}#${urlValue}`, description: 'Navigate to URL with crafted fragment' };
    case 'url.location.search':
      return { vector: `${page}?${urlValue}`, description: 'Navigate to URL with crafted query string' };
    case 'url.location.href':
    case 'url.document.URL':
    case 'url.document.documentURI':
    case 'url.document.baseURI':
      return { vector: `${page}?${urlValue}#${urlValue}`, description: 'Navigate to URL with crafted query/fragment' };
    case 'url.location.pathname':
      return { vector: `${page}/${urlValue}`, description: 'Navigate to URL with crafted path' };
    case 'url.searchParam': {
      const paramName = sourceKey || 'param';
      return { vector: `${page}?${paramName}=${encodeURIComponent(value)}`, description: `Navigate to URL with crafted "${paramName}" query parameter` };
    }
    case 'cookie': {
      const cookieName = sourceKey || 'key';
      return { vector: `document.cookie = "${cookieName}=${value}"`, description: `Set cookie "${cookieName}" via JavaScript console (requires prior XSS or subdomain control)` };
    }
    case 'storage.local': {
      const storageKey = sourceKey || 'key';
      return { vector: `localStorage.setItem(${JSON.stringify(storageKey)}, ${JSON.stringify(value)})`, description: `Set localStorage key "${storageKey}" via JavaScript console (requires prior XSS on same origin)` };
    }
    case 'storage.session': {
      const storageKey = sourceKey || 'key';
      return { vector: `sessionStorage.setItem(${JSON.stringify(storageKey)}, ${JSON.stringify(value)})`, description: `Set sessionStorage key "${storageKey}" via JavaScript console (requires prior XSS on same origin)` };
    }
    case 'postMessage.data':
    case 'postMessage (weak origin check)': {
      // Build the postMessage data shape from property chain
      let msgData;
      if (propertyChain && propertyChain.length > 0) {
        msgData = buildNestedObject(propertyChain, value);
      } else {
        msgData = JSON.stringify(value);
      }
      return {
        vector: `// From attacker page:\nvar w = window.open(${JSON.stringify(page)});\nsetTimeout(() => w.postMessage(${msgData}, '*'), 1000);`,
        description: 'Send postMessage from attacker-controlled window'
      };
    }
    case 'window.name':
      return { vector: `// Attacker sets window.name before navigating:\nvar w = window.open('', ${JSON.stringify(value)});\nw.location = ${JSON.stringify(page)};\n// Target page reads window.name`, description: 'Open page with crafted window.name' };
    case 'url.hashchange':
      return { vector: `location.hash = ${JSON.stringify('#' + value)}`, description: 'Trigger hashchange event with crafted hash' };
    case 'url.document.referrer':
      return { vector: `// Navigate from: https://evil.com/redirect?to=${encodeURIComponent(page)}\n// Referrer header will contain attacker-controlled URL`, description: 'Control document.referrer via navigation from attacker page' };
    case 'url.constructed':
      return { vector: `new URL(${JSON.stringify(value)})`, description: 'Constructed URL object carries taint from input' };
    default:
      return { vector: value, description: `Inject via ${sourceType}` };
  }
}

// Build a multi-step PoC vector from stateSteps on the source label.
// Emits working JavaScript with sequential postMessage calls or timer waits.
function buildMultiStepVector(stateSteps, propertyChain, rawInput, sourceType) {
  const page = 'https://victim.com/page';
  const prereqSteps = stateSteps.filter(s => s.action === 'prerequisite');
  const storeSteps = stateSteps.filter(s => s.action === 'store');
  const sinkSteps = stateSteps.filter(s => s.action === 'sink');
  if (storeSteps.length === 0 && prereqSteps.length === 0) return null;

  const isPostMessage = sourceType.startsWith('postMessage');
  if (!isPostMessage && prereqSteps.length === 0) return null;

  const lines = [];
  const totalSteps = prereqSteps.length + storeSteps.length + sinkSteps.length;
  lines.push(`// Multi-step PoC — ${totalSteps} step(s) required`);
  lines.push(`var w = window.open(${JSON.stringify(page)});`);

  // Prerequisites: state that must be set up via other event sources (URL, hashchange, etc.)
  for (let i = 0; i < prereqSteps.length; i++) {
    const prereq = prereqSteps[i];
    const condDesc = prereq.condition
      ? `${prereq.condition.discriminant} === ${JSON.stringify(prereq.condition.value)}`
      : 'state setup';
    if (prereq.sourceType === 'url.location.hash' || prereq.sourceType === 'url.hashchange') {
      const hashVal = prereq.condition?.value || '';
      lines.push(`// Step ${i + 1}: set URL hash to satisfy ${condDesc}`);
      lines.push(`w.location.hash = ${JSON.stringify(hashVal)};`);
    } else if (prereq.sourceType?.startsWith('url.')) {
      lines.push(`// Step ${i + 1}: navigate with URL param to satisfy ${condDesc}`);
      lines.push(`// Ensure URL contains: ${prereq.condition?.propName}=${JSON.stringify(prereq.condition?.value)}`);
    } else {
      lines.push(`// Step ${i + 1}: prerequisite — ${condDesc} (via ${prereq.sourceType})`);
    }
  }

  let delay = 1000;

  for (let i = 0; i < storeSteps.length; i++) {
    const store = storeSteps[i];
    const msgObj = {};
    // Set the condition discriminant (e.g., type: 'init')
    if (store.condition) {
      if (store.condition.negated) {
        // Negated condition: mode !== 'display' → use any OTHER value
        msgObj[store.condition.propName] = `not_${store.condition.value}`;
      } else {
        msgObj[store.condition.propName] = store.condition.value;
      }
    }
    // Add the payload under the property chain (skip 'data' as it's the postMessage root)
    const dataProps = propertyChain.filter(p => p !== 'data');
    if (dataProps.length > 0) {
      msgObj[dataProps[dataProps.length - 1]] = rawInput;
    } else if (!store.condition) {
      // No condition and no property chain — payload is the message data directly
      msgObj._raw = rawInput;
    }
    const msgData = msgObj._raw !== undefined ? JSON.stringify(msgObj._raw) : JSON.stringify(msgObj);
    const condDesc = store.condition
      ? (store.condition.negated
        ? `${store.condition.discriminant} !== ${JSON.stringify(store.condition.value)}`
        : `${store.condition.discriminant} === ${JSON.stringify(store.condition.value)}`)
      : 'handler';
    const stepNum = prereqSteps.length + i + 1;
    lines.push(`// Step ${stepNum}: store payload via ${condDesc}`);
    lines.push(`setTimeout(() => w.postMessage(${msgData}, '*'), ${delay});`);
    delay += 1000;
  }

  for (let i = 0; i < sinkSteps.length; i++) {
    const sink = sinkSteps[i];
    const stepNum = prereqSteps.length + storeSteps.length + i + 1;
    if (sink.handler === 'timer') {
      const timerDelay = sink.delay || 0;
      lines.push(`// Step ${stepNum}: wait ${timerDelay}ms for timer callback to fire and trigger sink`);
    } else if (sink.condition) {
      const triggerObj = {};
      if (sink.condition.negated) {
        triggerObj[sink.condition.propName] = `not_${sink.condition.value}`;
      } else {
        triggerObj[sink.condition.propName] = sink.condition.value;
      }
      const condDesc = sink.condition.negated
        ? `${sink.condition.discriminant} !== ${JSON.stringify(sink.condition.value)}`
        : `${sink.condition.discriminant} === ${JSON.stringify(sink.condition.value)}`;
      lines.push(`// Step ${stepNum}: trigger sink via ${condDesc}`);
      lines.push(`setTimeout(() => w.postMessage(${JSON.stringify(triggerObj)}, '*'), ${delay});`);
      delay += 1000;
    }
  }

  // If there are prerequisites but no store/sink steps, add the postMessage delivery
  // as the final step — the prerequisite sets up state, the postMessage delivers payload
  if (prereqSteps.length > 0 && storeSteps.length === 0 && sinkSteps.length === 0 && isPostMessage) {
    const stepNum = prereqSteps.length + 1;
    const msgObj = {};
    const dataProps = propertyChain.filter(p => p !== 'data');
    if (dataProps.length > 0) {
      let cur = msgObj;
      for (let pi = 0; pi < dataProps.length - 1; pi++) { cur[dataProps[pi]] = {}; cur = cur[dataProps[pi]]; }
      cur[dataProps[dataProps.length - 1]] = rawInput;
    } else {
      msgObj._raw = rawInput;
    }
    const msgData = msgObj._raw !== undefined ? JSON.stringify(msgObj._raw) : JSON.stringify(msgObj);
    lines.push(`// Step ${stepNum}: deliver payload via postMessage`);
    lines.push(`setTimeout(() => w.postMessage(${msgData}, '*'), 1000);`);
  }

  const msgCount = storeSteps.length + sinkSteps.filter(s => s.handler !== 'timer').length + (prereqSteps.length > 0 && storeSteps.length === 0 ? 1 : 0);
  return {
    vector: lines.join('\n'),
    description: `${prereqSteps.length > 0 ? 'Set up prerequisite state, then s' : 'S'}end ${msgCount} postMessage(s) to trigger exploit`,
  };
}

// Generate a PoC for a finding using its source labels' transforms and the sink
// Sources where the delivery prefix IS the first character of the value
// (e.g., location.hash returns "#foo", so slice(1) strips the "#" which is the URL fragment delimiter)
const SOURCE_PREFIX_CHAR = {
  'url.location.hash': '#',
  'url.location.search': '?',
};

/**
 * Constraint-driven PoC synthesizer.
 *
 * Generates a concrete, executable exploit from the finding's data flow trace.
 * Every piece of the PoC is derived from the taint analysis — nothing is hardcoded.
 *
 * Pipeline:
 * 1. GOAL: derive the payload that must arrive at the sink (from sinkClass / sinkModel)
 * 2. REVERSE: undo each transform in the chain to compute the raw source input
 * 3. CONSTRAINTS: satisfy all branch conditions the taint flowed through
 * 4. SHAPE: build the delivery object structure (property chains, JSON wrapping)
 * 5. MULTI-STEP: order stateSteps into sequential delivery for stateful exploits
 * 6. DELIVER: wrap in the source's delivery mechanism (URL, postMessage, storage)
 *
 * @param {Object} finding - Finding from the taint engine with source, sink, sinkModel
 * @param {string} [pageUrl] - Base URL for delivery (e.g., http://127.0.0.1:8080)
 * @returns {Object|null} {payload, input, vector, description, steps, transforms, constraints}
 */
export function generatePoC(finding, pageUrl) {
  const sources = finding.source || [];
  if (sources.length === 0) return null;

  const primarySource = sources[0];
  const transforms = primarySource.transforms || [];
  // Aggregate constraints from ALL source labels + sinkModel constraint sources.
  // This ensures the PoC satisfies ALL branch conditions from the data flow path,
  // including constraints from different labels that may cancel out (vacuous pairs).
  let constraints = primarySource.constraints ? [...primarySource.constraints] : [];
  // Add constraints from sinkModel's constraint sources (key + value constraints)
  if (finding.sinkModel?.constraintSource?.tainted) {
    for (const label of finding.sinkModel.constraintSource.toArray()) {
      if (label.constraints) constraints.push(...label.constraints);
    }
  }
  if (finding.sinkModel?.valueConstraintSource?.tainted) {
    for (const label of finding.sinkModel.valueConstraintSource.toArray()) {
      if (label.constraints) constraints.push(...label.constraints);
    }
  }
  // Remove vacuous pairs (===X and !==X from merged branches)
  constraints = _removeVacuousConstraints(constraints);

  // ── Step 1: GOAL — what must arrive at the sink ──
  const payload = sinkPayload(finding, constraints);

  // ── Step 2: REVERSE — undo transforms to compute raw source input ──
  let { value: rawInput, steps } = reverseTransforms(payload, transforms);

  // Source delimiter handling: hash/search prefix char is the URL delimiter itself.
  // When slice(1)/substring(1) strips the delimiter, the delivery URL provides it.
  const prefixChar = SOURCE_PREFIX_CHAR[primarySource.type];
  if (prefixChar && transforms.length > 0) {
    const first = transforms[0];
    if ((first.op === 'slice' || first.op === 'substring' || first.op === 'substr') && first.args[0] === 1) {
      if (rawInput.startsWith('_')) rawInput = rawInput.slice(1);
    }
  }

  // ── Step 3: CONSTRAINTS — satisfy branch conditions from the data flow path ──
  // Each constraint is a condition the taint flowed through (e.g., typeof x === "object",
  // key !== "__proto__"). The PoC input must satisfy ALL of them.
  if (constraints.length > 0) {
    rawInput = satisfyConstraints(rawInput, constraints, finding);
  }

  // ── Step 4: SHAPE — extract object structure from transforms ──
  // Leading property transforms represent the object destructuring path
  // e.g., e.data.config.html → propertyChain = ['data', 'config', 'html']
  const propertyChain = [];
  for (const t of transforms) {
    if (t.op === 'property' && typeof t.args[0] === 'string' && !/^\d+$/.test(t.args[0])) {
      propertyChain.push(t.args[0]);
    } else {
      break;
    }
  }

  // Extract .get('key') for URL query parameter delivery
  let getParamName = null;
  for (const t of transforms) {
    if (t.op === 'get' && t.args[0] != null) {
      getParamName = String(t.args[0]);
      break;
    }
  }

  let effectiveSourceType = primarySource.type;
  if (getParamName && (primarySource.type === 'url.location.search' || primarySource.type === 'url.location.href')) {
    effectiveSourceType = 'url.searchParam';
  }

  // ── Step 5: MULTI-STEP — stateful exploits with prerequisite state setup ──
  const stateSteps = primarySource.stateSteps;
  if (stateSteps && stateSteps.length > 0) {
    const multiStep = buildMultiStepVector(stateSteps, propertyChain, rawInput, effectiveSourceType);
    if (multiStep) {
      return {
        payload, input: rawInput, vector: multiStep.vector, description: multiStep.description,
        steps, transforms, constraints,
      };
    }
  }

  // ── Step 6: DELIVER — wrap in the source's delivery mechanism ──
  const delivery = wrapDelivery(effectiveSourceType, rawInput, pageUrl || null,
    primarySource.sourceKey || getParamName, propertyChain);

  return {
    payload, input: rawInput, vector: delivery.vector, description: delivery.description,
    steps, transforms, constraints,
  };
}

/**
 * Satisfy ALL constraints from the data flow path.
 * Modifies the raw input to comply with branch conditions the taint flowed through.
 *
 * Constraint types:
 * - {op:'!==', value:'__proto__'} → the key must NOT be __proto__; use constructor.prototype instead
 * - {op:'typeof', value:'object'} → the input must be an object (wrap in JSON if string)
 * - {op:'typeof', value:'string'} → the input must be a string
 * - {op:'===', value:'init'} → a discriminant field must equal 'init'
 * - {op:'regex', pattern:'...'} → the input must match this regex
 * - {op:'!regex', pattern:'...'} → the input must NOT match this regex
 *
 * For PP findings: use sinkModel.dangerousValues to pick the traversal key that satisfies
 * the !== constraints (e.g., if __proto__ is blocked, use constructor.prototype).
 */
/**
 * Constraint solver: modifies the raw input to satisfy ALL branch conditions
 * from the data flow path.
 *
 * The constraint set comes from TaintLabel.constraints[], accumulated as taint
 * flows through conditional branches in the source code. Each constraint
 * represents a condition that MUST be true for the taint to reach the sink.
 *
 * For PP: the constraints determine which traversal key is usable. The solver
 * picks a traversal that satisfies all !== guards and builds the nested object
 * structure from the transform chain's JSON.parse + property accesses.
 *
 * For XSS: typeof constraints determine the input type. Regex constraints
 * are verified and the input is adjusted if possible.
 *
 * The solver works entirely from the constraint data — no pattern matching.
 */
function satisfyConstraints(rawInput, constraints, finding) {
  let input = rawInput;

  // Collect exclusion constraints: values the input MUST NOT equal
  const blockedValues = new Set();
  for (const c of constraints) {
    if (c.op === '!==' || c.op === '!=') blockedValues.add(c.value);
    if (c.op === 'or' && c.clauses) {
      for (const clause of c.clauses) {
        if (clause.op === '!==' || clause.op === '!=') blockedValues.add(clause.value);
      }
    }
  }

  // Collect required type constraints
  const requiredTypes = new Set();
  for (const c of constraints) {
    if (c.op === 'typeof') requiredTypes.add(c.value);
  }

  // Collect equality constraints: fields that must equal specific values
  const requiredEqualities = new Map(); // variable → value
  for (const c of constraints) {
    if ((c.op === '===' || c.op === '==') && c.variable && c.value !== undefined) {
      requiredEqualities.set(c.variable, c.value);
    }
  }

  if (finding.type === 'Prototype Pollution') {
    // PP: build traversal object from permitted dangerous keys.
    // The sinkModel.dangerousValues lists which keys can reach Object.prototype.
    // Pick the first key not blocked by exclusion constraints.
    const dangerKeys = finding.sinkModel?.dangerousValues || ['__proto__', 'constructor'];
    let traversalKey = null;
    for (const key of dangerKeys) {
      if (!blockedValues.has(key)) { traversalKey = key; break; }
    }

    if (traversalKey) {
      // Build the PP payload object. The structure depends on the traversal:
      // __proto__: single level — {__proto__: {polluted: true}}
      // constructor: two levels — {constructor: {prototype: {polluted: true}}}
      let ppObj;
      if (traversalKey === 'constructor') {
        ppObj = { constructor: { prototype: { polluted: true } } };
      } else {
        ppObj = { [traversalKey]: { polluted: true } };
      }

      // Apply any required equality constraints as additional properties
      // e.g., if the code checks data.type === 'config', add {type: 'config'}
      for (const [variable, value] of requiredEqualities) {
        // Extract the property name from the variable path (e.g., 'data.type' → 'type')
        const parts = variable.split('.');
        const prop = parts[parts.length - 1];
        if (prop && !(prop in ppObj)) ppObj[prop] = value;
      }

      input = JSON.stringify(ppObj);
    }
  }

  // typeof constraints: verify input type matches
  if (requiredTypes.has('object') && !input.startsWith('{') && !input.startsWith('[')) {
    // Code requires an object but our input is a primitive — wrap it
    try { JSON.parse(input); } catch {
      input = JSON.stringify({ value: input });
    }
  }

  // Regex constraints: verify against all regex conditions
  for (const c of constraints) {
    if (c.op === 'regex' || c.op === '!regex') {
      try {
        const re = new RegExp(c.pattern, c.flags || '');
        const matches = re.test(input);
        if (c.op === 'regex' && !matches) {
          // Required to match but doesn't — the PoC input needs adjustment
          // This is a limitation: we can't always modify the input to match an arbitrary regex
          // The runtime verifier will catch this as a non-working PoC
        }
      } catch { /* invalid regex — skip */ }
    }
  }

  return input;
}

// Resolve call arguments to constant values for transform tracking
function resolveConstantArgs(args, env, ctx) {
  if (!args || args.length === 0) return [];
  const result = [];
  for (const arg of args) {
    const _av = resolveAbstract(arg, env, ctx);
    result.push(_av.concrete ? _av.value : null);
  }
  return result;
}
