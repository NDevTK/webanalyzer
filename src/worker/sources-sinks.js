/* sources-sinks.js — Defines taint sources, dangerous sinks, and sanitizers.
   Used by the taint engine to label data flow endpoints. */

// ── SOURCES: expressions that return attacker-controlled data ──

// Generate location-based sources from prefix/property combinations
const LOCATION_PREFIXES = [
  'location', 'window.location', 'document.location',
  'globalThis.location', 'self.location',
  'opener.location', 'window.opener.location',
  'parent.location', 'top.location',
];
const LOCATION_PROPS = {
  'href': 'url.location.href',
  'hash': 'url.location.hash',
  'search': 'url.location.search',
  'pathname': 'url.location.pathname',
};
// Only bare 'location' has host/hostname
const LOCATION_EXTRA_PROPS = {
  'host': 'url.location.host',
  'hostname': 'url.location.hostname',
};

export const MEMBER_SOURCES = Object.assign(
  {},
  // Generate all prefix.prop entries
  ...LOCATION_PREFIXES.flatMap(prefix =>
    Object.entries(LOCATION_PROPS).map(([prop, label]) => ({ [`${prefix}.${prop}`]: label }))
  ),
  // host/hostname only on bare 'location'
  ...Object.entries(LOCATION_EXTRA_PROPS).map(([prop, label]) => ({ [`location.${prop}`]: label })),
  // Non-location sources
  {
    'document.URL': 'url.document.URL',
    'document.documentURI': 'url.document.documentURI',
    'document.referrer': 'url.document.referrer',
    'document.cookie': 'cookie',
    'document.baseURI': 'url.document.baseURI',
    'window.document.cookie': 'cookie',
    'window.name': 'window.name',
  },
);

// Call expression sources: function calls that return tainted data
// { callee pattern → source label }
export const CALL_SOURCES = {
  // URLSearchParams
  'URLSearchParams.prototype.get': 'url.searchParam',
  'URLSearchParams.prototype.getAll': 'url.searchParam',
  'URLSearchParams.prototype.toString': 'url.searchParam',
  'URLSearchParams.prototype.entries': 'url.searchParam',
  'URLSearchParams.prototype.values': 'url.searchParam',
  // Storage
  'localStorage.getItem': 'storage.local',
  'sessionStorage.getItem': 'storage.session',
  // Hash/search parsing
  'decodeURIComponent': 'passthrough',  // propagates taint, doesn't create it
  'decodeURI': 'passthrough',
  'atob': 'passthrough',
  'btoa': 'passthrough',
  'JSON.parse': 'passthrough',
  'fetch': 'passthrough',       // tainted URL → tainted response for .then chains
  'String': 'passthrough',
  'Object': 'passthrough',
  'Number': 'passthrough',
  'Boolean': 'passthrough',
  'JSON.stringify': 'passthrough',
  'structuredClone': 'passthrough',
  'URL.createObjectURL': 'passthrough',
};

// Constructor sources: new Foo(tainted) where result is tainted
export const CONSTRUCTOR_SOURCES = {
  'URL': 'url.constructed',
  'URLSearchParams': 'url.searchParams',
};

// Event handler parameter sources: event.data in message handlers
export const EVENT_SOURCES = {
  'message': { property: 'data', label: 'postMessage.data' },
  'hashchange': { property: 'newURL', label: 'url.hashchange' },
};

// ── SINKS: operations where tainted data causes security impact ──

// Assignment sinks: obj.property = taintedValue
export const ASSIGNMENT_SINKS = {
  'innerHTML': { type: 'XSS', argIndex: 'rhs' },
  'outerHTML': { type: 'XSS', argIndex: 'rhs' },
  'srcdoc': { type: 'XSS', argIndex: 'rhs' },
  // Element href: a.href, base.href, link.href — javascript: URI on click/load
  'href': { type: 'XSS', argIndex: 'rhs', navigation: true },
  // Navigation sinks: XSS if javascript: possible, Open Redirect if scheme-checked
  'location.href': { type: 'XSS', argIndex: 'rhs', navigation: true },
  'window.location.href': { type: 'XSS', argIndex: 'rhs', navigation: true },
  'document.location.href': { type: 'XSS', argIndex: 'rhs', navigation: true },
  'document.location': { type: 'XSS', argIndex: 'rhs', navigation: true },
  'window.location': { type: 'XSS', argIndex: 'rhs', navigation: true },
  'location': { type: 'XSS', argIndex: 'rhs', navigation: true },
  // CSS injection
  'cssText': { type: 'CSS Injection', argIndex: 'rhs' },
  // Domain manipulation
  'document.domain': { type: 'XSS', argIndex: 'rhs' },
};

// Call sinks: function(taintedArg)
// taintedArgs: which argument indices must be tainted to trigger
export const CALL_SINKS = {
  'eval': { type: 'XSS', taintedArgs: [0], sinkClass: 'TrustedScript' },
  'Function': { type: 'XSS', taintedArgs: [0], sinkClass: 'TrustedScript' },
  'setTimeout': { type: 'XSS', taintedArgs: [0], stringOnly: true, sinkClass: 'TrustedScript' },
  'setInterval': { type: 'XSS', taintedArgs: [0], stringOnly: true, sinkClass: 'TrustedScript' },
  'document.write': { type: 'XSS', taintedArgs: [0], sinkClass: 'TrustedHTML' },
  'document.writeln': { type: 'XSS', taintedArgs: [0], sinkClass: 'TrustedHTML' },
  'Element.prototype.insertAdjacentHTML': { type: 'XSS', taintedArgs: [1], sinkClass: 'TrustedHTML' },
  'DOMParser.prototype.parseFromString': { type: 'XSS', taintedArgs: [0], sinkClass: 'TrustedHTML' },
  'Range.prototype.createContextualFragment': { type: 'XSS', taintedArgs: [0], sinkClass: 'TrustedHTML' },
  // jQuery sinks removed — detected via interprocedural tracing through actual library code
  // Navigation sinks: XSS if javascript: possible, Open Redirect if scheme-checked
  'location.assign': { type: 'XSS', taintedArgs: [0], navigation: true },
  'location.replace': { type: 'XSS', taintedArgs: [0], navigation: true },
  'window.open': { type: 'XSS', taintedArgs: [0], navigation: true },
  'window.location.assign': { type: 'XSS', taintedArgs: [0], navigation: true },
  'window.location.replace': { type: 'XSS', taintedArgs: [0], navigation: true },
  // Script injection
  'document.createElement': { type: 'XSS', taintedArgs: [0], checkValue: 'script' },
  // Fetch with tainted URL (SSRF-like in browser context, but mainly for data exfil)
};

// Pre-computed method-name → entries map for O(1) lookup in checkCallSink
const CALL_SINKS_BY_METHOD = new Map();
for (const [pattern, info] of Object.entries(CALL_SINKS)) {
  const parts = pattern.split('.');
  const method = parts[parts.length - 1];
  if (!CALL_SINKS_BY_METHOD.has(method)) CALL_SINKS_BY_METHOD.set(method, []);
  CALL_SINKS_BY_METHOD.get(method).push({ pattern, info });
}

// ── SANITIZERS: functions that neutralize taint ──
export const SANITIZERS = new Set([
  'DOMPurify.sanitize',
  'dompurify.sanitize',
  'sanitizeHtml',
  'escapeHtml',
  'escape',
  'encodeURIComponent',
  'encodeURI',
  'parseInt',
  'parseFloat',
  'Number',
  'Boolean',
  'Math.floor',
  'Math.ceil',
  'Math.round',
  'Math.abs',
  'Math.max',
  'Math.min',
  'Math.pow',
  'Math.sqrt',
  'Math.log',
  'Number.isNaN',
  'Number.isFinite',
  'Number.isInteger',
  'Number.isSafeInteger',
  'isNaN',
  'isFinite',
  'Array.isArray',
]);

// ── Helpers to match AST nodes against these definitions ──

// Resolve a MemberExpression or Identifier to a dot-path string
export function nodeToString(node) {
  if (!node) return null;
  // Iterative: walk MemberExpression chain leftward, collect parts, reverse and join
  const parts = [];
  let cur = node;
  while (cur) {
    if (cur.type === 'Identifier') { parts.push(cur.name); break; }
    if (cur.type === 'ThisExpression') { parts.push('this'); break; }
    if ((cur.type === 'MemberExpression' || cur.type === 'OptionalMemberExpression') && !cur.computed) {
      const prop = cur.property.name || cur.property.value || cur.property.id?.name;
      if (!prop) return null;
      parts.push(prop);
      cur = cur.object;
      continue;
    }
    if ((cur.type === 'MemberExpression' || cur.type === 'OptionalMemberExpression') && cur.computed && cur.property.type === 'StringLiteral') {
      parts.push(cur.property.value);
      cur = cur.object;
      continue;
    }
    return null;
  }
  parts.reverse();
  return parts.join('.');
}

// Check if a node is a taint source and return its label
export function checkMemberSource(node) {
  const str = nodeToString(node);
  if (!str) return null;
  return MEMBER_SOURCES[str] || null;
}

// Check if a call expression is a known source
export function checkCallSource(calleeStr) {
  return CALL_SOURCES[calleeStr] || null;
}

// Check if a call expression is a sink, return sink info
// Sinks that should only match as global/window calls, not arbitrary method names
const GLOBAL_ONLY_SINKS = new Set(['setTimeout', 'setInterval', 'eval', 'Function']);
// Methods that only match on location objects (not String.replace, Object.assign, etc.)
const LOCATION_ONLY_SINKS = new Set(['replace', 'assign']);

// Strip scope prefix from a key: "3:eval" → "eval", "global:document.write" → "document.write"
function _stripScope(key) {
  if (!key) return key;
  const colon = key.indexOf(':');
  if (colon === -1) return key;
  const prefix = key.slice(0, colon);
  // Scope prefixes are numeric UIDs or "global"
  if (prefix === 'global' || /^\d+$/.test(prefix)) return key.slice(colon + 1);
  // Not a scope prefix (e.g., "getter:obj.prop") — return as-is
  return key;
}

export function checkCallSink(calleeStr, methodName) {
  // Strip scope qualification for sink matching
  const bareCallee = _stripScope(calleeStr);
  // Direct match
  if (CALL_SINKS[bareCallee]) return CALL_SINKS[bareCallee];
  // Method name match via pre-computed map
  const entries = CALL_SINKS_BY_METHOD.get(methodName);
  if (!entries) return null;
  for (const { info } of entries) {
    // For global-only sinks, only match if called as global or on window
    if (GLOBAL_ONLY_SINKS.has(methodName)) {
      if (!bareCallee || bareCallee === methodName ||
          bareCallee === `window.${methodName}` || bareCallee === `globalThis.${methodName}` ||
          bareCallee === `self.${methodName}` || bareCallee === `this.${methodName}`) {
        return info;
      }
      continue;
    }
    // For location-only sinks, only match on location-like objects
    if (LOCATION_ONLY_SINKS.has(methodName)) {
      if (bareCallee && (bareCallee.includes('location') || bareCallee.includes('Location'))) {
        return info;
      }
      continue;
    }
    return info;
  }
  return null;
}

// Check if an assignment target is a sink
export function checkAssignmentSink(leftStr, propName) {
  if (ASSIGNMENT_SINKS[propName]) return ASSIGNMENT_SINKS[propName];
  if (ASSIGNMENT_SINKS[leftStr]) return ASSIGNMENT_SINKS[leftStr];
  return null;
}

// Check if callee is a sanitizer
export function isSanitizer(calleeStr, methodName) {
  const bareCallee = _stripScope(calleeStr);
  if (SANITIZERS.has(bareCallee)) return true;
  if (SANITIZERS.has(methodName)) return true;
  return false;
}

// Check if callee is a passthrough (propagates taint from args to return)
export function isPassthrough(calleeStr) {
  const info = CALL_SOURCES[calleeStr];
  return info === 'passthrough';
}
