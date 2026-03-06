/* sources-sinks.js — Defines taint sources, dangerous sinks, and sanitizers.
   Used by the taint engine to label data flow endpoints. */

// ── SOURCES: expressions that return attacker-controlled data ──

// Member expression sources: object.property patterns
export const MEMBER_SOURCES = {
  // location properties
  'location.href': 'url.location.href',
  'location.hash': 'url.location.hash',
  'location.search': 'url.location.search',
  'location.pathname': 'url.location.pathname',
  'location.host': 'url.location.host',
  'location.hostname': 'url.location.hostname',
  'window.location.href': 'url.location.href',
  'window.location.hash': 'url.location.hash',
  'window.location.search': 'url.location.search',
  'window.location.pathname': 'url.location.pathname',
  // document.location aliases
  'document.location.href': 'url.location.href',
  'document.location.hash': 'url.location.hash',
  'document.location.search': 'url.location.search',
  'document.location.pathname': 'url.location.pathname',
  // document properties
  'document.URL': 'url.document.URL',
  'document.documentURI': 'url.document.documentURI',
  'document.referrer': 'url.document.referrer',
  'document.cookie': 'cookie',
  'document.baseURI': 'url.document.baseURI',
  'window.document.cookie': 'cookie',
  // globalThis aliases (same as window/location)
  'globalThis.location.href': 'url.location.href',
  'globalThis.location.hash': 'url.location.hash',
  'globalThis.location.search': 'url.location.search',
  'globalThis.location.pathname': 'url.location.pathname',
  // self aliases (workers, but also valid in window context)
  'self.location.href': 'url.location.href',
  'self.location.hash': 'url.location.hash',
  'self.location.search': 'url.location.search',
  'self.location.pathname': 'url.location.pathname',
  // window
  'window.name': 'window.name',
};

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
  'JSON.parse': 'passthrough',
  'fetch': 'passthrough',       // tainted URL → tainted response for .then chains
  'String': 'passthrough',
  'JSON.stringify': 'passthrough',
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
  // Navigation sinks: XSS if javascript: possible, Open Redirect if scheme-checked
  'location.href': { type: 'XSS', argIndex: 'rhs', navigation: true },
  'window.location.href': { type: 'XSS', argIndex: 'rhs', navigation: true },
  'document.location.href': { type: 'XSS', argIndex: 'rhs', navigation: true },
  'document.location': { type: 'XSS', argIndex: 'rhs', navigation: true },
  'window.location': { type: 'XSS', argIndex: 'rhs', navigation: true },
  'location': { type: 'XSS', argIndex: 'rhs', navigation: true },
  // Domain manipulation
  'document.domain': { type: 'XSS', argIndex: 'rhs' },
};

// Call sinks: function(taintedArg)
// taintedArgs: which argument indices must be tainted to trigger
export const CALL_SINKS = {
  'eval': { type: 'XSS', taintedArgs: [0] },
  'Function': { type: 'XSS', taintedArgs: [0] }, // new Function(code)
  'setTimeout': { type: 'XSS', taintedArgs: [0], stringOnly: true },
  'setInterval': { type: 'XSS', taintedArgs: [0], stringOnly: true },
  'document.write': { type: 'XSS', taintedArgs: [0] },
  'document.writeln': { type: 'XSS', taintedArgs: [0] },
  'Element.prototype.insertAdjacentHTML': { type: 'XSS', taintedArgs: [1] },
  'DOMParser.prototype.parseFromString': { type: 'XSS', taintedArgs: [0] },
  'Range.prototype.createContextualFragment': { type: 'XSS', taintedArgs: [0] },
  // jQuery
  '$.html': { type: 'XSS', taintedArgs: [0] },
  'jQuery.html': { type: 'XSS', taintedArgs: [0] },
  '$.append': { type: 'XSS', taintedArgs: [0] },
  'jQuery.append': { type: 'XSS', taintedArgs: [0] },
  '$.prepend': { type: 'XSS', taintedArgs: [0] },
  // Navigation sinks: XSS if javascript: possible, Open Redirect if scheme-checked
  'location.assign': { type: 'XSS', taintedArgs: [0], navigation: true },
  'location.replace': { type: 'XSS', taintedArgs: [0], navigation: true },
  'window.open': { type: 'XSS', taintedArgs: [0], navigation: true },
  'window.location.assign': { type: 'XSS', taintedArgs: [0], navigation: true },
  'window.location.replace': { type: 'XSS', taintedArgs: [0], navigation: true },
  // Script injection
  'document.createElement': { type: 'Script Injection', taintedArgs: [0], checkValue: 'script' },
  // Fetch with tainted URL (SSRF-like in browser context, but mainly for data exfil)
};

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
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'ThisExpression') return 'this';
  if ((node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') && !node.computed) {
    const obj = nodeToString(node.object);
    const prop = node.property.name || node.property.value;
    if (obj && prop) return `${obj}.${prop}`;
  }
  if ((node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') && node.computed && node.property.type === 'StringLiteral') {
    const obj = nodeToString(node.object);
    if (obj) return `${obj}.${node.property.value}`;
  }
  return null;
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
export function checkCallSink(calleeStr, methodName) {
  // Direct match
  if (CALL_SINKS[calleeStr]) return CALL_SINKS[calleeStr];
  // Method name match (e.g., .insertAdjacentHTML)
  for (const [pattern, info] of Object.entries(CALL_SINKS)) {
    const parts = pattern.split('.');
    const method = parts[parts.length - 1];
    if (method === methodName) return info;
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
  if (SANITIZERS.has(calleeStr)) return true;
  if (SANITIZERS.has(methodName)) return true;
  return false;
}

// Check if callee is a passthrough (propagates taint from args to return)
export function isPassthrough(calleeStr) {
  const info = CALL_SOURCES[calleeStr];
  return info === 'passthrough';
}
