/**
 * ECMAScript built-in type data for the abstract value system.
 * Provides return types, property types, and purity classification
 * for all standard JS built-in objects and their methods.
 *
 * This data enables:
 * - Type tracking through transform chains (String.split → Array<string>)
 * - Concrete evaluation of pure functions (Math.round(3.5) → 4)
 * - PoC generation that reverses transforms accurately
 *
 * Source: ECMA-262 specification (stable — these don't change between engines)
 * NOT auto-generated — maintained manually as the spec is stable.
 */

// Return type for a method call: Interface.method → type string
// Types use JS typeof values: 'string', 'number', 'boolean', 'object', 'function', 'undefined'
// Special types: 'array' (Array instance), 'regexp' (RegExp instance)
export const METHOD_RETURN_TYPES = {
  // ── Math (all pure, all return number) ──
  'Math.abs': 'number',
  'Math.acos': 'number',
  'Math.acosh': 'number',
  'Math.asin': 'number',
  'Math.asinh': 'number',
  'Math.atan': 'number',
  'Math.atan2': 'number',
  'Math.atanh': 'number',
  'Math.cbrt': 'number',
  'Math.ceil': 'number',
  'Math.clz32': 'number',
  'Math.cos': 'number',
  'Math.cosh': 'number',
  'Math.exp': 'number',
  'Math.expm1': 'number',
  'Math.floor': 'number',
  'Math.fround': 'number',
  'Math.hypot': 'number',
  'Math.imul': 'number',
  'Math.log': 'number',
  'Math.log10': 'number',
  'Math.log1p': 'number',
  'Math.log2': 'number',
  'Math.max': 'number',
  'Math.min': 'number',
  'Math.pow': 'number',
  'Math.random': 'number',
  'Math.round': 'number',
  'Math.sign': 'number',
  'Math.sin': 'number',
  'Math.sinh': 'number',
  'Math.sqrt': 'number',
  'Math.tan': 'number',
  'Math.tanh': 'number',
  'Math.trunc': 'number',

  // ── Number ──
  'Number.isFinite': 'boolean',
  'Number.isInteger': 'boolean',
  'Number.isNaN': 'boolean',
  'Number.isSafeInteger': 'boolean',
  'Number.parseFloat': 'number',
  'Number.parseInt': 'number',
  'Number.prototype.toExponential': 'string',
  'Number.prototype.toFixed': 'string',
  'Number.prototype.toLocaleString': 'string',
  'Number.prototype.toPrecision': 'string',
  'Number.prototype.toString': 'string',
  'Number.prototype.valueOf': 'number',

  // ── String ──
  'String.fromCharCode': 'string',
  'String.fromCodePoint': 'string',
  'String.raw': 'string',
  'String.prototype.at': 'string',
  'String.prototype.charAt': 'string',
  'String.prototype.charCodeAt': 'number',
  'String.prototype.codePointAt': 'number',
  'String.prototype.concat': 'string',
  'String.prototype.endsWith': 'boolean',
  'String.prototype.includes': 'boolean',
  'String.prototype.indexOf': 'number',
  'String.prototype.lastIndexOf': 'number',
  'String.prototype.localeCompare': 'number',
  'String.prototype.match': 'object',    // Array or null
  'String.prototype.matchAll': 'object',  // iterator
  'String.prototype.normalize': 'string',
  'String.prototype.padEnd': 'string',
  'String.prototype.padStart': 'string',
  'String.prototype.repeat': 'string',
  'String.prototype.replace': 'string',
  'String.prototype.replaceAll': 'string',
  'String.prototype.search': 'number',
  'String.prototype.slice': 'string',
  'String.prototype.split': 'array',
  'String.prototype.startsWith': 'boolean',
  'String.prototype.substring': 'string',
  'String.prototype.toLocaleLowerCase': 'string',
  'String.prototype.toLocaleUpperCase': 'string',
  'String.prototype.toLowerCase': 'string',
  'String.prototype.toString': 'string',
  'String.prototype.toUpperCase': 'string',
  'String.prototype.trim': 'string',
  'String.prototype.trimEnd': 'string',
  'String.prototype.trimStart': 'string',
  'String.prototype.valueOf': 'string',

  // ── Array ──
  'Array.from': 'array',
  'Array.isArray': 'boolean',
  'Array.of': 'array',
  'Array.prototype.at': 'object',     // element type unknown
  'Array.prototype.concat': 'array',
  'Array.prototype.copyWithin': 'array',
  'Array.prototype.entries': 'object',
  'Array.prototype.every': 'boolean',
  'Array.prototype.fill': 'array',
  'Array.prototype.filter': 'array',
  'Array.prototype.find': 'object',
  'Array.prototype.findIndex': 'number',
  'Array.prototype.findLast': 'object',
  'Array.prototype.findLastIndex': 'number',
  'Array.prototype.flat': 'array',
  'Array.prototype.flatMap': 'array',
  'Array.prototype.forEach': 'undefined',
  'Array.prototype.includes': 'boolean',
  'Array.prototype.indexOf': 'number',
  'Array.prototype.join': 'string',
  'Array.prototype.keys': 'object',
  'Array.prototype.lastIndexOf': 'number',
  'Array.prototype.map': 'array',
  'Array.prototype.pop': 'object',
  'Array.prototype.push': 'number',    // returns new length
  'Array.prototype.reduce': 'object',
  'Array.prototype.reduceRight': 'object',
  'Array.prototype.reverse': 'array',
  'Array.prototype.shift': 'object',
  'Array.prototype.slice': 'array',
  'Array.prototype.some': 'boolean',
  'Array.prototype.sort': 'array',
  'Array.prototype.splice': 'array',
  'Array.prototype.toLocaleString': 'string',
  'Array.prototype.toReversed': 'array',
  'Array.prototype.toSorted': 'array',
  'Array.prototype.toSpliced': 'array',
  'Array.prototype.toString': 'string',
  'Array.prototype.unshift': 'number',
  'Array.prototype.values': 'object',
  'Array.prototype.with': 'array',

  // ── Object ──
  'Object.assign': 'object',
  'Object.create': 'object',
  'Object.defineProperties': 'object',
  'Object.defineProperty': 'object',
  'Object.entries': 'array',
  'Object.freeze': 'object',
  'Object.fromEntries': 'object',
  'Object.getOwnPropertyDescriptor': 'object',
  'Object.getOwnPropertyDescriptors': 'object',
  'Object.getOwnPropertyNames': 'array',
  'Object.getOwnPropertySymbols': 'array',
  'Object.getPrototypeOf': 'object',
  'Object.groupBy': 'object',
  'Object.hasOwn': 'boolean',
  'Object.is': 'boolean',
  'Object.isExtensible': 'boolean',
  'Object.isFrozen': 'boolean',
  'Object.isSealed': 'boolean',
  'Object.keys': 'array',
  'Object.preventExtensions': 'object',
  'Object.seal': 'object',
  'Object.setPrototypeOf': 'object',
  'Object.values': 'array',
  'Object.prototype.hasOwnProperty': 'boolean',
  'Object.prototype.isPrototypeOf': 'boolean',
  'Object.prototype.propertyIsEnumerable': 'boolean',
  'Object.prototype.toLocaleString': 'string',
  'Object.prototype.toString': 'string',
  'Object.prototype.valueOf': 'object',

  // ── JSON ──
  'JSON.parse': 'object',    // can also be string/number/boolean/null but typically object
  'JSON.stringify': 'string',

  // ── RegExp ──
  'RegExp.prototype.exec': 'object',   // Array or null
  'RegExp.prototype.test': 'boolean',
  'RegExp.prototype.toString': 'string',

  // ── Date ──
  'Date.now': 'number',
  'Date.parse': 'number',
  'Date.UTC': 'number',
  'Date.prototype.getDate': 'number',
  'Date.prototype.getDay': 'number',
  'Date.prototype.getFullYear': 'number',
  'Date.prototype.getHours': 'number',
  'Date.prototype.getMilliseconds': 'number',
  'Date.prototype.getMinutes': 'number',
  'Date.prototype.getMonth': 'number',
  'Date.prototype.getSeconds': 'number',
  'Date.prototype.getTime': 'number',
  'Date.prototype.getTimezoneOffset': 'number',
  'Date.prototype.toISOString': 'string',
  'Date.prototype.toJSON': 'string',
  'Date.prototype.toLocaleDateString': 'string',
  'Date.prototype.toLocaleString': 'string',
  'Date.prototype.toLocaleTimeString': 'string',
  'Date.prototype.toString': 'string',
  'Date.prototype.toTimeString': 'string',
  'Date.prototype.toUTCString': 'string',
  'Date.prototype.valueOf': 'number',

  // ── Promise ──
  'Promise.all': 'object',
  'Promise.allSettled': 'object',
  'Promise.any': 'object',
  'Promise.race': 'object',
  'Promise.reject': 'object',
  'Promise.resolve': 'object',
  'Promise.prototype.catch': 'object',
  'Promise.prototype.finally': 'object',
  'Promise.prototype.then': 'object',

  // ── Global functions ──
  'parseInt': 'number',
  'parseFloat': 'number',
  'isNaN': 'boolean',
  'isFinite': 'boolean',
  'encodeURI': 'string',
  'encodeURIComponent': 'string',
  'decodeURI': 'string',
  'decodeURIComponent': 'string',
  'btoa': 'string',
  'atob': 'string',

  // ── Reflect ──
  'Reflect.apply': 'object',
  'Reflect.construct': 'object',
  'Reflect.defineProperty': 'boolean',
  'Reflect.deleteProperty': 'boolean',
  'Reflect.get': 'object',
  'Reflect.getOwnPropertyDescriptor': 'object',
  'Reflect.getPrototypeOf': 'object',
  'Reflect.has': 'boolean',
  'Reflect.isExtensible': 'boolean',
  'Reflect.ownKeys': 'array',
  'Reflect.preventExtensions': 'boolean',
  'Reflect.set': 'boolean',
  'Reflect.setPrototypeOf': 'boolean',

  // ── Map/Set ──
  'Map.prototype.get': 'object',
  'Map.prototype.has': 'boolean',
  'Map.prototype.set': 'object',   // returns the Map
  'Map.prototype.delete': 'boolean',
  'Map.prototype.forEach': 'undefined',
  'Map.prototype.entries': 'object',
  'Map.prototype.keys': 'object',
  'Map.prototype.values': 'object',
  'Set.prototype.has': 'boolean',
  'Set.prototype.add': 'object',   // returns the Set
  'Set.prototype.delete': 'boolean',
  'Set.prototype.forEach': 'undefined',
  'Set.prototype.entries': 'object',
  'Set.prototype.keys': 'object',
  'Set.prototype.values': 'object',

  // ── Symbol ──
  'Symbol.for': 'symbol',
  'Symbol.keyFor': 'string',
};

// Property types: Interface.property → type string
export const PROPERTY_TYPES = {
  // ── Math constants ──
  'Math.E': 'number',
  'Math.LN10': 'number',
  'Math.LN2': 'number',
  'Math.LOG10E': 'number',
  'Math.LOG2E': 'number',
  'Math.PI': 'number',
  'Math.SQRT1_2': 'number',
  'Math.SQRT2': 'number',

  // ── Number constants ──
  'Number.EPSILON': 'number',
  'Number.MAX_SAFE_INTEGER': 'number',
  'Number.MAX_VALUE': 'number',
  'Number.MIN_SAFE_INTEGER': 'number',
  'Number.MIN_VALUE': 'number',
  'Number.NaN': 'number',
  'Number.NEGATIVE_INFINITY': 'number',
  'Number.POSITIVE_INFINITY': 'number',

  // ── String.prototype ──
  'String.prototype.length': 'number',

  // ── Array.prototype ──
  'Array.prototype.length': 'number',

  // ── RegExp ──
  'RegExp.prototype.global': 'boolean',
  'RegExp.prototype.ignoreCase': 'boolean',
  'RegExp.prototype.multiline': 'boolean',
  'RegExp.prototype.source': 'string',
  'RegExp.prototype.flags': 'string',
  'RegExp.prototype.lastIndex': 'number',

  // ── Infinity, NaN, undefined ──
  'Infinity': 'number',
  'NaN': 'number',
  'undefined': 'undefined',
};

// Pure functions: can be executed at analysis time with concrete arguments.
// The engine should literally call these with the resolved arguments and use the result.
// Key: method path. Value: the actual JS function reference for execution.
export const PURE_FUNCTIONS = {
  // Math — all deterministic (except Math.random)
  'Math.abs': Math.abs,
  'Math.acos': Math.acos,
  'Math.acosh': Math.acosh,
  'Math.asin': Math.asin,
  'Math.asinh': Math.asinh,
  'Math.atan': Math.atan,
  'Math.atan2': Math.atan2,
  'Math.atanh': Math.atanh,
  'Math.cbrt': Math.cbrt,
  'Math.ceil': Math.ceil,
  'Math.clz32': Math.clz32,
  'Math.cos': Math.cos,
  'Math.cosh': Math.cosh,
  'Math.exp': Math.exp,
  'Math.expm1': Math.expm1,
  'Math.floor': Math.floor,
  'Math.fround': Math.fround,
  'Math.hypot': Math.hypot,
  'Math.imul': Math.imul,
  'Math.log': Math.log,
  'Math.log10': Math.log10,
  'Math.log1p': Math.log1p,
  'Math.log2': Math.log2,
  'Math.max': Math.max,
  'Math.min': Math.min,
  'Math.pow': Math.pow,
  'Math.round': Math.round,
  'Math.sign': Math.sign,
  'Math.sin': Math.sin,
  'Math.sinh': Math.sinh,
  'Math.sqrt': Math.sqrt,
  'Math.tan': Math.tan,
  'Math.tanh': Math.tanh,
  'Math.trunc': Math.trunc,

  // Number
  'Number.isFinite': Number.isFinite,
  'Number.isInteger': Number.isInteger,
  'Number.isNaN': Number.isNaN,
  'Number.isSafeInteger': Number.isSafeInteger,
  'Number.parseFloat': Number.parseFloat,
  'Number.parseInt': Number.parseInt,
  'parseInt': parseInt,
  'parseFloat': parseFloat,
  'isNaN': isNaN,
  'isFinite': isFinite,

  // String — pure string operations
  'String.fromCharCode': String.fromCharCode,
  'String.fromCodePoint': String.fromCodePoint,
  'encodeURI': encodeURI,
  'encodeURIComponent': encodeURIComponent,
  'decodeURI': decodeURI,
  'decodeURIComponent': decodeURIComponent,
  'btoa': typeof btoa !== 'undefined' ? btoa : null,
  'atob': typeof atob !== 'undefined' ? atob : null,

  // JSON
  'JSON.stringify': JSON.stringify,
  'JSON.parse': JSON.parse,

  // Object — pure queries
  'Object.keys': Object.keys,
  'Object.values': Object.values,
  'Object.entries': Object.entries,
  'Object.getOwnPropertyNames': Object.getOwnPropertyNames,
  'Object.is': Object.is,
  'Object.hasOwn': Object.hasOwn,
  'Array.isArray': Array.isArray,
};

// Constructor return types: new Constructor() → type
export const CONSTRUCTOR_TYPES = {
  'Array': 'array',
  'ArrayBuffer': 'object',
  'Blob': 'object',
  'DataView': 'object',
  'Date': 'object',
  'Error': 'object',
  'Float32Array': 'object',
  'Float64Array': 'object',
  'FormData': 'object',
  'Headers': 'object',
  'Int8Array': 'object',
  'Int16Array': 'object',
  'Int32Array': 'object',
  'Map': 'object',
  'Object': 'object',
  'Promise': 'object',
  'Proxy': 'object',
  'RegExp': 'object',
  'Request': 'object',
  'Response': 'object',
  'Set': 'object',
  'SharedWorker': 'object',
  'Uint8Array': 'object',
  'Uint16Array': 'object',
  'Uint32Array': 'object',
  'Uint8ClampedArray': 'object',
  'URL': 'object',
  'URLSearchParams': 'object',
  'WeakMap': 'object',
  'WeakRef': 'object',
  'WeakSet': 'object',
  'WebSocket': 'object',
  'Worker': 'object',
  'XMLHttpRequest': 'object',
};

// Taint passthrough methods: the return value carries the input's taint.
// Used by the taint engine to propagate taint through transforms.
// Key: method. Value: which argument index carries taint through (0-based), or 'this' for instance methods.
export const TAINT_PASSTHROUGHS = {
  'String.prototype.slice': 'this',
  'String.prototype.substring': 'this',
  'String.prototype.substr': 'this',
  'String.prototype.trim': 'this',
  'String.prototype.trimEnd': 'this',
  'String.prototype.trimStart': 'this',
  'String.prototype.toLowerCase': 'this',
  'String.prototype.toUpperCase': 'this',
  'String.prototype.toLocaleLowerCase': 'this',
  'String.prototype.toLocaleUpperCase': 'this',
  'String.prototype.normalize': 'this',
  'String.prototype.padEnd': 'this',
  'String.prototype.padStart': 'this',
  'String.prototype.repeat': 'this',
  'String.prototype.replace': 'this',
  'String.prototype.replaceAll': 'this',
  'String.prototype.concat': 'this',
  'String.prototype.split': 'this',     // array elements carry taint
  'Array.prototype.join': 'this',        // joins tainted elements → tainted string
  'Array.prototype.slice': 'this',
  'Array.prototype.concat': 'this',
  'Array.prototype.filter': 'this',
  'Array.prototype.map': 'this',
  'Array.prototype.flat': 'this',
  'Array.prototype.flatMap': 'this',
  'Array.prototype.reverse': 'this',
  'Array.prototype.toReversed': 'this',
  'Array.prototype.toSorted': 'this',
  'encodeURI': 0,
  'encodeURIComponent': 0,
  'decodeURI': 0,
  'decodeURIComponent': 0,
  'btoa': 0,
  'atob': 0,
  'String': 0,                           // String(tainted) → tainted string
  'JSON.parse': 0,                       // JSON.parse(tainted) → tainted object
  'JSON.stringify': 0,                   // JSON.stringify(tainted) → tainted string
};
