#!/usr/bin/env node
/**
 * Parse ALL Chromium Blink IDL files to extract:
 * - Interface definitions with inheritance
 * - Mixin includes
 * - Attribute types (especially TrustedHTML, TrustedScript, TrustedScriptURL, [URL])
 * - Method signatures
 *
 * Output: JSON mapping of every JS-accessible property/method with its sink classification.
 * No hardcoding — classification is derived purely from IDL type annotations.
 */

import { readFileSync, writeFileSync, readdirSync, statSync } from 'fs';
import { join, basename } from 'path';

const CHROMIUM_DIR = process.argv[2] || 'd:/webappsec/chromium';
const IDL_ROOT = join(CHROMIUM_DIR, 'third_party/blink/renderer');
const OUTPUT = process.argv[3] || 'd:/webappsec/src/worker/chromium-sink-data.json';

// ═══════════════════════════════════════════
// Find all IDL files
// ═══════════════════════════════════════════

function findIDLFiles(dir) {
  const results = [];
  try {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        results.push(...findIDLFiles(full));
      } else if (entry.name.endsWith('.idl')) {
        results.push(full);
      }
    }
  } catch {}
  return results;
}

// ═══════════════════════════════════════════
// IDL Parser — extracts structure from IDL text
// ═══════════════════════════════════════════

function stripComments(text) {
  // Remove /* */ and // comments
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
}

function parseExtendedAttributes(text) {
  // Parse [Attr1, Attr2=Value, Attr3] into a map
  const attrs = {};
  if (!text) return attrs;
  // Simple tokenization — split on commas but respect nested parens/quotes
  let depth = 0;
  let current = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '(' || ch === '[') depth++;
    else if (ch === ')' || ch === ']') depth--;
    else if (ch === ',' && depth === 0) {
      parseOneAttr(current.trim(), attrs);
      current = '';
      continue;
    }
    current += ch;
  }
  if (current.trim()) parseOneAttr(current.trim(), attrs);
  return attrs;
}

function parseOneAttr(s, attrs) {
  const eq = s.indexOf('=');
  if (eq === -1) {
    attrs[s] = true;
  } else {
    attrs[s.slice(0, eq).trim()] = s.slice(eq + 1).trim();
  }
}

function parseIDL(text, filePath) {
  text = stripComments(text);

  const interfaces = [];
  const mixins = [];
  const includes = [];

  // Match interface/mixin definitions with optional extended attributes block
  // Pattern: [ExtAttrs] interface Name : Parent { ... };
  // Also: interface mixin Name { ... };
  // Also: partial interface Name { ... };

  // Extract includes statements: InterfaceName includes MixinName;
  const includesRe = /(\w+)\s+includes\s+(\w+)\s*;/g;
  let m;
  while ((m = includesRe.exec(text)) !== null) {
    includes.push({ target: m[1], mixin: m[2] });
  }

  // Extract interface/mixin blocks
  // Look for [ExtAttrs] followed by interface/partial interface/interface mixin
  const blockRe = /(?:\[\s*([\s\S]*?)\]\s*)?(partial\s+)?interface\s+(mixin\s+)?(\w+)(?:\s*:\s*(\w+))?\s*\{([\s\S]*?)\}\s*;/g;
  while ((m = blockRe.exec(text)) !== null) {
    const extAttrs = parseExtendedAttributes(m[1] || '');
    const isPartial = !!m[2];
    const isMixin = !!m[3];
    const name = m[4];
    const parent = m[5] || null;
    const body = m[6];

    const members = parseMembers(body);

    const entry = {
      name,
      parent,
      extAttrs,
      members,
      isPartial,
      file: filePath,
    };

    if (isMixin) {
      mixins.push(entry);
    } else {
      interfaces.push(entry);
    }
  }

  return { interfaces, mixins, includes };
}

function parseMembers(body) {
  const members = [];

  // Split on semicolons (respecting nesting)
  const statements = [];
  let depth = 0;
  let current = '';
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    else if (ch === ';' && depth === 0) {
      statements.push(current.trim());
      current = '';
      continue;
    }
    current += ch;
  }
  if (current.trim()) statements.push(current.trim());

  for (const stmt of statements) {
    if (!stmt) continue;

    // Extract extended attributes
    let rest = stmt;
    let extAttrs = {};
    const extMatch = stmt.match(/^\[\s*([\s\S]*?)\]\s*([\s\S]*)$/);
    if (extMatch) {
      extAttrs = parseExtendedAttributes(extMatch[1]);
      rest = extMatch[2].trim();
    }

    // Skip constructors
    if (rest.startsWith('constructor')) continue;

    // Attribute: [readonly] attribute Type name
    const attrMatch = rest.match(/^(readonly\s+)?attribute\s+([\s\S]+?)\s+(\w+)$/);
    if (attrMatch) {
      members.push({
        kind: 'attribute',
        readonly: !!attrMatch[1],
        type: attrMatch[2].trim(),
        name: attrMatch[3],
        extAttrs,
      });
      continue;
    }

    // Method: ReturnType name(params)
    const methodMatch = rest.match(/^(static\s+)?([\s\S]+?)\s+(\w+)\s*\(([\s\S]*)\)$/);
    if (methodMatch) {
      members.push({
        kind: 'method',
        isStatic: !!methodMatch[1],
        returnType: methodMatch[2].trim(),
        name: methodMatch[3],
        params: methodMatch[4].trim(),
        extAttrs,
      });
      continue;
    }
  }

  return members;
}

// ═══════════════════════════════════════════
// Resolve mixins and inheritance
// ═══════════════════════════════════════════

function resolveAll(parsed) {
  // Collect all interfaces and mixins by name
  const ifaceMap = new Map(); // name → merged interface
  const mixinMap = new Map(); // name → merged mixin

  for (const { interfaces, mixins } of parsed) {
    for (const iface of interfaces) {
      if (ifaceMap.has(iface.name)) {
        // Partial interface — merge members
        const existing = ifaceMap.get(iface.name);
        existing.members.push(...iface.members);
        if (iface.parent && !existing.parent) existing.parent = iface.parent;
      } else {
        ifaceMap.set(iface.name, { ...iface });
      }
    }
    for (const mixin of mixins) {
      if (mixinMap.has(mixin.name)) {
        mixinMap.get(mixin.name).members.push(...mixin.members);
      } else {
        mixinMap.set(mixin.name, { ...mixin });
      }
    }
  }

  // Apply includes (mixin members → interface)
  for (const { interfaces: _, mixins: __, includes } of parsed) {
    for (const inc of includes) {
      const iface = ifaceMap.get(inc.target);
      const mixin = mixinMap.get(inc.mixin);
      if (iface && mixin) {
        iface.members.push(...mixin.members);
      }
    }
  }

  // Resolve inheritance — walk parent chain, collect all members
  function getFullMembers(name, visited = new Set()) {
    if (visited.has(name)) return [];
    visited.add(name);
    const iface = ifaceMap.get(name);
    if (!iface) return [];
    const parentMembers = iface.parent ? getFullMembers(iface.parent, visited) : [];
    return [...parentMembers, ...iface.members];
  }

  return { ifaceMap, getFullMembers };
}

// ═══════════════════════════════════════════
// Classify sink type from IDL type annotation
// ═══════════════════════════════════════════

function classifySink(member) {
  const type = member.type || member.returnType || '';
  const extAttrs = member.extAttrs || {};

  // TrustedTypes — authoritative injection sink classification
  // Check TrustedScriptURL BEFORE TrustedScript (substring match order)
  if (type.includes('TrustedScriptURL')) return 'script-url';
  if (type.includes('TrustedHTML')) return 'html';
  if (type.includes('TrustedScript')) return 'script';

  // [URL] extended attribute — URL property (navigation or resource, needs further classification)
  if (extAttrs.URL || extAttrs.url) return 'url';

  return null;
}

// ═══════════════════════════════════════════
// Interface name → tag name mapping
// ═══════════════════════════════════════════

function interfaceToTagName(name) {
  // HTMLFooElement → foo
  // SVGFooElement → svg:foo
  const htmlMatch = name.match(/^HTML(.+)Element$/);
  if (htmlMatch) {
    // Special cases where name doesn't match tag
    const map = {
      'Anchor': 'a',
      'DList': 'dl',
      'Image': 'img',
      'OList': 'ol',
      'Paragraph': 'p',
      'TableCaption': 'caption',
      'TableCell': 'td',
      'TableCol': 'col',
      'TableRow': 'tr',
      'TableSection': 'tbody',
      'UList': 'ul',
      'Mod': 'ins', // also del
      'Quote': 'blockquote', // also q
      'Heading': 'h1',
      'Directory': 'dir',
      'Media': null, // abstract base
      'FormControlsCollection': null,
      'OptionsCollection': null,
    };
    const key = htmlMatch[1];
    if (key in map) return map[key];
    return key.toLowerCase();
  }
  return null;
}

// ═══════════════════════════════════════════
// Main
// ═══════════════════════════════════════════

console.log('Scanning IDL files...');
const idlFiles = findIDLFiles(IDL_ROOT);
console.log(`Found ${idlFiles.length} IDL files`);

const parsed = [];
for (const file of idlFiles) {
  try {
    const text = readFileSync(file, 'utf8');
    parsed.push(parseIDL(text, file));
  } catch (e) {
    // Skip unreadable files
  }
}

const { ifaceMap, getFullMembers } = resolveAll(parsed);
console.log(`Resolved ${ifaceMap.size} interfaces`);

// Build sink data
const sinkData = {
  // Per-interface sink properties
  interfaces: {},
  // Global sinks (Window, Document, Location, etc.)
  globals: {},
  // Metadata
  meta: {
    generated: new Date().toISOString(),
    idlFileCount: idlFiles.length,
    interfaceCount: ifaceMap.size,
  },
};

for (const [name, iface] of ifaceMap) {
  const allMembers = getFullMembers(name);
  const sinks = [];
  const members = [];

  for (const member of allMembers) {
    const sinkType = classifySink(member);
    if (sinkType) {
      sinks.push({
        name: member.name,
        kind: member.kind,
        sinkType,
        type: member.type || member.returnType || '',
        readonly: member.readonly || false,
      });
    }
    // Store ALL members with their types for the abstract value system.
    // This provides return types, property types, and method signatures
    // for complete type tracking through the analysis.
    const memberEntry = { name: member.name, kind: member.kind };
    if (member.type) memberEntry.type = member.type;
    if (member.returnType) memberEntry.returnType = member.returnType;
    if (member.params !== undefined) memberEntry.params = member.params;
    if (member.readonly) memberEntry.readonly = true;
    if (member.isStatic) memberEntry.isStatic = true;
    if (sinkType) memberEntry.sinkType = sinkType;
    members.push(memberEntry);
  }

  if (sinks.length === 0 && members.length === 0) continue;

  const tagName = interfaceToTagName(name);
  const entry = {
    interface: name,
    parent: iface.parent || null,
    tag: tagName,
    sinks,
    members,
  };

  // Classify: element interfaces go to interfaces, others to globals
  if (name.match(/^(Window|Document|Location|Navigation|Worker|SharedWorker|ServiceWorker|DOMParser|Range|ShadowRoot|History|XMLHttpRequest|EventSource|WebSocket|Blob|URL|DedicatedWorkerGlobalScope|SharedWorkerGlobalScope|ServiceWorkerGlobalScope|Navigator|Crypto|SubtleCrypto)/)) {
    sinkData.globals[name] = entry;
  } else {
    sinkData.interfaces[name] = entry;
  }
}

// ═══════════════════════════════════════════
// Extract DOM-producing properties: properties whose return type is an Element subtype
// e.g., Document.body → HTMLElement, Document.head → HTMLHeadElement
// ═══════════════════════════════════════════

// Build set of all known Element subtypes from the interface hierarchy
const elementSubtypes = new Set();
for (const [name] of ifaceMap) {
  // Walk base classes to see if Element is an ancestor
  let cur = name;
  const visited = new Set();
  while (cur && !visited.has(cur)) {
    visited.add(cur);
    if (cur === 'Element' || cur === 'Node') {
      elementSubtypes.add(name);
      break;
    }
    cur = ifaceMap.get(cur)?.parent;
  }
}

sinkData.domProperties = {};

for (const [ifaceName, iface] of ifaceMap) {
  const allMembers = getFullMembers(ifaceName);
  for (const member of allMembers) {
    if (member.kind !== 'attribute') continue;
    const rawType = member.type || '';
    // Extract the type name, stripping nullable (?), sequence, etc.
    const typeMatch = rawType.match(/(?:HTML\w+|SVG\w+|Element|Node|Document\w*|ShadowRoot)/);
    if (!typeMatch) continue;
    const returnTypeName = typeMatch[0];
    if (!elementSubtypes.has(returnTypeName) && returnTypeName !== 'Element' && returnTypeName !== 'Node') continue;

    // This property returns a DOM element — record it
    const tag = interfaceToTagName(returnTypeName);
    if (!sinkData.domProperties[ifaceName]) sinkData.domProperties[ifaceName] = {};
    sinkData.domProperties[ifaceName][member.name] = {
      returnType: returnTypeName,
      tag: tag,  // null if generic Element/Node
      isDomAttached: true,
    };
  }
}

const domPropCount = Object.values(sinkData.domProperties).reduce((s, e) => s + Object.keys(e).length, 0);
console.log(`\nDOM-producing properties: ${domPropCount} across ${Object.keys(sinkData.domProperties).length} interfaces`);
for (const [iface, props] of Object.entries(sinkData.domProperties)) {
  for (const [prop, info] of Object.entries(props)) {
    if (info.tag) console.log(`  ${iface}.${prop} → <${info.tag}> (${info.returnType})`);
  }
}

// Summary stats
const totalSinks = Object.values(sinkData.interfaces).reduce((s, e) => s + e.sinks.length, 0)
  + Object.values(sinkData.globals).reduce((s, e) => s + e.sinks.length, 0);

console.log(`\nSink classification results:`);
console.log(`  Element interfaces with sinks: ${Object.keys(sinkData.interfaces).length}`);
console.log(`  Global/API interfaces with sinks: ${Object.keys(sinkData.globals).length}`);
console.log(`  Total sink properties/methods: ${totalSinks}`);

// Print summary
console.log(`\n--- Element sinks ---`);
for (const [name, entry] of Object.entries(sinkData.interfaces)) {
  const tag = entry.tag ? `<${entry.tag}>` : name;
  for (const sink of entry.sinks) {
    console.log(`  ${tag}.${sink.name} → ${sink.sinkType} (${sink.type})`);
  }
}

console.log(`\n--- Global/API sinks ---`);
for (const [name, entry] of Object.entries(sinkData.globals)) {
  for (const sink of entry.sinks) {
    console.log(`  ${name}.${sink.name} → ${sink.sinkType} (${sink.type})`);
  }
}

// ═══════════════════════════════════════════
// Build type index: Interface.member → {type, returnType, kind}
// This provides the taint engine with complete type information for
// ALL browser API properties and methods (not just sinks).
// ═══════════════════════════════════════════

sinkData.typeIndex = {};
for (const [name, iface] of ifaceMap) {
  const allMembers = getFullMembers(name);
  const typeEntry = {};
  for (const member of allMembers) {
    const key = member.name;
    if (!key) continue;
    const info = { kind: member.kind };
    if (member.type) info.type = member.type;
    if (member.returnType) info.returnType = member.returnType;
    if (member.params !== undefined) info.params = member.params;
    if (member.readonly) info.readonly = true;
    if (member.isStatic) info.isStatic = true;
    typeEntry[key] = info;
  }
  if (Object.keys(typeEntry).length > 0) {
    sinkData.typeIndex[name] = typeEntry;
  }
}

// ═══════════════════════════════════════════
// Build prototype chain: Interface → parent chain
// Enables the taint engine to resolve inherited methods/properties.
// ═══════════════════════════════════════════

sinkData.prototypeChain = {};
for (const [name, iface] of ifaceMap) {
  if (iface.parent) {
    sinkData.prototypeChain[name] = iface.parent;
  }
}

// ═══════════════════════════════════════════
// Classify pure functions: deterministic methods that can be evaluated at analysis time.
// Math.*, String.prototype.*, Array.prototype methods that don't modify external state.
// ═══════════════════════════════════════════

const PURE_INTERFACES = new Set(['Math', 'Number', 'String', 'RegExp', 'JSON', 'Date', 'Array', 'Object',
  'Map', 'Set', 'WeakMap', 'WeakSet', 'Promise', 'Symbol', 'BigInt', 'Intl', 'ArrayBuffer',
  'DataView', 'Float32Array', 'Float64Array', 'Int8Array', 'Int16Array', 'Int32Array',
  'Uint8Array', 'Uint16Array', 'Uint32Array', 'Uint8ClampedArray']);

sinkData.pureFunctions = {};
for (const name of PURE_INTERFACES) {
  const iface = ifaceMap.get(name);
  if (!iface) continue;
  const methods = [];
  for (const member of iface.members) {
    if (member.kind === 'method' && member.name) {
      methods.push(member.name);
    }
  }
  if (methods.length > 0) sinkData.pureFunctions[name] = methods;
}

const totalMembers = Object.values(sinkData.typeIndex).reduce((s, e) => s + Object.keys(e).length, 0);
console.log(`\nType index: ${totalMembers} members across ${Object.keys(sinkData.typeIndex).length} interfaces`);
console.log(`Prototype chains: ${Object.keys(sinkData.prototypeChain).length}`);
console.log(`Pure function interfaces: ${Object.keys(sinkData.pureFunctions).length}`);

writeFileSync(OUTPUT, JSON.stringify(sinkData, null, 2));
console.log(`\nWritten to ${OUTPUT}`);
