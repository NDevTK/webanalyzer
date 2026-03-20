#!/usr/bin/env node
/**
 * Combines Chromium IDL analysis + C++ taint analysis into a single
 * sink classification file for the taint engine.
 *
 * Input:
 *   - chromium-sink-data.json (from parse-chromium-idl.mjs)
 *   - chromium-taint-results.json (from chromium-taint.mjs)
 *
 * Output:
 *   - src/worker/sink-data.json — unified sink classification
 */

import { readFileSync, writeFileSync } from 'fs';

const idlData = JSON.parse(readFileSync('src/worker/chromium-sink-data.json', 'utf8'));
const taintData = JSON.parse(readFileSync('src/worker/chromium-taint-results.json', 'utf8'));

// ═══════════════════════════════════════════
// Step 1: Determine which classes reach navigation terminals
// ═══════════════════════════════════════════

const navClasses = new Set();
for (const path of taintData.taintPaths) {
  if (path.terminalType === 'navigation') {
    navClasses.add(path.property.split('.')[0]);
  }
}

// Propagate through known inheritance (base → children)
// This could be automated by parsing .h files but these are stable Blink base classes
const inheritance = {
  'HTMLFrameElementBase': ['HTMLIFrameElement', 'HTMLFrameElement'],
  'HTMLAnchorElementBase': ['HTMLAnchorElement', 'HTMLAreaElement'],
};
for (const [base, children] of Object.entries(inheritance)) {
  if (navClasses.has(base)) {
    for (const child of children) navClasses.add(child);
  }
}

// ═══════════════════════════════════════════
// Step 2: Build unified classification
// ═══════════════════════════════════════════

// Sink types:
//   'html'       — TrustedHTML sink (innerHTML, outerHTML, srcdoc)
//   'script'     — TrustedScript sink (textContent, innerText, script.text)
//   'script-url' — TrustedScriptURL sink (script.src, embed.src, object.data)
//   'navigation' — URL property that reaches Frame::Navigate (iframe.src, a.href)
//   'url'        — URL property that loads a resource (img.src, video.src) — not a sink

const output = {
  // Property sinks by element tag name
  // tag → { property → sinkType }
  elements: {},

  // Inherited sinks that apply to ALL elements (from Element, Node, HTMLElement)
  inherited: {},

  // Non-element API sinks (Document, ShadowRoot, etc.)
  apis: {},

  meta: {
    generated: new Date().toISOString(),
    sources: ['chromium-idl', 'chromium-cpp-taint'],
    idlInterfaces: idlData.meta.interfaceCount,
    taintPaths: taintData.taintPaths.length,
  },
};

// Base element sinks (apply to all elements via inheritance)
const BASE_INTERFACES = new Set(['Element', 'Node', 'HTMLElement', 'SVGElement']);

for (const [ifaceName, entry] of Object.entries(idlData.interfaces)) {
  const isBase = BASE_INTERFACES.has(ifaceName);
  const tagName = entry.tag;

  for (const sink of entry.sinks) {
    // Reclassify 'url' sinks using taint analysis
    let sinkType = sink.sinkType;
    if (sinkType === 'url') {
      sinkType = navClasses.has(ifaceName) ? 'navigation' : null; // null = not a sink
    }

    if (!sinkType) continue; // Skip resource-only URL properties

    // Skip readonly attributes (can't be set from JS)
    if (sink.readonly && sink.kind === 'attribute') continue;

    const sinkEntry = {
      type: sinkType,
      idlType: sink.type,
    };

    if (isBase) {
      if (sinkType === 'script') {
        // TrustedScript sinks (textContent, innerText) are context-dependent:
        // - On <script>/<style>: text IS code → dangerous
        // - On all other elements: text is plain text → safe
        // Don't add to inherited — only add to script/style elements
        for (const execTag of ['script', 'style']) {
          if (!output.elements[execTag]) output.elements[execTag] = {};
          output.elements[execTag][sink.name] = sinkEntry;
        }
      } else {
        // TrustedHTML sinks (innerHTML, outerHTML) are always dangerous
        output.inherited[sink.name] = sinkEntry;
      }
    } else if (tagName) {
      // For non-base interfaces: TrustedScript sinks are also context-dependent
      // Only keep them on script/style elements
      if (sinkType === 'script' && tagName !== 'script' && tagName !== 'style') {
        continue; // Skip: textContent/innerText on non-script elements is safe
      }
      if (!output.elements[tagName]) output.elements[tagName] = {};
      output.elements[tagName][sink.name] = sinkEntry;
    } else {
      // Non-tag interface (e.g., SVGAnimatedString, TrustedTypePolicy)
      if (!output.apis[ifaceName]) output.apis[ifaceName] = {};
      output.apis[ifaceName][sink.name] = sinkEntry;
    }
  }
}

// Add global API sinks
for (const [ifaceName, entry] of Object.entries(idlData.globals)) {
  for (const sink of entry.sinks) {
    let sinkType = sink.sinkType;
    if (sinkType === 'url') {
      sinkType = navClasses.has(ifaceName) ? 'navigation' : null;
    }
    if (!sinkType) continue;
    if (sink.readonly && sink.kind === 'attribute') continue;

    if (!output.apis[ifaceName]) output.apis[ifaceName] = {};
    output.apis[ifaceName][sink.name] = {
      type: sinkType,
      idlType: sink.type,
    };
  }
}

// ═══════════════════════════════════════════
// Step 2b: Add navigation sinks discovered by C++ taint analysis
// that aren't in IDL (e.g., a.href from HTMLHyperlinkElementUtils mixin)
// ═══════════════════════════════════════════

// Interface name → tag name mapping (reuse from IDL data)
function ifaceToTag(name) {
  const htmlMatch = name.match(/^HTML(.+)Element$/);
  if (!htmlMatch) return null;
  const map = {
    'Anchor': 'a', 'DList': 'dl', 'Image': 'img', 'OList': 'ol',
    'Paragraph': 'p', 'TableCaption': 'caption', 'TableCell': 'td',
    'TableCol': 'col', 'TableRow': 'tr', 'TableSection': 'tbody',
    'UList': 'ul', 'Mod': 'ins', 'Quote': 'blockquote', 'Heading': 'h1',
    'Media': null, 'Area': 'area',
  };
  const key = htmlMatch[1];
  return key in map ? map[key] : key.toLowerCase();
}

for (const path of taintData.taintPaths) {
  if (path.terminalType !== 'navigation') continue;
  const [className, propName] = path.property.split('.');
  if (!propName) continue;

  // Resolve tag name from class, including base class children
  const tags = [];
  const tag = ifaceToTag(className);
  if (tag) tags.push(tag);

  // Also apply to children of base classes
  if (inheritance[className]) {
    for (const child of inheritance[className]) {
      const childTag = ifaceToTag(child);
      if (childTag) tags.push(childTag);
    }
  }

  for (const t of tags) {
    if (!output.elements[t]) output.elements[t] = {};
    // Only add if not already present (IDL data takes priority)
    if (!output.elements[t][propName]) {
      output.elements[t][propName] = {
        type: 'navigation',
        idlType: 'USVString',
        source: 'cpp-taint',
      };
    }
  }
}

// ═══════════════════════════════════════════
// Step 3: Print summary and write
// ═══════════════════════════════════════════

console.log('Unified sink classification:');
console.log(`  Elements with specific sinks: ${Object.keys(output.elements).length}`);
console.log(`  Inherited sinks (all elements): ${Object.keys(output.inherited).length}`);
console.log(`  API sinks: ${Object.keys(output.apis).length}`);

console.log('\n--- Inherited (all elements) ---');
for (const [prop, info] of Object.entries(output.inherited)) {
  console.log(`  .${prop} → ${info.type}`);
}

console.log('\n--- Element-specific ---');
for (const [tag, props] of Object.entries(output.elements)) {
  for (const [prop, info] of Object.entries(props)) {
    console.log(`  <${tag}>.${prop} → ${info.type}`);
  }
}

console.log('\n--- APIs ---');
for (const [api, props] of Object.entries(output.apis)) {
  for (const [prop, info] of Object.entries(props)) {
    console.log(`  ${api}.${prop} → ${info.type}`);
  }
}

writeFileSync('src/worker/sink-data.json', JSON.stringify(output, null, 2));
console.log('\nWritten to src/worker/sink-data.json');
