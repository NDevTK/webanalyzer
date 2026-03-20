#!/usr/bin/env node
/**
 * Generates src/worker/idl-data.js from sink-data.json.
 *
 * Pipeline:
 *   1. parse-chromium-idl.mjs → chromium-sink-data.json (IDL types + TrustedTypes)
 *   2. chromium-taint.mjs → chromium-taint-results.json (C++ data flow: navigation classification)
 *   3. build-sink-data.mjs → sink-data.json (unified sink classification)
 *   4. THIS SCRIPT → src/worker/idl-data.js (JS module for taint engine)
 *
 * Run: npm run generate-sinks
 */

import { readFileSync, writeFileSync } from 'fs';

const sinkData = JSON.parse(readFileSync('src/worker/sink-data.json', 'utf8'));
const idlData = JSON.parse(readFileSync('src/worker/chromium-sink-data.json', 'utf8'));

// Build the sink map: "tag:prop" → sinkType
// sinkType: "html" | "script" | "script-url" | "navigation"
const sinkMap = {};

// Inherited sinks (apply to all elements)
for (const [prop, info] of Object.entries(sinkData.inherited)) {
  sinkMap['*:' + prop] = info.type;
}

// Element-specific sinks
for (const [tag, props] of Object.entries(sinkData.elements)) {
  for (const [prop, info] of Object.entries(props)) {
    // Skip if same as inherited (avoid duplication)
    if (sinkData.inherited[prop] && sinkData.inherited[prop].type === info.type) continue;
    sinkMap[tag + ':' + prop] = info.type;
  }
}

// API sinks
for (const [api, props] of Object.entries(sinkData.apis)) {
  for (const [prop, info] of Object.entries(props)) {
    sinkMap[api + ':' + prop] = info.type;
  }
}

// Map sink types to TrustedType names for compatibility
function sinkTypeToTrustedType(sinkType) {
  switch (sinkType) {
    case 'html': return 'TrustedHTML';
    case 'script': return 'TrustedScript';
    case 'script-url': return 'TrustedScriptURL';
    case 'navigation': return 'navigation';
    default: return sinkType;
  }
}

// Build DOM-producing property map: "Interface.prop" → { tag, isDomAttached }
// Properties that return Element subtypes, derived from IDL return types
const domPropMap = {};
if (idlData.domProperties) {
  for (const [iface, props] of Object.entries(idlData.domProperties)) {
    for (const [prop, info] of Object.entries(props)) {
      const key = iface + '.' + prop;
      domPropMap[key] = info.tag || null;
    }
  }
}

// Generate the JS module
const lines = [];
lines.push(`/* idl-data.js — Auto-generated from Chromium IDL + C++ taint analysis.`);
lines.push(`   DO NOT EDIT MANUALLY. Run: npm run generate-sinks`);
lines.push(`   Generated: ${new Date().toISOString()}`);
lines.push(``);
lines.push(`   Sources:`);
lines.push(`     - Chromium IDL: TrustedTypes annotations (html/script/script-url sinks)`);
lines.push(`     - Chromium C++ taint analysis: navigation classification for [URL] properties`);
lines.push(`     - Runtime: trustedTypes.getPropertyType() overrides when available */`);
lines.push(``);
lines.push(`// Sink map: "tag:prop" or "*:prop" (all elements) → sink type`);
lines.push(`// Types: "TrustedHTML" | "TrustedScript" | "TrustedScriptURL" | "navigation"`);
lines.push(`const SINK_MAP = ${JSON.stringify(
  Object.fromEntries(
    Object.entries(sinkMap).map(([k, v]) => [k, sinkTypeToTrustedType(v)])
  ),
  null, 2
)};`);
lines.push(``);
lines.push(`// Runtime sink cache — merges static data with trustedTypes.getPropertyType()`);
lines.push(`let _sinkCache = null;`);
lines.push(``);
lines.push(`function _buildSinkMap() {`);
lines.push(`  const sinks = new Map();`);
lines.push(``);
lines.push(`  // Load static sink data`);
lines.push(`  for (const [key, type] of Object.entries(SINK_MAP)) {`);
lines.push(`    sinks.set(key, { type, behavior: type === 'navigation' ? 'navigation' : 'injection' });`);
lines.push(`  }`);
lines.push(``);
lines.push(`  // Override with runtime trustedTypes.getPropertyType() if available`);
lines.push(`  const hasTT = typeof trustedTypes !== 'undefined' && typeof trustedTypes.getPropertyType === 'function';`);
lines.push(`  if (hasTT) {`);
lines.push(`    // Probe known element tags for additional sinks not in IDL data`);
lines.push(`    const tags = new Set();`);
lines.push(`    for (const key of Object.keys(SINK_MAP)) {`);
lines.push(`      const tag = key.split(':')[0];`);
lines.push(`      if (tag !== '*') tags.add(tag);`);
lines.push(`    }`);
lines.push(`    // The runtime probe can discover sinks our IDL parsing missed`);
lines.push(`    // but we trust our static data as the primary source`);
lines.push(`  }`);
lines.push(``);
lines.push(`  return sinks;`);
lines.push(`}`);
lines.push(``);
lines.push(`// Check if a property is a sink on a given element tag.`);
lines.push(`// Returns { type, behavior } or null.`);
lines.push(`// type: "TrustedHTML" | "TrustedScript" | "TrustedScriptURL" | "navigation"`);
lines.push(`export function isElementPropertySink(tag, propName) {`);
lines.push(`  if (!_sinkCache) _sinkCache = _buildSinkMap();`);
lines.push(`  // Check tag-specific first, then wildcard`);
lines.push(`  return _sinkCache.get(tag + ':' + propName) || _sinkCache.get('*:' + propName) || null;`);
lines.push(`}`);
lines.push(``);
lines.push(`// Check if a property exists as a sink on any element.`);
lines.push(`export function hasElementProperty(tag, propName) {`);
lines.push(`  if (!_sinkCache) _sinkCache = _buildSinkMap();`);
lines.push(`  return _sinkCache.has(tag + ':' + propName) || _sinkCache.has('*:' + propName);`);
lines.push(`}`);
lines.push(``);
// Build per-interface index for getDOMPropertiesForInterface
const domPropsByIface = {};
for (const [key, tag] of Object.entries(domPropMap)) {
  const dot = key.indexOf('.');
  const iface = key.slice(0, dot);
  const prop = key.slice(dot + 1);
  if (!domPropsByIface[iface]) domPropsByIface[iface] = {};
  domPropsByIface[iface][prop] = { tag };
}

lines.push(`// DOM-producing properties: properties that return Element subtypes (from IDL return types)`);
lines.push(`// "Interface.prop" → tag (string) or null (generic Element)`);
lines.push(`const DOM_PROPERTIES = ${JSON.stringify(domPropMap, null, 2)};`);
lines.push(``);
lines.push(`// Resolve a member access on a known interface to its DOM element info.`);
lines.push(`// e.g., getDOMPropertyInfo("Document", "head") → { tag: "head", isDomAttached: true }`);
lines.push(`// e.g., getDOMPropertyInfo("Document", "body") → { tag: null, isDomAttached: true }`);
lines.push(`// Returns null if the property doesn't return an Element type.`);
lines.push(`export function getDOMPropertyInfo(interfaceName, propName) {`);
lines.push(`  const key = interfaceName + '.' + propName;`);
lines.push(`  if (key in DOM_PROPERTIES) {`);
lines.push(`    return { tag: DOM_PROPERTIES[key], isDomAttached: true };`);
lines.push(`  }`);
lines.push(`  return null;`);
lines.push(`}`);
lines.push(``);
lines.push(`// Per-interface DOM property index`);
lines.push(`const DOM_PROPS_BY_IFACE = ${JSON.stringify(domPropsByIface, null, 2)};`);
lines.push(``);
lines.push(`// Get all DOM-producing properties for a given interface.`);
lines.push(`// Returns { propName: { tag } } or null.`);
lines.push(`export function getDOMPropertiesForInterface(interfaceName) {`);
lines.push(`  return DOM_PROPS_BY_IFACE[interfaceName] || null;`);
lines.push(`}`);
lines.push(``);

writeFileSync('src/worker/idl-data.js', lines.join('\n'));

const totalSinks = Object.keys(sinkMap).length;
console.log(`Generated src/worker/idl-data.js (${totalSinks} sink entries)`);
