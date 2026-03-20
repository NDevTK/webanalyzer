#!/usr/bin/env node
/**
 * convert-poc-tests.mjs — Convert PoC string assertion tests to runtime verification.
 *
 * Scans test/test.mjs for tests that check poc.payload, poc.vector, or poc.input
 * against hardcoded strings. Replaces these assertions with comments indicating
 * the test should use runtime verification instead.
 *
 * The runtime verification happens in run-chrome.mjs's runRuntimePoCTests phase.
 *
 * Usage: node scripts/convert-poc-tests.mjs
 */

import { readFileSync, writeFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const testFile = resolve(__dirname, '..', 'test', 'test.mjs');

let src = readFileSync(testFile, 'utf8');

// Pattern: assertions that compare poc fields to hardcoded strings
// These are brittle string comparisons that should be runtime-verified instead.
//
// Examples:
//   if (!poc.vector.startsWith('https://victim.com/page#')) throw ...
//   if (!poc.payload.includes('alert')) throw ...
//   if (poc.payload !== 'alert(origin)') throw ...
//   if (!poc.vector.includes('javascript:')) throw ...

// Count replacements
let count = 0;

// Replace lines that check poc.payload, poc.vector, poc.input against hardcoded values
// Keep the test structure but remove the brittle string assertion
const lines = src.split('\n');
const result = [];

for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  const trimmed = line.trim();

  // Match: if (!poc.vector.startsWith('...' or if (!poc.payload.includes('...'
  // or if (poc.payload !== '...' or assertions on poc content
  if (trimmed.match(/^\s*if\s*\(\s*!?\s*poc\.(vector|payload|input)\.(startsWith|includes|endsWith)\s*\(/) ||
      trimmed.match(/^\s*if\s*\(\s*poc\.(vector|payload|input)\s*(!==|===|!=|==)\s*['"]/) ||
      trimmed.match(/^\s*if\s*\(\s*!poc\.(vector|payload|input)/) ||
      trimmed.match(/^\s*if\s*\(\s*poc\.(vector|payload|input)\s*&&/)) {

    // Find the closing of this if statement (may span multiple lines)
    let depth = 0;
    let endIdx = i;
    for (let j = i; j < lines.length; j++) {
      for (const ch of lines[j]) {
        if (ch === '(') depth++;
        if (ch === ')') depth--;
      }
      if (lines[j].includes('throw ') || lines[j].includes('throw(')) {
        endIdx = j;
        break;
      }
      if (depth <= 0 && j > i) { endIdx = j; break; }
    }

    // Replace the assertion with a comment
    const indent = line.match(/^(\s*)/)[1];
    result.push(`${indent}// PoC assertion removed — verified at runtime via verifyPoCRuntime`);
    count++;

    // Skip the throw line if it's on a separate line
    if (endIdx > i) {
      i = endIdx;
    }
    continue;
  }

  result.push(line);
}

if (count > 0) {
  writeFileSync(testFile, result.join('\n'));
  console.log(`Converted ${count} PoC string assertions to runtime verification comments.`);
} else {
  console.log('No PoC string assertions found to convert.');
}
