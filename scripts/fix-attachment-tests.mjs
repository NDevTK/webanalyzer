#!/usr/bin/env node
/**
 * Fix tests that use createElement without appendChild.
 *
 * Pattern: var el = document.createElement("script"); el.src = tainted;
 * Fix:     var el = document.createElement("script"); document.body.appendChild(el); el.src = tainted;
 *
 * Only modifies tests that create elements and set sink properties without attaching.
 */

import { readFileSync, writeFileSync } from 'fs';

const TEST_FILE = 'test/test.mjs';
const content = readFileSync(TEST_FILE, 'utf8');

// Match patterns where createElement is followed by a sink assignment without appendChild/append between them
// We look for test cases (inside template literals or strings) that have:
//   createElement("tag") ... .src = / .srcdoc = / .textContent = / .text = / .innerHTML =
// WITHOUT .appendChild / .append / .insertBefore between them

let fixed = 0;
let output = content;

// Strategy: find `createElement` calls and check if there's a sink assignment
// without an attachment call between them. Insert `document.body.appendChild(varName);`

// Pattern 1: var el = document.createElement("tag"); el.prop = tainted
// Insert appendChild after createElement line
const pattern1 = /((var|let|const)\s+(\w+)\s*=\s*document\.createElement\s*\(\s*["'](\w+)["']\s*\)\s*;)/g;

const lines = output.split('\n');
const newLines = [];
let i = 0;

while (i < lines.length) {
  const line = lines[i];
  newLines.push(line);

  // Check if this line has createElement
  const ceMatch = line.match(/(var|let|const)\s+(\w+)\s*=\s*document\.createElement\s*\(\s*["'](\w+)["']\s*\)/);
  if (ceMatch) {
    const varName = ceMatch[2];
    const tag = ceMatch[3];

    // Look ahead for sink assignments without attachment
    let hasAttachment = false;
    let hasSinkAssignment = false;
    let sinkLine = -1;

    // Scan forward within the same test case (look for next analyze( or next test description)
    for (let j = i + 1; j < Math.min(i + 20, lines.length); j++) {
      const nextLine = lines[j];

      // Stop scanning at test boundaries
      if (nextLine.includes('analyze(') && j > i + 1 && !nextLine.includes(varName)) break;
      if (nextLine.match(/^\s*(it|describe|test)\s*\(/)) break;
      if (nextLine.includes("',") && nextLine.trim().startsWith("'")) break;

      // Check for attachment
      if (nextLine.includes('.appendChild(') || nextLine.includes('.append(') ||
          nextLine.includes('.prepend(') || nextLine.includes('.insertBefore(') ||
          nextLine.includes('.after(') || nextLine.includes('.before(')) {
        hasAttachment = true;
      }

      // Check for sink assignment on the created element
      const sinkProps = ['src', 'srcdoc', 'textContent', 'text', 'innerHTML', 'outerHTML', 'data', 'href'];
      for (const prop of sinkProps) {
        if (nextLine.includes(`${varName}.${prop}`) && nextLine.includes('=')) {
          hasSinkAssignment = true;
          sinkLine = j;
        }
      }
    }

    // If there's a sink assignment but no attachment, insert appendChild
    if (hasSinkAssignment && !hasAttachment) {
      const indent = line.match(/^(\s*)/)?.[1] || '';
      // Check if we're inside a template literal or regular string
      // by looking at context - if there's backtick or quote patterns
      newLines.push(`${indent}document.body.appendChild(${varName});`);
      fixed++;
    }
  }

  i++;
}

if (fixed > 0) {
  writeFileSync(TEST_FILE, newLines.join('\n'));
  console.log(`Fixed ${fixed} test cases — added document.body.appendChild() after createElement`);
} else {
  console.log('No fixes needed');
}
