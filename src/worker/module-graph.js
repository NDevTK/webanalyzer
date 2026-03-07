/* module-graph.js — Cross-file analysis: tracks global scope sharing
   (non-module scripts) and ES module import/export bindings.
   Enables taint to flow across script boundaries. */

import { TaintEnv, TaintSet } from './taint.js';

export class ModuleGraph {
  constructor() {
    // Per-page analysis contexts
    // pageId → PageContext
    this.pages = new Map();
  }

  getPage(pageId) {
    if (!this.pages.has(pageId)) {
      this.pages.set(pageId, new PageContext(pageId));
    }
    return this.pages.get(pageId);
  }

  resetPage(pageId) {
    this.pages.set(pageId, new PageContext(pageId));
  }
}

export class PageContext {
  constructor(pageId) {
    this.pageId = pageId;
    this.origin = '';

    // Shared global taint env for non-module scripts (they share window scope)
    this.globalEnv = new TaintEnv();

    // Module registry: url → ModuleInfo
    this.modules = new Map();

    // Script order for non-module scripts (analyze in DOM order)
    this.scriptOrder = [];

    // Collected function declarations across all scripts (for cross-file calls)
    this.globalFuncMap = new Map(); // funcName → { ast, file }

    // Export bindings: url → { exportName → { localName, taint } }
    this.exports = new Map();

    // Import bindings: url → [{ source, imported, local }]
    this.imports = new Map();

    // Debounce timer for cross-file analysis
    this.pendingAnalysis = null;

    // All findings for this page
    this.findings = [];

    // Hashes of scripts already analyzed
    this.analyzedHashes = new Set();
  }

  addScript(scriptInfo) {
    if (this.analyzedHashes.has(scriptInfo.hash)) return false;
    this.analyzedHashes.add(scriptInfo.hash);

    if (scriptInfo.isModule) {
      this.modules.set(scriptInfo.url, {
        source: scriptInfo.source,
        url: scriptInfo.url,
        hash: scriptInfo.hash,
        ast: null,  // set during analysis
        analyzed: false,
      });
    } else {
      this.scriptOrder.push({
        source: scriptInfo.source,
        url: scriptInfo.url,
        hash: scriptInfo.hash,
        ast: null,
        analyzed: false,
      });
    }
    return true;
  }
}

// ── Extract import/export info from an AST ──

export function extractImports(ast) {
  const imports = [];
  for (const node of ast.program.body) {
    if (node.type === 'ImportDeclaration') {
      const source = node.source.value;
      for (const spec of node.specifiers) {
        if (spec.type === 'ImportDefaultSpecifier') {
          imports.push({ source, imported: 'default', local: spec.local.name });
        } else if (spec.type === 'ImportSpecifier') {
          imports.push({
            source,
            imported: spec.imported.name || spec.imported.value,
            local: spec.local.name,
          });
        } else if (spec.type === 'ImportNamespaceSpecifier') {
          imports.push({ source, imported: '*', local: spec.local.name });
        }
      }
    }
  }
  return imports;
}

export function extractExports(ast) {
  const exports = [];
  for (const node of ast.program.body) {
    if (node.type === 'ExportNamedDeclaration') {
      if (node.declaration) {
        if (node.declaration.type === 'VariableDeclaration') {
          for (const decl of node.declaration.declarations) {
            if (decl.id.type === 'Identifier') {
              exports.push({ exported: decl.id.name, local: decl.id.name });
            }
          }
        } else if (node.declaration.id) {
          exports.push({ exported: node.declaration.id.name, local: node.declaration.id.name });
        }
      }
      for (const spec of (node.specifiers || [])) {
        exports.push({
          exported: spec.exported.name || spec.exported.value,
          local: spec.local.name || spec.local.value,
        });
      }
    } else if (node.type === 'ExportDefaultDeclaration') {
      exports.push({ exported: 'default', local: '_default' });
    }
  }
  return exports;
}

// ── Resolve import bindings: map imported names to exported taint ──

export function resolveImportTaint(pageCtx, importingUrl, imports) {
  const env = new TaintEnv();

  for (const imp of imports) {
    // Resolve source URL relative to the importing module
    const resolvedUrl = resolveModuleUrl(imp.source, importingUrl);
    const exportTaints = pageCtx.exports.get(resolvedUrl);

    if (exportTaints) {
      const exportTaint = exportTaints.get(imp.imported);
      if (exportTaint) {
        env.set(imp.local, exportTaint);
      }
    }
  }

  return env;
}

// ── Collect global declarations from non-module scripts ──

export function extractGlobalDeclarations(ast, funcMap, file) {
  for (const node of ast.program.body) {
    if (node.type === 'FunctionDeclaration' && node.id) {
      funcMap.set(node.id.name, node);
    }
    // Variable declarations at top level
    if (node.type === 'VariableDeclaration') {
      for (const decl of node.declarations) {
        if (decl.id.type === 'Identifier' && decl.init &&
            (decl.init.type === 'FunctionExpression' || decl.init.type === 'ArrowFunctionExpression')) {
          funcMap.set(decl.id.name, decl.init);
        }
      }
    }
    // Assignments to window.X or global function expressions
    if (node.type === 'ExpressionStatement' &&
        node.expression.type === 'AssignmentExpression') {
      const left = node.expression.left;
      const right = node.expression.right;
      if (left.type === 'MemberExpression' &&
          left.object.type === 'Identifier' && left.object.name === 'window' &&
          left.property.type === 'Identifier' &&
          (right.type === 'FunctionExpression' || right.type === 'ArrowFunctionExpression')) {
        funcMap.set(left.property.name, right);
      }
    }
    // Class declarations: extract methods into funcMap
    if (node.type === 'ClassDeclaration' && node.id) {
      extractClassMethods(node, node.id.name, funcMap);
    }
  }
}

// Extract methods from a ClassDeclaration/ClassExpression into funcMap
// Registers as "ClassName.method" for static, "method" for instance methods
function extractClassMethods(classNode, className, funcMap) {
  if (!classNode.body || !classNode.body.body) return;
  for (const member of classNode.body.body) {
    if (member.type !== 'ClassMethod' && member.type !== 'MethodDefinition') continue;
    const name = member.key?.name || member.key?.value;
    if (!name) continue;
    if (member.static) {
      // Static: Foo.bar()
      funcMap.set(`${className}.${name}`, member);
      funcMap.set(name, member);
    } else if (name === 'constructor') {
      // Constructor: new Foo()
      funcMap.set(className, member);
    } else {
      // Instance method: registered by plain name for method-call resolution
      funcMap.set(name, member);
    }
  }
}

// ── postMessage origin check detection ──
// Scans event listener callbacks for message events to check if origin is validated

export function checkPostMessageHandler(ast, file) {
  const findings = [];

  // We look for addEventListener('message', handler) patterns
  // and check if the handler validates event.origin
  for (const node of ast.program.body) {
    scanForMessageHandlers(node, file, findings, []);
  }

  return findings;
}

function scanForMessageHandlers(node, file, findings, ancestors) {
  if (!node || typeof node !== 'object') return;

  if (node.type === 'CallExpression') {
    const callee = node.callee;
    // addEventListener('message', fn)  or  window.addEventListener('message', fn)
    if (callee.type === 'MemberExpression' && callee.property?.name === 'addEventListener') {
      const firstArg = node.arguments[0];
      if (firstArg && (firstArg.type === 'StringLiteral' || firstArg.type === 'Literal') &&
          (firstArg.value === 'message')) {
        const handler = node.arguments[1];
        if (handler && (handler.type === 'ArrowFunctionExpression' || handler.type === 'FunctionExpression')) {
          if (!handlerChecksOrigin(handler)) {
            // This handler doesn't check origin — data from it is tainted
            // Flag is informational; the actual taint flow will be detected by the engine
            // when event.data flows to a sink
          }
          // Return: the taint engine handles the actual flow
        }
      }
    }
    // window.onmessage = fn
    if (callee.type === 'MemberExpression' || node.type === 'AssignmentExpression') {
      // handled by taint engine
    }
  }

  // Recurse into child nodes
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'start' || key === 'end' || key === 'leadingComments' ||
        key === 'trailingComments' || key === 'innerComments') continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (item && typeof item === 'object' && item.type) {
          scanForMessageHandlers(item, file, findings, [...ancestors, node]);
        }
      }
    } else if (child && typeof child === 'object' && child.type) {
      scanForMessageHandlers(child, file, findings, [...ancestors, node]);
    }
  }
}

// Check if a node is a MemberExpression accessing .origin by AST structure
function isOriginMemberAccess(node) {
  if (!node) return false;
  if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
    if (!node.computed && node.property?.name === 'origin') return true;
    if (node.computed && node.property?.type === 'StringLiteral' && node.property.value === 'origin') return true;
    if (node.computed && node.property?.type === 'Literal' && node.property.value === 'origin') return true;
  }
  return false;
}

function handlerChecksOrigin(funcNode) {
  // Walk the function body looking for origin checks
  return containsOriginCheck(funcNode.body);
}

function containsOriginCheck(node) {
  if (!node || typeof node !== 'object') return false;

  // Look for: event.origin === '...' or e.origin !== '...' or .origin checks
  if (node.type === 'BinaryExpression' &&
      (node.operator === '===' || node.operator === '==' ||
       node.operator === '!==' || node.operator === '!=')) {
    if (isOriginMemberAccess(node.left) || isOriginMemberAccess(node.right)) {
      return true;
    }
  }

  // Look for if (event.origin ...) or switch on origin
  if (node.type === 'IfStatement' && containsOriginCheck(node.test)) return true;
  if (node.type === 'SwitchStatement' && containsOriginCheck(node.discriminant)) return true;

  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'start' || key === 'end') continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (item && typeof item === 'object' && item.type && containsOriginCheck(item)) return true;
      }
    } else if (child && typeof child === 'object' && child.type && containsOriginCheck(child)) {
      return true;
    }
  }

  return false;
}

function memberToString(node) {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression' && !node.computed) {
    const obj = memberToString(node.object);
    if (obj && node.property?.name) return `${obj}.${node.property.name}`;
  }
  return null;
}

// ── URL resolution ──

function resolveModuleUrl(specifier, fromUrl) {
  if (specifier.startsWith('./') || specifier.startsWith('../') || specifier.startsWith('/')) {
    try {
      return new URL(specifier, fromUrl).href;
    } catch {
      return specifier;
    }
  }
  // Bare specifier (npm package) — can't resolve in browser context
  return specifier;
}
