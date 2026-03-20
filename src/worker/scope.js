/* scope.js — Uses @babel/traverse to build a scope-aware binding map.
   Maps each Identifier AST node to a canonical binding key that respects
   variable shadowing, closures, hoisting, and block scoping. */

import _traverse from '@babel/traverse';
const traverse = _traverse.default || _traverse;

// Build a scope info map for an AST
// Returns ScopeInfo with methods to resolve identifiers to canonical keys
export function buildScopeInfo(ast) {
  // Map from AST node → canonical binding key
  // Using node start position as identity since Babel nodes are unique objects
  const nodeBindingMap = new Map();   // node reference → bindingKey
  const bindingScopes = new Map();    // bindingKey → scope uid
  const bindingNodes = new Map();     // bindingKey → declaration node

  function mapBinding(node, scope) {
    if (nodeBindingMap.has(node)) return;
    const binding = scope.getBinding(node.name);
    if (binding) {
      nodeBindingMap.set(node, `${binding.scope.uid}:${node.name}`);
    }
  }

  let programScopeUid = null;
  const programChildScopes = new Set();

  traverse(ast, {
    // Capture the program scope UID and its direct child scopes
    Program(path) {
      programScopeUid = path.scope.uid;
      // Collect scope UIDs of direct children of the program scope
      // (class declarations, block scopes for let/const at top level)
      for (const childPath of path.get('body')) {
        if (childPath.scope && childPath.scope.uid !== programScopeUid) {
          programChildScopes.add(childPath.scope.uid);
        }
      }
    },
    // Capture all scope-creating nodes to register bindings
    Scope(path) {
      const scope = path.scope;
      for (const [name, binding] of Object.entries(scope.bindings)) {
        const key = `${scope.uid}:${name}`;
        bindingScopes.set(key, scope.uid);
        bindingNodes.set(key, binding.path.node);

        // Map the declaration identifier
        if (binding.identifier) {
          nodeBindingMap.set(binding.identifier, key);
        }

        // Map all reference identifiers
        for (const refPath of binding.referencePaths) {
          nodeBindingMap.set(refPath.node, key);
        }

        // Map all constant violation identifiers (reassignments)
        for (const violPath of binding.constantViolations) {
          const violNode = violPath.node;
          if (violNode.type === 'AssignmentExpression' && violNode.left?.type === 'Identifier') {
            nodeBindingMap.set(violNode.left, key);
          } else if (violNode.type === 'UpdateExpression' && violNode.argument?.type === 'Identifier') {
            nodeBindingMap.set(violNode.argument, key);
          }
        }
      }
    },

    // For function parameters, capture in the function scope
    'FunctionDeclaration|FunctionExpression|ArrowFunctionExpression'(path) {
      const scope = path.scope;
      for (const param of path.node.params) {
        walkPattern(param, (idNode) => {
          const name = idNode.name;
          const binding = scope.getBinding(name);
          if (binding) {
            const key = `${scope.uid}:${name}`;
            nodeBindingMap.set(idNode, key);
          }
        });
      }
    },

    // Capture identifiers in all references
    ReferencedIdentifier(path) {
      mapBinding(path.node, path.scope);
    },

    // Capture identifiers in binding declarations (let x = ...)
    BindingIdentifier(path) {
      mapBinding(path.node, path.scope);
    },
  });

  return new ScopeInfo(nodeBindingMap, bindingScopes, bindingNodes, programScopeUid, programChildScopes);
}

export class ScopeInfo {
  constructor(nodeBindingMap, bindingScopes, bindingNodes, programScopeUid, programChildScopes) {
    this.nodeBindingMap = nodeBindingMap;
    this.bindingScopes = bindingScopes;
    this.bindingNodes = bindingNodes;
    this.programScopeUid = programScopeUid; // UID of the Program scope (outermost)
    this._programChildScopes = programChildScopes || new Set();
  }

  // Check if a binding key belongs to the program (outermost) scope
  // or a scope directly parented by it (e.g., class body scope for class declarations).
  // Uses _programChildScopes populated during traversal.
  isProgramScope(bindingKey) {
    if (!bindingKey || this.programScopeUid === null) return false;
    if (bindingKey.startsWith(`${this.programScopeUid}:`)) return true;
    // Check if the binding's scope is a direct child of the program scope
    const scopeUid = this.bindingScopes.get(bindingKey);
    if (scopeUid === undefined) return false;
    return this._programChildScopes?.has(scopeUid) || false;
  }

  // Resolve an Identifier AST node to its canonical binding key
  // Returns a unique string like "3:myVar" (scope uid + name)
  // Falls back to "global:name" for unresolved globals
  resolve(identifierNode) {
    if (!identifierNode) return null;
    const mapped = this.nodeBindingMap.get(identifierNode);
    if (mapped) return mapped;
    // Unresolved → treat as global
    if (identifierNode.type === 'Identifier') {
      return `global:${identifierNode.name}`;
    }
    return null;
  }

  // Check if two identifier nodes refer to the same binding
  sameBinding(nodeA, nodeB) {
    const keyA = this.resolve(nodeA);
    const keyB = this.resolve(nodeB);
    return keyA && keyB && keyA === keyB;
  }

  // Get all binding keys in a given scope
  bindingsInScope(scopeUid) {
    const keys = [];
    for (const [key, uid] of this.bindingScopes) {
      if (uid === scopeUid) keys.push(key);
    }
    return keys;
  }
}

// Walk a pattern node (Identifier, ObjectPattern, ArrayPattern, etc.)
// calling visitor for each Identifier leaf
function walkPattern(node, visitor) {
  if (!node) return;
  // Iterative: explicit stack of pattern nodes to visit
  const stack = [node];
  while (stack.length > 0) {
    const n = stack.pop();
    if (!n) continue;
    switch (n.type) {
      case 'Identifier':
        visitor(n);
        break;
      case 'ObjectPattern':
        for (let i = n.properties.length - 1; i >= 0; i--) {
          const prop = n.properties[i];
          stack.push(prop.type === 'RestElement' ? prop.argument : prop.value);
        }
        break;
      case 'ArrayPattern':
        for (let i = n.elements.length - 1; i >= 0; i--) {
          const elem = n.elements[i];
          if (elem) stack.push(elem.type === 'RestElement' ? elem.argument : elem);
        }
        break;
      case 'AssignmentPattern':
        stack.push(n.left);
        break;
    }
  }
}
