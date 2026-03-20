// Script to replace all nodeToString usages in taint.js with scope-qualified alternatives
import { readFileSync, writeFileSync } from 'fs';

let src = readFileSync('src/worker/taint.js', 'utf8');
let count = 0;

function replace(old, newStr) {
  if (src.includes(old)) {
    src = src.replace(old, newStr);
    count++;
  } else {
    console.log('NOT FOUND:', old.slice(0, 80));
  }
}

function replaceAll(old, newStr) {
  while (src.includes(old)) {
    src = src.replace(old, newStr);
    count++;
  }
}

// 1. Remove from import
replace(
  '  nodeToString, checkMemberSource, checkCallSink, checkAssignmentSink,',
  '  checkMemberSource, checkCallSink, checkAssignmentSink,'
);

// 2. _scopeQualifyMemberExpr fallbacks — remove the || nodeToString fallback
replaceAll('_scopeQualifyMemberExpr(argNode, ctx) || nodeToString(argNode)', '_scopeQualifyMemberExpr(argNode, ctx)');
replaceAll('_scopeQualifyMemberExpr(objNode, ctx) || nodeToString(objNode)', '_scopeQualifyMemberExpr(objNode, ctx)');
replaceAll('_scopeQualifyMemberExpr(callee.object, ctx) || nodeToString(callee.object)', '_scopeQualifyMemberExpr(callee.object, ctx)');
replaceAll('_scopeQualifyMemberExpr(arg, ctx) || nodeToString(arg)', '_scopeQualifyMemberExpr(arg, ctx)');
replaceAll('_scopeQualifyMemberExpr(cc.object, ctx) || nodeToString(cc.object)', '_scopeQualifyMemberExpr(cc.object, ctx)');
replaceAll('_scopeQualifyMemberExpr(node.init.object, ctx) || nodeToString(node.init.object)', '_scopeQualifyMemberExpr(node.init.object, ctx)');
replaceAll('_scopeQualifyMemberExpr(node.init.arguments[0], ctx) || nodeToString(node.init.arguments[0])', '_scopeQualifyMemberExpr(node.init.arguments[0], ctx)');
replaceAll('_scopeQualifyMemberExpr(node.left.object, ctx) || nodeToString(node.left.object)', '_scopeQualifyMemberExpr(node.left.object, ctx)');
replaceAll('_scopeQualifyMemberExpr(node.left, ctx) || nodeToString(node.left)', '_scopeQualifyMemberExpr(node.left, ctx)');
replaceAll('_scopeQualifyMemberExpr(_n.callee, _c) || nodeToString(_n.callee)', '_scopeQualifyMemberExpr(_n.callee, _c)');
replaceAll('_scopeQualifyMemberExpr(leftNode, ctx) || nodeToString(leftNode)', '_scopeQualifyMemberExpr(leftNode, ctx)');
replaceAll('_scopeQualifyMemberExpr(rhsRef, ctx) || nodeToString(rhsRef)', '_scopeQualifyMemberExpr(rhsRef, ctx)');

// 3. _scopeQualifyMemberExpr in _scopeQualifyMemberExpr itself (fallbacks for unknown types)
replace(
  "  if (node.type !== 'MemberExpression' && node.type !== 'OptionalMemberExpression') return nodeToString(node);",
  "  if (node.type !== 'MemberExpression' && node.type !== 'OptionalMemberExpression') return null;"
);
replace(
  '  if (!prop) return nodeToString(node);',
  '  if (!prop) return null;'
);

// 4. _resolveObjKey fallback
replace(
  "  return objNameOrNode?.name || nodeToString(objNameOrNode) || '';",
  "  return objNameOrNode?.name || '';"
);

// 5. All remaining nodeToString → _scopeQualifyMemberExpr where ctx is available
// Pattern: nodeToString(someExpr) used for key lookups

// In extractConditionInfo (discriminant)
replace(
  'const discriminant = nodeToString(memberSide);',
  'const discriminant = _scopeQualifyMemberExpr(memberSide, ctx);'
);

// In processNode debug path
replace(
  "const path = nodeToString(cur);",
  "const path = _scopeQualifyMemberExpr(cur, ctx);"
);

// findProtocolMember
replace(
  'return nodeToString(node.object);',
  'return null; // scope-unaware, callers use ctx-based lookups'
);

// superClass resolution
replace(
  "const superName = node.superClass ? (node.superClass.type === 'Identifier' ? resolveId(node.superClass, ctx) : nodeToString(node.superClass)) : null;",
  "const superName = node.superClass ? (node.superClass.type === 'Identifier' ? resolveId(node.superClass, ctx) : _scopeQualifyMemberExpr(node.superClass, ctx)) : null;"
);

// with() statement
replace(
  'const withObj = nodeToString(node.object);',
  'const withObj = _scopeQualifyMemberExpr(node.object, ctx);'
);

// getDOMQueryInfo
replace(
  "const objName = obj.type === 'Identifier' ? obj.name : nodeToString(obj);",
  "const objName = _scopeQualifyMemberExpr(obj, ctx);"
);

// processVarDeclarator objStr (line ~3603 — used for display comparison only, alias already scope-qualified)
replace(
  'const objStr = nodeToString(node.init.object);',
  'const objStr = _scopeQualifyMemberExpr(node.init.object, ctx);'
);

// constructor callee
replace(
  "ctx._lastNewCallee = ctorCallee.type === 'Identifier' ? resolveId(ctorCallee, ctx) : nodeToString(ctorCallee);",
  "ctx._lastNewCallee = ctorCallee.type === 'Identifier' ? resolveId(ctorCallee, ctx) : _scopeQualifyMemberExpr(ctorCallee, ctx);"
);

// constraint variable
replace(
  "variable: nodeToString(node.left) || '',",
  "variable: _scopeQualifyMemberExpr(node.left, ctx) || '',"
);

// CustomEvent evName
replace(
  "const evName = node.left.type === 'Identifier' ? node.left.name : nodeToString(node.left);",
  "const evName = _scopeQualifyMemberExpr(node.left, ctx);"
);

// leftStr in processAssignment (line ~4100-4101)
replace(
  "? `${_resolveObjKey(node.left.object, ctx)}.${node.left.property?.name || nodeToString(node.left.property)}`\n        : nodeToString(node.left));",
  "? `${_resolveObjKey(node.left.object, ctx)}.${node.left.property?.name || node.left.property?.value || ''}`\n        : _scopeQualifyMemberExpr(node.left, ctx));"
);

// Computed bulk copy
replace(
  "const lhsKeyStr = nodeToString(node.left.property);",
  "const lhsKeyStr = _scopeQualifyMemberExpr(node.left.property, ctx);"
);
replace(
  "const rhsKeyStr = nodeToString(node.right.property);",
  "const rhsKeyStr = _scopeQualifyMemberExpr(node.right.property, ctx);"
);

// leftStr for checkSinkAssignment (line ~4330)
replace(
  "const leftStr = nodeToString(node.left);",
  "const leftStr = _scopeQualifyMemberExpr(node.left, ctx);"
);

// MemberExpression evaluator — _mFullPath
replace(
  "const _mFullPath = nodeToString(_n);",
  "const _mFullPath = _scopeQualifyMemberExpr(_n, _c);"
);

// _mObjStr in source check
replace(
  "const _mObjStr = nodeToString(_mCur.object);",
  "const _mObjStr = _scopeQualifyMemberExpr(_mCur.object, _c);"
);

// _mSourceLabel display
replace(
  "V.push(_applyOuterProps(TaintSet.from(new TaintLabel(_mSourceLabel, _c.file, _mLoc.line || 0, _mLoc.column || 0, nodeToString(_mCur))), _mOuterProps));",
  "V.push(_applyOuterProps(TaintSet.from(new TaintLabel(_mSourceLabel, _c.file, _mLoc.line || 0, _mLoc.column || 0, _scopeQualifyMemberExpr(_mCur, _c) || '')), _mOuterProps));"
);

// _mFullStr property fallbacks
replaceAll(
  "|| nodeToString(_mCur.property)",
  "|| _mCur.property?.value || ''"
);
replace(
  "|| nodeToString(_mRoot.property))",
  "|| _mRoot.property?.value || '')"
);

// _mFullStr fallback for non-identifier root
replace(
  "_mFullStr = nodeToString(_mCur);",
  "_mFullStr = _scopeQualifyMemberExpr(_mCur, _c);"
);

// Tagged template callee
replace(
  "const tagCalleeStr = nodeToString(tagCallee);",
  "const tagCalleeStr = _scopeQualifyMemberExpr(tagCallee, ctx);"
);

// setAttribute objName
replace(
  "const objName = nodeToString(node.callee.object);",
  "const objName = _scopeQualifyMemberExpr(node.callee.object, ctx);"
);

// objStr in evaluateCallExpr (display strings for findings)
replaceAll(
  "const objStr = nodeToString(objNode) || 'obj';",
  "const objStr = _scopeQualifyMemberExpr(objNode, ctx) || 'obj';"
);
replaceAll(
  "const objStr = nodeToString(node.arguments[0]) || 'obj';",
  "const objStr = _scopeQualifyMemberExpr(node.arguments[0], ctx) || 'obj';"
);

// Object.assign/values argKey
replace(
  "const argKey = argNode.type === 'Identifier' ? resolveId(argNode, ctx) : nodeToString(argNode);",
  "const argKey = _scopeQualifyMemberExpr(argNode, ctx);"
);

// Object.assign targetStr
replace(
  "const targetStr = targetNode ? nodeToString(targetNode) : null;",
  "const targetStr = targetNode ? _scopeQualifyMemberExpr(targetNode, ctx) : null;"
);

// Object.assign srcStr/srcKey (already partially fixed)
replaceAll(
  "srcNode.type === 'Identifier' ? resolveId(srcNode, ctx) : nodeToString(srcNode)",
  "_scopeQualifyMemberExpr(srcNode, ctx)"
);

// Chain fallback ctorName
replace(
  "chainObj.callee.type === 'Identifier' ? resolveId(chainObj.callee, ctx) : nodeToString(chainObj.callee)",
  "_scopeQualifyMemberExpr(chainObj.callee, ctx)"
);

// argStr in event listener
replace(
  "const argStr = nodeToString(argNode);\n              if (argStr",
  "const argStr = _scopeQualifyMemberExpr(argNode, ctx);\n              if (argStr"
);

// eventStr in dispatchEvent
replace(
  "const eventStr = eventArg.type === 'Identifier' ? eventArg.name : nodeToString(eventArg);",
  "const eventStr = _scopeQualifyMemberExpr(eventArg, ctx);"
);

// Promise.resolve source resolution
replace(
  "resolvedSrcNode.type === 'Identifier' ? resolveId(resolvedSrcNode, ctx) : nodeToString(resolvedSrcNode)",
  "_scopeQualifyMemberExpr(resolvedSrcNode, ctx)"
);

// argStr in param setup (two locations)
replaceAll(
  "const argStr = nodeToString(argNode);\n        if (argStr)",
  "const argStr = _scopeQualifyMemberExpr(argNode, ctx);\n        if (argStr)"
);

// argPath in param setup
replace(
  "const argPath = nodeToString(argNode);",
  "const argPath = _scopeQualifyMemberExpr(argNode, ctx);"
);

// argStr in postProcess (two with _callerCtx)
replaceAll(
  "argNode.type === 'Identifier' ? _resolveObjKey(argNode, _callerCtx) : nodeToString(argNode)",
  "_scopeQualifyMemberExpr(argNode, _callerCtx)"
);

// collectClosureTaint str
replace(
  "const str = nodeToString(node);",
  "const str = _scopeQualifyMemberExpr(node, ctx);"
);

// checkSinkAssignment varName/objName for finding display
replace(
  "const varName = nodeToString(rhsNode);",
  "const varName = _scopeQualifyMemberExpr(rhsNode, ctx);"
);
replace(
  "const objName = nodeToString(rhsNode.object);",
  "const objName = _scopeQualifyMemberExpr(rhsNode.object, ctx);"
);

// checkSinkAssignment leftStr (line ~10138 CSS injection display)
replace(
  "const leftStr = nodeToString(leftNode);\n    pushFinding",
  "const leftStr = _scopeQualifyMemberExpr(leftNode, ctx) || '';\n    pushFinding"
);

// checkSinkAssignment objKey
replace(
  "const objKey = objNode?.type === 'Identifier' ? resolveId(objNode, ctx) : nodeToString(objNode);",
  "const objKey = _scopeQualifyMemberExpr(objNode, ctx);"
);

// checkElementPropertySink argStr
replace(
  "const argStr = nodeToString(argNode);\n  if (!argStr",
  "const argStr = _scopeQualifyMemberExpr(argNode, ctx);\n  if (!argStr"
);

// PP check debug/display strings
replaceAll(
  "nodeToString(left) || 'obj[key1][key2]'",
  "_scopeQualifyMemberExpr(left, ctx) || 'obj[key1][key2]'"
);
replaceAll(
  "nodeToString(left) || `obj.${objProp}.prop`",
  "_scopeQualifyMemberExpr(left, ctx) || `obj.${objProp}.prop`"
);
replaceAll(
  "nodeToString(left) || 'obj.constructor.prototype[key]'",
  "_scopeQualifyMemberExpr(left, ctx) || 'obj.constructor.prototype[key]'"
);
replaceAll(
  "nodeToString(left) || 'obj.__proto__'",
  "_scopeQualifyMemberExpr(left, ctx) || 'obj.__proto__'"
);
replace(
  "keyNode?.type === 'Identifier' ? keyNode.name : nodeToString(keyNode)",
  "keyNode?.type === 'Identifier' ? keyNode.name : (_scopeQualifyMemberExpr(keyNode, ctx) || '')"
);
replaceAll(
  "nodeToString(left.object) || 'obj'",
  "_scopeQualifyMemberExpr(left.object, ctx) || 'obj'"
);
replace(
  "const objStr2 = nodeToString(left.object);",
  "const objStr2 = _scopeQualifyMemberExpr(left.object, ctx);"
);

// Debug assign computed
replace(
  'nodeToString(pattern.property)||',
  "_scopeQualifyMemberExpr(pattern.property, ctx)||"
);

// PP-CHECK debug
replace(
  '`[PP-CHECK] ${nodeToString(left)||left.type}',
  '`[PP-CHECK] ${_scopeQualifyMemberExpr(left, ctx)||left.type}'
);

writeFileSync('src/worker/taint.js', src);
console.log(`\nReplaced ${count} occurrences`);

// Verify no nodeToString remain
const remaining = (src.match(/nodeToString/g) || []).length;
console.log(`Remaining nodeToString: ${remaining}`);
