/* cfg.js — Builds a Control Flow Graph from a Babel AST function body.
   Each BasicBlock contains an ordered list of AST statement/expression nodes.
   Edges represent possible control flow transitions. */

let blockIdCounter = 0;

export class BasicBlock {
  constructor() {
    this.id = blockIdCounter++;
    this.nodes = [];        // AST nodes in execution order
    this.successors = [];   // BasicBlock[]
    this.predecessors = []; // BasicBlock[]
  }

  addNode(node) {
    if (node) this.nodes.push(node);
  }

  connect(target) {
    if (!target) return;
    if (!this.successors.includes(target)) {
      this.successors.push(target);
      target.predecessors.push(this);
    }
  }
}

export class CFG {
  constructor() {
    this.entry = new BasicBlock();
    this.exit = new BasicBlock();
    this.blocks = [this.entry, this.exit];
  }

  createBlock() {
    const b = new BasicBlock();
    this.blocks.push(b);
    return b;
  }
}

// Build CFG context tracks break/continue targets for loops and labeled stmts
class BuildContext {
  constructor() {
    this.breakTargets = [];    // stack of {label, block}
    this.continueTargets = []; // stack of {label, block}
    this.returnTarget = null;  // exit block for returns
    this.throwTarget = null;   // catch block or exit
  }

  pushLoop(breakBlock, continueBlock, label) {
    this.breakTargets.push({ label, block: breakBlock });
    this.continueTargets.push({ label, block: continueBlock });
  }

  popLoop() {
    this.breakTargets.pop();
    this.continueTargets.pop();
  }

  pushSwitch(breakBlock, label) {
    this.breakTargets.push({ label, block: breakBlock });
  }

  popSwitch() {
    this.breakTargets.pop();
  }

  getBreakTarget(label) {
    if (label) {
      for (let i = this.breakTargets.length - 1; i >= 0; i--) {
        if (this.breakTargets[i].label === label) return this.breakTargets[i].block;
      }
    }
    return this.breakTargets.length > 0
      ? this.breakTargets[this.breakTargets.length - 1].block
      : null;
  }

  getContinueTarget(label) {
    if (label) {
      for (let i = this.continueTargets.length - 1; i >= 0; i--) {
        if (this.continueTargets[i].label === label) return this.continueTargets[i].block;
      }
    }
    return this.continueTargets.length > 0
      ? this.continueTargets[this.continueTargets.length - 1].block
      : null;
  }
}

// Build a CFG for a function body (or program body)
export function buildCFG(bodyNode) {
  blockIdCounter = 0;
  const cfg = new CFG();
  const ctx = new BuildContext();
  ctx.returnTarget = cfg.exit;
  ctx.throwTarget = cfg.exit;

  const stmts = bodyNode.body || bodyNode;
  const afterBlock = buildStatements(stmts, cfg.entry, cfg, ctx);
  if (afterBlock) afterBlock.connect(cfg.exit);

  return cfg;
}

// Process a list of statements, returning the "current" block after processing
// Returns null if control flow is definitely terminated (return/throw/break/continue)
function buildStatements(stmts, current, cfg, ctx) {
  for (const stmt of stmts) {
    if (!current) return null; // dead code after terminator
    current = buildStatement(stmt, current, cfg, ctx);
  }
  return current;
}

function buildStatement(stmt, current, cfg, ctx) {
  if (!stmt) return current;

  switch (stmt.type) {
    case 'ExpressionStatement':
      current.addNode(stmt.expression);
      return current;

    case 'VariableDeclaration':
      for (const decl of stmt.declarations) {
        if (stmt.kind === 'let' || stmt.kind === 'const') decl._blockScoped = true;
        current.addNode(decl);
      }
      return current;

    case 'ReturnStatement':
      current.addNode(stmt);
      current.connect(ctx.returnTarget);
      return null; // terminates

    case 'ThrowStatement':
      current.addNode(stmt);
      current.connect(ctx.throwTarget);
      return null;

    case 'BreakStatement': {
      const target = ctx.getBreakTarget(stmt.label?.name);
      if (target) current.connect(target);
      return null;
    }

    case 'ContinueStatement': {
      const target = ctx.getContinueTarget(stmt.label?.name);
      if (target) current.connect(target);
      return null;
    }

    case 'IfStatement':
      return buildIf(stmt, current, cfg, ctx);

    case 'WhileStatement':
      return buildWhile(stmt, current, cfg, ctx);

    case 'DoWhileStatement':
      return buildDoWhile(stmt, current, cfg, ctx);

    case 'ForStatement':
      return buildFor(stmt, current, cfg, ctx);

    case 'ForInStatement':
    case 'ForOfStatement':
      return buildForIn(stmt, current, cfg, ctx);

    case 'SwitchStatement':
      return buildSwitch(stmt, current, cfg, ctx);

    case 'TryStatement':
      return buildTry(stmt, current, cfg, ctx);

    case 'LabeledStatement':
      return buildLabeled(stmt, current, cfg, ctx);

    case 'BlockStatement':
      return buildStatements(stmt.body, current, cfg, ctx);

    case 'FunctionDeclaration':
      // Function declarations are hoisted; add as node for reference
      current.addNode(stmt);
      return current;

    case 'ClassDeclaration':
      current.addNode(stmt);
      return current;

    case 'ImportDeclaration':
    case 'ExportNamedDeclaration':
    case 'ExportDefaultDeclaration':
    case 'ExportAllDeclaration':
      current.addNode(stmt);
      return current;

    case 'EmptyStatement':
    case 'DebuggerStatement':
      return current;

    default:
      // Unknown statement type — add as opaque node
      current.addNode(stmt);
      return current;
  }
}

function buildIf(stmt, current, cfg, ctx) {
  // Test expression is in current block
  current.addNode({ type: '_Test', test: stmt.test, loc: stmt.loc });

  const thenBlock = cfg.createBlock();
  const joinBlock = cfg.createBlock();

  // True edge — annotate with the branch condition for path-sensitive analysis
  thenBlock.branchCondition = stmt.test;
  thenBlock.branchPolarity = true;
  current.connect(thenBlock);
  const afterThen = buildStatement(stmt.consequent, thenBlock, cfg, ctx);
  if (afterThen) afterThen.connect(joinBlock);

  // False edge
  if (stmt.alternate) {
    const elseBlock = cfg.createBlock();
    elseBlock.branchCondition = stmt.test;
    elseBlock.branchPolarity = false;
    current.connect(elseBlock);
    const afterElse = buildStatement(stmt.alternate, elseBlock, cfg, ctx);
    if (afterElse) afterElse.connect(joinBlock);
  } else {
    // No else clause: fall-through represents the false branch.
    // If the consequent terminates (return/throw/break), the join block only
    // executes when the test is FALSE — annotate with negated condition.
    if (!afterThen) {
      joinBlock.branchCondition = stmt.test;
      joinBlock.branchPolarity = false;
    }
    current.connect(joinBlock);
  }

  return joinBlock.predecessors.length > 0 ? joinBlock : null;
}

function buildWhile(stmt, current, cfg, ctx) {
  const headerBlock = cfg.createBlock();
  const bodyBlock = cfg.createBlock();
  const exitBlock = cfg.createBlock();

  current.connect(headerBlock);
  headerBlock.addNode({ type: '_Test', test: stmt.test, loc: stmt.loc });

  headerBlock.connect(bodyBlock);   // true → body
  headerBlock.connect(exitBlock);   // false → exit

  ctx.pushLoop(exitBlock, headerBlock, null);
  const afterBody = buildStatement(stmt.body, bodyBlock, cfg, ctx);
  ctx.popLoop();

  if (afterBody) afterBody.connect(headerBlock); // loop back

  return exitBlock;
}

function buildDoWhile(stmt, current, cfg, ctx) {
  const bodyBlock = cfg.createBlock();
  const testBlock = cfg.createBlock();
  const exitBlock = cfg.createBlock();

  current.connect(bodyBlock);

  ctx.pushLoop(exitBlock, testBlock, null);
  const afterBody = buildStatement(stmt.body, bodyBlock, cfg, ctx);
  ctx.popLoop();

  if (afterBody) afterBody.connect(testBlock);
  testBlock.addNode({ type: '_Test', test: stmt.test, loc: stmt.loc });
  testBlock.connect(bodyBlock);  // true → loop
  testBlock.connect(exitBlock);  // false → exit

  return exitBlock;
}

function buildFor(stmt, current, cfg, ctx) {
  // Init
  if (stmt.init) {
    if (stmt.init.type === 'VariableDeclaration') {
      for (const decl of stmt.init.declarations) {
        if (stmt.init.kind === 'let' || stmt.init.kind === 'const') decl._blockScoped = true;
        current.addNode(decl);
      }
    } else {
      current.addNode(stmt.init);
    }
  }

  const headerBlock = cfg.createBlock();
  const bodyBlock = cfg.createBlock();
  const updateBlock = cfg.createBlock();
  const exitBlock = cfg.createBlock();

  current.connect(headerBlock);

  if (stmt.test) {
    headerBlock.addNode({ type: '_Test', test: stmt.test, loc: stmt.loc });
    headerBlock.connect(bodyBlock);
    headerBlock.connect(exitBlock);
  } else {
    headerBlock.connect(bodyBlock); // infinite loop (no test)
  }

  ctx.pushLoop(exitBlock, updateBlock, null);
  const afterBody = buildStatement(stmt.body, bodyBlock, cfg, ctx);
  ctx.popLoop();

  if (afterBody) afterBody.connect(updateBlock);
  if (stmt.update) updateBlock.addNode(stmt.update);
  updateBlock.connect(headerBlock);

  return exitBlock;
}

function buildForIn(stmt, current, cfg, ctx) {
  const headerBlock = cfg.createBlock();
  const bodyBlock = cfg.createBlock();
  const exitBlock = cfg.createBlock();

  current.addNode(stmt.right); // evaluate the iterable
  current.connect(headerBlock);

  // Header: implicit "has next?" test
  headerBlock.addNode({ type: '_ForInOf', left: stmt.left, right: stmt.right, loc: stmt.loc });
  headerBlock.connect(bodyBlock);
  headerBlock.connect(exitBlock);

  ctx.pushLoop(exitBlock, headerBlock, null);
  const afterBody = buildStatement(stmt.body, bodyBlock, cfg, ctx);
  ctx.popLoop();

  if (afterBody) afterBody.connect(headerBlock);

  return exitBlock;
}

function buildSwitch(stmt, current, cfg, ctx) {
  current.addNode(stmt.discriminant);
  const exitBlock = cfg.createBlock();

  ctx.pushSwitch(exitBlock, null);

  let prevFallthrough = null;
  for (const caseNode of stmt.cases) {
    const caseBlock = cfg.createBlock();

    // Edge from switch test to each case
    current.connect(caseBlock);

    // Fall-through from previous case
    if (prevFallthrough) prevFallthrough.connect(caseBlock);

    if (caseNode.test) {
      caseBlock.addNode({ type: '_Test', test: caseNode.test, loc: caseNode.loc });
    }

    const afterCase = buildStatements(caseNode.consequent, caseBlock, cfg, ctx);
    prevFallthrough = afterCase; // may be null if break/return
  }

  ctx.popSwitch();

  // Last case falls through to exit if no break
  if (prevFallthrough) prevFallthrough.connect(exitBlock);

  // If no default case, switch test can skip to exit
  const hasDefault = stmt.cases.some(c => c.test === null);
  if (!hasDefault) current.connect(exitBlock);

  return exitBlock;
}

function buildTry(stmt, current, cfg, ctx) {
  const tryBlock = cfg.createBlock();
  const joinBlock = cfg.createBlock();

  current.connect(tryBlock);

  let catchBlock = null;
  if (stmt.handler) {
    catchBlock = cfg.createBlock();
    catchBlock.addNode({ type: '_CatchParam', param: stmt.handler.param, loc: stmt.handler.loc });

    const prevThrow = ctx.throwTarget;
    ctx.throwTarget = catchBlock;
    const afterTry = buildStatement(stmt.block, tryBlock, cfg, ctx);
    ctx.throwTarget = prevThrow;

    if (afterTry) afterTry.connect(joinBlock);

    // Try block can also throw → catch
    tryBlock.connect(catchBlock);

    const afterCatch = buildStatement(stmt.handler.body, catchBlock, cfg, ctx);
    if (afterCatch) afterCatch.connect(joinBlock);
  } else {
    const afterTry = buildStatement(stmt.block, tryBlock, cfg, ctx);
    if (afterTry) afterTry.connect(joinBlock);
  }

  if (stmt.finalizer) {
    const finallyBlock = cfg.createBlock();
    const afterFinally = cfg.createBlock();

    // Everything goes through finally
    // Redirect joinBlock to finally
    joinBlock.connect(finallyBlock);
    const afterFin = buildStatement(stmt.finalizer, finallyBlock, cfg, ctx);
    if (afterFin) afterFin.connect(afterFinally);
    return afterFinally.predecessors.length > 0 ? afterFinally : null;
  }

  return joinBlock.predecessors.length > 0 ? joinBlock : null;
}

function buildLabeled(stmt, current, cfg, ctx) {
  const label = stmt.label.name;
  const exitBlock = cfg.createBlock();

  // Push break target for this label
  ctx.breakTargets.push({ label, block: exitBlock });

  // If it's a loop, the loop builder will push its own continue target
  const afterBody = buildStatement(stmt.body, current, cfg, ctx);

  // Pop the break target we pushed
  const idx = ctx.breakTargets.findIndex(t => t.label === label);
  if (idx >= 0) ctx.breakTargets.splice(idx, 1);

  if (afterBody) afterBody.connect(exitBlock);
  return exitBlock.predecessors.length > 0 ? exitBlock : null;
}
