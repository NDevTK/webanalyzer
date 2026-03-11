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

  _getTarget(targets, label) {
    if (label) {
      for (let i = targets.length - 1; i >= 0; i--) {
        if (targets[i].label === label) return targets[i].block;
      }
    }
    return targets.length > 0 ? targets[targets.length - 1].block : null;
  }

  getBreakTarget(label) { return this._getTarget(this.breakTargets, label); }
  getContinueTarget(label) { return this._getTarget(this.continueTargets, label); }
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

function addDeclarations(declarations, kind, block) {
  for (const decl of declarations) {
    if (kind === 'let' || kind === 'const') decl._blockScoped = true;
    block.addNode(decl);
  }
}

// Fully iterative CFG builder using explicit frame stack
// Frame types: STMTS, IF, WHILE, DO_WHILE, FOR, FOR_IN, SWITCH, TRY, LABELED
function buildStatements(rootStmts, rootCurrent, cfg, ctx) {
  const S = []; // frame stack
  let cr; // child result from completed frame

  S.push({ t: 'S', stmts: rootStmts, idx: 0, cur: rootCurrent });

  while (S.length > 0) {
    const f = S[S.length - 1];

    switch (f.t) {
      case 'S': { // STMTS — process a statement list
        if (cr !== undefined) { f.cur = cr; cr = undefined; }
        if (!f.cur || f.idx >= f.stmts.length) {
          cr = f.cur; S.pop(); continue;
        }
        const stmt = f.stmts[f.idx++];
        if (!stmt) continue;

        switch (stmt.type) {
          // ── Simple (non-recursive) statements ──
          case 'ExpressionStatement':
            f.cur.addNode(stmt.expression); continue;
          case 'VariableDeclaration':
            addDeclarations(stmt.declarations, stmt.kind, f.cur); continue;
          case 'ReturnStatement':
            f.cur.addNode(stmt); f.cur.connect(ctx.returnTarget); f.cur = null; continue;
          case 'ThrowStatement':
            f.cur.addNode(stmt); f.cur.connect(ctx.throwTarget); f.cur = null; continue;
          case 'BreakStatement': {
            const target = ctx.getBreakTarget(stmt.label?.name);
            if (target) f.cur.connect(target);
            f.cur = null; continue;
          }
          case 'ContinueStatement': {
            const target = ctx.getContinueTarget(stmt.label?.name);
            if (target) f.cur.connect(target);
            f.cur = null; continue;
          }
          case 'FunctionDeclaration':
          case 'ClassDeclaration':
          case 'ImportDeclaration':
          case 'ExportNamedDeclaration':
          case 'ExportDefaultDeclaration':
          case 'ExportAllDeclaration':
            f.cur.addNode(stmt); continue;
          case 'EmptyStatement':
          case 'DebuggerStatement':
            continue;

          // ── Complex statements → push frame ──
          case 'IfStatement': {
            const thenBlock = cfg.createBlock();
            const joinBlock = cfg.createBlock();
            thenBlock.branchCondition = stmt.test;
            thenBlock.branchPolarity = true;
            f.cur.addNode({ type: '_Test', test: stmt.test, loc: stmt.loc });
            f.cur.connect(thenBlock);
            S.push({ t: 'IF', step: 0, stmt, oc: f.cur, thenBlock, joinBlock });
            S.push({ t: 'S', stmts: [stmt.consequent], idx: 0, cur: thenBlock });
            continue;
          }
          case 'WhileStatement': {
            const headerBlock = cfg.createBlock();
            const bodyBlock = cfg.createBlock();
            const exitBlock = cfg.createBlock();
            f.cur.connect(headerBlock);
            headerBlock.addNode({ type: '_Test', test: stmt.test, loc: stmt.loc });
            headerBlock.connect(bodyBlock);
            headerBlock.connect(exitBlock);
            ctx.pushLoop(exitBlock, headerBlock, null);
            S.push({ t: 'W', headerBlock, exitBlock });
            S.push({ t: 'S', stmts: [stmt.body], idx: 0, cur: bodyBlock });
            continue;
          }
          case 'DoWhileStatement': {
            const bodyBlock = cfg.createBlock();
            const testBlock = cfg.createBlock();
            const exitBlock = cfg.createBlock();
            f.cur.connect(bodyBlock);
            ctx.pushLoop(exitBlock, testBlock, null);
            S.push({ t: 'DW', stmt, bodyBlock, testBlock, exitBlock });
            S.push({ t: 'S', stmts: [stmt.body], idx: 0, cur: bodyBlock });
            continue;
          }
          case 'ForStatement': {
            if (stmt.init) {
              if (stmt.init.type === 'VariableDeclaration') {
                addDeclarations(stmt.init.declarations, stmt.init.kind, f.cur);
              } else {
                f.cur.addNode(stmt.init);
              }
            }
            const headerBlock = cfg.createBlock();
            const bodyBlock = cfg.createBlock();
            const updateBlock = cfg.createBlock();
            const exitBlock = cfg.createBlock();
            f.cur.connect(headerBlock);
            if (stmt.test) {
              headerBlock.addNode({ type: '_Test', test: stmt.test, loc: stmt.loc });
              headerBlock.connect(bodyBlock);
              headerBlock.connect(exitBlock);
            } else {
              headerBlock.connect(bodyBlock);
            }
            ctx.pushLoop(exitBlock, updateBlock, null);
            S.push({ t: 'F', stmt, updateBlock, headerBlock, exitBlock });
            S.push({ t: 'S', stmts: [stmt.body], idx: 0, cur: bodyBlock });
            continue;
          }
          case 'ForInStatement':
          case 'ForOfStatement': {
            const headerBlock = cfg.createBlock();
            const bodyBlock = cfg.createBlock();
            const exitBlock = cfg.createBlock();
            f.cur.addNode(stmt.right);
            f.cur.connect(headerBlock);
            headerBlock.addNode({ type: '_ForInOf', left: stmt.left, right: stmt.right, loc: stmt.loc, _isForIn: stmt.type === 'ForInStatement' });
            headerBlock.connect(bodyBlock);
            headerBlock.connect(exitBlock);
            ctx.pushLoop(exitBlock, headerBlock, null);
            S.push({ t: 'FI', headerBlock, exitBlock });
            S.push({ t: 'S', stmts: [stmt.body], idx: 0, cur: bodyBlock });
            continue;
          }
          case 'SwitchStatement': {
            f.cur.addNode(stmt.discriminant);
            const exitBlock = cfg.createBlock();
            ctx.pushSwitch(exitBlock, null);
            S.push({ t: 'SW', stmt, ci: 0, pf: null, sc: f.cur, exitBlock });
            continue;
          }
          case 'TryStatement': {
            const tryBlock = cfg.createBlock();
            const joinBlock = cfg.createBlock();
            f.cur.connect(tryBlock);
            let catchBlock = null;
            let prevThrow = null;
            if (stmt.handler) {
              catchBlock = cfg.createBlock();
              catchBlock.addNode({ type: '_CatchParam', param: stmt.handler.param, loc: stmt.handler.loc });
              prevThrow = ctx.throwTarget;
              ctx.throwTarget = catchBlock;
            }
            S.push({ t: 'TRY', step: 0, stmt, tryBlock, joinBlock, catchBlock, prevThrow });
            S.push({ t: 'S', stmts: [stmt.block], idx: 0, cur: tryBlock });
            continue;
          }
          case 'LabeledStatement': {
            const label = stmt.label.name;
            const exitBlock = cfg.createBlock();
            ctx.breakTargets.push({ label, block: exitBlock });
            S.push({ t: 'L', label, exitBlock });
            S.push({ t: 'S', stmts: [stmt.body], idx: 0, cur: f.cur });
            continue;
          }
          case 'BlockStatement':
            S.push({ t: 'S', stmts: stmt.body, idx: 0, cur: f.cur });
            continue;
          case 'WithStatement':
            f.cur.addNode({ type: '_WithScope', object: stmt.object, loc: stmt.loc });
            S.push({ t: 'S', stmts: [stmt.body], idx: 0, cur: f.cur });
            continue;
          default:
            f.cur.addNode(stmt); continue;
        }
        break; // unreachable
      }

      case 'IF': {
        switch (f.step) {
          case 0: { // After consequent
            const afterThen = cr; cr = undefined;
            f.afterThen = afterThen;
            if (afterThen) afterThen.connect(f.joinBlock);
            if (f.stmt.alternate) {
              f.step = 1;
              const elseBlock = cfg.createBlock();
              elseBlock.branchCondition = f.stmt.test;
              elseBlock.branchPolarity = false;
              f.oc.connect(elseBlock);
              S.push({ t: 'S', stmts: [f.stmt.alternate], idx: 0, cur: elseBlock });
            } else {
              if (!afterThen) {
                f.joinBlock.branchCondition = f.stmt.test;
                f.joinBlock.branchPolarity = false;
              }
              f.oc.connect(f.joinBlock);
              cr = f.joinBlock.predecessors.length > 0 ? f.joinBlock : null;
              S.pop();
            }
            continue;
          }
          case 1: { // After alternate
            const afterElse = cr; cr = undefined;
            if (afterElse) afterElse.connect(f.joinBlock);
            cr = f.joinBlock.predecessors.length > 0 ? f.joinBlock : null;
            S.pop();
            continue;
          }
        }
        break;
      }

      case 'W': { // WHILE — after body
        const afterBody = cr; cr = undefined;
        ctx.popLoop();
        if (afterBody) afterBody.connect(f.headerBlock);
        cr = f.exitBlock;
        S.pop(); continue;
      }

      case 'DW': { // DO_WHILE — after body
        const afterBody = cr; cr = undefined;
        ctx.popLoop();
        if (afterBody) afterBody.connect(f.testBlock);
        f.testBlock.addNode({ type: '_Test', test: f.stmt.test, loc: f.stmt.loc });
        f.testBlock.connect(f.bodyBlock);
        f.testBlock.connect(f.exitBlock);
        cr = f.exitBlock;
        S.pop(); continue;
      }

      case 'F': { // FOR — after body
        const afterBody = cr; cr = undefined;
        ctx.popLoop();
        if (afterBody) afterBody.connect(f.updateBlock);
        if (f.stmt.update) f.updateBlock.addNode(f.stmt.update);
        f.updateBlock.connect(f.headerBlock);
        cr = f.exitBlock;
        S.pop(); continue;
      }

      case 'FI': { // FOR_IN/OF — after body
        const afterBody = cr; cr = undefined;
        ctx.popLoop();
        if (afterBody) afterBody.connect(f.headerBlock);
        cr = f.exitBlock;
        S.pop(); continue;
      }

      case 'SW': { // SWITCH — iterates over cases
        if (cr !== undefined) { f.pf = cr; cr = undefined; f.ci++; }
        if (f.ci >= f.stmt.cases.length) {
          ctx.popSwitch();
          if (f.pf) f.pf.connect(f.exitBlock);
          const hasDefault = f.stmt.cases.some(c => c.test === null);
          if (!hasDefault) f.sc.connect(f.exitBlock);
          cr = f.exitBlock;
          S.pop(); continue;
        }
        const caseNode = f.stmt.cases[f.ci];
        const caseBlock = cfg.createBlock();
        f.sc.connect(caseBlock);
        if (f.pf) f.pf.connect(caseBlock);
        if (caseNode.test) {
          caseBlock.addNode({ type: '_Test', test: caseNode.test, loc: caseNode.loc });
        }
        S.push({ t: 'S', stmts: caseNode.consequent, idx: 0, cur: caseBlock });
        continue;
      }

      case 'TRY': {
        switch (f.step) {
          case 0: { // After try block
            const afterTry = cr; cr = undefined;
            if (f.catchBlock) {
              ctx.throwTarget = f.prevThrow;
              if (afterTry) afterTry.connect(f.joinBlock);
              f.tryBlock.connect(f.catchBlock);
              f.step = 1;
              S.push({ t: 'S', stmts: [f.stmt.handler.body], idx: 0, cur: f.catchBlock });
            } else {
              if (afterTry) afterTry.connect(f.joinBlock);
              if (f.stmt.finalizer) {
                f.step = 2;
                const finallyBlock = cfg.createBlock();
                f.afterFinally = cfg.createBlock();
                f.joinBlock.connect(finallyBlock);
                S.push({ t: 'S', stmts: [f.stmt.finalizer], idx: 0, cur: finallyBlock });
              } else {
                cr = f.joinBlock.predecessors.length > 0 ? f.joinBlock : null;
                S.pop();
              }
            }
            continue;
          }
          case 1: { // After catch body
            const afterCatch = cr; cr = undefined;
            if (afterCatch) afterCatch.connect(f.joinBlock);
            if (f.stmt.finalizer) {
              f.step = 2;
              const finallyBlock = cfg.createBlock();
              f.afterFinally = cfg.createBlock();
              f.joinBlock.connect(finallyBlock);
              S.push({ t: 'S', stmts: [f.stmt.finalizer], idx: 0, cur: finallyBlock });
            } else {
              cr = f.joinBlock.predecessors.length > 0 ? f.joinBlock : null;
              S.pop();
            }
            continue;
          }
          case 2: { // After finally
            const afterFin = cr; cr = undefined;
            if (afterFin) afterFin.connect(f.afterFinally);
            cr = f.afterFinally.predecessors.length > 0 ? f.afterFinally : null;
            S.pop();
            continue;
          }
        }
        break;
      }

      case 'L': { // LABELED — after body
        const afterBody = cr; cr = undefined;
        const idx = ctx.breakTargets.findIndex(t => t.label === f.label);
        if (idx >= 0) ctx.breakTargets.splice(idx, 1);
        if (afterBody) afterBody.connect(f.exitBlock);
        cr = f.exitBlock.predecessors.length > 0 ? f.exitBlock : null;
        S.pop(); continue;
      }
    }
  }

  return cr;
}
