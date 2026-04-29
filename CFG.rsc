module analysis::CFG

// ============================================================
//  Trust-Transpiler — Control Flow Graph Builder
//  analysis::CFG
//
//  Converts a UIRProc (list of BasicBlocks) into an explicit
//  CFG and provides interprocedural call-graph support.
// ============================================================

import lang::universal::IR;
import Set;
import Map;
import List;
import Relation;

// ------------------------------------------------------------------
// 1. CFG node types
// ------------------------------------------------------------------

data CFGNode
  = entry(str procName)
  | exit(str procName)
  | instrNode(str procName, str blockLabel, int instrIndex, UIRInstr instr)
  ;

// A labelled directed edge
alias CFGEdge = tuple[CFGNode from, CFGNode to, EdgeKind kind];

data EdgeKind
  = flowEdge()       // normal sequential flow
  | trueEdge()       // conditional — taken when condition is true
  | falseEdge()      // conditional — taken when condition is false
  | callEdge()       // call site → callee entry
  | returnEdge()     // callee exit → call-site successor
  | exceptionEdge()  // throw → catch handler
  ;

// ------------------------------------------------------------------
// 2. Intra-procedural CFG for a single UIRProc
// ------------------------------------------------------------------

data ProcCFG = procCFG(
  str name,
  CFGNode entryNode,
  CFGNode exitNode,
  set[CFGNode] nodes,
  set[CFGEdge] edges,
  map[str, BasicBlock] blockIndex,   // label → block
  map[CFGNode, set[CFGNode]] pred,   // predecessor map
  map[CFGNode, set[CFGNode]] succ    // successor map
);

// ------------------------------------------------------------------
// 3. Build intra-procedural CFG from a UIRProc
// ------------------------------------------------------------------

ProcCFG buildProcCFG(UIRProc p) {
  str pname = p.name;

  CFGNode entryN = entry(pname);
  CFGNode exitN  = exit(pname);

  set[CFGNode] nodes = {entryN, exitN};
  set[CFGEdge] edges = {};

  map[str, BasicBlock] blkIdx = ( b.label : b | b <- p.blocks );

  // --- Build instruction nodes for each block ----------------
  // Map: blockLabel → ordered list of CFGNodes for its instrs
  map[str, list[CFGNode]] blockNodes = ();

  for (BasicBlock blk <- p.blocks) {
    list[CFGNode] bns = [];
    for (int idx <- [0 .. size(blk.instrs)]) {
      CFGNode n = instrNode(pname, blk.label, idx, blk.instrs[idx]);
      nodes += {n};
      bns   += [n];
    }
    blockNodes[blk.label] = bns;
  }

  // --- Sequential edges within each block -------------------
  for (BasicBlock blk <- p.blocks) {
    list[CFGNode] bns = blockNodes[blk.label];
    for (int idx <- [0 .. size(bns) - 1]) {
      edges += {<bns[idx], bns[idx + 1], flowEdge()>};
    }
  }

  // --- Entry → first instruction of first block -------------
  if (!isEmpty(p.blocks)) {
    BasicBlock first = p.blocks[0];
    if (!isEmpty(blockNodes[first.label])) {
      edges += {<entryN, blockNodes[first.label][0], flowEdge()>};
    } else {
      edges += {<entryN, exitN, flowEdge()>};
    }
  } else {
    edges += {<entryN, exitN, flowEdge()>};
  }

  // --- Inter-block edges (jumps / branches) -----------------
  for (BasicBlock blk <- p.blocks) {
    list[CFGNode] bns = blockNodes[blk.label];
    if (isEmpty(bns)) continue;

    CFGNode lastN = bns[size(bns) - 1];
    UIRInstr lastI = blk.instrs[size(blk.instrs) - 1];

    switch (lastI) {
      case iJump(lbl): {
        if (lbl in blockNodes) {
          edges += {<lastN, blockNodes[lbl][0], flowEdge()>};
        }
      }
      case iCondJump(_, tLbl, fLbl): {
        if (tLbl in blockNodes)
          edges += {<lastN, blockNodes[tLbl][0], trueEdge()>};
        if (fLbl in blockNodes)
          edges += {<lastN, blockNodes[fLbl][0], falseEdge()>};
      }
      case iReturn(_, _): {
        edges += {<lastN, exitN, flowEdge()>};
      }
      case iThrow(_): {
        // Conservative: connect throws to exit (handler wiring done below)
        edges += {<lastN, exitN, exceptionEdge()>};
      }
      default: {
        // Fall through to next block if defined in successor list
        for (str succ <- blk.successors) {
          if (succ in blockNodes && !isEmpty(blockNodes[succ])) {
            edges += {<lastN, blockNodes[succ][0], flowEdge()>};
          }
        }
      }
    }
  }

  // --- Wire iCatch handlers ---------------------------------
  for (BasicBlock blk <- p.blocks) {
    for (int idx <- [0 .. size(blk.instrs)]) {
      if (iCatch(_, _, hLbl) := blk.instrs[idx]) {
        CFGNode catchNode = instrNode(pname, blk.label, idx, blk.instrs[idx]);
        if (hLbl in blockNodes && !isEmpty(blockNodes[hLbl])) {
          edges += {<catchNode, blockNodes[hLbl][0], exceptionEdge()>};
        }
      }
    }
  }

  // --- Build pred / succ maps from edge set -----------------
  map[CFGNode, set[CFGNode]] succMap = ();
  map[CFGNode, set[CFGNode]] predMap = ();

  for (CFGNode n <- nodes) {
    succMap[n] = {};
    predMap[n] = {};
  }
  for (<CFGNode f, CFGNode t, _> <- edges) {
    succMap[f] = (f in succMap ? succMap[f] : {}) + {t};
    predMap[t] = (t in predMap ? predMap[t] : {}) + {f};
  }

  return procCFG(
    pname,
    entryN,
    exitN,
    nodes,
    edges,
    blkIdx,
    predMap,
    succMap
  );
}

// ------------------------------------------------------------------
// 4. Program-level (interprocedural) call graph
// ------------------------------------------------------------------

data CallGraph = callGraph(
  set[str] procs,                      // all procedure names
  rel[str caller, str callee] calls,   // direct call edges
  map[str, ProcCFG] cfgs               // per-proc CFG
);

CallGraph buildCallGraph(UIRUnit u) {
  set[str] allProcs = { p.name | p <- u.procs };
  rel[str, str] callRel = {};
  map[str, ProcCFG] cfgMap = ();

  for (UIRProc p <- u.procs) {
    ProcCFG pcfg = buildProcCFG(p);
    cfgMap[p.name] = pcfg;

    // Detect direct calls in every instruction
    for (BasicBlock blk <- p.blocks) {
      for (UIRInstr i <- blk.instrs) {
        switch (i) {
          case iCall(_, callee, _, _):
            callRel += {<p.name, callee>};
          case iMethodCall(_, _, method, _, _):
            // Record as  caller → "receiver.method" (approximation)
            callRel += {<p.name, method>};
          default: ;
        }
      }
    }
  }

  return callGraph(allProcs, callRel, cfgMap);
}

// ------------------------------------------------------------------
// 5. Dominance helpers (simple iterative algorithm)
// ------------------------------------------------------------------

// Returns the set of nodes dominated by `n` in a proc CFG.
// dom(n) = {n} ∪ (∩ dom(p) for p in pred(n))
map[CFGNode, set[CFGNode]] computeDominators(ProcCFG cfg) {
  map[CFGNode, set[CFGNode]] dom = ();

  // Initialise: entry dominates only itself; rest dominate everything
  dom[cfg.entryNode] = {cfg.entryNode};
  for (CFGNode n <- cfg.nodes) {
    if (n != cfg.entryNode) dom[n] = cfg.nodes;
  }

  bool changed = true;
  while (changed) {
    changed = false;
    for (CFGNode n <- cfg.nodes) {
      if (n == cfg.entryNode) continue;

      set[CFGNode] preds = cfg.pred[n] ? {};
      set[CFGNode] newDom;

      if (isEmpty(preds)) {
        newDom = {n};
      } else {
        newDom = cfg.nodes;
        for (CFGNode p <- preds) {
          newDom = newDom & dom[p];
        }
        newDom += {n};
      }

      if (newDom != dom[n]) {
        dom[n] = newDom;
        changed = true;
      }
    }
  }
  return dom;
}

// ------------------------------------------------------------------
// 6. Reachability query (BFS over CFG edges)
// ------------------------------------------------------------------

bool isReachable(CFGNode src, CFGNode tgt, ProcCFG cfg) {
  if (src == tgt) return true;

  set[CFGNode] visited = {src};
  list[CFGNode] worklist = [src];

  while (!isEmpty(worklist)) {
    CFGNode cur = worklist[0];
    worklist = worklist[1..];

    for (CFGNode nxt <- (cfg.succ[cur] ? {})) {
      if (nxt == tgt) return true;
      if (nxt notin visited) {
        visited += {nxt};
        worklist += [nxt];
      }
    }
  }
  return false;
}

// ------------------------------------------------------------------
// 7. Pretty-printer (DOT format) for debugging
// ------------------------------------------------------------------

str toDot(ProcCFG cfg) {
  str dot = "digraph \"<cfg.name>\" {\n";
  dot += "  rankdir=TB;\n";
  dot += "  node [shape=box fontname=\"Courier\" fontsize=9];\n";

  for (CFGNode n <- cfg.nodes) {
    str lbl = nodeDotLabel(n);
    str shape = (n == cfg.entryNode || n == cfg.exitNode) ? "ellipse" : "box";
    dot += "  \"<nodeDotId(n)>\" [label=\"<lbl>\" shape=<shape>];\n";
  }

  for (<CFGNode f, CFGNode t, EdgeKind k> <- cfg.edges) {
    str style = edgeDotStyle(k);
    dot += "  \"<nodeDotId(f)>\" -\> \"<nodeDotId(t)>\" [<style>];\n";
  }

  dot += "}\n";
  return dot;
}

private str nodeDotId(CFGNode n) {
  switch (n) {
    case entry(p):              return "entry_<p>";
    case exit(p):               return "exit_<p>";
    case instrNode(p, b, i, _): return "<p>_<b>_<i>";
  }
}

private str nodeDotLabel(CFGNode n) {
  switch (n) {
    case entry(p):              return "ENTRY\\n<p>";
    case exit(p):               return "EXIT\\n<p>";
    case instrNode(_, b, i, instr): return "<b>[<i>]\\n<instrShortName(instr)>";
  }
}

private str instrShortName(UIRInstr i) {
  switch (i) {
    case iAssign(d, _, _):       return "ASSIGN <d>";
    case iCall(d, c, _, _):      return "CALL <c> -\> <d>";
    case iMethodCall(d, _, m, _, _): return "MCALL .<m> -\> <d>";
    case iReturn(_, _):          return "RETURN";
    case iStore(_, _, _):        return "STORE";
    case iLoad(d, _, _):         return "LOAD -\> <d>";
    case iJump(l):               return "JUMP <l>";
    case iCondJump(_, t, f):     return "BRANCH T:<t> F:<f>";
    case iLabel(l):              return "LABEL <l>";
    case iThrow(_):              return "THROW";
    case iCatch(v, _, h):        return "CATCH <v> @ <h>";
    case iNop():                 return "NOP";
    case iComment(t):            return "// <t>";
    case iEnterScope(n):         return "ENTER <n>";
    case iExitScope(n):          return "EXIT <n>";
    default:                     return "INSTR";
  }
}

private str edgeDotStyle(EdgeKind k) {
  switch (k) {
    case flowEdge():      return "color=black";
    case trueEdge():      return "color=green label=\"T\"";
    case falseEdge():     return "color=red label=\"F\"";
    case callEdge():      return "color=blue style=dashed label=\"call\"";
    case returnEdge():    return "color=purple style=dashed label=\"ret\"";
    case exceptionEdge(): return "color=orange style=dotted label=\"exn\"";
    default:              return "";
  }
}
