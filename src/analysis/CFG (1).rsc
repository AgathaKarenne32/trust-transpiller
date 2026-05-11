module analysis::CFG

/*
  Fixes applied:
  1. Removed type annotations inside switch patterns that caused
     "Undeclared type: UIRInstr" — Rascal does not allow explicit type
     in pattern match variables inside switch; use bare names.
  2. Replaced all uses of the `expr ? default` map-lookup operator with
     explicit `(k in m) ? m[k] : default` — the short form is unreliable
     in Rascal 0.42 and caused runtime errors.
  3. iReturn field renamed retVal to match IR.rsc.
*/

import lang::universal::IR;
import lang::universal::SecurityDefs;
import Set;
import Map;
import List;
import Relation;

data CFGNode
  = entry(str procName)
  | exit(str procName)
  | instrNode(str procName, str blockLabel, int instrIndex, UIRInstr instr)
  ;

alias CFGEdge = tuple[CFGNode from, CFGNode to, EdgeKind kind];

data EdgeKind
  = flowEdge()
  | trueEdge()
  | falseEdge()
  | callEdge()
  | returnEdge()
  | exceptionEdge()
  ;

data ProcCFG = procCFG(
  str name,
  CFGNode entryNode,
  CFGNode exitNode,
  set[CFGNode] nodes,
  set[CFGEdge] edges,
  map[str, BasicBlock] blockIndex,
  map[CFGNode, set[CFGNode]] pred,
  map[CFGNode, set[CFGNode]] succ
);

data CallGraph = callGraph(
  set[str] procs,
  rel[str caller, str callee] calls,
  map[str, ProcCFG] cfgs
);

// Safe map lookups
private set[CFGNode] getSucc(map[CFGNode, set[CFGNode]] m, CFGNode k) {
  if (k in m) return m[k];
  return {};
}

private set[CFGNode] getPred(map[CFGNode, set[CFGNode]] m, CFGNode k) {
  if (k in m) return m[k];
  return {};
}

ProcCFG buildProcCFG(UIRProc p) {
  str pname = p.name;

  CFGNode entryN = entry(pname);
  CFGNode exitN  = exit(pname);

  set[CFGNode] nodes = {entryN, exitN};
  set[CFGEdge] edges = {};

  map[str, BasicBlock] blkIdx = (b.label : b | b <- p.blocks);

  map[str, list[CFGNode]] blockNodes = ();

  for (BasicBlock blk <- p.blocks) {
    list[CFGNode] bns = [];
    for (int idx <- index(blk.instrs)) {
      CFGNode n = instrNode(pname, blk.label, idx, blk.instrs[idx]);
      nodes    += {n};
      bns      += [n];
    }
    blockNodes[blk.label] = bns;
  }

  for (BasicBlock blk <- p.blocks) {
    list[CFGNode] bns = blockNodes[blk.label];
    for (int idx <- [0 .. size(bns) - 1]) {
      edges += {<bns[idx], bns[idx + 1], flowEdge()>};
    }
  }

  if (!isEmpty(p.blocks)) {
    BasicBlock first = p.blocks[0];
    if (first.label in blockNodes && !isEmpty(blockNodes[first.label])) {
      edges += {<entryN, blockNodes[first.label][0], flowEdge()>};
    } else {
      edges += {<entryN, exitN, flowEdge()>};
    }
  } else {
    edges += {<entryN, exitN, flowEdge()>};
  }

  for (BasicBlock blk <- p.blocks) {
    list[CFGNode] bns = blockNodes[blk.label];
    if (isEmpty(bns)) continue;

    CFGNode  lastN = bns[size(bns) - 1];
    UIRInstr lastI = blk.instrs[size(blk.instrs) - 1];

    switch (lastI) {
      case iJump(lbl): {
        if (lbl in blockNodes && !isEmpty(blockNodes[lbl]))
          edges += {<lastN, blockNodes[lbl][0], flowEdge()>};
      }
      case iCondJump(_, tLbl, fLbl): {
        if (tLbl in blockNodes && !isEmpty(blockNodes[tLbl]))
          edges += {<lastN, blockNodes[tLbl][0], trueEdge()>};
        if (fLbl in blockNodes && !isEmpty(blockNodes[fLbl]))
          edges += {<lastN, blockNodes[fLbl][0], falseEdge()>};
      }
      case iReturn(_, _): {
        edges += {<lastN, exitN, flowEdge()>};
      }
      case iThrow(_): {
        edges += {<lastN, exitN, exceptionEdge()>};
      }
      default: {
        for (str succLbl <- blk.successors) {
          if (succLbl in blockNodes && !isEmpty(blockNodes[succLbl]))
            edges += {<lastN, blockNodes[succLbl][0], flowEdge()>};
        }
      }
    }
  }

  for (BasicBlock blk <- p.blocks) {
    for (int idx <- index(blk.instrs)) {
      if (iCatch(_, _, hLbl) := blk.instrs[idx]) {
        CFGNode catchNode = instrNode(pname, blk.label, idx, blk.instrs[idx]);
        if (hLbl in blockNodes && !isEmpty(blockNodes[hLbl]))
          edges += {<catchNode, blockNodes[hLbl][0], exceptionEdge()>};
      }
    }
  }

  map[CFGNode, set[CFGNode]] succMap = (n : {} | n <- nodes);
  map[CFGNode, set[CFGNode]] predMap = (n : {} | n <- nodes);

  for (<CFGNode f, CFGNode t, _> <- edges) {
    succMap[f] = getSucc(succMap, f) + {t};
    predMap[t] = getPred(predMap, t) + {f};
  }

  return procCFG(pname, entryN, exitN, nodes, edges, blkIdx, predMap, succMap);
}

CallGraph buildCallGraph(UIRUnit u) {
  set[str] allProcs        = {p.name | p <- u.procs};
  rel[str, str] callRel    = {};
  map[str, ProcCFG] cfgMap = ();

  for (UIRProc p <- u.procs) {
    cfgMap[p.name] = buildProcCFG(p);

    for (BasicBlock blk <- p.blocks) {
      for (UIRInstr i <- blk.instrs) {
        switch (i) {
          case iCall(_, callee, _, _):
            callRel += {<p.name, callee>};
          case iMethodCall(_, _, method, _, _):
            callRel += {<p.name, method>};
          default: ;
        }
      }
    }
  }

  return callGraph(allProcs, callRel, cfgMap);
}

map[CFGNode, set[CFGNode]] computeDominators(ProcCFG cfg) {
  map[CFGNode, set[CFGNode]] dom = ();
  dom[cfg.entryNode] = {cfg.entryNode};
  for (CFGNode n <- cfg.nodes) {
    if (n != cfg.entryNode) dom[n] = cfg.nodes;
  }

  bool changed = true;
  while (changed) {
    changed = false;
    for (CFGNode n <- cfg.nodes) {
      if (n == cfg.entryNode) continue;

      set[CFGNode] preds = getPred(cfg.pred, n);
      set[CFGNode] newDom;

      if (isEmpty(preds)) {
        newDom = {n};
      } else {
        newDom = cfg.nodes;
        for (CFGNode pr <- preds) newDom = newDom & dom[pr];
        newDom += {n};
      }

      if (newDom != dom[n]) {
        dom[n]  = newDom;
        changed = true;
      }
    }
  }
  return dom;
}

bool isReachable(CFGNode src, CFGNode tgt, ProcCFG cfg) {
  if (src == tgt) return true;

  set[CFGNode]  visited  = {src};
  list[CFGNode] worklist = [src];

  while (!isEmpty(worklist)) {
    CFGNode cur = worklist[0];
    worklist    = worklist[1..];

    for (CFGNode nxt <- getSucc(cfg.succ, cur)) {
      if (nxt == tgt)        return true;
      if (nxt notin visited) {
        visited  += {nxt};
        worklist += [nxt];
      }
    }
  }
  return false;
}

str toDot(ProcCFG cfg) {
  str dot = "digraph \"<cfg.name>\" {\n";
  dot    += "  rankdir=TB;\n";
  dot    += "  node [shape=box fontname=\"Courier\" fontsize=9];\n";

  for (CFGNode n <- cfg.nodes) {
    str lbl   = nodeDotLabel(n);
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
    default:                    return "unknown";
  }
}

private str nodeDotLabel(CFGNode n) {
  switch (n) {
    case entry(p):                   return "ENTRY\\n<p>";
    case exit(p):                    return "EXIT\\n<p>";
    case instrNode(_, b, i, instr):  return "<b>[<i>]\\n<instrShortName(instr)>";
    default:                         return "?";
  }
}

private str instrShortName(UIRInstr i) {
  switch (i) {
    case iAssign(d, _, _):            return "ASSIGN <d>";
    case iCall(d, c, _, _):           return "CALL <c> -\> <d>";
    case iMethodCall(d, _, m, _, _):  return "MCALL .<m> -\> <d>";
    case iReturn(_, _):               return "RETURN";
    case iStore(_, _, _):             return "STORE";
    case iLoad(d, _, _):              return "LOAD -\> <d>";
    case iJump(l):                    return "JUMP <l>";
    case iCondJump(_, t, f):          return "BRANCH T:<t> F:<f>";
    case iLabel(l):                   return "LABEL <l>";
    case iThrow(_):                   return "THROW";
    case iCatch(v, _, h):             return "CATCH <v> @ <h>";
    case iNop():                      return "NOP";
    case iComment(t):                 return "// <t>";
    case iEnterScope(sn):             return "ENTER <sn>";
    case iExitScope(sn):              return "EXIT <sn>";
    default:                          return "INSTR";
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
