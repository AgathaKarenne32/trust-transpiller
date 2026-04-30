module validation::Gatekeeper

// ============================================================
//  Trust-Transpiler — Gatekeeper (Taint Analysis Engine)
// ============================================================

import lang::universal::IR;
import analysis::CFG;
import Set;
import Map;
import List;
import IO;
import String;

// ------------------------------------------------------------------
// 1. Vulnerability report types
// ------------------------------------------------------------------

data Severity = critical() | high() | medium() | low() | info();

data VulnKind
  = sqlInjection()
  | xss()
  | shellInjection()
  | pathTraversal()
  | openRedirect()
  | genericTaint(str sinkCategory)
  ;

data VulnReport = vuln(
  VulnKind kind,
  Severity severity,
  str procName,
  str blockLabel,
  int instrIndex,
  str sourceOrigin,
  str sinkTarget,
  str taintedVar,
  list[str] missingCleaners,
  str message
);

data AuditResult = auditResult(
  str sourceFile,
  int totalProcs,
  int totalInstrs,
  list[VulnReport] vulnerabilities,
  bool clean
);

// ------------------------------------------------------------------
// 2. Taint lattice
// ------------------------------------------------------------------

alias TaintEnv = map[str, set[str]];

TaintEnv joinEnv(TaintEnv a, TaintEnv b) {
  TaintEnv result = a;
  for (str v <- b) {
    result[v] = (result[v] ? {}) + b[v];
  }
  return result;
}

bool envLeq(TaintEnv a, TaintEnv b) {
  for (str v <- a) {
    if (v notin b)        return false;
    if (!(a[v] <= b[v]))  return false;
  }
  return true;
}

// ------------------------------------------------------------------
// 3. Transfer function — one instruction
// ------------------------------------------------------------------

tuple[TaintEnv, list[VulnReport]] transferInstr(
    UIRInstr instr,
    TaintEnv env,
    str procName,
    str blockLabel,
    int instrIdx) {

  list[VulnReport] reports = [];

  switch (instr) {
    case iAssign(str dest, UIRValue src, Source(str cat, str origin, _)): {
      set[str] srcTaint = taintOfValue(src, env);
      env[dest] = srcTaint + {cat};
      return <env, reports>;
    }

    case iCall(str dest, str _, list[UIRValue] _, Source(str cat, str _, set[str] propagates)): {
      for (str v <- propagates) env[v] = {cat};
      if (dest != "") env[dest] = {cat};
      return <env, reports>;
    }

    case iAssign(str dest, UIRValue _, Sanitizer(str cat, str _, set[str] cleaned)): {
      for (str v <- cleaned + {dest}) {
        if (v in env) {
          env[v] = env[v] - {cat};
          if (isEmpty(env[v])) env = delete(env, v);
        }
      }
      return <env, reports>;
    }

    case iCall(str _, str _, list[UIRValue] args, Sink(str sinkCat, str sinkTarget, set[str] required)): {
      for (UIRValue arg <- args) {
        set[str] argTaint = taintOfValue(arg, env);
        if (!isEmpty(argTaint)) {
          list[str] missing = [ r | r <- toList(required), r notin argTaint ];
          reports += [buildReport(sinkCat, procName, blockLabel, instrIdx,
                      intercalate(",", toList(argTaint)), sinkTarget, valueStr(arg), missing)];
        }
      }
      return <env, reports>;
    }

    case iAssign(str dest, UIRValue src, _): {
      set[str] srcTaint = taintOfValue(src, env);
      if (!isEmpty(srcTaint)) env[dest] = srcTaint;
      else env = delete(env, dest);
      return <env, reports>;
    }

    case iLoad(str dest, UIRValue src, _): {
      set[str] srcTaint = taintOfValue(src, env);
      if (!isEmpty(srcTaint)) env[dest] = srcTaint;
      return <env, reports>;
    }

    default: return <env, reports>;
  }
}

// ------------------------------------------------------------------
// 4. Taint of a value expression
// ------------------------------------------------------------------

set[str] taintOfValue(UIRValue v, TaintEnv env) {
  switch (v) {
    case valVar(str name, _): return (env[name] ? {});
    case valBinOp(_, UIRValue l, UIRValue r):
        return taintOfValue(l, env) + taintOfValue(r, env);
    case valPhi(list[tuple[UIRValue val, str predLabel]] branches):
        return ( {} | it + taintOfValue(b.val, env) | b <- branches );
    default: return {};
  }
}

// ------------------------------------------------------------------
// 5. Intra-procedural fixed-point dataflow
// ------------------------------------------------------------------

// FIX: declarar os tipos das variáveis retornadas por analyseProc
//      explicitamente para evitar ambiguidade no pattern matching
tuple[map[CFGNode, TaintEnv], list[VulnReport]]
    analyseProc(UIRProc p, ProcCFG cfg, TaintEnv initialEnv) {

  map[CFGNode, TaintEnv] inEnv  = ( n : () | n <- cfg.nodes );
  map[CFGNode, TaintEnv] outEnv = ( n : () | n <- cfg.nodes );
  list[VulnReport] allReports   = [];

  inEnv[cfg.entryNode] = initialEnv;

  list[CFGNode]  worklist   = [cfg.entryNode];
  set[CFGNode]   inWorklist = {cfg.entryNode};

  while (!isEmpty(worklist)) {
    CFGNode cur  = worklist[0];
    worklist     = worklist[1..];
    inWorklist  -= {cur};

    TaintEnv curIn  = inEnv[cur];
    TaintEnv curOut = curIn;

    if (instrNode(str pname, str blabel, int idx, UIRInstr instr) := cur) {
      // FIX: declarar variáveis do resultado explicitamente
      tuple[TaintEnv env, list[VulnReport] reps] res =
          transferInstr(instr, curIn, pname, blabel, idx);
      curOut      = res.env;
      allReports += res.reps;
    }

    outEnv[cur] = curOut;

    for (CFGNode succ <- (cfg.succ[cur] ? {})) {
      TaintEnv newIn = joinEnv(inEnv[succ], curOut);
      if (!envLeq(newIn, inEnv[succ])) {
        inEnv[succ] = newIn;
        if (succ notin inWorklist) {
          worklist   += [succ];
          inWorklist += {succ};
        }
      }
    }
  }
  return <outEnv, allReports>;
}

// ------------------------------------------------------------------
// 6. Unit-level analysis entry point
// ------------------------------------------------------------------

AuditResult auditUnit(UIRUnit u, CallGraph cg) {
  list[VulnReport] allVulns = [];
  int totalInstrs = 0;

  for (UIRProc p <- u.procs) {
    for (BasicBlock blk <- p.blocks) totalInstrs += size(blk.instrs);

    TaintEnv initEnv = ();
    for (str pName <- p.paramTags) {
      if (Source(str cat, _, _) := p.paramTags[pName]) initEnv[pName] = {cat};
    }

    if (p.name in cg.cfgs) {
      // FIX: usar variáveis tipadas ao receber o resultado da análise
      tuple[map[CFGNode, TaintEnv] envs, list[VulnReport] vulns] r =
          analyseProc(p, cg.cfgs[p.name], initEnv);
      allVulns += r.vulns;
    }
  }

  return auditResult(u.sourceFile, size(u.procs), totalInstrs, allVulns, isEmpty(allVulns));
}

// ------------------------------------------------------------------
// 7. Factory e Helpers
// ------------------------------------------------------------------

VulnReport buildReport(str sinkCat, str procName, str blockLabel, int instrIdx,
                       str origins, str sinkTarget, str taintedVar, list[str] missing) {
  // FIX: declarar variáveis explicitamente ao usar tuple destructuring
  tuple[VulnKind kind, Severity sev] cls = classifySink(sinkCat);
  str msg = "Unsanitised <sinkCat> taint from [<origins>] reaches `<sinkTarget>`";
  return vuln(cls.kind, cls.sev, procName, blockLabel, instrIdx,
              origins, sinkTarget, taintedVar, missing, msg);
}

tuple[VulnKind, Severity] classifySink(str cat) {
  switch (cat) {
    case "SQL_EXEC":    return <sqlInjection(),  critical()>;
    case "HTML_OUTPUT": return <xss(),           high()>;
    case "SHELL_EXEC":  return <shellInjection(), critical()>;
    default:            return <genericTaint(cat), medium()>;
  }
}

str formatReport(AuditResult ar) {
  str out = "TRUST-TRANSPILER AUDIT REPORT\nFile: <ar.sourceFile>\nStatus: <ar.clean ? "CLEAN" : "VULNERABLE">\n";
  for (VulnReport v <- ar.vulnerabilities) {
    out += "[<v.severity>] <v.kind> in <v.procName> (Block: <v.blockLabel>)\n";
  }
  return out;
}

private str valueStr(UIRValue v) {
  if (valVar(str n, _) := v) return n;
  return "expr";
}
