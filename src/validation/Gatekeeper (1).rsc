module validation::Gatekeeper

/*
  Fixes applied:
  1. "Undeclared type UIRInstr" in switch patterns — removed explicit
     type annotations from match variables inside switch cases.
  2. Added missing iMethodCall + Sink case (XSS was never detected).
  3. taintOfValue: valPhi now uses 2-arg form (phiA, phiB).
  4. All map lookups use explicit `(k in m) ? m[k] : default` form.
  5. formatReport expanded with full per-vuln detail.
*/

import lang::universal::IR;
import lang::universal::SecurityDefs;
import analysis::CFG;
import Set;
import Map;
import List;
import IO;
import String;

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

alias TaintEnv = map[str, set[str]];

TaintEnv joinEnv(TaintEnv a, TaintEnv b) {
  TaintEnv result = a;
  for (str v <- b) {
    result[v] = (v in result ? result[v] : {}) + b[v];
  }
  return result;
}

bool envLeq(TaintEnv a, TaintEnv b) {
  for (str v <- a) {
    if (v notin b)       return false;
    if (!(a[v] <= b[v])) return false;
  }
  return true;
}

set[str] taintOfValue(UIRValue v, TaintEnv env) {
  switch (v) {
    case valVar(name, _):
        return (name in env) ? env[name] : {};
    case valBinOp(_, l, r):
        return taintOfValue(l, env) + taintOfValue(r, env);
    case valPhi(phiA, phiB):
        return taintOfValue(phiA, env) + taintOfValue(phiB, env);
    case valField(obj, _):
        return taintOfValue(obj, env);
    case valIndex(arr, idx):
        return taintOfValue(arr, env) + taintOfValue(idx, env);
    case valUnOp(_, operand):
        return taintOfValue(operand, env);
    case valCast(_, src):
        return taintOfValue(src, env);
    default: return {};
  }
}

private list[VulnReport] checkSinkArgs(
    list[UIRValue] args,
    TaintEnv env,
    str sinkCat,
    str sinkTarget,
    set[str] required,
    str procName,
    str blockLabel,
    int instrIdx) {
  list[VulnReport] reps = [];
  for (UIRValue arg <- args) {
    set[str] argTaint = taintOfValue(arg, env);
    if (!isEmpty(argTaint)) {
      list[str] missing = toList(required);
      reps += [buildReport(sinkCat, procName, blockLabel, instrIdx,
                           intercalate(",", toList(argTaint)),
                           sinkTarget, valueStr(arg), missing)];
    }
  }
  return reps;
}

tuple[TaintEnv, list[VulnReport]] transferInstr(
    UIRInstr instr,
    TaintEnv env,
    str procName,
    str blockLabel,
    int instrIdx) {

  list[VulnReport] reports = [];

  switch (instr) {

    case iAssign(dest, src, Source(cat, _, propagates)): {
      env[dest] = taintOfValue(src, env) + {cat};
      for (str v <- propagates) {
        if (v != dest) env[v] = (v in env ? env[v] : {}) + {cat};
      }
      return <env, reports>;
    }

    case iLoad(dest, src, Source(cat, _, propagates)): {
      env[dest] = taintOfValue(src, env) + {cat};
      for (str v <- propagates) {
        if (v != dest) env[v] = (v in env ? env[v] : {}) + {cat};
      }
      return <env, reports>;
    }

    case iCall(dest, _, _, Source(cat, _, propagates)): {
      for (str v <- propagates) env[v] = (v in env ? env[v] : {}) + {cat};
      if (dest != "") env[dest] = (dest in env ? env[dest] : {}) + {cat};
      return <env, reports>;
    }

    case iMethodCall(dest, _, _, _, Source(cat, _, propagates)): {
      for (str v <- propagates) env[v] = (v in env ? env[v] : {}) + {cat};
      if (dest != "" && dest != "_") env[dest] = (dest in env ? env[dest] : {}) + {cat};
      return <env, reports>;
    }

    case iAssign(dest, _, Sanitizer(cat, _, cleaned)): {
      for (str v <- cleaned + {dest}) {
        if (v in env) {
          env[v] = env[v] - {cat};
          if (isEmpty(env[v])) env = delete(env, v);
        }
      }
      return <env, reports>;
    }

    case iCall(dest, _, _, Sanitizer(cat, _, cleaned)): {
      for (str v <- cleaned + {dest}) {
        if (v in env) {
          env[v] = env[v] - {cat};
          if (isEmpty(env[v])) env = delete(env, v);
        }
      }
      return <env, reports>;
    }

    case iCall(_, _, args, Sink(sinkCat, sinkTarget, required)): {
      reports += checkSinkArgs(args, env, sinkCat, sinkTarget, required,
                               procName, blockLabel, instrIdx);
      return <env, reports>;
    }

    case iMethodCall(_, _, _, args, Sink(sinkCat, sinkTarget, required)): {
      reports += checkSinkArgs(args, env, sinkCat, sinkTarget, required,
                               procName, blockLabel, instrIdx);
      return <env, reports>;
    }

    case iAssign(dest, src, Propagation(_, _)): {
      set[str] t = taintOfValue(src, env);
      if (!isEmpty(t)) env[dest] = t;
      else if (dest in env) env = delete(env, dest);
      return <env, reports>;
    }

    case iAssign(dest, src, _): {
      set[str] t = taintOfValue(src, env);
      if (!isEmpty(t)) env[dest] = t;
      else if (dest in env) env = delete(env, dest);
      return <env, reports>;
    }

    case iLoad(dest, src, _): {
      set[str] t = taintOfValue(src, env);
      if (!isEmpty(t)) env[dest] = t;
      return <env, reports>;
    }

    default: return <env, reports>;
  }
}

tuple[map[CFGNode, TaintEnv], list[VulnReport]]
    analyseProc(UIRProc p, ProcCFG cfg, TaintEnv initialEnv) {

  map[CFGNode, TaintEnv] inEnv  = (n : () | n <- cfg.nodes);
  map[CFGNode, TaintEnv] outEnv = (n : () | n <- cfg.nodes);
  list[VulnReport] allReports   = [];

  inEnv[cfg.entryNode] = initialEnv;

  list[CFGNode] worklist   = [cfg.entryNode];
  set[CFGNode]  inWorklist = {cfg.entryNode};

  while (!isEmpty(worklist)) {
    CFGNode cur = worklist[0];
    worklist    = worklist[1..];
    inWorklist -= {cur};

    TaintEnv curIn  = inEnv[cur];
    TaintEnv curOut = curIn;

    if (instrNode(pname, blabel, idx, instr) := cur) {
      tuple[TaintEnv env, list[VulnReport] reps] res =
          transferInstr(instr, curIn, pname, blabel, idx);
      curOut      = res.env;
      allReports += res.reps;
    }

    outEnv[cur] = curOut;

    set[CFGNode] succs = (cur in cfg.succ) ? cfg.succ[cur] : {};
    for (CFGNode s <- succs) {
      TaintEnv newIn = joinEnv(inEnv[s], curOut);
      if (!envLeq(newIn, inEnv[s])) {
        inEnv[s] = newIn;
        if (s notin inWorklist) {
          worklist   += [s];
          inWorklist += {s};
        }
      }
    }
  }
  return <outEnv, allReports>;
}

AuditResult auditUnit(UIRUnit u, CallGraph cg) {
  list[VulnReport] allVulns = [];
  int totalInstrs = 0;

  for (UIRProc p <- u.procs) {
    for (BasicBlock blk <- p.blocks) totalInstrs += size(blk.instrs);

    TaintEnv initEnv = ();
    for (str pName <- p.paramTags) {
      if (Source(cat, _, _) := p.paramTags[pName]) {
        initEnv[pName] = {cat};
      }
    }

    if (p.name in cg.cfgs) {
      tuple[map[CFGNode, TaintEnv] envs, list[VulnReport] vulns] r =
          analyseProc(p, cg.cfgs[p.name], initEnv);
      allVulns += r.vulns;
    }
  }

  return auditResult(u.sourceFile, size(u.procs), totalInstrs, allVulns, isEmpty(allVulns));
}

VulnReport buildReport(str sinkCat, str procName, str blockLabel, int instrIdx,
                       str origins, str sinkTarget, str taintedVar, list[str] missing) {
  tuple[VulnKind kind, Severity sev] cls = classifySink(sinkCat);
  str msg = "Taint nao-sanitizado [<origins>] alcanca `<sinkTarget>` (faltam: <intercalate(", ", missing)>)";
  return vuln(cls.kind, cls.sev, procName, blockLabel, instrIdx,
              origins, sinkTarget, taintedVar, missing, msg);
}

tuple[VulnKind, Severity] classifySink(str cat) {
  switch (cat) {
    case "SQL_EXEC":    return <sqlInjection(),   critical()>;
    case "HTML_OUTPUT": return <xss(),            high()>;
    case "SHELL_EXEC":  return <shellInjection(), critical()>;
    default:            return <genericTaint(cat), medium()>;
  }
}

str formatReport(AuditResult ar) {
  str sep = "---------------------------------------------\n";
  str out = sep;
  out    += "TRUST-TRANSPILER AUDIT REPORT\n";
  out    += "Arquivo : <ar.sourceFile>\n";
  out    += "Status  : <ar.clean ? "CLEAN" : "VULNERABLE">\n";
  out    += "Procs   : <ar.totalProcs>  | Instrucoes: <ar.totalInstrs>\n";

  if (!isEmpty(ar.vulnerabilities)) {
    out += sep;
    out += "VULNERABILIDADES (<size(ar.vulnerabilities)>)\n";
    out += sep;
    for (VulnReport v <- ar.vulnerabilities) {
      out += "[<severityStr(v.severity)>] <kindStr(v.kind)>\n";
      out += "  Proc   : <v.procName>  Bloco: <v.blockLabel>  Instr #<v.instrIndex>\n";
      out += "  Origem : <v.sourceOrigin>\n";
      out += "  Sink   : <v.sinkTarget>  (var: <v.taintedVar>)\n";
      out += "  Faltam : <intercalate(", ", v.missingCleaners)>\n";
      out += "  Msg    : <v.message>\n\n";
    }
  }
  out += sep;
  return out;
}

private str severityStr(Severity s) {
  switch (s) {
    case critical(): return "CRITICO";
    case high():     return "ALTO   ";
    case medium():   return "MEDIO  ";
    case low():      return "BAIXO  ";
    default:         return "INFO   ";
  }
}

private str kindStr(VulnKind k) {
  switch (k) {
    case sqlInjection():      return "SQL Injection";
    case xss():               return "Cross-Site Scripting (XSS)";
    case shellInjection():    return "Shell Injection";
    case pathTraversal():     return "Path Traversal";
    case openRedirect():      return "Open Redirect";
    case genericTaint(c):     return "Taint Generico (<c>)";
    default:                  return "Desconhecido";
  }
}

private str valueStr(UIRValue v) {
  switch (v) {
    case valVar(n, _): return n;
    default:           return "expr";
  }
}
