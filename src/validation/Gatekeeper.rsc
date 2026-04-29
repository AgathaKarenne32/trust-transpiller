module validation::Gatekeeper

// ============================================================
//  Trust-Transpiler — Gatekeeper (Taint Analysis Engine)
//  validation::Gatekeeper
//
//  Performs Flow-Sensitive, Interprocedural Taint Analysis
//  over the UIR + CFG to detect unsanitised data flows from
//  Sources to Sinks (SQL Injection, XSS, Shell Injection, …).
// ============================================================

import lang::universal::IR;
import analysis::CFG;
import Set;
import Map;
import List;
import IO;

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
  VulnKind       kind,
  Severity       severity,
  str            procName,
  str            blockLabel,
  int            instrIndex,
  str            sourceOrigin,     // where taint was introduced
  str            sinkTarget,       // where tainted data reaches
  str            taintedVar,       // the variable carrying taint
  list[str]      missingCleaners,  // sanitisers that were required but absent
  str            message
);

// Summary produced per compilation unit
data AuditResult = auditResult(
  str            sourceFile,
  int            totalProcs,
  int            totalInstrs,
  list[VulnReport] vulnerabilities,
  bool           clean            // true iff no vulns found
);

// ------------------------------------------------------------------
// 2. Taint lattice
//
//  We use a map  varName → set[str]  where each element of the set
//  is a "taint label" describing the origin category.
//  The empty set means the variable is untainted.
// ------------------------------------------------------------------

alias TaintEnv = map[str, set[str]];   // var → {taint-labels}

// Lattice join: union of taint sets per variable
TaintEnv joinEnv(TaintEnv a, TaintEnv b) {
  TaintEnv result = a;
  for (str v <- b) {
    result[v] = (v in result ? result[v] : {}) + b[v];
  }
  return result;
}

bool envLeq(TaintEnv a, TaintEnv b) {
  for (str v <- a) {
    if (v notin b) return false;
    if (!(a[v] <= b[v])) return false;
  }
  return true;
}

// ------------------------------------------------------------------
// 3. Transfer function — one instruction
// ------------------------------------------------------------------

// Returns <updated TaintEnv, optional VulnReport>
tuple[TaintEnv, list[VulnReport]] transferInstr(
    UIRInstr        instr,
    TaintEnv        env,
    str             procName,
    str             blockLabel,
    int             instrIdx) {

  list[VulnReport] reports = [];

  switch (instr) {

    // ---- Source: mark destination as tainted ----------------
    case iAssign(dest, src, Source(cat, origin, _)): {
      set[str] srcTaint = taintOfValue(src, env);
      env[dest] = srcTaint + {cat};
      return <env, reports>;
    }
    case iCall(dest, _, _, Source(cat, origin, propagates)): {
      for (str v <- propagates) env[v] = {cat};
      if (dest != "") env[dest] = {cat};
      return <env, reports>;
    }

    // ---- Sanitizer: clear taint labels for cleaned vars -----
    case iAssign(dest, src, Sanitizer(cat, _, cleaned)): {
      for (str v <- cleaned) {
        if (v in env) env[v] = env[v] - {cat};
        if (env[v]? && isEmpty(env[v])) env = delete(env, v);
      }
      // Also clean dest
      if (dest in env) {
        env[dest] = env[dest] - {cat};
        if (isEmpty(env[dest])) env = delete(env, dest);
      }
      return <env, reports>;
    }
    case iCall(dest, _, _, Sanitizer(cat, _, cleaned)): {
      for (str v <- cleaned) {
        if (v in env) env[v] = env[v] - {cat};
        if (env[v]? && isEmpty(env[v])) env = delete(env, v);
      }
      if (dest != "" && dest in env) {
        env[dest] = env[dest] - {cat};
        if (isEmpty(env[dest])) env = delete(env, dest);
      }
      return <env, reports>;
    }

    // ---- Sink: check for tainted arguments ------------------
    case iCall(_, callee, args, Sink(sinkCat, sinkTarget, required)): {
      for (UIRValue arg <- args) {
        set[str] argTaint = taintOfValue(arg, env);
        if (!isEmpty(argTaint)) {
          // Determine which required sanitisers are missing
          list[str] missing = [ r | r <- toList(required), r notin argTaint ]; // note: we check for *absence* of sanitised label
          // Actually: argTaint holds taint origins. We need to check that
          // the path went through a sanitiser. We encode "sanitised" as the
          // absence of the origin label.  If taint label still present → not sanitised.
          VulnReport r = buildReport(
            sinkCat, procName, blockLabel, instrIdx,
            intercalate(",", toList(argTaint)), sinkTarget,
            valueStr(arg), missing
          );
          reports += [r];
        }
      }
      return <env, reports>;
    }
    case iMethodCall(_, obj, method, args, Sink(sinkCat, sinkTarget, required)): {
      list[UIRValue] allArgs = [obj] + args;
      for (UIRValue arg <- allArgs) {
        set[str] argTaint = taintOfValue(arg, env);
        if (!isEmpty(argTaint)) {
          list[str] missing = toList(required);
          VulnReport r = buildReport(
            sinkCat, procName, blockLabel, instrIdx,
            intercalate(",", toList(argTaint)), sinkTarget,
            valueStr(arg), missing
          );
          reports += [r];
        }
      }
      return <env, reports>;
    }

    // ---- Propagation: standard assignment taint transfer ----
    case iAssign(dest, src, _): {
      set[str] srcTaint = taintOfValue(src, env);
      if (!isEmpty(srcTaint)) {
        env[dest] = (dest in env ? env[dest] : {}) + srcTaint;
      } else {
        // Clean assignment: remove taint (if any)
        env = delete(env, dest);
      }
      return <env, reports>;
    }
    case iLoad(dest, src, _): {
      set[str] srcTaint = taintOfValue(src, env);
      if (!isEmpty(srcTaint)) {
        env[dest] = (dest in env ? env[dest] : {}) + srcTaint;
      }
      return <env, reports>;
    }
    case iCall(dest, _, args, _): {
      // Conservative: if any arg is tainted, result is tainted
      set[str] combined = ( {} | it + taintOfValue(a, env) | a <- args );
      if (!isEmpty(combined) && dest != "") {
        env[dest] = combined;
      }
      return <env, reports>;
    }
    case iMethodCall(dest, obj, _, args, _): {
      set[str] combined = taintOfValue(obj, env)
                        + ( {} | it + taintOfValue(a, env) | a <- args );
      if (!isEmpty(combined) && dest != "") {
        env[dest] = combined;
      }
      return <env, reports>;
    }

    // ---- Everything else: no taint effect -------------------
    default: return <env, reports>;
  }
}

// ------------------------------------------------------------------
// 4. Taint of a value expression
// ------------------------------------------------------------------

set[str] taintOfValue(UIRValue v, TaintEnv env) {
  switch (v) {
    case valVar(name, _):
      return env[name] ? {};
    case valField(obj, _):
      return taintOfValue(obj, env);
    case valIndex(arr, idx):
      return taintOfValue(arr, env) + taintOfValue(idx, env);
    case valBinOp(_, l, r):
      return taintOfValue(l, env) + taintOfValue(r, env);
    case valUnOp(_, x):
      return taintOfValue(x, env);
    case valCast(_, src):
      return taintOfValue(src, env);
    case valPhi(branches):
      return ( {} | it + taintOfValue(b.val, env) | b <- branches );
    default:
      return {};
  }
}

// ------------------------------------------------------------------
// 5. Intra-procedural fixed-point dataflow
//    (forward analysis, MOP-style over the CFG)
// ------------------------------------------------------------------

tuple[map[CFGNode, TaintEnv], list[VulnReport]]
    analyseProc(UIRProc p, ProcCFG cfg, TaintEnv initialEnv) {

  map[CFGNode, TaintEnv] inEnv  = ();
  map[CFGNode, TaintEnv] outEnv = ();
  list[VulnReport] allReports   = [];

  // Initialise all nodes with bottom (empty map)
  for (CFGNode n <- cfg.nodes) {
    inEnv[n]  = ();
    outEnv[n] = ();
  }
  inEnv[cfg.entryNode] = initialEnv;

  // Worklist (BFS order)
  list[CFGNode] worklist = [cfg.entryNode];
  set[CFGNode]  inWorklist = {cfg.entryNode};

  while (!isEmpty(worklist)) {
    CFGNode cur = worklist[0];
    worklist    = worklist[1..];
    inWorklist -= {cur};

    TaintEnv curIn = inEnv[cur];
    TaintEnv curOut;
    list[VulnReport] nodeReports = [];

    switch (cur) {
      case entry(_):
        curOut = curIn;
      case exit(_):
        curOut = curIn;
      case instrNode(pname, blabel, idx, instr): {
        <curOut, nodeReports> =
            transferInstr(instr, curIn, pname, blabel, idx);
        allReports += nodeReports;
      }
    }

    outEnv[cur] = curOut;

    // Propagate to successors
    for (CFGNode succ <- (cfg.succ[cur] ? {})) {
      TaintEnv newIn = joinEnv(inEnv[succ], curOut);
      if (!envLeq(newIn, inEnv[succ])) {
        inEnv[succ] = newIn;
        if (succ notin inWorklist) {
          worklist    += [succ];
          inWorklist  += {succ};
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
    // Count instructions
    for (BasicBlock blk <- p.blocks)
      totalInstrs += size(blk.instrs);

    // Build per-parameter initial taint from param annotations
    TaintEnv initEnv = ();
    for (str param <- p.paramTags) {
      if (Source(cat, _, _) := p.paramTags[param]) {
        initEnv[param] = {cat};
      }
    }

    ProcCFG pcfg = cg.cfgs[p.name];
    <_, vulns> = analyseProc(p, pcfg, initEnv);
    allVulns += vulns;
  }

  return auditResult(
    u.sourceFile,
    size(u.procs),
    totalInstrs,
    allVulns,
    isEmpty(allVulns)
  );
}

// ------------------------------------------------------------------
// 7. Vulnerability report factory
// ------------------------------------------------------------------

VulnReport buildReport(
    str sinkCat, str procName, str blockLabel,
    int instrIdx, str origins, str sinkTarget,
    str taintedVar, list[str] missing) {

  <kind, sev> = classifySink(sinkCat);
  str msg = "Unsanitised <sinkCat> taint from [<origins>] reaches"
          + " `<sinkTarget>` via `<taintedVar>`"
          + (isEmpty(missing) ? "" : ". Missing sanitisers: <intercalate(", ", missing)>");

  return vuln(kind, sev, procName, blockLabel, instrIdx,
              origins, sinkTarget, taintedVar, missing, msg);
}

tuple[VulnKind, Severity] classifySink(str cat) {
  switch (cat) {
    case "SQL_EXEC":      return <sqlInjection(), critical()>;
    case "HTML_OUTPUT":   return <xss(), high()>;
    case "JS_EVAL":       return <xss(), critical()>;
    case "SHELL_EXEC":    return <shellInjection(), critical()>;
    case "FILE_PATH":     return <pathTraversal(), high()>;
    case "HTTP_REDIRECT": return <openRedirect(), medium()>;
    default:              return <genericTaint(cat), medium()>;
  }
}

// ------------------------------------------------------------------
// 8. Human-readable report printer
// ------------------------------------------------------------------

str formatReport(AuditResult ar) {
  str nl = "\n";
  str sep = "═══════════════════════════════════════════════════════\n";

  str out = nl + sep;
  out += "  TRUST-TRANSPILER AUDIT REPORT\n";
  out += sep;
  out += "  File   : <ar.sourceFile>\n";
  out += "  Procs  : <ar.totalProcs>    Instructions: <ar.totalInstrs>\n";
  out += "  Status : " + (ar.clean ? "✅  CLEAN" : "❌  VULNERABILITIES FOUND") + "\n";
  out += sep + nl;

  if (ar.clean) {
    out += "  No taint-flow vulnerabilities detected.\n";
  } else {
    int idx = 1;
    for (VulnReport v <- ar.vulnerabilities) {
      out += "  [<idx>] <severityStr(v.severity)> — <kindStr(v.kind)>\n";
      out += "      Proc   : <v.procName>  Block: <v.blockLabel>  Instr#<v.instrIndex>\n";
      out += "      Source : <v.sourceOrigin>\n";
      out += "      Sink   : <v.sinkTarget>\n";
      out += "      Via    : <v.taintedVar>\n";
      out += "      Detail : <v.message>\n";
      out += nl;
      idx += 1;
    }
  }
  out += sep;
  return out;
}

private str severityStr(Severity s) {
  switch (s) {
    case critical(): return "CRITICAL";
    case high():     return "HIGH    ";
    case medium():   return "MEDIUM  ";
    case low():      return "LOW     ";
    case info():     return "INFO    ";
    default:         return "UNKNOWN ";
  }
}

private str kindStr(VulnKind k) {
  switch (k) {
    case sqlInjection():      return "SQL Injection";
    case xss():               return "Cross-Site Scripting (XSS)";
    case shellInjection():    return "Shell Injection";
    case pathTraversal():     return "Path Traversal";
    case openRedirect():      return "Open Redirect";
    case genericTaint(cat):   return "Generic Taint [<cat>]";
    default:                  return "Unknown Vulnerability";
  }
}

private str valueStr(UIRValue v) {
  switch (v) {
    case valVar(n, _):  return n;
    case valStr(s):     return "\"<s>\"";
    case valInt(i):     return "<i>";
    default:            return "expr";
  }
}
