module test::AllTests

import lang::universal::IR;
import lang::universal::SecurityDefs;
import analysis::CFG;
import validation::Gatekeeper;
import List;
import Set;
import IO;

// ----------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------

private map[str, SecurityTag] noTags    = ();
private map[str, UIRType]     noGlobals = ();

// ----------------------------------------------------------------
// Testes: CFG
// ----------------------------------------------------------------

test bool cfgEmptyProc() {
  UIRProc p   = proc("empty", [], tVoid(), [], noTags);
  ProcCFG cfg = buildProcCFG(p);
  return cfg.entryNode == entry("empty")
      && cfg.exitNode  == exit("empty")
      && <entry("empty"), exit("empty"), flowEdge()> in cfg.edges;
}

test bool cfgSingleBlock() {
  UIRProc p = proc("f", [], tVoid(),
    [block("entry", [iReturn(valNull(), Neutral())], [])],
    noTags);
  ProcCFG cfg = buildProcCFG(p);
  return isReachable(cfg.entryNode, cfg.exitNode, cfg);
}

test bool cfgCondJumpCreatesTwoEdges() {
  UIRProc p = proc("g", [], tVoid(),
    [
      block("entry", [
        iCondJump(valBool(true), "t", "f")
      ], ["t", "f"]),
      block("t", [iReturn(valNull(), Neutral())], []),
      block("f", [iReturn(valNull(), Neutral())], [])
    ], noTags);
  ProcCFG cfg = buildProcCFG(p);
  // deve ter trueEdge e falseEdge saindo do nó do iCondJump
  set[EdgeKind] kinds = {k | <_, _, k> <- cfg.edges,
                             k == trueEdge() || k == falseEdge()};
  return trueEdge() in kinds && falseEdge() in kinds;
}

test bool cfgCallGraphRegistersCallee() {
  UIRProc caller = proc("caller", [], tVoid(),
    [block("entry", [
        iCall("r", "callee", [], Neutral()),
        iReturn(valNull(), Neutral())
      ], [])],
    noTags);
  UIRUnit u  = unit("test.rsc", "Rascal", [caller], noGlobals);
  CallGraph cg = buildCallGraph(u);
  return <"caller", "callee"> in cg.calls;
}

// ----------------------------------------------------------------
// Testes: Taint (Gatekeeper)
// ----------------------------------------------------------------

test bool taintSourcePropagates() {
  UIRProc p = proc("src", [], tVoid(),
    [block("entry", [
        iAssign("x", valVar("ext", tString()),
          Source("HTTP_PARAM", "ext", {"x"})),
        iReturn(valNull(), Neutral())
      ], [])],
    noTags);
  UIRUnit  u  = unit("t.rsc", "Rascal", [p], noGlobals);
  CallGraph cg = buildCallGraph(u);
  AuditResult ar = auditUnit(u, cg);
  // sem sink — nenhuma vuln, mas o taint existe internamente
  return ar.clean;
}

test bool taintSqlInjectionDetected() {
  UIRProc p = proc("sqli", [], tVoid(),
    [block("entry", [
        iAssign("id", valVar("raw", tString()),
          Source("HTTP_PARAM", "raw", {"id"})),
        iCall("_", "db_query", [valVar("id", tString())],
          Sink("SQL_EXEC", "db_query", {"PREPARED_STMT"})),
        iReturn(valNull(), Neutral())
      ], [])],
    noTags);
  UIRUnit   u  = unit("sqli.rsc", "Rascal", [p], noGlobals);
  CallGraph cg = buildCallGraph(u);
  AuditResult ar = auditUnit(u, cg);
  return !ar.clean && size(ar.vulnerabilities) == 1
      && ar.vulnerabilities[0].kind == sqlInjection();
}

test bool taintSanitizerClearsVuln() {
  UIRProc p = proc("clean", [], tVoid(),
    [block("entry", [
        iAssign("raw", valVar("ext", tString()),
          Source("HTTP_PARAM", "ext", {"raw"})),
        iAssign("safe", valCast(tInt(), valVar("raw", tString())),
          Sanitizer("HTTP_PARAM", "INTVAL", {"raw", "safe"})),
        iCall("_", "db_query", [valVar("safe", tString())],
          Sink("SQL_EXEC", "db_query", {"PREPARED_STMT", "INTVAL"})),
        iReturn(valNull(), Neutral())
      ], [])],
    noTags);
  UIRUnit   u  = unit("clean.rsc", "Rascal", [p], noGlobals);
  CallGraph cg = buildCallGraph(u);
  AuditResult ar = auditUnit(u, cg);
  return ar.clean;
}

test bool taintXssViaMethodCallDetected() {
  UIRProc p = proc("xss", [param("req", tAny()), param("res", tAny())], tVoid(),
    [block("entry", [
        iLoad("name",
          valField(valVar("req", tAny()), "name"),
          Source("HTTP_PARAM", "req.name", {"name"})),
        iMethodCall("_", valVar("res", tAny()), "send",
          [valVar("name", tString())],
          Sink("HTML_OUTPUT", "res.send", {"HTML_ESCAPE"})),
        iReturn(valNull(), Neutral())
      ], [])],
    noTags);
  UIRUnit   u  = unit("xss.rsc", "JS", [p], noGlobals);
  CallGraph cg = buildCallGraph(u);
  AuditResult ar = auditUnit(u, cg);
  return !ar.clean && ar.vulnerabilities[0].kind == xss();
}

test bool taintDoesNotCrossUntaintedVar() {
  UIRProc p = proc("notaint", [], tVoid(),
    [block("entry", [
        iAssign("safe", valStr("literal"), Neutral()),
        iCall("_", "db_query", [valVar("safe", tString())],
          Sink("SQL_EXEC", "db_query", {"PREPARED_STMT"})),
        iReturn(valNull(), Neutral())
      ], [])],
    noTags);
  UIRUnit   u  = unit("notaint.rsc", "Rascal", [p], noGlobals);
  CallGraph cg = buildCallGraph(u);
  AuditResult ar = auditUnit(u, cg);
  return ar.clean;
}

// ----------------------------------------------------------------
// Runner (chamado pelo workflow com --call runAll)
// ----------------------------------------------------------------

void runAll() {
  println("=== Trust-Transpiler Unit Tests ===\n");

  list[tuple[str name, bool result]] tests = [
    <"cfgEmptyProc",                  cfgEmptyProc()>,
    <"cfgSingleBlock",                cfgSingleBlock()>,
    <"cfgCondJumpCreatesTwoEdges",    cfgCondJumpCreatesTwoEdges()>,
    <"cfgCallGraphRegistersCallee",   cfgCallGraphRegistersCallee()>,
    <"taintSourcePropagates",         taintSourcePropagates()>,
    <"taintSqlInjectionDetected",     taintSqlInjectionDetected()>,
    <"taintSanitizerClearsVuln",      taintSanitizerClearsVuln()>,
    <"taintXssViaMethodCallDetected", taintXssViaMethodCallDetected()>,
    <"taintDoesNotCrossUntaintedVar", taintDoesNotCrossUntaintedVar()>
  ];

  int passed = 0;
  int failed = 0;

  for (<name, result> <- tests) {
    if (result) {
      println("  [PASS] <name>");
      passed += 1;
    } else {
      println("  [FAIL] <name>");
      failed += 1;
    }
  }

  println("\nResultado: <passed>/<size(tests)> passaram.");
  if (failed > 0) {
    println("[!] <failed> teste(s) falharam.");
  } else {
    println("[OK] Todos os testes passaram.");
  }
}
