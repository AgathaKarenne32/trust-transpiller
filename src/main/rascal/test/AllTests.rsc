module test::AllTests

import lang::universal::IR;
import lang::universal::SecurityDefs;
import analysis::CFG;
import validation::Gatekeeper;
import List;
import Set;
import IO;

private map[str, SecurityTag] noTags    = ();
private map[str, UIRType]     noGlobals = ();

// Testes Existentes de infraestrutura do CFG
test bool cfgEmptyProc() {
  UIRProc p   = proc("empty", [], tVoid(), [], noTags);
  ProcCFG cfg = buildProcCFG(p);
  return cfg.entryNode == entry("empty") && cfg.exitNode == exit("empty");
}

test bool cfgSingleBlock() {
  UIRProc p = proc("f", [], tVoid(), [block("entry", [iReturn(valNull(), Neutral())], [])], noTags);
  ProcCFG cfg = buildProcCFG(p);
  return isReachable(cfg.entryNode, cfg.exitNode, cfg);
}

test bool cfgCondJumpCreatesTwoEdges() {
  UIRProc p = proc("g", [], tVoid(), [block("entry", [iCondJump(valBool(true), "t", "f")], ["t", "f"]), block("t", [iReturn(valNull(), Neutral())], []), block("f", [iReturn(valNull(), Neutral())], [])], noTags);
  ProcCFG cfg = buildProcCFG(p);
  set[EdgeKind] kinds = {k | <_, _, k> <- cfg.edges, k == trueEdge() || k == falseEdge()};
  return trueEdge() in kinds && falseEdge() in kinds;
}

test bool cfgCallGraphRegistersCallee() {
  UIRProc caller = proc("caller", [], tVoid(), [block("entry", [iCall("r", "callee", [], Neutral()), iReturn(valNull(), Neutral())], [])], noTags);
  UIRUnit u  = unit("test.rsc", "Rascal", [caller], noGlobals);
  CallGraph cg = buildCallGraph(u);
  return <"caller", "callee"> in cg.calls;
}

// Novos Testes de Taint focados em OWASP & CLASP (Misuse Cases)
test bool taintBrokenAuthDetected() {
  UIRProc p = proc("auth", [], tVoid(),
    [block("entry", [
        iAssign("p", valStr("key"), Source("HARDCODED_SECRET", "config", {"p"})),
        iCall("_", "auth", [valVar("p", tString())], Sink("CREDENTIAL_STORE", "auth", {"HASH"}))
      ], [])], noTags);
  UIRUnit u = unit("t.rsc", "Java", [p], noGlobals);
  AuditResult ar = auditUnit(u, buildCallGraph(u));
  return !ar.clean && ar.vulnerabilities[0].kind == brokenAuthentication();
}

test bool taintLdapInjectionDetected() {
  UIRProc p = proc("ldap", [], tVoid(),
    [block("entry", [
        iAssign("u", valVar("input", tString()), Source("HTTP_PARAM", "input", {"u"})),
        iCall("_", "search", [valVar("u", tString())], Sink("LDAP_QUERY", "search", {"LDAP_ESCAPE"}))
      ], [])], noTags);
  UIRUnit u = unit("t.rsc", "Java", [p], noGlobals);
  AuditResult ar = auditUnit(u, buildCallGraph(u));
  return !ar.clean && ar.vulnerabilities[0].kind == ldapInjection();
}

test bool taintSqlInjectionDetected() {
  UIRProc p = proc("sqli", [], tVoid(), [block("entry", [iAssign("id", valVar("raw", tString()), Source("HTTP_PARAM", "raw", {"id"})), iCall("_", "db_query", [valVar("id", tString())], Sink("SQL_EXEC", "db_query", {"PREPARED_STMT"}))], [])], noTags);
  AuditResult ar = auditUnit(unit("sqli.rsc", "Rascal", [p], noGlobals), buildCallGraph(unit("sqli.rsc", "Rascal", [p], noGlobals)));
  return !ar.clean && ar.vulnerabilities[0].kind == sqlInjection();
}

test bool taintSanitizerClearsVuln() {
  UIRProc p = proc("clean", [], tVoid(), [block("entry", [iAssign("raw", valVar("ext", tString()), Source("HTTP_PARAM", "ext", {"raw"})), iAssign("safe", valCast(tInt(), valVar("raw", tString())), Sanitizer("HTTP_PARAM", "INTVAL", {"raw", "safe"})), iCall("_", "db_query", [valVar("safe", tString())], Sink("SQL_EXEC", "db_query", {"PREPARED_STMT", "INTVAL"}))], [])], noTags);
  AuditResult ar = auditUnit(unit("clean.rsc", "Rascal", [p], noGlobals), buildCallGraph(unit("clean.rsc", "Rascal", [p], noGlobals)));
  return ar.clean;
}

test bool taintXssViaMethodCallDetected() {
  UIRProc p = proc("xss", [param("req", tAny()), param("res", tAny())], tVoid(), [block("entry", [iLoad("name", valField(valVar("req", tAny()), "name"), Source("HTTP_PARAM", "req.name", {"name"})), iMethodCall("_", valVar("res", tAny()), "send", [valVar("name", tString())], Sink("HTML_OUTPUT", "res.send", {"HTML_ESCAPE"}))], [])], noTags);
  AuditResult ar = auditUnit(unit("xss.rsc", "JS", [p], noGlobals), buildCallGraph(unit("xss.rsc", "JS", [p], noGlobals)));
  return !ar.clean && ar.vulnerabilities[0].kind == xss();
}