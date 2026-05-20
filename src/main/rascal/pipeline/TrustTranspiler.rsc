module pipeline::TrustTranspiler

import lang::universal::IR;
import lang::universal::SecurityDefs;
import analysis::CFG;
import validation::Gatekeeper;
import IO;
import List;
import Set;

// Fixture para OWASP A07 (Broken Auth / Segredos Expostos)
UIRUnit brokenAuthDemo() {
  map[str, SecurityTag] noTags    = ();
  map[str, UIRType]     noGlobals = ();
  UIRProc checkAuth = proc(
    "checkAuth", [], tVoid(),
    [block("entry", [
        iAssign("passwd", valStr("admin_password_123"), 
          Source("HARDCODED_SECRET", "static_config", {"passwd"})),
        iCall("_", "login_attempt", [valVar("passwd", tString())], 
          Sink("CREDENTIAL_STORE", "login_attempt", {"HASH_SHA256"})),
        iReturn(valNull(), Neutral())
      ], [])
    ], noTags);
  return unit("demo_auth.java", "Java", [checkAuth], noGlobals);
}

UIRUnit sqlInjectionDemo() {
  map[str, SecurityTag] noTags    = ();
  map[str, UIRType]     noGlobals = ();
  UIRProc fetchUser = proc(
    "fetchUser", [], tVoid(),
    [block("entry", [
        iAssign("id", valVar("_GET_id", tString()), Source("HTTP_PARAM", "$_GET[id]", {"id"})),
        iAssign("sql", valBinOp(".", valStr("SELECT * FROM users WHERE id="), valVar("id", tString())), Propagation({"id"}, {"sql"})),
        iCall("result", "mysql_query", [valVar("sql", tString())], Sink("SQL_EXEC", "mysql_query", {"PREPARED_STMT", "INTVAL"})),
        iReturn(valNull(), Neutral())
      ], [])
    ], noTags);
  return unit("demo_sqli.php", "PHP", [fetchUser], noGlobals);
}

UIRUnit xssDemo() {
  map[str, SecurityTag] noTags    = ();
  map[str, UIRType]     noGlobals = ();
  UIRProc greetHandler = proc(
    "greetHandler", [param("req", tAny()), param("res", tAny())], tVoid(),
    [block("entry", [
        iLoad("name", valField(valField(valVar("req", tAny()), "query"), "name"), Source("HTTP_PARAM", "req.query.name", {"name"})),
        iAssign("greeting", valBinOp("+", valBinOp("+", valStr("Hello "), valVar("name", tString())), valStr("!")), Propagation({"name"}, {"greeting"})),
        iMethodCall("_", valVar("res", tAny()), "send", [valVar("greeting", tString())], Sink("HTML_OUTPUT", "res.send", {"HTML_ESCAPE", "DOMPurify"})),
        iReturn(valNull(), Neutral())
      ], [])
    ], noTags);
  return unit("demo_xss.js", "JavaScript", [greetHandler], noGlobals);
}

UIRUnit cleanSqlDemo() {
  map[str, SecurityTag] noTags    = ();
  map[str, UIRType]     noGlobals = ();
  UIRProc safeFetchUser = proc(
    "safeFetchUser", [], tVoid(),
    [block("entry", [
        iAssign("raw", valVar("_GET_id", tString()), Source("HTTP_PARAM", "$_GET[id]", {"raw"})),
        iAssign("id", valCast(tInt(), valVar("raw", tString())), Sanitizer("HTTP_PARAM", "INTVAL", {"raw", "id"})),
        iAssign("sql", valBinOp(".", valStr("SELECT * FROM users WHERE id="), valVar("id", tInt())), Propagation({"id"}, {"sql"})),
        iCall("result", "mysql_query", [valVar("sql", tString())], Sink("SQL_EXEC", "mysql_query", {"PREPARED_STMT", "INTVAL"})),
        iReturn(valNull(), Neutral())
      ], [])
    ], noTags);
  return unit("demo_clean_sql.php", "PHP", [safeFetchUser], noGlobals);
}

UIRUnit shellInjectionDemo() {
  map[str, SecurityTag] noTags    = ();
  map[str, UIRType]     noGlobals = ();
  UIRProc listDir = proc(
    "listDir", [param("user", tString())], tVoid(),
    [
      block("check", [
        iCall("isAdmin", "isAdmin", [valVar("user", tString())], Neutral()),
        iCondJump(valVar("isAdmin", tBool()), "exec", "end")
      ], ["exec", "end"]),
      block("exec", [
        iAssign("dir", valVar("_POST_dir", tString()), Source("HTTP_PARAM", "$_POST[dir]", {"dir"})),
        iAssign("cmd", valBinOp(".", valStr("ls "), valVar("dir", tString())), Propagation({"dir"}, {"cmd"})),
        iCall("_", "shell_exec", [valVar("cmd", tString())], Sink("SHELL_EXEC", "shell_exec", {"ESCAPESHELLARG"})),
        iJump("end")
      ], ["end"]),
      block("end", [
        iReturn(valNull(), Neutral())
      ], [])
    ], noTags);
  return unit("demo_shell.php", "PHP", [listDir], noGlobals);
}

CallGraph buildGraphs(UIRUnit u) = buildCallGraph(u);
AuditResult runAudit(UIRUnit u, CallGraph cg) = auditUnit(u, cg);

void printAudit(AuditResult ar) {
  println(formatReport(ar));
}

AuditResult runPipeline(UIRUnit u) {
  println("\n[TrustTranspiler] Processando: <u.sourceFile> (<u.sourceLanguage>)");
  CallGraph   cg = buildGraphs(u);
  AuditResult ar = runAudit(u, cg);
  printAudit(ar);
  return ar;
}

void main() {
  println("=======================================================");
  println("  TRUST-TRANSPILER  v0.1.0 - SECURITY GAUNTLET");
  println("  Universal Static Security Analysis (Rascal MPL)");
  println("=======================================================");

  list[UIRUnit] units = [
    sqlInjectionDemo(),
    xssDemo(),
    cleanSqlDemo(),
    shellInjectionDemo(),
    brokenAuthDemo() // Nova unidade integrada
  ];

  list[AuditResult] results = [runPipeline(u) | u <- units];

  int totalVulns = (0 | it + size(r.vulnerabilities) | r <- results);
  int cleanUnits = size([r | r <- results, r.clean]);

  println("\nSumario de Execucao Final:");
  println("  Unidades escaneadas : <size(units)>");
  println("  Unidades limpas     : <cleanUnits>");
  println("  Total vulns         : <totalVulns>");

  // Implementação Prática do Security Gate (CLASP Principle)
  if (totalVulns > 0) {
    println("\n[!] SECURITY GATE TRIGGERED: Vulnerabilidades críticas ativas.");
    // Força a interrupção abrupta da execução com erro sem capturar, quebrando a build do CI
    throw "BUILD FAILED - Falhas de seguranca detectadas no orquestrador.";
  } else {
    println("\n[OK] BUILD PASSED - Codigo em conformidade corporativa.");
  }
}