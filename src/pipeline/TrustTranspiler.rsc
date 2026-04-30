module pipeline::TrustTranspiler

// ============================================================
//  Trust-Transpiler — Pipeline Orchestrator
// ============================================================

import lang::universal::IR;
import analysis::CFG;
import validation::Gatekeeper;
import IO;
import List;
import Set;

// ------------------------------------------------------------------
// 1. Demo fixtures
// ------------------------------------------------------------------

// FIX: UIRProc.params is now list[tuple[str, UIRType]] (anonymous tuples)
//      to match the corrected IR.rsc definition.

UIRUnit sqlInjectionDemo() {
  map[str, SecurityTag] noTags    = ();
  map[str, UIRType]     noGlobals = ();

  UIRProc fetchUser = proc(
    "fetchUser",
    [],
    tVoid(),
    [
      block("entry", [
        iAssign("id",
          valVar("_GET_id", tString()),
          Source("HTTP_PARAM", "$_GET[\'id\']", {"id"})
        ),
        iAssign("sql",
          valBinOp(".", valStr("SELECT * FROM users WHERE id="), valVar("id", tString())),
          Propagation({"id"}, {"sql"})
        ),
        iCall("result", "mysql_query", [valVar("sql", tString())],
          Sink("SQL_EXEC", "mysql_query", {"PREPARED_STMT", "INTVAL"})
        ),
        iReturn(valNull(), Neutral())
      ], [])
    ],
    noTags
  );
  return unit("demo_sqli.php", "PHP", [fetchUser], noGlobals);
}

UIRUnit xssDemo() {
  map[str, SecurityTag] noTags    = ();
  map[str, UIRType]     noGlobals = ();

  UIRProc greetHandler = proc(
    "greetHandler",
    [<"req", tAny()>, <"res", tAny()>],
    tVoid(),
    [
      block("entry", [
        iLoad("name",
          valField(valField(valVar("req", tAny()), "query"), "name"),
          Source("HTTP_PARAM", "req.query.name", {"name"})
        ),
        iAssign("greeting",
          valBinOp("+",
            valBinOp("+", valStr("\<h1\>Hello "), valVar("name", tString())),
            valStr("\</h1\>")),
          Propagation({"name"}, {"greeting"})
        ),
        iMethodCall("_", valVar("res", tAny()), "send",
          [valVar("greeting", tString())],
          Sink("HTML_OUTPUT", "res.send", {"HTML_ESCAPE", "DOMPurify"})
        ),
        iReturn(valNull(), Neutral())
      ], [])
    ],
    noTags
  );
  return unit("demo_xss.js", "JavaScript", [greetHandler], noGlobals);
}

UIRUnit cleanSqlDemo() {
  map[str, SecurityTag] noTags    = ();
  map[str, UIRType]     noGlobals = ();

  UIRProc safeFetchUser = proc(
    "safeFetchUser",
    [],
    tVoid(),
    [
      block("entry", [
        iAssign("raw",
          valVar("_GET_id", tString()),
          Source("HTTP_PARAM", "$_GET[\'id\']", {"raw"})
        ),
        iAssign("id",
          valCast(tInt(), valVar("raw", tString())),
          Sanitizer("HTTP_PARAM", "INTVAL", {"raw", "id"})
        ),
        iAssign("sql",
          valBinOp(".", valStr("SELECT * FROM users WHERE id="),
                        valVar("id", tInt())),
          Propagation({"id"}, {"sql"})
        ),
        iCall("result", "mysql_query", [valVar("sql", tString())],
          Sink("SQL_EXEC", "mysql_query", {"PREPARED_STMT", "INTVAL"})
        ),
        iReturn(valNull(), Neutral())
      ], [])
    ],
    noTags
  );
  return unit("demo_clean_sql.php", "PHP", [safeFetchUser], noGlobals);
}

UIRUnit shellInjectionDemo() {
  map[str, SecurityTag] noTags    = ();
  map[str, UIRType]     noGlobals = ();

  UIRProc listDir = proc(
    "listDir",
    [<"user", tString()>],
    tVoid(),
    [
      block("check", [
        iCall("isAdmin", "isAdmin", [valVar("user", tString())], Neutral()),
        iCondJump(valVar("isAdmin", tBool()), "exec", "end")
      ], ["exec", "end"]),

      block("exec", [
        iAssign("dir",
          valVar("_POST_dir", tString()),
          Source("HTTP_PARAM", "$_POST[\'dir\']", {"dir"})
        ),
        iAssign("cmd",
          valBinOp(".", valStr("ls "), valVar("dir", tString())),
          Propagation({"dir"}, {"cmd"})
        ),
        iCall("_", "shell_exec", [valVar("cmd", tString())],
          Sink("SHELL_EXEC", "shell_exec", {"ESCAPESHELLARG"})
        ),
        iJump("end")
      ], ["end"]),

      block("end", [
        iReturn(valNull(), Neutral())
      ], [])
    ],
    noTags
  );
  return unit("demo_shell.php", "PHP", [listDir], noGlobals);
}

// ------------------------------------------------------------------
// 2. Pipeline stages
// ------------------------------------------------------------------

CallGraph buildGraphs(UIRUnit u) = buildCallGraph(u);

AuditResult runAudit(UIRUnit u, CallGraph cg) = auditUnit(u, cg);

void printAudit(AuditResult ar) {
  println(formatReport(ar));
}

AuditResult runPipeline(UIRUnit u) {
  println("\n[TrustTranspiler] Processing: <u.sourceFile> (<u.sourceLanguage>)");
  CallGraph   cg = buildGraphs(u);
  AuditResult ar = runAudit(u, cg);
  printAudit(ar);
  return ar;
}

// ------------------------------------------------------------------
// 3. Main entry point
// ------------------------------------------------------------------

void main() {
  println("╔══════════════════════════════════════════════════════╗");
  println("║         TRUST-TRANSPILER  v0.1.0                     ║");
  println("║   Universal Static Security Analysis (Rascal MPL)    ║");
  println("╚══════════════════════════════════════════════════════╝");

  list[UIRUnit] units = [
    sqlInjectionDemo(),
    xssDemo(),
    cleanSqlDemo(),
    shellInjectionDemo()
  ];

  list[AuditResult] results = [ runPipeline(u) | u <- units ];

  int totalVulns = ( 0 | it + size(r.vulnerabilities) | r <- results );
  int cleanUnits = size([ r | r <- results, r.clean ]);

  println("\nSumário de Execução:");
  println(" - Unidades escaneadas: <size(units)>");
  println(" - Unidades limpas    : <cleanUnits>");
  println(" - Total vulns        : <totalVulns>");

  if (totalVulns > 0) {
    println("[!] BUILD FAILED — vulnerabilidades detectadas.");
  } else {
    println("[✓] BUILD PASSED — sistema íntegro.");
  }
}
