module pipeline::TrustTranspiler

// ============================================================
//  Trust-Transpiler — Pipeline Orchestrator
//  pipeline::TrustTranspiler
//
//  Main entry point.  Wires together:
//    1. Front-end fixture / loader  (demo UIR units)
//    2. CFG builder                 (analysis::CFG)
//    3. Taint analysis engine       (validation::Gatekeeper)
//    4. Report formatter & printer
// ============================================================

import lang::universal::IR;
import analysis::CFG;
import validation::Gatekeeper;
import IO;
import List;

// ------------------------------------------------------------------
// 1. Demo fixtures — hand-crafted UIR units that model real vulns
// ------------------------------------------------------------------

// ---- 1a. SQL Injection (PHP-style) --------------------------------
//
//  <?php
//    $id   = $_GET['id'];                  // ← Source
//    $sql  = "SELECT * FROM users WHERE id=" . $id;
//    $res  = mysql_query($sql);            // ← Sink
//  ?>
//
UIRUnit sqlInjectionDemo() {
  UIRProc fetchUser = proc(
    "fetchUser",
    [],
    tVoid(),
    [
      block("entry", [
        // $id = $_GET['id']   — HTTP source
        iAssign("id",
          valVar("_GET_id", tString()),
          Source("HTTP_PARAM", "$_GET[\'id\']", {"id"})
        ),
        // $sql = "SELECT..." . $id  — propagation via string concat
        iAssign("sql",
          valBinOp(".", valStr("SELECT * FROM users WHERE id="), valVar("id", tString())),
          Propagation({"id"}, {"sql"})
        ),
        // mysql_query($sql)  — SQL sink
        iCall("result", "mysql_query", [valVar("sql", tString())],
          Sink("SQL_EXEC", "mysql_query", {"PREPARED_STMT", "INTVAL"})
        ),
        iReturn(valNull(), Neutral())
      ], [])
    ],
    ()
  );

  return unit("demo_sqli.php", "PHP", [fetchUser], ());
}

// ---- 1b. XSS (JavaScript/Node.js) ---------------------------------
//
//  app.get('/greet', (req, res) => {
//    const name = req.query.name;          // ← Source
//    res.send('<h1>Hello ' + name + '</h1>'); // ← Sink
//  });
//
UIRUnit xssDemo() {
  UIRProc greetHandler = proc(
    "greetHandler",
    [<"req", tAny()>, <"res", tAny()>],
    tVoid(),
    [
      block("entry", [
        // name = req.query.name
        iLoad("name",
          valField(valField(valVar("req", tAny()), "query"), "name"),
          Source("HTTP_PARAM", "req.query.name", {"name"})
        ),
        // greeting = '<h1>Hello ' + name + '</h1>'
        iAssign("greeting",
          valBinOp("+",
            valBinOp("+", valStr("\<h1\>Hello "), valVar("name", tString())),
            valStr("\</h1\>")),
          Propagation({"name"}, {"greeting"})
        ),
        // res.send(greeting)   — HTML output sink
        iMethodCall("_", valVar("res", tAny()), "send",
          [valVar("greeting", tString())],
          Sink("HTML_OUTPUT", "res.send", {"HTML_ESCAPE", "DOMPurify"})
        ),
        iReturn(valNull(), Neutral())
      ], [])
    ],
    ()
  );

  return unit("demo_xss.js", "JavaScript", [greetHandler], ());
}

// ---- 1c. Clean path (sanitised SQL) --------------------------------
//
//  Demonstrates a TRUE NEGATIVE — should produce zero reports.
//
//  $id = (int) $_GET['id'];   // ← Source + Sanitizer (INTVAL cast)
//  $sql = "SELECT * FROM users WHERE id=" . $id;
//  $res = mysql_query($sql);  // ← Sink — taint is gone
//
UIRUnit cleanSqlDemo() {
  UIRProc safeFetchUser = proc(
    "safeFetchUser",
    [],
    tVoid(),
    [
      block("entry", [
        // raw = $_GET['id']
        iAssign("raw",
          valVar("_GET_id", tString()),
          Source("HTTP_PARAM", "$_GET[\'id\']", {"raw"})
        ),
        // id = (int) raw  — sanitiser: integer cast eliminates SQL taint
        iAssign("id",
          valCast(tInt(), valVar("raw", tString())),
          Sanitizer("HTTP_PARAM", "INTVAL", {"raw", "id"})
        ),
        // sql = "... WHERE id=" . id
        iAssign("sql",
          valBinOp(".", valStr("SELECT * FROM users WHERE id="),
                        valVar("id", tInt())),
          Propagation({"id"}, {"sql"})
        ),
        // mysql_query($sql)  — sink, but taint should be clear
        iCall("result", "mysql_query", [valVar("sql", tString())],
          Sink("SQL_EXEC", "mysql_query", {"PREPARED_STMT", "INTVAL"})
        ),
        iReturn(valNull(), Neutral())
      ], [])
    ],
    ()
  );

  return unit("demo_clean_sql.php", "PHP", [safeFetchUser], ());
}

// ---- 1d. Shell injection (multi-block with branch) ----------------
//
//  if (isAdmin(user)) {
//    $cmd = "ls " . $_POST['dir'];   // ← Source
//    shell_exec($cmd);               // ← Sink
//  }
//
UIRUnit shellInjectionDemo() {
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
        // dir = $_POST['dir']
        iAssign("dir",
          valVar("_POST_dir", tString()),
          Source("HTTP_PARAM", "$_POST[\'dir\']", {"dir"})
        ),
        // cmd = "ls " . dir
        iAssign("cmd",
          valBinOp(".", valStr("ls "), valVar("dir", tString())),
          Propagation({"dir"}, {"cmd"})
        ),
        // shell_exec($cmd)  — sink
        iCall("_", "shell_exec", [valVar("cmd", tString())],
          Sink("SHELL_EXEC", "shell_exec", {"ESCAPESHELLARG"})
        ),
        iJump("end")
      ], ["end"]),

      block("end", [
        iReturn(valNull(), Neutral())
      ], [])
    ],
    ()
  );

  return unit("demo_shell.php", "PHP", [listDir], ());
}

// ------------------------------------------------------------------
// 2. Pipeline stages
// ------------------------------------------------------------------

// Stage 1 – Build CFG + Call-graph
CallGraph buildGraphs(UIRUnit u) = buildCallGraph(u);

// Stage 2 – Run Gatekeeper
AuditResult runAudit(UIRUnit u, CallGraph cg) = auditUnit(u, cg);

// Stage 3 – Print report to stdout
void printAudit(AuditResult ar) {
  println(formatReport(ar));
}

// ------------------------------------------------------------------
// 3. Run a single UIR unit through the full pipeline
// ------------------------------------------------------------------

AuditResult runPipeline(UIRUnit u) {
  println("\n[TrustTranspiler] Processing: <u.sourceFile> (<u.sourceLanguage>)");
  CallGraph cg    = buildGraphs(u);
  AuditResult ar  = runAudit(u, cg);
  printAudit(ar);
  return ar;
}

// ------------------------------------------------------------------
// 4. Main entry point
// ------------------------------------------------------------------

void main(list[str] args) {
  println("╔══════════════════════════════════════════════════════╗");
  println("║          TRUST-TRANSPILER  v0.1.0                   ║");
  println("║   Universal Static Security Analysis (Rascal MPL)   ║");
  println("╚══════════════════════════════════════════════════════╝");

  list[UIRUnit] units = [
    sqlInjectionDemo(),
    xssDemo(),
    cleanSqlDemo(),
    shellInjectionDemo()
  ];

  list[AuditResult] results = [ runPipeline(u) | u <- units ];

  // ---- Aggregate summary ---
  int totalVulns = ( 0 | it + size(r.vulnerabilities) | r <- results );
  int cleanUnits = size([ r | r <- results, r.clean ]);

  println("\n╔══════════════════════════════════════════════════════╗");
  println("║  AGGREGATE SUMMARY                                   ║");
  println("╠══════════════════════════════════════════════════════╣");
  println("║  Units scanned : <size(units)>                                    ║");
  println("║  Clean units   : <cleanUnits>                                    ║");
  println("║  Total vulns   : <totalVulns>                                    ║");
  println("╚══════════════════════════════════════════════════════╝\n");

  if (totalVulns > 0) {
    println("[!] BUILD FAILED — vulnerabilities detected.");
  } else {
    println("[✓] BUILD PASSED — no vulnerabilities detected.");
  }
}
