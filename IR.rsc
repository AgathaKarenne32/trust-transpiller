module lang::universal::IR

// ============================================================
//  Trust-Transpiler — Universal Intermediate Representation
//  lang::universal::IR
//
//  Defines the language-agnostic instruction set (UIR) used
//  as the single target for all front-end transpilers.
//  Security annotations are first-class citizens of the IR.
// ============================================================

// ------------------------------------------------------------------
// 1. Primitive value types
// ------------------------------------------------------------------

data UIRType
  = tInt()
  | tFloat()
  | tString()
  | tBool()
  | tVoid()
  | tAny()                          // opaque / unresolved
  | tRef(UIRType inner)             // pointer / reference
  | tArray(UIRType elem)
  | tMap(UIRType key, UIRType val)
  ;

// ------------------------------------------------------------------
// 2. Value expressions (pure, side-effect free)
// ------------------------------------------------------------------

data UIRValue
  = valInt(int n)
  | valFloat(real r)
  | valStr(str s)
  | valBool(bool b)
  | valNull()
  | valVar(str name, UIRType \type)
  | valField(UIRValue obj, str field)
  | valIndex(UIRValue arr, UIRValue idx)
  | valBinOp(str op, UIRValue lhs, UIRValue rhs)   // "+", "==", "&&", …
  | valUnOp(str op, UIRValue operand)               // "!", "-", …
  | valCast(UIRType target, UIRValue src)
  | valPhi(list[tuple[UIRValue val, str predLabel]] branches)  // SSA φ-node
  ;

// ------------------------------------------------------------------
// 3. Security annotations
//
//  Every instruction *may* carry one annotation that describes its
//  role in a taint-flow story.
// ------------------------------------------------------------------

data SecurityTag
  = Source(
      str category,                 // "SQL_INPUT" | "HTTP_PARAM" | "FILE_READ" | …
      str origin,                   // e.g. "$_GET['id']", "request.getParameter(…)"
      set[str] propagatesTo         // variable names this source taints initially
    )
  | Sink(
      str category,                 // "SQL_EXEC" | "HTML_OUTPUT" | "SHELL_EXEC" | …
      str target,                   // expression / function call being reached
      set[str] requiredSanitizers   // at least ONE must be on the path
    )
  | Sanitizer(
      str category,                 // must match a Sink's requiredSanitizers member
      str technique,                // e.g. "PREPARED_STMT", "HTML_ESCAPE", "REGEX_FILTER"
      set[str] cleanedVars          // variables rendered safe by this sanitizer
    )
  | Propagation(                    // implicit taint move (assignment, concat, …)
      set[str] from,
      set[str] to
    )
  | Neutral()                       // no security relevance
  ;

// ------------------------------------------------------------------
// 4. Instructions
// ------------------------------------------------------------------

data UIRInstr
  // ---- Data-flow ----
  = iAssign(
      str dest,
      UIRValue src,
      SecurityTag tag
    )
  | iCall(
      str dest,                     // "" when result is discarded
      str callee,
      list[UIRValue] args,
      SecurityTag tag
    )
  | iMethodCall(
      str dest,
      UIRValue receiver,
      str method,
      list[UIRValue] args,
      SecurityTag tag
    )
  | iReturn(
      UIRValue val,
      SecurityTag tag
    )
  | iStore(                         // heap / field write
      UIRValue target,
      UIRValue val,
      SecurityTag tag
    )
  | iLoad(                          // heap / field read
      str dest,
      UIRValue src,
      SecurityTag tag
    )

  // ---- Control-flow ----
  | iJump(str label)
  | iCondJump(
      UIRValue cond,
      str trueLabel,
      str falseLabel
    )
  | iLabel(str name)

  // ---- Exception handling ----
  | iThrow(UIRValue exn)
  | iCatch(str varName, UIRType exnType, str handlerLabel)

  // ---- Meta ----
  | iNop()
  | iComment(str text)
  | iEnterScope(str name)           // function / block boundary marker
  | iExitScope(str name)
  ;

// ------------------------------------------------------------------
// 5. Basic block
// ------------------------------------------------------------------

data BasicBlock = block(
  str label,
  list[UIRInstr] instrs,
  list[str] successors             // labels of successor blocks
);

// ------------------------------------------------------------------
// 6. Procedure (function / method)
// ------------------------------------------------------------------

data UIRProc = proc(
  str name,
  list[tuple[str paramName, UIRType paramType]] params,
  UIRType returnType,
  list[BasicBlock] blocks,
  map[str, SecurityTag] paramTags  // taint annotation per parameter
);

// ------------------------------------------------------------------
// 7. Compilation unit (module / file)
// ------------------------------------------------------------------

data UIRUnit = unit(
  str sourceFile,
  str sourceLanguage,              // "PHP" | "JavaScript" | "Java" | …
  list[UIRProc] procs,
  map[str, UIRType] globals
);

// ------------------------------------------------------------------
// 8. Helpers
// ------------------------------------------------------------------

// Retrieve the SecurityTag from any instruction (default Neutral)
SecurityTag getTag(UIRInstr i) {
  switch (i) {
    case iAssign(_, _, t):      return t;
    case iCall(_, _, _, t):     return t;
    case iMethodCall(_, _, _, _, t): return t;
    case iReturn(_, t):         return t;
    case iStore(_, _, t):       return t;
    case iLoad(_, _, t):        return t;
    default:                    return Neutral();
  }
}

// True if the instruction introduces tainted data
bool isSource(UIRInstr i) = Source(_, _, _) := getTag(i);

// True if the instruction is a sensitive sink
bool isSink(UIRInstr i) = Sink(_, _, _) := getTag(i);

// True if the instruction sanitizes tainted data
bool isSanitizer(UIRInstr i) = Sanitizer(_, _, _) := getTag(i);

// Extract destination variable name (empty string if none)
str getDest(UIRInstr i) {
  switch (i) {
    case iAssign(d, _, _):        return d;
    case iCall(d, _, _, _):       return d;
    case iMethodCall(d, _, _, _, _): return d;
    case iLoad(d, _, _):          return d;
    default:                      return "";
  }
}

// Collect all variable names read by a value expression
set[str] readsOf(UIRValue v) {
  switch (v) {
    case valVar(n, _):            return {n};
    case valField(obj, _):        return readsOf(obj);
    case valIndex(a, i):          return readsOf(a) + readsOf(i);
    case valBinOp(_, l, r):       return readsOf(l) + readsOf(r);
    case valUnOp(_, x):           return readsOf(x);
    case valCast(_, s):           return readsOf(s);
    case valPhi(branches):        return ( {} | it + readsOf(b.val) | b <- branches );
    default:                      return {};
  }
}
