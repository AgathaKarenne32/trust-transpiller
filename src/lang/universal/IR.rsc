module lang::universal::IR

// ============================================================
// Trust-Transpiler — Universal Intermediate Representation
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
  | tAny()
  | tRef(UIRType inner)
  | tArray(UIRType elem)
  | tMap(UIRType key, UIRType val)
  ;

// ------------------------------------------------------------------
// 2. Value expressions (pure, side-effect free)
// ------------------------------------------------------------------

// FIX: valPhi cannot use named tuple fields inside a data constructor
//      argument type. Use anonymous tuple[UIRValue, str] instead.
data UIRValue
  = valInt(int n)
  | valFloat(real r)
  | valStr(str s)
  | valBool(bool b)
  | valNull()
  | valVar(str name, UIRType \type)
  | valField(UIRValue obj, str field)
  | valIndex(UIRValue arr, UIRValue idx)
  | valBinOp(str op, UIRValue lhs, UIRValue rhs)
  | valUnOp(str op, UIRValue operand)
  | valCast(UIRType target, UIRValue src)
  | valPhi(list[tuple[UIRValue, str]] branches)
  ;

// ------------------------------------------------------------------
// 3. Security annotations
// ------------------------------------------------------------------

data SecurityTag
  = Source(str category, str origin, set[str] propagatesTo)
  | Sink(str category, str target, set[str] requiredSanitizers)
  | Sanitizer(str category, str technique, set[str] cleanedVars)
  | Propagation(set[str] from, set[str] to)
  | Neutral()
  ;

// ------------------------------------------------------------------
// 4. Instructions
// ------------------------------------------------------------------

data UIRInstr
  = iAssign(str dest, UIRValue src, SecurityTag tag)
  | iCall(str dest, str callee, list[UIRValue] args, SecurityTag tag)
  | iMethodCall(str dest, UIRValue receiver, str method, list[UIRValue] args, SecurityTag tag)
  | iReturn(UIRValue val, SecurityTag tag)
  | iStore(UIRValue target, UIRValue val, SecurityTag tag)
  | iLoad(str dest, UIRValue src, SecurityTag tag)
  | iJump(str label)
  | iCondJump(UIRValue cond, str trueLabel, str falseLabel)
  | iLabel(str name)
  | iThrow(UIRValue exn)
  | iCatch(str varName, UIRType exnType, str handlerLabel)
  | iNop()
  | iComment(str text)
  | iEnterScope(str name)
  | iExitScope(str name)
  ;

// ------------------------------------------------------------------
// 5. Data structures
// ------------------------------------------------------------------

data BasicBlock = block(
  str label,
  list[UIRInstr] instrs,
  list[str] successors
);

data UIRProc = proc(
  str name,
  list[tuple[str, UIRType]] params,
  UIRType returnType,
  list[BasicBlock] blocks,
  map[str, SecurityTag] paramTags
);

data UIRUnit = unit(
  str sourceFile,
  str sourceLanguage,
  list[UIRProc] procs,
  map[str, UIRType] globals
);

// ------------------------------------------------------------------
// 6. Helpers
// ------------------------------------------------------------------

SecurityTag getTag(UIRInstr i) {
  switch (i) {
    case iAssign(_, _, SecurityTag t):           return t;
    case iCall(_, _, _, SecurityTag t):          return t;
    case iMethodCall(_, _, _, _, SecurityTag t): return t;
    case iReturn(_, SecurityTag t):              return t;
    case iStore(_, _, SecurityTag t):            return t;
    case iLoad(_, _, SecurityTag t):             return t;
    default:                                     return Neutral();
  }
}

bool isSource(UIRInstr i)    = Source(_, _, _) := getTag(i);
bool isSink(UIRInstr i)      = Sink(_, _, _)   := getTag(i);
bool isSanitizer(UIRInstr i) = Sanitizer(_, _, _) := getTag(i);

str getDest(UIRInstr i) {
  switch (i) {
    case iAssign(str d, _, _):           return d;
    case iCall(str d, _, _, _):          return d;
    case iMethodCall(str d, _, _, _, _): return d;
    case iLoad(str d, _, _):             return d;
    default:                             return "";
  }
}

// FIX: valPhi branches are now tuple[UIRValue, str] (anonymous).
//      Access positionally: b[0] for the value, b[1] for the label.
set[str] readsOf(UIRValue v) {
  switch (v) {
    case valVar(str n, _):   return {n};
    case valField(obj, _):   return readsOf(obj);
    case valIndex(a, i):     return readsOf(a) + readsOf(i);
    case valBinOp(_, l, r):  return readsOf(l) + readsOf(r);
    case valUnOp(_, x):      return readsOf(x);
    case valCast(_, s):      return readsOf(s);
    case valPhi(list[tuple[UIRValue, str]] branches):
      return ( {} | it + readsOf(b[0]) | b <- branches );
    default: return {};
  }
}
