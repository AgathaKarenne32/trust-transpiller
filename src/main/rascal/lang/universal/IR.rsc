module lang::universal::IR

import lang::universal::SecurityDefs;

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

data UIRValue
  = valInt(int n)
  | valFloat(real r)
  | valStr(str s)
  | valBool(bool b)
  | valNull()
  | valVar(str name, UIRType typ)
  | valField(UIRValue obj, str field)
  | valIndex(UIRValue arr, UIRValue idx)
  | valBinOp(str op, UIRValue lhs, UIRValue rhs)
  | valUnOp(str op, UIRValue operand)
  | valCast(UIRType target, UIRValue src)
  | valPhi(UIRValue phiA, UIRValue phiB)
  ;

data UIRInstr
  = iAssign(str dest, UIRValue src, SecurityTag tag)
  | iCall(str dest, str callee, list[UIRValue] args, SecurityTag tag)
  | iMethodCall(str dest, UIRValue recv, str method, list[UIRValue] args, SecurityTag tag)
  | iReturn(UIRValue retVal, SecurityTag tag)
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

data BasicBlock = block(
  str label,
  list[UIRInstr] instrs,
  list[str] successors
);

data UIRParam = param(str paramName, UIRType paramType);

data UIRProc = proc(
  str name,
  list[UIRParam] params,
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

bool isSource(UIRInstr i)    = Source(_, _, _)    := getTag(i);
bool isSink(UIRInstr i)      = Sink(_, _, _)      := getTag(i);
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

set[str] readsOf(UIRValue v) {
  switch (v) {
    case valVar(str n, _):                     return {n};
    case valField(UIRValue obj, _):            return readsOf(obj);
    case valIndex(UIRValue a, UIRValue idx):   return readsOf(a) + readsOf(idx);
    case valBinOp(_, UIRValue l, UIRValue r):  return readsOf(l) + readsOf(r);
    case valUnOp(_, UIRValue x):               return readsOf(x);
    case valCast(_, UIRValue s):               return readsOf(s);
    case valPhi(UIRValue phiA, UIRValue phiB): return readsOf(phiA) + readsOf(phiB);
    default:                                   return {};
  }
}
