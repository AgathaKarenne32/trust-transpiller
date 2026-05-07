module lang::universal::IR

import lang::universal::SecurityDefs;

data UIRType
  = tInt() | tFloat() | tString() | tBool() | tVoid() | tAny()
  | tRef(UIRType inner) | tArray(UIRType elem) | tMap(UIRType key, UIRType val);

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
  | valPhi(list[tuple[UIRValue val, str predLabel]] branches);

data UIRInstr
  = iAssign(str dest, UIRValue src, SecurityTag tag)
  | iCall(str dest, str callee, list[UIRValue] args, SecurityTag tag)
  | iMethodCall(str dest, UIRValue recv, str method, list[UIRValue] args, SecurityTag tag)
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
  | iExitScope(str name);

data BasicBlock = block(str label, list[UIRInstr] instrs, list[str] successors);
data UIRParam = param(str paramName, UIRType paramType);
data UIRProc = proc(str name, list[UIRParam] params, UIRType returnType, list[BasicBlock] blocks, map[str, SecurityTag] paramTags);
data UIRUnit = unit(str sourceFile, str sourceLanguage, list[UIRProc] procs, map[str, UIRType] globals);

// Helpers simplificados para evitar erros de match
SecurityTag getTag(UIRInstr i) {
  if (iAssign(_, _, t) := i) return t;
  if (iCall(_, _, _, t) := i) return t;
  if (iMethodCall(_, _, _, _, t) := i) return t;
  if (iReturn(_, t) := i) return t;
  if (iStore(_, _, t) := i) return t;
  if (iLoad(_, _, t) := i) return t;
  return Neutral();
}

set[str] readsOf(UIRValue v) {
  switch (v) {
    case valVar(n, _): return {n};
    case valField(obj, _): return readsOf(obj);
    case valBinOp(_, l, r): return readsOf(l) + readsOf(r);
    case valPhi(list[tuple[UIRValue val, str predLabel]] bs): return ( {} | it + readsOf(b.val) | b <- bs );
    default: return {};
  }
}