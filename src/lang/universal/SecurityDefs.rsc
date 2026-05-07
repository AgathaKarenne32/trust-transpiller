module lang::universal::SecurityDefs

data SecurityTag
  = Source(str category, str origin, set[str] propagatesTo)
  | Sink(str category, str target, set[str] requiredSanitizers)
  | Sanitizer(str category, str technique, set[str] cleanedVars)
  | Propagation(set[str] fromVars, set[str] toVars)
  | Neutral()
  ;
