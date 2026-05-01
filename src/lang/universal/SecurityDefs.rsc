module lang::universal::SecurityDefs

data SecurityTag
  = Source(str category, str origin, str propagatesTo)
  | Sink(str category, str target, str requiredSanitizers)
  | Sanitizer(str category, str technique, str cleanedVars)
  | Propagation(str fromVars, str toVars)
  | Neutral()
  ;
