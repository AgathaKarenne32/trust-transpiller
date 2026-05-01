module lang::universal::IRTest

data SecurityTag = Neutral() | Source(str s);
data UIRValue = valInt(int n) | valNull();
data UIRInstr = iReturn(UIRValue retVal) | iAssign(str dest, SecurityTag tag);
