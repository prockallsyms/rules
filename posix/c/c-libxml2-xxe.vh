author = "prockallsyms"
name = "c-libxml2-xxe"
platform = "posix-binary"
architecture = "*:*:*"
-- libxml2 parse with dangerous option flags enabling XXE / external DTD / billion-laughs:
-- XML_PARSE_NOENT(2), XML_PARSE_DTDLOAD(4), XML_PARSE_HUGE(0x80000). (CWE-611/CWE-776)
scopes = {
  scope:calls{to="xmlReadFile",      using={}, with=opt3},
  scope:calls{to="xmlReadDoc",       using={}, with=opt3},
  scope:calls{to="xmlCtxtReadFile",  using={}, with=opt4},   -- ctxt,url,enc,options
  scope:calls{to="xmlReadMemory",    using={}, with=opt5},   -- buf,size,url,enc,options
  scope:calls{to="xmlCtxtReadMemory",using={}, with=opt6},
}
local function dangerous(op)
  if op==nil or not op:is_const() or op.constant==nil then return false end
  local c=op.constant; local function bit(n) return not c:band(BitVec.from_integer(n,c:bits())):is_zero() end
  return bit(2) or bit(4) or bit(0x80000)
end
local function fire(context)
  return result:high{name="libxml2-xxe",
    description="libxml2 parse with XML_PARSE_NOENT/DTDLOAD/HUGE — enables XXE, external DTD load, or billion-laughs. (CWE-611/CWE-776)",
    cwes={"CWE-611","CWE-776"}, evidence={functions={[context.caller.address]={annotate:at{location=context.caller.call_address,message="dangerous XML parse flags"}}}}}
end
function opt3(p,context) if dangerous(context.inputs[3]) then return fire(context) end end
function opt4(p,context) if dangerous(context.inputs[4]) then return fire(context) end end
function opt5(p,context) if dangerous(context.inputs[5]) then return fire(context) end end
function opt6(p,context) if dangerous(context.inputs[6]) then return fire(context) end end
