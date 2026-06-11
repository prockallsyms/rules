author = "prockallsyms"
name = "c-memset-misuse"
platform = "posix-binary"
architecture = "*:*:*"

-- Operand-based (ported from insecure-use-memset / raptor-incorrect-use-of-memset):
-- a memset whose length argument is a constant 0 does nothing. This catches both
-- memset(p, 0, 0) and the classic swapped-argument bug memset(p, sizeof(x), 0)
-- where the count and fill value are transposed. (CWE-665/CWE-628)
scopes = {
  scope:calls{to = "memset",          using = {}, with = check},
  scope:calls{to = "memset_explicit", using = {}, with = check},
}

-- memset(dest, value, length): length is the 3rd argument (inputs[3]).
function check(project, context)
  local len = context.inputs[3]
  if len == nil or not len:is_const() then return end
  if len.constant ~= nil and len.constant:is_zero() then
    return result:medium{
      name = "memset-misuse",
      description = "memset with a constant length of 0 writes nothing — ineffective buffer clear, or a transposed-argument bug (count/value swapped). (CWE-665/CWE-628)",
      cwes = {"CWE-665", "CWE-628"},
      evidence = {functions = {[context.caller.address] = {
        annotate:at{location = context.caller.call_address, message = "memset length is constant 0."}}}}
    }
  end
end
-- vim: ft=lua
