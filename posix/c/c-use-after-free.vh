author = "vulhunt-dev"
name = "c-use-after-free"
platform = "posix-binary"
architecture = "*:*:*"
extensions = "decompiler"

-- Achievable TODAY with the shipped engine — no new analysis. Uses the decompiler
-- + Weggli structural query on decompiled C. Scoped to functions that call free()
-- so we only decompile candidates (decompilation is expensive). Weggli variable
-- binding ($p) + the `not: $p = _;` guard make this precise: a pointer freed and
-- then freed again / used again, with no reassignment in between. (CWE-415/CWE-416)
scopes = scope:calls{to = "free", using = {}, with = check}

local function count(m) if m == nil then return 0 end local d = m:dump() return d and #d or 0 end

function check(project, context)
  local fa = context.caller.address
  local d = project:decompile(fa)
  local f = type(d) == "table" and d[1] or d
  if f == nil then return end

  local double = f:query("free($p); not: $p = _; free($p);")  -- double free
  local uaf    = f:query("free($p); not: $p = _; _($p);")      -- use after free

  if count(double) > 0 then
    return result:high{
      name = "double-free",
      description = "A pointer is freed twice with no reassignment in between (double free). (CWE-415)",
      cwes = {"CWE-415"},
      evidence = {functions = {[fa] = {annotate:at{location = fa,
        message = "Pointer freed twice without reassignment."}}}}
    }
  elseif count(uaf) > 0 then
    return result:high{
      name = "use-after-free",
      description = "A pointer is used after being freed, with no reassignment in between. (CWE-416)",
      cwes = {"CWE-416"},
      evidence = {functions = {[fa] = {annotate:at{location = fa,
        message = "Pointer used after free."}}}}
    }
  end
end
-- vim: ft=lua
