author = "prockallsyms"
name = "c-alloc-size-multiplication"
platform = "posix-binary"
architecture = "*:*:*"
extensions = "decompiler"

-- Achievable TODAY (no engine work) — verified the multiply survives decompilation:
-- `malloc(param1 * param2)`. Allocation size computed by multiplication is a classic
-- integer-overflow → undersized-buffer vector (e.g. n*size wraps). Scoped to allocator
-- call sites so we only decompile candidates. (CWE-190/CWE-131)
-- (Ported from itermalum/0xdea raptor-integer-wraparound; previously deferred.)
scopes = {
  scope:calls{to = "malloc",  using = {}, with = check},
  scope:calls{to = "calloc",  using = {}, with = check},  -- two-arg calloc is the safe form; flag products in either arg
  scope:calls{to = "realloc", using = {}, with = check},
  scope:calls{to = "valloc",  using = {}, with = check},
  scope:calls{to = "aligned_alloc", using = {}, with = check},
}

local function count(m) if m == nil then return 0 end local d = m:dump() return d and #d or 0 end

function check(project, context)
  local fa = context.caller.address
  local d = project:decompile(fa)
  local f = type(d) == "table" and d[1] or d
  if f == nil then return end
  -- any allocator call whose size argument is a product of two non-constant terms
  local hits = count(f:query("malloc($a * $b);"))
             + count(f:query("realloc(_, $a * $b);"))
             + count(f:query("calloc($a * $b, _);"))
             + count(f:query("aligned_alloc(_, $a * $b);"))
  if hits > 0 then
    return result:medium{
      name = "alloc-size-multiplication",
      description = "Allocation size is computed by multiplication; if the factors are attacker-influenced this can integer-overflow and under-allocate, leading to heap overflow. (CWE-190/CWE-131)",
      cwes = {"CWE-190", "CWE-131"},
      evidence = {functions = {[fa] = {annotate:at{location = fa,
        message = "Allocation size is a product of two values (overflow risk)."}}}}
    }
  end
end
-- vim: ft=lua
