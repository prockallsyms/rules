author = "prockallsyms"
name = "c-tainted-input-to-sink"
platform = "posix-binary"
architecture = "*:*:*"

-- Dataflow heuristic (generalises getenv-into-shell; covers External-Control,
-- Process-Control, Relative-Path-Traversal, format-built-shell-command). A
-- function that reads untrusted input AND reaches a dangerous sink, with the
-- read ordered before the sink, is a likely injection/overflow path. This is
-- co-occurrence + ordering, not precise taint. (CWE-77/CWE-78/CWE-120)
scopes = scope:project{with = check}

local SOURCES = {"getenv", "secure_getenv", "recv", "recvfrom", "read", "fgets", "fread"}
local SINKS = {"system", "popen", "execl", "execlp", "execle", "execv", "execvp", "execve",
               "strcpy", "strcat", "sprintf"}

local function first_call(f, names)
  for _, n in ipairs(names) do
    local cs = f:calls(n)
    if cs and #cs > 0 then return cs[1], n end
  end
  return nil
end

local function has_any(f, names)
  for _, n in ipairs(names) do if f:has_call(n) then return true end end
  return false
end

function check(project, context)
  local funcs = project:functions_where(function(f)
    return has_any(f, SOURCES) and has_any(f, SINKS)
  end)
  if #funcs == 0 then return end

  local evidence = {}
  for _, f in ipairs(funcs) do
    local src, sname = first_call(f, SOURCES)
    local sink, kname = first_call(f, SINKS)
    if src and sink and src < sink then  -- source precedes sink
      evidence[f.address] = {
        annotate:at{location = src,  message = "Untrusted input read here (" .. sname .. ")..."},
        annotate:at{location = sink, message = "...and reaches a dangerous sink (" .. kname .. ") in the same function."}
      }
    end
  end
  if next(evidence) == nil then return end

  return result:medium{
    name = "tainted-input-to-sink",
    description = "A function reads untrusted input and reaches a command/exec or unbounded-copy sink. If the value flows through, this is injection or buffer overflow. (CWE-77/CWE-78/CWE-120)",
    cwes = {"CWE-77", "CWE-78", "CWE-120"},
    evidence = {functions = evidence}
  }
end
-- vim: ft=lua
