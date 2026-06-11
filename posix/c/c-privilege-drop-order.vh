author = "prockallsyms"
name = "c-privilege-drop-order"
platform = "posix-binary"
architecture = "*:*:*"

-- Ordering heuristic (ported from raptor-incorrect-order-setuid-setgid). Dropping
-- the user id before the group id is wrong: after setuid() drops root the process
-- can no longer change its group, so setgid() may silently fail and supplementary
-- groups remain. Flag a function where setuid precedes setgid. (CWE-696)
scopes = scope:project{with = check}

local function first_call(f, name)
  local cs = f:calls(name)
  if cs and #cs > 0 then return cs[1] end
  return nil
end

function check(project, context)
  local funcs = project:functions_where(function(f)
    return (f:has_call("setuid") or f:has_call("seteuid")) and
           (f:has_call("setgid") or f:has_call("setegid"))
  end)
  if #funcs == 0 then return end

  local evidence = {}
  for _, f in ipairs(funcs) do
    local uid = first_call(f, "setuid") or first_call(f, "seteuid")
    local gid = first_call(f, "setgid") or first_call(f, "setegid")
    -- ordering proxy: uid call site precedes gid call site
    if uid and gid and uid < gid then
      evidence[f.address] = {
        annotate:at{location = uid, message = "User id dropped here (setuid)..."},
        annotate:at{location = gid, message = "...before the group id (setgid) — wrong order; setgid may fail."}
      }
    end
  end
  if next(evidence) == nil then return end

  return result:medium{
    name = "privilege-drop-order",
    description = "setuid()/seteuid() is called before setgid()/setegid(). Drop the group id first; once the user id is dropped the process may be unable to change groups. (CWE-696)",
    cwes = {"CWE-696"},
    evidence = {functions = evidence}
  }
end
-- vim: ft=lua
