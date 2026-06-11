author = "vulhunt-dev"
name = "c-format-string"
platform = "posix-binary"
architecture = "*:*:*"

-- Higher-signal than presence: flag printf-family calls whose FORMAT argument
-- is not a compile-time constant (i.e. attacker may control the format).
-- The format-arg index differs per function, so each scope uses a dedicated
-- check that knows the 1-based index of the format operand. (CWE-134)
scopes = {
  scope:calls{to = "printf",   using = {}, with = check1},  -- printf(fmt, ...)
  scope:calls{to = "vprintf",  using = {}, with = check1},
  scope:calls{to = "fprintf",  using = {}, with = check2},  -- fprintf(stream, fmt, ...)
  scope:calls{to = "vfprintf", using = {}, with = check2},
  scope:calls{to = "dprintf",  using = {}, with = check2},  -- dprintf(fd, fmt, ...)
  scope:calls{to = "sprintf",  using = {}, with = check2},  -- sprintf(buf, fmt, ...)
  scope:calls{to = "vsprintf", using = {}, with = check2},
  scope:calls{to = "syslog",   using = {}, with = check2},  -- syslog(prio, fmt, ...)
  scope:calls{to = "snprintf", using = {}, with = check3},  -- snprintf(buf, n, fmt, ...)
  scope:calls{to = "vsnprintf",using = {}, with = check3},
}

local function fmt_check(context, idx)
  local fmt = context.inputs[idx]
  if fmt == nil then return end
  -- A constant format (string literal) is fine; a non-constant format means
  -- the format string itself may be attacker-influenced.
  if fmt:is_const() then return end
  if fmt.string ~= nil then return end  -- resolved to a literal string

  return result:high{
    name = "format-string",
    description = "printf-family call with a non-constant format string. If the format derives from untrusted input this is a format-string vulnerability (info leak / memory corruption via %n). (CWE-134)",
    cwes = {"CWE-134"},
    evidence = {functions = {[context.caller.address] = {
      annotate:at{location = context.caller.call_address,
        message = "Format argument is not a compile-time constant."}
    }}}
  }
end

function check1(project, context) return fmt_check(context, 1) end
function check2(project, context) return fmt_check(context, 2) end
function check3(project, context) return fmt_check(context, 3) end
-- vim: ft=lua
