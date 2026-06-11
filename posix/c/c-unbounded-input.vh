author = "prockallsyms"
name = "c-unbounded-input"
platform = "posix-binary"
architecture = "*:*:*"

-- Consolidated unbounded-input sinks: gets and the scanf family. glibc lowers
-- scanf -> __isoc99_scanf (etc.), so both forms are listed. (CWE-120/CWE-242)
scopes = {
  scope:calls{to = "gets",            using = {}, with = check},
  scope:calls{to = "getwd",           using = {}, with = check},
  scope:calls{to = "scanf",           using = {}, with = check},
  scope:calls{to = "sscanf",          using = {}, with = check},
  scope:calls{to = "fscanf",          using = {}, with = check},
  scope:calls{to = "vscanf",          using = {}, with = check},
  scope:calls{to = "vsscanf",         using = {}, with = check},
  scope:calls{to = "vfscanf",         using = {}, with = check},
  scope:calls{to = "__isoc99_scanf",  using = {}, with = check},
  scope:calls{to = "__isoc99_sscanf", using = {}, with = check},
  scope:calls{to = "__isoc99_fscanf", using = {}, with = check},
}

function check(project, context)
  return result:medium{
    name = "unbounded-input",
    description = "Use of gets/getwd or an unbounded scanf-family read. These can write past a fixed-size buffer when no width limit is given. (CWE-120/CWE-242)",
    cwes = {"CWE-120", "CWE-242"},
    evidence = {functions = {[context.caller.address] = {
      annotate:at{location = context.caller.call_address,
        message = "Unbounded input read into a caller buffer."}
    }}}
  }
end
-- vim: ft=lua
