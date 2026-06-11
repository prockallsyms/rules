author = "prockallsyms"
name = "c-obsolete-api"
platform = "posix-binary"
architecture = "*:*:*"

-- Consolidated from gitlab c_obsolete_rule-* / c_misc_rule-* and lang.
-- Obsolete / spoofable / thread-unsafe APIs. (CWE-477/CWE-676)
scopes = {
  scope:calls{to = "gsignal",  using = {}, with = check},
  scope:calls{to = "ssignal",  using = {}, with = check},
  scope:calls{to = "ulimit",   using = {}, with = check},
  scope:calls{to = "usleep",   using = {}, with = check},
  scope:calls{to = "vfork",    using = {}, with = check},
  scope:calls{to = "cuserid",  using = {}, with = check},
  scope:calls{to = "getpass",  using = {}, with = check},  -- deprecated; echoes/leaks
  scope:calls{to = "getlogin", using = {}, with = check},  -- spoofable
  scope:calls{to = "strtok",   using = {}, with = check},  -- not thread-safe (use strtok_r)
}

function check(project, context)
  return result:info{
    name = "obsolete-api",
    description = "Use of an obsolete, spoofable, or thread-unsafe API (gsignal/ssignal/ulimit/usleep/vfork/cuserid/getpass/getlogin/strtok). Prefer the documented modern replacement. (CWE-477)",
    cwes = {"CWE-477"},
    evidence = {functions = {[context.caller.address] = {
      annotate:at{location = context.caller.call_address,
        message = "Obsolete / unsafe legacy API."}
    }}}
  }
end
-- vim: ft=lua
