author = "vulhunt-dev"
name = "c-unchecked-numeric-conversion"
platform = "posix-binary"
architecture = "*:*:*"

-- Ported from gitlab c_integer_rule-atoi-atol, lang incorrect-use-ato-fn.
-- atoi/atol/atoll/atof do no error detection (return 0 on failure, UB on
-- overflow). Prefer strtol/strtoll with errno checking. (CWE-190/CWE-704)
scopes = {
  scope:calls{to = "atoi",  using = {}, with = check},
  scope:calls{to = "atol",  using = {}, with = check},
  scope:calls{to = "atoll", using = {}, with = check},
  scope:calls{to = "atof",  using = {}, with = check},
}

function check(project, context)
  return result:info{
    name = "unchecked-numeric-conversion",
    description = "atoi/atol/atoll/atof perform no error detection and have undefined behaviour on overflow. Prefer strtol-family with errno checks. (CWE-190/CWE-704)",
    cwes = {"CWE-190", "CWE-704"},
    evidence = {functions = {[context.caller.address] = {
      annotate:at{location = context.caller.call_address,
        message = "Numeric conversion with no error/overflow detection."}
    }}}
  }
end
-- vim: ft=lua
