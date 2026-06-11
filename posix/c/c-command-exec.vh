author = "prockallsyms"
name = "c-command-execution"
platform = "posix-binary"
architecture = "*:*:*"

-- Ported/consolidated from C SAST rules: gitlab c_shell_rule-*, itermalum &
-- 0xdea raptor-command-injection, lang. POSIX exec/shell sinks. (CWE-78/CWE-77)
scopes = {
  scope:calls{to = "system",   using = {}, with = check},
  scope:calls{to = "popen",    using = {}, with = check},
  scope:calls{to = "execl",    using = {}, with = check},
  scope:calls{to = "execlp",   using = {}, with = check},
  scope:calls{to = "execle",   using = {}, with = check},
  scope:calls{to = "execv",    using = {}, with = check},
  scope:calls{to = "execvp",   using = {}, with = check},
  scope:calls{to = "execve",   using = {}, with = check},
  scope:calls{to = "execvpe",  using = {}, with = check},
}

function check(project, context)
  return result:medium{
    name = "command-execution",
    description = "Call to a process/shell-execution function (system/popen/exec*). If any argument incorporates untrusted input this is command injection (CWE-78).",
    cwes = {"CWE-78", "CWE-77"},
    evidence = {functions = {[context.caller.address] = {
      annotate:at{location = context.caller.call_address,
        message = "Process/shell execution sink — verify arguments are not attacker-controlled."}
    }}}
  }
end
-- vim: ft=lua
