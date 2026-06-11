author = "vulhunt-dev"
name = "go-command-execution"
platform = "posix-binary"
architecture = "*:*:*"

-- Ported from lang dangerous-exec-command/dangerous-syscall-exec and the
-- validated go-exec-command example. (CWE-78)
scopes = {
  scope:calls{to = "os/exec.Command",        using = {}, with = check},
  scope:calls{to = "os/exec.CommandContext", using = {}, with = check},
  scope:calls{to = "os/exec.LookPath",       using = {}, with = check},
  scope:calls{to = "syscall.Exec",           using = {}, with = check},
  scope:calls{to = "syscall.ForkExec",       using = {}, with = check},
  scope:calls{to = "syscall.StartProcess",   using = {}, with = check},
}

function check(project, context)
  return result:medium{
    name = "command-execution",
    description = "Process/command execution (os/exec or syscall). If the program or arguments incorporate untrusted input this is command injection. (CWE-78)",
    cwes = {"CWE-78"},
    evidence = {functions = {[context.caller.address] = {
      annotate:at{location = context.caller.call_address, message = "Command/process execution — verify args are not attacker-controlled."}}}}
  }
end
-- vim: ft=lua
