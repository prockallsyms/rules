author = "prockallsyms"
name = "rust-command-execution"
platform = "posix-binary"
architecture = "*:*:*"
-- Rust v0-mangled, not demangled by the engine; match the stable path segment
-- of std::process::Command::new (`...3std7process...7Command3new`). Ported from
-- security/rust-command-injection + framework *-command-injection rules (sink side).
-- (CWE-78)
scopes = scope:functions{
  target = {matching = "3std7process.*7Command3new", kind = "symbol"},
  with = check
}
function check(project, context)
  return result:medium{
    name = "rust-command-execution",
    description = "Use of std::process::Command. If the program/args derive from untrusted input this is command injection. (CWE-78)",
    cwes = {"CWE-78"},
    evidence = {functions = {[context.address] = {annotate:prototype "std::process::Command::new"}}}}
end
