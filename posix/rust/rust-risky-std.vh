author = "prockallsyms"
name = "rust-risky-std-api"
platform = "posix-binary"
architecture = "*:*:*"
-- Risky std APIs (mangled v0 path segments). Ported from lang: remove-dir-all
-- (symlink race), TcpListener::bind (review for bind-all), mem::transmute.
-- (CWE-59/CWE-843/CWE-668)
scopes = scope:functions{
  target = {matching = "2fs14remove_dir_all|11TcpListener4bind|4core3mem9transmute", kind = "symbol"},
  with = check
}
function check(project, context)
  return result:low{
    name = "rust-risky-std-api",
    description = "Use of a risky std API (fs::remove_dir_all symlink race / TcpListener::bind — review for 0.0.0.0 / mem::transmute). (CWE-59/CWE-843)",
    cwes = {"CWE-59", "CWE-843"},
    evidence = {functions = {[context.address] = {annotate:prototype "risky std API"}}}}
end
