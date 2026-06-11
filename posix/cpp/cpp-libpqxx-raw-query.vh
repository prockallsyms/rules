author = "prockallsyms"
name = "cpp-libpqxx-raw-query"
platform = "posix-binary"
architecture = "*:*:*"
-- libpqxx transaction_base::exec(string) runs a raw SQL string (vs parameterized
-- exec_params) — SQL injection if the string is built from input. (CWE-89)
scopes = scope:functions{
  target = {matching = "4pqxx16transaction_base4execE", kind = "symbol"},
  with = check
}
function check(project, context)
  return result:medium{name="libpqxx-raw-query",
    description="pqxx::transaction_base::exec(string) — raw SQL; prefer exec_params for parameterization. (CWE-89)",
    cwes={"CWE-89"}, evidence={functions={[context.address]={annotate:prototype "pqxx raw exec"}}}}
end
