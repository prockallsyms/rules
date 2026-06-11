author = "prockallsyms"
name = "rust-raw-sql-query"
platform = "posix-binary"
architecture = "*:*:*"
-- Raw SQL execution paths (sqlx::raw_sql, diesel::sql_query) — SQL injection if the
-- query string is built from untrusted input (vs parameterized query!/bind). (CWE-89)
scopes = scope:functions{ target = {matching = "raw_sql|sql_query", kind = "symbol"}, with = check }
function check(project, context)
  return result:medium{name="rust-raw-sql-query",
    description="Raw SQL execution (sqlx::raw_sql / diesel::sql_query) — verify the query is parameterized, not string-built. (CWE-89)",
    cwes={"CWE-89"}, evidence={functions={[context.address]={annotate:prototype "raw SQL"}}}} end
