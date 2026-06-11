author = "vulhunt-dev"
name = "go-raw-sql-query"
platform = "posix-binary"
architecture = "*:*:*"
-- Raw SQL execution sinks (database/sql, gorm, sqlx). SQL injection if the query is
-- built from untrusted input rather than parameterized. Review-required. (CWE-89)
scopes = {
  scope:calls{to="database/sql.(*DB).Query", using={}, with=c},
  scope:calls{to="database/sql.(*DB).Exec", using={}, with=c},
  scope:calls{to="gorm.io/gorm.(*DB).Raw", using={}, with=c},
  scope:calls{to="gorm.io/gorm.(*DB).Exec", using={}, with=c},
  scope:calls{to="github.com/jmoiron/sqlx.(*DB).Queryx", using={}, with=c},
  scope:calls{to="github.com/jmoiron/sqlx.(*DB).MustExec", using={}, with=c},
}
function c(project, context) return result:medium{name="go-raw-sql-query",
  description="Raw SQL execution sink (database/sql Query/Exec, gorm Raw/Exec, or sqlx Queryx/MustExec) -- verify the statement is parameterized, not built from untrusted input. (CWE-89)",
  cwes={"CWE-89"}, evidence={functions={[context.caller.address]={annotate:at{location=context.caller.call_address,message="raw SQL execution"}}}}} end
