author = "vulhunt-dev"
name = "cpp-qt-additional-sinks"
platform = "posix-binary"
architecture = "*:*:*"
-- Additional Qt sinks: QSqlQuery::exec(QString) (SQLi — string query vs prepared exec()),
-- QProcess::startCommand (command-line parse), QWebEnginePage::runJavaScript (XSS). (CWE-89/78/79)
scopes = scope:functions{
  target = {matching = "9QSqlQuery4execERK|8QProcess12startCommand|14QWebEnginePage13runJavaScript", kind = "symbol"},
  with = check
}
function check(project, context)
  return result:medium{name="qt-additional-sink",
    description="Qt sink: QSqlQuery::exec(QString) (SQLi), QProcess::startCommand (cmd parse), or QWebEnginePage::runJavaScript (XSS) — verify inputs are trusted/parameterized. (CWE-89/CWE-78/CWE-79)",
    cwes={"CWE-89","CWE-78","CWE-79"}, evidence={functions={[context.address]={annotate:prototype "Qt injection sink"}}}}
end
