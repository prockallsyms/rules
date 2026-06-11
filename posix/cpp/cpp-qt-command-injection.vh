author = "prockallsyms"
name = "cpp-qt-process-execution"
platform = "posix-binary"
architecture = "*:*:*"

-- Ported from cpp qt-qprocess-command-injection / qt-qprocess-shell-expansion.
-- Qt's QProcess::execute / start / startDetached run external programs; with a
-- shell or untrusted arguments this is command injection. (CWE-78)
--
-- The engine doesn't demangle, but Itanium mangling is ABI-stable: QProcess
-- methods are `_ZN8QProcess<len><method>E<params>`. The `8QProcess<method>`
-- class::method prefix is identical across Qt 5/6 and independent of the
-- parameter overload (only the suffix varies: Qt5 `QStringList` vs Qt6
-- `QList<QString>`, plus `@Qt_6` symbol versioning). A regex on the prefix is
-- therefore version-agnostic, and matches both DEFINED symbols (libQt*Core / static
-- Qt) and IMPORT references (`imp._ZN8QProcess...` in an application binary).
--
-- VALIDATED on real Qt6: fires on libQt6Core.so.6 (5 defined) and on a binary that
-- imports QProcess, QtCore.abi3.so (10) — not just the synthetic stub.
scopes = scope:functions{
  target = {matching = "_ZN8QProcess(7execute|5start|13startDetached)", kind = "symbol"},
  with = check
}

function check(project, context)
  return result:high{
    name = "qt-process-execution",
    description = "Qt QProcess external-program execution (execute/start/startDetached). If the program or arguments are attacker-influenced — or a shell is invoked — this is command injection. (CWE-78)",
    cwes = {"CWE-78"},
    evidence = {functions = {[context.address] = {
      annotate:prototype "QProcess process-execution sink (Qt)"
    }}}
  }
end
-- vim: ft=lua
