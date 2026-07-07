author = "prockallsyms"
name = "GO-2024-2567"
platform = "posix-binary"
architecture = "*:*:*"
signatures = {project = "github.com/jackc/pgx", from = "5.5.1", to = "5.5.2"}

-- GO-2024-2567 / GHSA-fqpg-rq76-99pq --
-- github.com/jackc/pgx/v5 (pgconn): (*Pipeline).Sync panic when the PgConn is busy
-- or closed -> denial of service (CWE-476 nil deref / CWE-754 improper check).
--
-- When StartPipeline is invoked on a PgConn whose lock() fails (busy/closed), the
-- returned *Pipeline is created with closed=true, err=<lock error>. Through v5.5.1,
-- (*Pipeline).Sync lacked the closed-guard that the sibling methods (Flush,
-- SendPrepare, ...) carried, so it unconditionally called
-- p.conn.frontend.SendSync(...) and then Flush() ->
-- flushWithPotentialWriteReadDeadlock() on a connection in an invalid/nil state,
-- causing a panic. Any goroutine calling Sync() on a closed-pipeline handle crashes
-- the process.
--
-- The v5.5.2 fix (commit dfd198003a03dbb96e4607b0d3a0bb9a7398ccb7) inserts, at the
-- top of (*Pipeline).Sync, the guard:
--     if p.closed {
--         if p.err != nil { return p.err }
--         return errors.New("pipeline closed")
--     }
--
-- DISCRIMINATOR (telnetd model -- fire when the fix-signal is ABSENT):
-- Scope = pgconn.(*Pipeline).Sync (symbol present in both builds).
-- The fix's errors.New("pipeline closed") is inlined to an allocation of an
-- errors.errorString: a CALL to runtime.newobject (verified live via go tool
-- objdump: errors.go:62 LEAQ + CALL runtime.newobject building the errorString).
--   v5.5.1 (VULN):    Sync calls = {SendSync, Flush, morestack}; NO runtime.newobject.
--   v5.5.2 (PATCHED): Sync additionally calls runtime.newobject (for the new
--                     errors.New("pipeline closed") guard).
-- Verified live via probe rule: VULN newobject count = 0, PATCHED newobject count = 1.
-- We fire ONLY when runtime.newobject is ABSENT inside Sync; if present, the closed
-- guard is in place -> patched -> nil. The scope (symbol match on Sync) is the
-- vuln-shape anchor; runtime.newobject is the fix signal.

-- NB: `matching` is an UNANCHORED REGEX over symbol names -- escape `.`/`(`/`)`/`*`.
scopes = scope:functions{
  target = {matching = "pgconn\\.\\(\\*Pipeline\\)\\.Sync$", kind = "symbol"},
  with = check
}

function check(project, context)
  -- Fix-signal: the v5.5.2 closed-guard allocates errors.New("pipeline closed"),
  -- which compiles to a CALL runtime.newobject inside Sync. Present => patched => nil.
  local newobj = context:calls("runtime.newobject")
  if #newobj > 0 then return end

  return result:high{
    name = "GO-2024-2567",
    description = "github.com/jackc/pgx/v5 before v5.5.2 has a denial of service in pgconn.(*Pipeline).Sync (CWE-476 / CWE-754). When PgConn.StartPipeline is called on a connection that is busy or closed, lock() fails and the returned *Pipeline is initialized with closed=true and err set. Through v5.5.1, (*Pipeline).Sync lacked the closed-pipeline guard that its sibling methods carried, so it unconditionally called p.conn.frontend.SendSync(...) and then Flush() -> flushWithPotentialWriteReadDeadlock() on a connection in an invalid/nil state, causing a nil-pointer panic. Any goroutine that calls Sync() on a closed-pipeline handle crashes the process. Fixed in v5.5.2 (commit dfd198003a03dbb96e4607b0d3a0bb9a7398ccb7) by inserting an `if p.closed { ...; return errors.New(\"pipeline closed\") }` guard at the top of Sync; that errors.New call compiles to a runtime.newobject allocation inside Sync, which is absent in v5.5.1. Upgrade to >= v5.5.2.",
    provenance = {
      kind = "posix.ELF",
      linkage = "project",
      vendor = "jackc",
      product = "github.com/jackc/pgx/v5",
      license = "MIT",
      affected_versions = {"<5.5.2"}
    },
    cwes = {"CWE-476", "CWE-754"},
    cvss = cvss:v3_1{
      base = "7.5",
      exploitability = "3.9",
      impact = "3.6",
      vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    },
    patch = "https://github.com/jackc/pgx/commit/dfd198003a03dbb96e4607b0d3a0bb9a7398ccb7",
    identifiers = {"GO-2024-2567", "GHSA-fqpg-rq76-99pq"},
    references = {
      ["Go"] = "https://pkg.go.dev/vuln/GO-2024-2567",
      ["GHSA"] = "https://github.com/advisories/GHSA-fqpg-rq76-99pq"
    },
    evidence = {
      functions = {
        [context.address] = {
          annotate:prototype "func (p *Pipeline) Sync() error",
          annotate:at{
            location = context.address,
            message = "pgconn.(*Pipeline).Sync lacks the closed-pipeline guard: it does NOT allocate the errors.New(\"pipeline closed\") error (no runtime.newobject call for the guard), so it unconditionally calls SendSync/Flush on a connection that may be in a closed/busy state set by a failed StartPipeline lock(), causing a nil-pointer panic (DoS). The v5.5.2 fix adds `if p.closed { return errors.New(\"pipeline closed\") }` at the top of Sync. Upgrade to >= v5.5.2."
          }
        }
      }
    }
  }
end

--
-- vim: ft=lua
--
