author = "vulhunt-pipeline"
name = "GO-2024-2978"
platform = "posix-binary"
architecture = "*:*:*"
signatures = {project = "google.golang.org/grpc", from = "1.64.0", to = "1.64.1"}

-- GO-2024-2978 / GHSA-xr7q-jx4m-x55m -- google.golang.org/grpc/metadata
-- Insertion of Sensitive Information into Log File (CWE-532). In grpc v1.64.0 the MD type in
-- the metadata package implemented fmt.Stringer via a String() method that formatted ALL
-- metadata key/value pairs into "MD{key=[val1, val2], ...}". gRPC metadata routinely carries
-- authorization tokens (e.g. "authorization: Bearer <token>"), so any application that printed
-- or logged a context/metadata value -- via fmt.Println, log.Printf, structured loggers, or any
-- library that calls .String() on a value -- leaked those bearer tokens / session credentials
-- into log output.
--
-- Fix commit ab292411ddc0f3b7a7786754d1fe05264c3021eb (PR grpc/grpc-go#7374, v1.64.1) DELETES
-- the entire (md MD) String() string fmt.Stringer method from metadata/metadata.go. MD no longer
-- satisfies Stringer, so the convenience method that made token logging easy is gone.
--
-- DISCRIMINATOR (CODE; symbol-presence, PRESENT-ONLY-IN-VULN -- inverse of the fix-symbol model).
-- The vulnerable build CONTAINS the compiled function google.golang.org/grpc/metadata.MD.String;
-- the patched build does NOT (the method was removed). We scope a metadata function present in
-- BOTH builds -- metadata.MD.Get -- so the scope is not itself the signal, and FIRE (vulnerable)
-- only when project:functions("...metadata.MD.String") resolves to a real function. We stay
-- SILENT (return nil) when MD.String is absent (patched, >= v1.64.1).
-- Verified with `go tool nm` on both committed Linux ELFs (-gcflags=all=-l, not stripped):
--   vuln  v1.64.0:  metadata.MD.Get PRESENT; metadata.MD.String PRESENT
--   fixed v1.64.1:  metadata.MD.Get PRESENT; metadata.MD.String ABSENT
-- `signatures` gates to the affected range as a forward-compatible no-op.
scopes = scope:functions{
  target = {matching = "google\\.golang\\.org/grpc/metadata\\.MD\\.Get$", kind = "symbol"},
  with = check
}

function check(project, context)
  -- Vulnerability signature: the MD.String fmt.Stringer method that leaks metadata tokens.
  -- Present  => vulnerable (v1.64.0).
  -- Absent   => patched (>= v1.64.1) => silent.
  local vuln_fn = project:functions("google.golang.org/grpc/metadata.MD.String")
  if not vuln_fn then
    return
  end

  return result:high{
    name = "GO-2024-2978",
    description = "google.golang.org/grpc v1.64.0 (CWE-532, Insertion of Sensitive Information into Log File): the MD type in the metadata package implemented fmt.Stringer via a String() method that formatted all metadata key/value pairs into a human-readable string of the form \"MD{key=[val1, val2], ...}\". gRPC metadata routinely carries authorization tokens (e.g. \"authorization: Bearer <token>\"), so any application that printed or logged a context/metadata value -- directly via fmt.Println / fmt.Sprintf, through log.Printf, via structured-logging frameworks, or via any library that calls .String() on context values -- leaked those bearer tokens, session cookies, and other auth credentials into log output. The fix (commit ab292411ddc0f3b7a7786754d1fe05264c3021eb, PR grpc/grpc-go#7374, v1.64.1) completely removed the (md MD) String() method so MD no longer satisfies fmt.Stringer. This binary contains the compiled google.golang.org/grpc/metadata.MD.String method, so it is the vulnerable v1.64.0 build. Upgrade google.golang.org/grpc to >= v1.64.1.",
    provenance = {
      kind = "posix.ELF",
      linkage = "project",
      vendor = "google",
      product = "google.golang.org/grpc",
      license = "Apache-2.0",
      affected_versions = {"v1.64.0"}
    },
    cwes = {"CWE-532"},
    patch = "https://github.com/grpc/grpc-go/commit/ab292411ddc0f3b7a7786754d1fe05264c3021eb",
    identifiers = {"GO-2024-2978", "GHSA-xr7q-jx4m-x55m"},
    references = {
      ["Go"] = "https://pkg.go.dev/vuln/GO-2024-2978",
      ["GHSA"] = "https://github.com/advisories/GHSA-xr7q-jx4m-x55m"
    },
    evidence = {
      functions = {
        [context.address] = {
          annotate:prototype "func (md MD) String() string",
          annotate:at{
            location = context.address,
            message = "This binary links google.golang.org/grpc/metadata.MD.String, the fmt.Stringer method present only in grpc v1.64.0. It formats all metadata key/value pairs (including \"authorization: Bearer <token>\") into a string, so logging a context or MD value leaks bearer tokens / session credentials into logs (GO-2024-2978, GHSA-xr7q-jx4m-x55m, CWE-532). The method was removed in v1.64.1 (commit ab292411). Upgrade google.golang.org/grpc to >= v1.64.1 and avoid logging contexts/metadata."
          }
        }
      }
    }
  }
end

--
-- vim: ft=lua
--
