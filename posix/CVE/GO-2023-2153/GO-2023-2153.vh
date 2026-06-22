author = "vulhunt-pipeline"
name = "GO-2023-2153"
platform = "posix-binary"
architecture = "*:*:*"
signatures = {project = "google.golang.org/grpc", from = "1.58.0", to = "1.58.3"}

-- GO-2023-2153 / GHSA-m425-mq94-257g / CVE-2023-44487 --
-- google.golang.org/grpc HTTP/2 Rapid Reset DoS (CWE-400, Uncontrolled Resource
-- Consumption). The HTTP/2 server transport did not bound the number of concurrently
-- executing method-handler goroutines against MaxConcurrentStreams. An attacker opens
-- HTTP/2 streams (HEADERS) then immediately cancels them with RST_STREAM before the
-- server responds; `(*Server).serveStreams` kept spawning a handler goroutine (or
-- queuing a worker job) per incoming stream with no cap, so the server launched an
-- unbounded number of handlers -> goroutine/memory exhaustion -> denial of service.
-- Reached via the public API grpc.NewServer(...).Serve(listener).
--
-- Fix (commit f2180b4d5403d2210b30b93098eb7da31c05c721, PR #6703, v1.58.3 / v1.57.1 /
-- v1.56.3): adds a blocking counting semaphore `atomicSemaphore` initialized to
-- maxConcurrentStreams. serveStreams now builds it with newHandlerQuota and calls
-- streamQuota.acquire() synchronously before launching each handler (blocking the
-- accept loop when the quota is exhausted) and defers streamQuota.release(), so at
-- most maxConcurrentStreams handlers run per transport regardless of RST_STREAM spam.
--
-- DISCRIMINATOR (telnetd model -- fire when the fix signal is ABSENT):
--   Scope  = grpc.(*Server).serveStreams (symbol PRESENT in both v1.58.2 and v1.58.3;
--            the vuln-shape anchor -- symbol alone does NOT discriminate).
--   Fix    = the symbol grpc.(*atomicSemaphore).acquire. acquire blocks on a channel
--            receive (`<-q.wait`), so the Go compiler never inlines it; it is emitted
--            as a real symbol in fixed builds and is ENTIRELY ABSENT from vulnerable
--            builds (verified via go tool nm: v1.58.2 has no atomicSemaphore symbol;
--            v1.58.3 has (*atomicSemaphore).acquire/.release + newHandlerQuota).
--   Fire (vulnerable) when (*atomicSemaphore).acquire is ABSENT; silent (patched)
--   when it is PRESENT. We only test the project:functions handle ~= nil/non-empty;
--   we never iterate it.

local SCOPE  = "grpc\\.\\(\\*Server\\)\\.serveStreams$"
local FIXSYM = "grpc\\.\\(\\*atomicSemaphore\\)\\.acquire$"

scopes = {
  scope:functions{
    target = {matching = SCOPE, kind = "symbol"},
    using = {},
    with = check
  }
}

function check(project, context)
  -- project:functions can RAISE a Lua error on some ELFs; an unhandled error aborts
  -- the whole scan. Wrap in pcall so a failure degrades to "symbol not present" for
  -- THIS rule only and never tears down the batch.
  local function safe_functions(pat)
    local ok, res = pcall(function()
      return project:functions({matching = pat, kind = "symbol", all = true})
    end)
    return ok and res
  end

  -- Confirm the scope really matched serveStreams (present in both builds).
  local anchor = safe_functions(SCOPE)
  if type(anchor) ~= "table" or #anchor == 0 then
    return
  end

  -- Fix present (>= v1.58.3): the counting-semaphore acquire symbol exists, so the
  -- per-transport concurrent-handler cap is enforced -> not vulnerable.
  local fixed = safe_functions(FIXSYM)
  if type(fixed) == "table" and #fixed > 0 then
    return
  end

  return result:high{
    name = "GO-2023-2153",
    description = "google.golang.org/grpc before v1.58.3 (also < v1.57.1, < v1.56.3) is vulnerable to the HTTP/2 Rapid Reset denial of service (CWE-400, CVE-2023-44487). The HTTP/2 server transport did not bound the number of concurrently executing method-handler goroutines against MaxConcurrentStreams: `(*Server).serveStreams` spawned a handler goroutine (or queued a worker job) per incoming stream with no cap. A remote unauthenticated attacker opens many HTTP/2 streams and immediately cancels each with RST_STREAM before the server responds, so the server keeps launching handlers without limit -> goroutine and memory exhaustion -> denial of service. Reached via the public API grpc.NewServer(...).Serve(listener). The v1.58.3 fix (commit f2180b4d5403, PR #6703) adds a blocking counting semaphore (atomicSemaphore, built by newHandlerQuota and initialized to maxConcurrentStreams) whose acquire() is called synchronously before each handler is launched and whose release() is deferred, capping concurrent handlers per transport. This build lacks the (*atomicSemaphore).acquire fix symbol, so serveStreams still spawns handlers unbounded. Upgrade google.golang.org/grpc to >= v1.58.3 (or >= v1.57.1 / >= v1.56.3).",
    provenance = {
      kind = "posix.ELF",
      linkage = "project",
      vendor = "Google",
      product = "google.golang.org/grpc",
      license = "Apache-2.0",
      affected_versions = {"<1.58.3"}
    },
    cwes = {"CWE-400"},
    cvss = cvss:v3_1{
      base = "7.5",
      exploitability = "3.9",
      impact = "3.6",
      vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    },
    patch = "https://github.com/grpc/grpc-go/commit/f2180b4d5403d2210b30b93098eb7da31c05c721",
    identifiers = {"GHSA-m425-mq94-257g", "GO-2023-2153", "CVE-2023-44487"},
    references = {
      ["Go"] = "https://pkg.go.dev/vuln/GO-2023-2153",
      ["GHSA"] = "https://github.com/advisories/GHSA-m425-mq94-257g"
    },
    evidence = {
      functions = {
        [context.address] = {
          annotate:prototype "func (s *Server) serveStreams(st transport.ServerTransport)",
          annotate:at{
            location = context.address,
            message = "(*Server).serveStreams lacks the v1.58.3 concurrent-handler cap: there is no (*atomicSemaphore).acquire symbol (the counting semaphore added by newHandlerQuota), so each incoming HTTP/2 stream spawns a handler goroutine with no bound. An attacker that opens streams and immediately sends RST_STREAM (HTTP/2 Rapid Reset, CVE-2023-44487) drives unbounded goroutine/memory growth -> DoS. Upgrade google.golang.org/grpc to >= v1.58.3."
          }
        }
      }
    }
  }
end

--
-- vim: ft=lua
--
