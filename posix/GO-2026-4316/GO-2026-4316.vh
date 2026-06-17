author = "vulhunt-pipeline"
name = "GO-2026-4316"
platform = "posix-binary"
architecture = "*:*:*"
signatures = {project = "github.com/go-chi/chi", from = "5.2.3", to = "5.2.4"}

-- GO-2026-4316 / CVE-2025-69725 / GHSA-mqqf-5wvp-8fh8 --
-- github.com/go-chi/chi/v5 open redirect in the RedirectSlashes middleware (CWE-601).
--
-- Through v5.2.3, RedirectSlashes' trailing-slash redirect branch trimmed leading/
-- trailing slashes via `strings.Trim(path, "/")` and re-prefixed a single "/", WITHOUT
-- normalizing backslashes. A request path like `/\evil.com/` (or `/%5Cevil.com/`,
-- decoded by net/http to `/\evil.com/`) survived the trim as `/\evil.com` and was
-- emitted verbatim as the redirect Location header. Browsers interpret a Location
-- beginning with `/\` as protocol-relative (`//evil.com`), navigating to an attacker
-- domain -> open redirect (CWE-601). Any chi server mounting middleware.RedirectSlashes
-- is usable as an open redirector.
--
-- The v5.2.4 fix (commit 6eb35881) inserts `path = strings.ReplaceAll(path, "\\", "/")`
-- immediately before the strings.Trim line inside the redirect branch, converting
-- backslashes to forward slashes before the path becomes the Location target.
--
-- DISCRIMINATOR (telnetd model -- fire when the fix-signal is ABSENT):
-- Scope = the RedirectSlashes closure (symbol `RedirectSlashes.func1`, present in both).
--   v5.2.3 (VULN):    func1 CALLS strings.Trim, but NOT strings.Replace.
--   v5.2.4 (PATCHED): strings.ReplaceAll inlines to a `strings.Replace` CALL inside
--                     func1 (verified live via `go tool objdump`), present in addition
--                     to strings.Trim.
-- Verified live via probe: VULN func1 calls = {strings.Trim}; PATCHED func1 calls =
-- {strings.Replace, strings.Trim}. We fire only when strings.Replace is ABSENT AND the
-- vuln-shape strings.Trim is present (so the call check is scoped to the redirect path,
-- never binary-global where strings.Replace appears everywhere).

-- NB: `matching` is an UNANCHORED REGEX over symbol names -- escape the `.` metachars.
scopes = scope:functions{
  target = {matching = "go-chi/chi/v5/middleware\\.RedirectSlashes\\.func1$", kind = "symbol"},
  with = check
}

function check(project, context)
  -- Fix-signal: strings.ReplaceAll inlines to strings.Replace inside the closure
  -- (v5.2.4+). If present, the backslash normalization is in place -> patched -> nil.
  local replace = context:calls("strings.Replace")
  if #replace > 0 then return end

  -- Vuln-shape confirmation: the redirect branch's strings.Trim call must be present
  -- so we know we are looking at the slash-collapsing path (not an empty/inlined body).
  local trim = context:calls("strings.Trim")
  if #trim == 0 then return end
  local trim_call = trim[1]

  return result:high{
    name = "GO-2026-4316",
    description = "github.com/go-chi/chi/v5 before v5.2.4 has an open redirect in the RedirectSlashes middleware (CWE-601). The trailing-slash redirect branch trims leading/trailing slashes with strings.Trim(path, \"/\") and re-prefixes a single \"/\" without normalizing backslashes, so a request path like /\\evil.com/ (or the URL-encoded /%5Cevil.com/, decoded by net/http) survives as /\\evil.com and is emitted verbatim as the redirect Location header. Browsers interpret a Location starting with /\\ as protocol-relative (//evil.com) and navigate to an attacker-controlled domain. Any server mounting middleware.RedirectSlashes can be abused as an open redirector. Fixed in v5.2.4 (commit 6eb35881) by inserting strings.ReplaceAll(path, \"\\\\\", \"/\") to normalize backslashes to forward slashes before the path is used as the redirect target.",
    provenance = {
      kind = "posix.ELF",
      linkage = "project",
      vendor = "go-chi",
      product = "github.com/go-chi/chi/v5",
      license = "MIT",
      affected_versions = {"<5.2.4"}
    },
    cwes = {"CWE-601"},
    cvss = cvss:v3_1{
      base = "6.1",
      exploitability = "2.8",
      impact = "2.7",
      vector = "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    },
    patch = "https://github.com/go-chi/chi/commit/6eb35881c0e438ffb663ddbad3a61babaa5e5d8a",
    identifiers = {"GO-2026-4316", "CVE-2025-69725", "GHSA-mqqf-5wvp-8fh8"},
    references = {
      ["Go"] = "https://pkg.go.dev/vuln/GO-2026-4316",
      ["NVD"] = "https://nvd.nist.gov/vuln/detail/CVE-2025-69725",
      ["GHSA"] = "https://github.com/advisories/GHSA-mqqf-5wvp-8fh8"
    },
    evidence = {
      functions = {
        [context.address] = {
          annotate:prototype "func RedirectSlashes(next http.Handler) http.Handler -- closure fn",
          annotate:at{
            location = trim_call,
            message = "The RedirectSlashes redirect branch collapses slashes with strings.Trim but does NOT normalize backslashes (no strings.ReplaceAll/strings.Replace call), so a path like /\\evil.com/ is emitted as the redirect Location /\\evil.com -- a protocol-relative open redirect (CWE-601). The v5.2.4 fix adds strings.ReplaceAll(path, \"\\\\\", \"/\") before this trim. Upgrade to >= v5.2.4."
          }
        }
      }
    }
  }
end

--
-- vim: ft=lua
--
