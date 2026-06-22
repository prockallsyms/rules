# GO-2026-4316 — go/go-chi RedirectSlashes open redirect (CWE-601)

| | |
|---|---|
| **Library** | `github.com/go-chi/chi` |
| **Aliases** | CVE-2025-69725, GHSA-mqqf-5wvp-8fh8 |
| **CWE** | CWE-601 |
| **Affected / fixed** | `>= 5.2.3` … fixed in `5.2.4` |
| **Rule** | [`GO-2026-4316.vh`](./GO-2026-4316.vh) |

## Summary

The `RedirectSlashes` middleware in `github.com/go-chi/chi/v5` (versions through v5.2.3) performed a trailing-slash redirect by trimming all leading and trailing slashes from the request path and prepending a single `/`. This did not account for backslash characters: a path such as `/\evil.com/` would survive the `strings.Trim(path, "/")` call with its backslash intact and be emitted as the `Location` header value `/\evil.com`. Many browsers (Chrome, Edge, Safari) interpret a URL path beginning with `/\` as a protocol-relative reference and navigate to `//evil.com`, enabling an open redirect to an attacker-controlled domain. This is CWE-601 (URL Redirection to Untrusted Site). The impact is that any chi server that mounts `middleware.RedirectSlashes` can be used as an open redirector when a user visits a URL of the form `https://victim.example/\evil.com/`.

## Detection discriminator

This engine has no library-version gate, so the rule proves the **vulnerable code structure** and is silent on the patched build.

The v5.2.4 fix (commit 6eb35881) inserts `path = strings.ReplaceAll(path, "\\", "/")`
before the `strings.Trim` line inside the redirect branch. `strings.ReplaceAll` is a thin
wrapper that the Go compiler inlines to a `strings.Replace` CALL. Verified live via
`go tool objdump -s 'RedirectSlashes\.func1'`:

- VULN v5.2.3 func1 CALLs:  fmt.Sprintf, net/http.Redirect, strings.Trim
                            (NO strings.Replace)
- PATCHED v5.2.4 func1 CALLs: fmt.Sprintf, net/http.Redirect, strings.Replace, strings.Trim

DISCRIMINATOR: within the RedirectSlashes.func1 closure, a `strings.Replace` call is
PRESENT in patched and ABSENT in vuln. strings.Replace is binary-global, so the check is
SCOPED to the closure (not binary-wide). Fire when strings.Replace is ABSENT AND the
vuln-shape strings.Trim call is PRESENT; return nil (silent) when strings.Replace is present.

## Reproducing the test binaries

The committed sample links the **real vulnerable package** (no stubs). Minimal consumer (`main.go`):

```go
package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.RedirectSlashes)
	r.Get("/evil.com", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("reached"))
	})
	http.ListenAndServe(":8080", r)
}
```

Pinned dependency (vulnerable build): `require github.com/go-chi/chi/v5 v5.2.4` — the patched build uses the fixed version. Build each with:

```bash
GOOS=linux GOARCH=amd64 go build -o consumer .
```

Committed sample artifacts:

```
GO-2026-4316/consumer_vuln
GO-2026-4316/patched/consumer_fixed
GO-2026-4316/src/go.mod
GO-2026-4316/src/go.sum
GO-2026-4316/src/main.go
```

## Upstream fix

Patch: https://github.com/go-chi/chi/commit/6eb35881c0e438ffb663ddbad3a61babaa5e5d8a

Fix commit: `6eb35881c0e438ffb663ddbad3a61babaa5e5d8a`  
File: `middleware/strip.go`

```diff
--- a/middleware/strip.go
+++ b/middleware/strip.go
@@ -47,15 +47,22 @@ func RedirectSlashes(next http.Handler) http.Handler {
 		} else {
 			path = r.URL.Path
 		}
+
 		if len(path) > 1 && path[len(path)-1] == '/' {
-			// Trim all leading and trailing slashes (e.g., "//evil.com", "/some/path//")
-			path = "/" + strings.Trim(path, "/")
+			// Normalize backslashes to forward slashes to prevent "/\evil.com" style redirects
+			// that some clients may interpret as protocol-relative.
+			path = strings.ReplaceAll(path, `\`, `/`)
+
+			// Collapse leading/trailing slashes and force a single leading slash.
+			path := "/" + strings.Trim(path, "/")
+
 			if r.URL.RawQuery != "" {
 				path = fmt.Sprintf("%s?%s", path, r.URL.RawQuery)
 			}
 			http.Redirect(w, r, path, 301)
 			return
 		}
+
 		next.ServeHTTP(w, r)
 	}
 	return http.HandlerFunc(fn)
```

**Precise description of the fix delta:**

The fix inserted a new call `path = strings.ReplaceAll(path, `\`, `/`)` immediately before the existing `strings.Trim` line inside the trailing-slash redirect branch. This call replaces every backslash in the path with a forward slash before the path is used as the redirect `Location` value. After `ReplaceAll`, the subsequent `strings.Trim(path, "/")` correctly collapses any resulting leading slashes (e.g. `//evil.com` → `evil.com`, then re-prefixed to `/evil.com`). Without the `ReplaceAll`, a path like `/\evil.com/` passed through `strings.Trim` unchanged, producing a `Location` of `/\evil.com` which browsers treat as an external redirect.

Two structural changes were made:
1. **Added**: `path = strings.ReplaceAll(path, `\`, `/`)` — a new call to `strings.ReplaceAll` with the backslash rune as the pattern, before the trim.
2. **Shadowed re-declaration**: `path :=` (short variable declaration with `:=`) replaces the plain assignment `path =` for the trim line, scoping the post-trim path to the inner block. This is stylistic and does not affect behavior.

The backslash-to-slash normalization is the security-relevant addition.

## Verification

`GO-2026-4316 | created | go/go-chi RedirectSlashes open redirect (CWE-601). discriminator=RedirectSlashes.func1 in-fn call strings.Replace (ReplaceAll backslash->slash fix) present-patched, absent vuln. aliases CVE-2025-69725/GHSA-mqqf-5wvp-8fh8. vuln v5.2.3 FIRED, patched v5.2.4 SILENT.`

## Provenance

Generated by the multi-agent CVE-rule pipeline (research → build both versions → binary-observable discriminator → self-verify → independent GATE). Build recipe, discriminator, and scan results above are drawn from the pipeline's research dossier and signature notes for this CVE.

References:

- Go: https://pkg.go.dev/vuln/GO-2026-4316
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-69725
- GHSA: https://github.com/advisories/GHSA-mqqf-5wvp-8fh8
