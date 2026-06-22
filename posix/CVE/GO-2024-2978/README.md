# GO-2024-2978 — In `google

| | |
|---|---|
| **Library** | `google.golang.org/grpc` |
| **Aliases** | GHSA-xr7q-jx4m-x55m |
| **CWE** | CWE-532 |
| **Affected / fixed** | `>= 1.64.0` … fixed in `1.64.1` |
| **Rule** | [`GO-2024-2978.vh`](./GO-2024-2978.vh) |

## Summary

In `google.golang.org/grpc` v1.64.0, the `MD` type in the `metadata` package implemented the `fmt.Stringer` interface via a `String()` method that formatted all metadata key-value pairs into a human-readable string of the form `MD{key=[val1, val2], ...}`. Because gRPC metadata routinely carries authorization tokens (e.g. `authorization: Bearer <token>`), any application that printed or logged a context containing gRPC metadata — directly or through `fmt.Println`, `log.Printf`, structured-logging frameworks, or any library that calls `.String()` on context values — would leak those token values to log output. CWE-532 (Insertion of Sensitive Information into Log File). Impact is confidentiality loss for bearer tokens, session cookies, and other auth credentials stored in metadata.

## Detection discriminator

This engine has no library-version gate, so the rule proves the **vulnerable code structure** and is silent on the patched build.

Build: pure-Go consumer importing google.golang.org/grpc/metadata, constructing metadata.MD via
metadata.Pairs and calling fmt.Println(md) (Stringer path links MD.String in v1.64.0) plus
md.Get (common anchor). GOOS=linux GOARCH=amd64 go build -gcflags=all=-l, not stripped.

`go tool nm` on both committed Linux ELFs:
  vuln  v1.64.0:  metadata.MD.Get PRESENT; metadata.MD.String PRESENT
  fixed v1.64.1:  metadata.MD.Get PRESENT; metadata.MD.String ABSENT

Scope = metadata.MD.Get (present in BOTH builds, so the scope is not itself the signal).
FIRE (vulnerable) when project:functions("...metadata.MD.String") returns non-nil.
SILENT (return nil) when MD.String is absent (patched, >= v1.64.1).

The engine matches the literal-dot full symbol path; Go ELF symbol is
`google.golang.org/grpc/metadata.MD.String` (verified with nm — no %2e encoding needed here as
the package path "grpc/metadata" has no dot in the segment containing String; the dots in the
domain are literal and matched as literal dots in a regex-escaped scope pattern).

## Reproducing the test binaries

The committed sample links the **real vulnerable package** (no stubs). Minimal consumer (`main.go`):

```go
package main

import (
	"fmt"

	"google.golang.org/grpc/metadata"
)

//go:noinline
func keep(md metadata.MD) {
	// Forces MD.String() to be reachable (Stringer path) in v1.64.0.
	// In v1.64.1 MD has no String() method; fmt uses default reflect formatting.
	fmt.Println(md)
	// Also exercise a common metadata function present in both versions.
	fmt.Println(md.Get("authorization"))
}

func main() {
	md := metadata.Pairs(
		"authorization", "Bearer secret-token-abc123",
		"x-custom-header", "value",
	)
	keep(md)
}
```

Pinned dependency (vulnerable build): `require google.golang.org/grpc v1.64.0` — the patched build uses the fixed version. Build each with:

```bash
GOOS=linux GOARCH=amd64 go build -o consumer .
```

Committed sample artifacts:

```
GO-2024-2978/go.mod
GO-2024-2978/go.sum
GO-2024-2978/grpc_meta_vuln_linux
GO-2024-2978/main.go
GO-2024-2978/patched/go.mod
GO-2024-2978/patched/go.sum
GO-2024-2978/patched/grpc_meta_fixed_linux
GO-2024-2978/patched/main.go
```

## Upstream fix

Patch: https://github.com/grpc/grpc-go/commit/ab292411ddc0f3b7a7786754d1fe05264c3021eb

Commit: `ab292411ddc0f3b7a7786754d1fe05264c3021eb`
PR: grpc/grpc-go#7374
Author: Doug Fawley, merged 2024-07-01

```diff
--- a/metadata/metadata.go
+++ b/metadata/metadata.go
@@ -90,21 +90,6 @@ func Pairs(kv ...string) MD {
 	return md
 }
 
-// String implements the Stringer interface for pretty-printing a MD.
-// Ordering of the values is non-deterministic as it ranges over a map.
-func (md MD) String() string {
-	var sb strings.Builder
-	fmt.Fprintf(&sb, "MD{")
-	for k, v := range md {
-		if sb.Len() > 3 {
-			fmt.Fprintf(&sb, ", ")
-		}
-		fmt.Fprintf(&sb, "%s=[%s]", k, strings.Join(v, ", "))
-	}
-	fmt.Fprintf(&sb, "}")
-	return sb.String()
-}
-
 // Len returns the number of items in md.
 func (md MD) Len() int {
 	return len(md)
```

Prose description: The fix **completely removed** the `(md MD).String() string` method from `metadata/metadata.go`. This method implemented `fmt.Stringer` and called `fmt.Fprintf` three times with format strings `"MD{"`, `", "`, and `"%s=[%s]"` (the last concatenating values with `strings.Join`), then returned the assembled string. By deleting the method entirely, `MD` no longer satisfies the `Stringer` interface; any code that previously caused `MD.String()` to be called now falls back to Go's default `map[string][]string` reflect formatter (which still exposes values, but the fix intent was to remove the explicit convenience method that made logging easy). The test `TestStringerMD` in `metadata/metadata_test.go` was also removed.

## Provenance

Generated by the multi-agent CVE-rule pipeline (research → build both versions → binary-observable discriminator → self-verify → independent GATE). Build recipe, discriminator, and scan results above are drawn from the pipeline's research dossier and signature notes for this CVE.

References:

- Go: https://pkg.go.dev/vuln/GO-2024-2978
- GHSA: https://github.com/advisories/GHSA-xr7q-jx4m-x55m
