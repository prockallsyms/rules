# Go portable rulepacks

Ported from `../../sast-rules/go`; triage + coverage in `../../triage/GO-COVERAGE.md`.
**Go ports are call-presence only** — see the coverage doc for why operand/struct-config
rules don't translate. 4 core packs + 6 library packs (all call-presence).

| Pack | technique | validated |
|------|-----------|-----------|
| go-weak-crypto | call presence: crypto/md5,sha1,des,rc4,sha256.New224 | ✅ verify_go.elf |
| go-command-exec | call presence: os/exec.*, syscall.Exec/ForkExec | ✅ verify_go.elf |
| go-weak-random | call presence: math/rand.* | ✅ all 11 entry points |
| go-misc-dangerous | call presence: reflect / cgi / doublestar | ✅ verify_go.elf |
| **go-jwt-unverified** | golang-jwt v4/v5 `(*Parser).ParseUnverified` (no-sig-check, auth bypass) | ✅ gostub.elf (4) |
| **go-jwt-deprecated-lib** | presence of `dgrijalva/jwt-go` (CVE-2020-26160) via `scope:functions` on `…jwt-go.init$` | ✅ gostub.elf (1) |
| **go-raw-sql-query** | `database/sql`/`gorm`/`sqlx` raw Query/Exec/Raw sinks | ✅ gostub.elf (14) |
| **go-redis-eval** | go-redis server-side Lua `cmdable.eval` (Eval/EvalSha) | ✅ gostub.elf (3) |
| **go-template-injection** | `text/template.(*Template).Parse` (no escaping → SSTI/XSS) | ✅ gostub.elf (2) |
| **go-untrusted-deserialization** | `encoding/gob` Decode + `yaml.v2` unmarshal | ✅ gostub.elf (5) |

The library rules come from `../../triage/LIBRARY-API-CATALOG.md`, validated on
`examples/gostub.elf` (built from `examples/gostub/` — a real go.mod with golang-jwt v4/v5,
dgrijalva/jwt-go, gorm, sqlx, go-redis/v9, yaml.v2): **43 findings, 0 errors** (raw-sql 14,
reflect 11¹, deser 5, jwt-unverified 4, weak-crypto 3¹, redis 3, template 2, deprecated-jwt 1).
¹ reflect/weak-crypto are the pre-existing core packs firing on library internals.

**Removed during verification (don't survive Go's inliner — confirmed):**
`go-ssh-no-hostkey` (`ssh.InsecureIgnoreHostKey` inlines to "return nil", no symbol on
optimized builds) and the `net/http.FileServer` scope. See `../../triage/VERIFICATION.md`.

**Go-inliner lesson for library rules:** small exported wrappers inline away, but the
shared lowercase *worker* survives — so target it: go-redis `(*Client).Eval` → match
`cmdable.eval`; `yaml.Unmarshal` → match the package-level `unmarshal`. Package paths with
a `.` in a path element are `%2e`-encoded in symbols (`gopkg.in/yaml%2ev2.unmarshal`).
For pure import-presence (blank import, no calls — dgrijalva), `scope:functions` on the
package `init` symbol (`<pkg>.init$`) gives exactly one clean finding.

Validated against `examples/verify_go.elf` (real x/crypto + doublestar) and
`examples/gostub.elf`. Symbols are full package paths (`crypto/md5.Sum`, `os/exec.Command`,
`database/sql.(*DB).Query`, `github.com/golang-jwt/jwt/v5.(*Parser).ParseUnverified`).

## Key limitations (Go-specific)
- **No operand differentiators**: Go strings are length-delimited so `.string` over-reads;
  register ABI blurs arg mapping. The C-style constant-arg precision is unavailable.
- **Struct-config invisible**: `tls.Config{InsecureSkipVerify:true}`, cookie flags, etc.
  leave no symbol — Go's most valuable security checks are NOT portable by symbol.
- **Heavy static-runtime noise**: Go runtime is always static and uses crypto/exec/rand;
  validate by user-function attribution.

## Run
```sh
export BIAS_DATA=/Users/samv/vulhunt-dev/biasdata
vulhunt-ce scan <go-elf> -d "$BIAS_DATA" -r posix/go --pretty
```
