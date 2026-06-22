# GO-2023-2334 — go/go-jose PBES2 billion-hashes DoS (CWE-400)

| | |
|---|---|
| **Library** | `github.com/go-jose/go-jose` |
| **Aliases** | GHSA-2c7c-3mj9-8fqh |
| **CWE** | CWE-400 |
| **Affected / fixed** | `>= 3.0.0` … fixed in `3.0.1` |
| **Rule** | [`GO-2023-2334.vh`](./GO-2023-2334.vh) |

## Summary

`github.com/go-jose/go-jose/v3` (and legacy `github.com/square/go-jose`) permit an unauthenticated attacker to supply a PBES2-encrypted JWE token whose `p2c` header field (the PBKDF2 iteration count) is an arbitrarily large integer. Because the library reads `p2c` directly from the unverified JWE header and passes it unchanged to `pbkdf2.Key(...)`, the decrypting party exhausts CPU proportional to the attacker-chosen count, enabling a "billion hashes" Denial-of-Service (CWE-400: Uncontrolled Resource Consumption). The fix caps `p2c` at 1,000,000 iterations, returning an immediate error for any higher value. Affected versions: `github.com/go-jose/go-jose/v3` < 3.0.1; all versions of `github.com/square/go-jose`.

## Detection discriminator

This engine has no library-version gate, so the rule proves the **vulnerable code structure** and is silent on the patched build.

Both builds emit `(*symmetricKeyCipher).decryptKey` at the same address; symbol
alone does not discriminate. `fmt.Errorf` is already present in the vuln function
(the `p2c <= 0` guard), so fmt.Errorf presence does not discriminate either.

The robust handle is the new immediate comparison against 1000000 = 0xF4240.
Disassembly (`go tool objdump -s 'symmetricKeyCipher\).decryptKey$'`):

  PATCHED, symmetric.go:415-418:
    4885c0          TESTQ AX, AX          (existing p2c<=0)
    0f8e42020000    JLE   ...
    483d40420f00    CMPQ  AX, $0xf4240    <-- NEW upper-bound check
    0f8f08020000    JG    ...             <-- NEW jump to "too high" error

  VULN: TESTQ/JLE present, but no CMPQ AX,$0xf4240 / JG follows.

### Byte pattern chosen
The bare `483d40420f00` (CMPQ AX,$0xf4240) is NOT unique: 2 occurrences in vuln,
3 in patched (1000000 is compared elsewhere in unrelated code) -> binary-global
search_code would match both builds. FALSE handle.

Extend by one instruction to the JG opcode that follows the fix's compare. The
relative jump offset bytes (08020000) are position-dependent, so include only the
opcode `0f8f`. Final contiguous, position-independent pattern:

    483d40420f000f8f      = CMPQ AX,$0xf4240 ; JG

Raw-byte occurrence (whole ELF):
    VULN     483d40420f000f8f : 0
    PATCHED  483d40420f000f8f : 1   (exactly the fix site in decryptKey)

Rule fires when this fix-signature is ABSENT (vuln); returns nil (silent) when
present (patched v3.0.1+).

## Reproducing the test binaries

The committed sample links the **real vulnerable package** (no stubs). Minimal consumer (`main.go`):

```go
package main

import (
	"fmt"

	jose "github.com/go-jose/go-jose/v3"
)

func main() {
	// Compact JWE with a PBES2 alg so Decrypt -> decryptKey (PBES2 path) links.
	token := "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJjIjoyMDAwMDAwLCJwMnMiOiJBQUFBQUFBQUFBQUFBQSJ9.invalid.invalid.invalid.invalid"
	obj, err := jose.ParseEncrypted(token)
	if err != nil {
		fmt.Println("parse error (expected):", err)
		return
	}
	_, err = obj.Decrypt([]byte("secret"))
	fmt.Println("decrypt result:", err)
}
```

Pinned dependency (vulnerable build): `require github.com/go-jose/go-jose/v3 v3.0.0` — the patched build uses the fixed version. Build each with:

```bash
GOOS=linux GOARCH=amd64 go build -o consumer .
```

Committed sample artifacts:

```
GO-2023-2334/consumer_vuln
GO-2023-2334/go.mod
GO-2023-2334/go.sum
GO-2023-2334/main.go
GO-2023-2334/patched/consumer_fixed
GO-2023-2334/patched/go.mod
GO-2023-2334/patched/go.sum
GO-2023-2334/patched/main.go
```

## Upstream fix

Patch: https://github.com/go-jose/go-jose/commit/65351c27657d58960c2e6c9fbb2b00f818e50568

Fix commit: `65351c27657d58960c2e6c9fbb2b00f818e50568`
Repository: https://github.com/go-jose/go-jose

```diff
--- a/symmetric.go
+++ b/symmetric.go
@@ -415,6 +415,11 @@ func (ctx *symmetricKeyCipher) decryptKey(headers rawHeader, recipient *recipien
        if p2c <= 0 {
            return nil, fmt.Errorf("go-jose/go-jose: invalid P2C: must be a positive integer")
        }
+       if p2c > 1000000 {
+           // An unauthenticated attacker can set a high P2C value. Set an upper limit to avoid
+           // DoS attacks.
+           return nil, fmt.Errorf("go-jose/go-jose: invalid P2C: too high")
+       }
 
        // salt is UTF8(Alg) || 0x00 || Salt Input
        alg := headers.getAlgorithm()
```

Confirmed by `diff go-jose-v3.0.0/symmetric.go go-jose-v3/symmetric.go` — the diff output is exactly:

```
417a418,422
>       if p2c > 1000000 {
>           // An unauthenticated attacker can set a high P2C value. Set an upper limit to avoid
>           // DoS attacks.
>           return nil, fmt.Errorf("go-jose/go-jose: invalid P2C: too high")
>       }
```

**What the fix changed:** After the existing `p2c <= 0` guard at line 415 (v3.0.0), the fix inserts a new upper-bound comparison `p2c > 1000000` followed by an immediate `return nil, fmt.Errorf("go-jose/go-jose: invalid P2C: too high")`. This is a pure addition of a new conditional branch and error return; no existing code was modified or removed. The constant `1000000` is the new upper bound (one million iterations).

The variable `p2c` is of type `int`, decoded from the JSON `"p2c"` field via `json.Unmarshal` in `shared.go:getP2C()`. No type change was needed; the comparison is a straightforward integer comparison.

## Verification

`GO-2023-2334 | created | go/go-jose PBES2 billion-hashes DoS (CWE-400). discriminator=fix p2c>1000000 bound-check byte-pattern 483d40420f000f8f (CMPQ $0xf4240;JG) in decryptKey, 0x vuln/1x patched. alias GHSA-2c7c-3mj9-8fqh (no CVE). CODEGEN-SENSITIVE byte pattern. vuln v3.0.0 FIRED, patched v3.0.1 SILENT.`

## Provenance

Generated by the multi-agent CVE-rule pipeline (research → build both versions → binary-observable discriminator → self-verify → independent GATE). Build recipe, discriminator, and scan results above are drawn from the pipeline's research dossier and signature notes for this CVE.

References:

- Go: https://pkg.go.dev/vuln/GO-2023-2334
- GHSA: https://github.com/advisories/GHSA-2c7c-3mj9-8fqh
