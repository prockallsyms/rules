# GO-2023-1859 — go/lestrrat-go-jwx AES-CBC-HMAC JWE timing/padding-oracle (CWE-208)

| | |
|---|---|
| **Library** | `github.com/lestrrat-go/jwx` |
| **Aliases** | GHSA-rm8v-mxj3-5rmq |
| **CWE** | CWE-208 |
| **Affected / fixed** | `>= 2.0.10` … fixed in `2.0.11` |
| **Rule** | [`GO-2023-1859.vh`](./GO-2023-1859.vh) |

## Summary

AES-CBC-HMAC (AES_CBC_HMAC) decryption in the `lestrrat-go/jwx` JWE implementation suffered
from a padding oracle vulnerability (CWE-208: Observable Timing Discrepancy). The vulnerable
`unpad()` function returned distinct errors on different padding failure modes and returned
early once an invalid padding byte was detected, causing execution time to vary with the length
and content of the padding — leaking timing information an attacker could exploit to recover
plaintext. Additionally, padding validation and MAC tag verification were performed sequentially
rather than atomically: a failed padding check raised an error before the MAC result was
combined with the padding result, allowing an attacker to distinguish padding errors from MAC
errors via timing. The fix replaces `unpad()` with a constant-time `extractPadding()` (modeled
on Go's TLS implementation) and combines its `good` byte result with the
`subtle.ConstantTimeCompare` output via bitwise AND, ensuring padding and MAC failures are
indistinguishable in both timing and error message. Affected: all v2 releases < v2.0.11, all
v1 releases < v1.2.26. Impact: an attacker who can observe many decryption attempts can recover
JWE ciphertext content without the key.

## Detection discriminator

This engine has no library-version gate, so the rule proves the **vulnerable code structure** and is silent on the patched build.

CODE — fix-added callee symbol presence in `jwe/internal/aescbc`.

- Anchor (present in BOTH builds):
  `github.com/lestrrat-go/jwx/v2/jwe/internal/aescbc.(*Hmac).Open`
- Vuln-only symbol: `...aescbc.unpad` (timing-leaky early-exit padding check)
- Patched-only symbol: `...aescbc.extractPadding` (constant-time, branchless; fix replaces unpad)

Telnetd model: scope on `(*Hmac).Open`, FIRE when `...aescbc.extractPadding` is ABSENT (vuln),
SILENT when present (patched, >= v2.0.11).

## Reproducing the test binaries

The committed sample links the **real vulnerable package** (no stubs). Minimal consumer (`main.go`):

```go
package main

import (
    "fmt"
    "github.com/lestrrat-go/jwx/v2/jwa"
    "github.com/lestrrat-go/jwx/v2/jwe"
)

func main() {
    key := make([]byte, 32)
    _, err := jwe.Decrypt([]byte("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..dummy..dummy..dummy"),
        jwe.WithKey(jwa.A128CBC_HS256, key))
    fmt.Println(err)
}
```

Pinned dependency (vulnerable build): `require github.com/lestrrat-go/jwx/v2 v2.0.10` — the patched build uses the fixed version. Build each with:

```bash
GOOS=linux GOARCH=amd64 go build -o consumer .
```

Committed sample artifacts:

```
GO-2023-1859/consumer_vuln
GO-2023-1859/go.mod
GO-2023-1859/go.sum
GO-2023-1859/main.go
GO-2023-1859/patched/consumer_patched
GO-2023-1859/patched/go.mod
GO-2023-1859/patched/go.sum
GO-2023-1859/patched/main.go
```

## Upstream fix

Patch: https://github.com/lestrrat-go/jwx/commit/c8b6bec919a1c13998e5503db63b1b9fd0bea9cc

Fix commit (v2): `c8b6bec919a1c13998e5503db63b1b9fd0bea9cc`
("Merge pull request from GHSA-rm8v-mxj3-5rmq")

File: `jwe/internal/aescbc/aescbc.go`

```diff
-func unpad(buf []byte, n int) ([]byte, error) {
-	lbuf := len(buf)
-	rem := lbuf % n
-
-	// First, `buf` must be a multiple of `n`
-	if rem != 0 {
-		return nil, fmt.Errorf("input buffer must be multiple of block size %d", n)
-	}
-
-	last := buf[lbuf-1]
-	expected := int(last)
-
-	if expected == 0 ||
-		expected > n ||
-		expected > lbuf {
-		return nil, fmt.Errorf(`invalid padding byte at the end of buffer`)
-	}
-
-	for i := 1; i < expected; i++ {
-		if buf[lbuf-i] != last {
-			return nil, fmt.Errorf(`invalid padding`)
-		}
-	}
-
-	return buf[:lbuf-expected], nil
-}
+// extractPadding returns, in constant time, the length of the padding to remove
+// from the end of payload. It also returns a byte which is equal to 255 if the
+// padding was valid and 0 otherwise. See RFC 2246, Section 6.2.3.2.
+func extractPadding(payload []byte) (toRemove int, good byte) {
+	if len(payload) < 1 {
+		return 0, 0
+	}
+
+	paddingLen := payload[len(payload)-1]
+	t := uint(len(payload)) - uint(paddingLen)
+	good = byte(int32(^t) >> 31)
+
+	toCheck := 256
+	if toCheck > len(payload) {
+		toCheck = len(payload)
+	}
+
+	for i := 1; i <= toCheck; i++ {
+		t := uint(paddingLen) - uint(i)
+		mask := byte(int32(^t) >> 31)
+		b := payload[len(payload)-i]
+		good &^= mask&paddingLen ^ mask&b
+	}
+
+	good &= good << 4
+	good &= good << 2
+	good &= good << 1
+	good = uint8(int8(good) >> 7)
+	paddingLen &= good
+
+	toRemove = int(paddingLen)
+	return
+}
```

Key change in `Hmac.Open` (around line 217 in the patched file):

```diff
-	if subtle.ConstantTimeCompare(expectedTag, tag) != 1 {
-		return nil, fmt.Errorf(`invalid ciphertext (tag mismatch)`)
-	}
-
 	cbc := cipher.NewCBCDecrypter(c.blockCipher, nonce)
 	buf := make([]byte, tagOffset)
 	cbc.CryptBlocks(buf, ciphertext)

-	plaintext, err := unpad(buf, c.blockCipher.BlockSize())
-	if err != nil {
-		return nil, fmt.Errorf(`failed to generate plaintext from decrypted blocks: %w`, err)
-	}
+	toRemove, good := extractPadding(buf)
+	cmp := subtle.ConstantTimeCompare(expectedTag, tag) & int(good)
+	if cmp != 1 {
+		return nil, errors.New(`invalid ciphertext`)
+	}
+
+	plaintext := buf[:len(buf)-toRemove]
```

**What the fix changed:**

1. **Removed `unpad()`**: The old function had early-exit error branches that leaked timing
   information about which byte was bad and how far into the padding block the check progressed.
   It was replaced by `extractPadding()` — a branchless, const

*(diff truncated — see upstream patch)*

## Verification

```
- VULN  consumer_vuln    -> FIRED (queried GHSA-rm8v-mxj3-5rmq) exit 0
- PATCHED consumer_patched -> SILENT exit 1
```

## Provenance

Generated by the multi-agent CVE-rule pipeline (research → build both versions → binary-observable discriminator → self-verify → independent GATE). Build recipe, discriminator, and scan results above are drawn from the pipeline's research dossier and signature notes for this CVE.

References:

- Go: https://pkg.go.dev/vuln/GO-2023-1859
- GHSA: https://github.com/lestrrat-go/jwx/security/advisories/GHSA-rm8v-mxj3-5rmq
