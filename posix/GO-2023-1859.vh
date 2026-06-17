author = "vulhunt-pipeline"
name = "GO-2023-1859"
platform = "posix-binary"
architecture = "*:*:*"
signatures = {project = "github.com/lestrrat-go/jwx", from = "2.0.10", to = "2.0.11"}

-- GO-2023-1859 / GHSA-rm8v-mxj3-5rmq -- github.com/lestrrat-go/jwx/v2
-- AES-CBC-HMAC JWE padding oracle / observable timing discrepancy (CWE-208) before v2.0.11.
-- In jwe/internal/aescbc, the AES-CBC-HMAC authenticated-decryption routine (*Hmac).Open
-- validated the CBC padding with unpad(), a timing-leaky helper that early-exits on the first
-- bad padding byte and returns distinct error messages for the various failure modes. The MAC
-- tag comparison (subtle.ConstantTimeCompare) ran BEFORE unpad() and also returned early, so an
-- attacker observing many decryption attempts could distinguish padding failures from MAC
-- failures by timing/error path -> a padding oracle that recovers JWE plaintext without the key.
--
-- Fix commit c8b6bec919a1c13998e5503db63b1b9fd0bea9cc (PR from GHSA-rm8v-mxj3-5rmq, v2.0.11)
-- REMOVES unpad() entirely and replaces it with a NEW constant-time, branchless helper
-- extractPadding() (modeled on Go's crypto/tls padding check). extractPadding returns a `good`
-- byte (0xFF valid / 0x00 invalid); (*Hmac).Open then combines it with the MAC result via a
-- bitwise AND -- cmp := subtle.ConstantTimeCompare(expectedTag, tag) & int(good) -- and returns a
-- single generic "invalid ciphertext" error, eliminating both the timing and error-text oracles.
--
-- DISCRIMINATOR (telnetd model: fire when the FIX is ABSENT).
-- Scope = github.com/lestrrat-go/jwx/v2/jwe/internal/aescbc.(*Hmac).Open -- this symbol exists
-- in BOTH the vulnerable (v2.0.10) and patched (v2.0.11) ELFs (verified with `go tool nm`), so
-- the scope anchors on the actual AES-CBC-HMAC decrypt function in either build. The engine's
-- scope:functions{matching} performs a FULL (anchored) match on the literal-dot symbol path.
--   v2.0.10 (vuln):    ...aescbc.unpad is PRESENT and ...aescbc.extractPadding is ABSENT.
--   v2.0.11 (patched): ...aescbc.extractPadding is PRESENT and ...aescbc.unpad is ABSENT.
-- (Both verified with `go tool nm` in the CONSUMER ELFs.) extractPadding is a non-trivial
-- constant-time loop, not inlineable, so it survives codegen as a named top-level symbol.
-- project:functions(<symbol>) returns a function object when the symbol exists and nil otherwise.
--
-- We FIRE (vulnerable) when the fix-added symbol ...aescbc.extractPadding is ABSENT, and stay
-- SILENT (return nil) when it is present (patched, >= v2.0.11). The `signatures` window gates this
-- to the affected range as a forward-compatible no-op.
scopes = scope:functions{
  target = {matching = "github\\.com/lestrrat-go/jwx/v2/jwe/internal/aescbc\\.\\(\\*Hmac\\)\\.Open", kind = "symbol"},
  with = check
}

function check(project, context)
  -- Fix signature: the new constant-time padding helper (added in v2.0.11, replaces unpad).
  -- Present => patched (>= v2.0.11) => silent.
  local fix_fn = project:functions("github.com/lestrrat-go/jwx/v2/jwe/internal/aescbc.extractPadding")
  if fix_fn then
    return
  end

  return result:high{
    name = "GO-2023-1859",
    description = "github.com/lestrrat-go/jwx/v2 before v2.0.11: AES-CBC-HMAC JWE decryption is vulnerable to a padding oracle / observable timing discrepancy (CWE-208). (*Hmac).Open in jwe/internal/aescbc validates CBC padding with the timing-leaky unpad() helper, which early-exits on the first bad padding byte and returns distinct error messages per failure mode; the MAC tag comparison runs before unpad() and also returns early, letting an attacker who observes many decryption attempts distinguish padding failures from MAC failures by timing/error path and recover JWE plaintext without the key. The fix (v2.0.11) removes unpad() and introduces a constant-time, branchless extractPadding() whose `good` byte is bitwise-AND-ed with the subtle.ConstantTimeCompare result before a single generic \"invalid ciphertext\" error is returned. This build lacks the extractPadding helper (the constant-time padding/MAC hardening is absent). Upgrade github.com/lestrrat-go/jwx/v2 to >= v2.0.11 (or v1 to >= v1.2.26).",
    provenance = {
      kind = "posix.ELF",
      linkage = "project",
      vendor = "lestrrat-go",
      product = "github.com/lestrrat-go/jwx/v2",
      license = "MIT",
      affected_versions = {"<v2.0.11"}
    },
    cwes = {"CWE-208"},
    cvss = cvss:v3_1{
      base = "5.9",
      exploitability = "2.2",
      impact = "3.6",
      vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
    },
    patch = "https://github.com/lestrrat-go/jwx/commit/c8b6bec919a1c13998e5503db63b1b9fd0bea9cc",
    identifiers = {"GO-2023-1859", "GHSA-rm8v-mxj3-5rmq"},
    references = {
      ["Go"] = "https://pkg.go.dev/vuln/GO-2023-1859",
      ["GHSA"] = "https://github.com/lestrrat-go/jwx/security/advisories/GHSA-rm8v-mxj3-5rmq"
    },
    evidence = {
      functions = {
        [context.address] = {
          annotate:prototype "func (h *Hmac) Open(dst, nonce, ciphertext, data []byte) ([]byte, error)",
          annotate:at{
            location = context.address,
            message = "aescbc.(*Hmac).Open validates CBC padding with the timing-leaky unpad() and compares the MAC tag separately; the v2.0.11 constant-time helper aescbc.extractPadding is absent from this binary. Padding failures are distinguishable from MAC failures by timing/error -> AES-CBC-HMAC JWE padding oracle. Upgrade lestrrat-go/jwx/v2 to >= v2.0.11."
          }
        }
      }
    }
  }
end

--
-- vim: ft=lua
--
