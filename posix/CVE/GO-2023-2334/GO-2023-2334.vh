author = "prockallsyms"
name = "GO-2023-2334"
platform = "posix-binary"
architecture = "*:*:*"
signatures = {project = "github.com/go-jose/go-jose", from = "3.0.0", to = "3.0.1"}

-- GO-2023-2334 / GHSA-2c7c-3mj9-8fqh -- github.com/go-jose/go-jose/v3 < 3.0.1
-- PBES2 "billion hashes" DoS (CWE-400). An unauthenticated attacker supplies a
-- PBES2-encrypted JWE whose `p2c` header (PBKDF2 iteration count) is arbitrarily
-- large; `(*symmetricKeyCipher).decryptKey` reads p2c from the unverified header
-- and passes it straight to `pbkdf2.Key(...)`, so the decrypting party burns CPU
-- proportional to the attacker-chosen count. Reached via the public API
-- `jose.ParseEncrypted(token).Decrypt(key)` (PBES2-HS*+A*KW alg).
--
-- Fix (commit 65351c27, v3.0.1): adds an upper-bound guard in decryptKey, after
-- the existing `p2c <= 0` check:
--     if p2c > 1000000 { return nil, fmt.Errorf("...: invalid P2C: too high") }
--
-- Discriminator (telnetd model, present-in-patched). Both builds export
-- `(*symmetricKeyCipher).decryptKey` at the same address, so symbol alone does not
-- discriminate; `fmt.Errorf` is already present in the vuln function (the p2c<=0
-- guard) so it does not discriminate either. The robust handle is the NEW immediate
-- comparison against 1000000 = 0xF4240. Disassembly of the patched decryptKey:
--     483d40420f00  CMPQ AX, $0xf4240   (new upper-bound check)
--     0f8f........  JG   <too-high err> (new jump)
-- The bare CMPQ-imm bytes 483d40420f00 are NOT unique (1000000 is compared in
-- unrelated code: 2x vuln, 3x patched) -> would match both builds. Extending by the
-- following JG opcode (position-independent; the relative offset bytes are dropped)
-- gives the contiguous pattern 483d40420f000f8f, which occurs 0x in v3.0.0 and
-- exactly once (the fix site) in v3.0.1 -- verified on both ELFs.
--
-- So: if the fix byte-pattern is PRESENT, the build is patched (>= 3.0.1) -> nil
-- (silent). If ABSENT, decryptKey lacks the p2c upper bound -> vulnerable.

scopes = {
  scope:functions{
    target = {matching = "symmetricKeyCipher\\)\\.decryptKey$", kind = "symbol"},
    using = {},
    with = check
  }
}

function check(project, context)
  -- project:search_code can RAISE a Lua error on some ELFs; an unhandled error aborts
  -- the whole scan. Wrap in pcall so a search failure degrades to "pattern not present"
  -- for THIS rule only and never tears the batch down.
  local function safe_search(hex)
    local ok, res = pcall(function() return project:search_code(hex) end)
    return ok and res
  end

  -- Fix-signature: `CMPQ AX,$0xf4240 ; JG` (the new p2c > 1000000 upper-bound
  -- check + jump to the "too high" error). Present only in v3.0.1+.
  if safe_search("483d40420f000f8f") then
    return
  end

  return result:high{
    name = "GO-2023-2334",
    description = "github.com/go-jose/go-jose/v3 before v3.0.1: (*symmetricKeyCipher).decryptKey reads the attacker-controlled PBES2 `p2c` (PBKDF2 iteration count) from an unverified JWE header and passes it unchanged to pbkdf2.Key(...), with no upper bound. An unauthenticated attacker can supply a PBES2-HS*+A*KW JWE with an arbitrarily large p2c (e.g. 2^31-1) so that ParseEncrypted(token).Decrypt(key) exhausts CPU proportional to the attacker-chosen count -- a \"billion hashes\" denial of service (CWE-400). The fix (v3.0.1) caps p2c at 1000000.",
    provenance = {
      kind = "posix.ELF",
      linkage = "project",
      vendor = "go-jose",
      product = "github.com/go-jose/go-jose/v3",
      license = "Apache-2.0",
      affected_versions = {"<3.0.1"}
    },
    cwes = {"CWE-400"},
    cvss = cvss:v3_1{
      base = "7.5",
      exploitability = "3.9",
      impact = "3.6",
      vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    },
    patch = "https://github.com/go-jose/go-jose/commit/65351c27657d58960c2e6c9fbb2b00f818e50568",
    identifiers = {"GO-2023-2334", "GHSA-2c7c-3mj9-8fqh"},
    references = {
      ["Go"] = "https://pkg.go.dev/vuln/GO-2023-2334",
      ["GHSA"] = "https://github.com/advisories/GHSA-2c7c-3mj9-8fqh"
    },
    evidence = {
      functions = {
        [context.address] = {
          annotate:at{
            location = context.address,
            message = "(*symmetricKeyCipher).decryptKey lacks the p2c upper-bound guard `p2c > 1000000` (added in v3.0.1); an attacker-chosen PBES2 p2c is passed unbounded to pbkdf2.Key -> billion-hashes DoS. Upgrade go-jose/go-jose/v3 to >= 3.0.1."
          }
        }
      }
    }
  }
end

--
-- vim: ft=lua
--
