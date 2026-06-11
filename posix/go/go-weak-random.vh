author = "prockallsyms"
name = "go-insecure-randomness"
platform = "posix-binary"
architecture = "*:*:*"

-- Ported from lang math-random-used. math/rand is not cryptographically secure;
-- use crypto/rand for security-sensitive values. Targets the math/rand package
-- specifically (crypto/rand is the safe one). (CWE-338)
scopes = {
  scope:calls{to = "math/rand.Int",     using = {}, with = check},
  scope:calls{to = "math/rand.Intn",    using = {}, with = check},
  scope:calls{to = "math/rand.Int31",   using = {}, with = check},
  scope:calls{to = "math/rand.Int31n",  using = {}, with = check},
  scope:calls{to = "math/rand.Int63",   using = {}, with = check},
  scope:calls{to = "math/rand.Int63n",  using = {}, with = check},
  scope:calls{to = "math/rand.Float64", using = {}, with = check},
  scope:calls{to = "math/rand.Float32", using = {}, with = check},
  scope:calls{to = "math/rand.Perm",    using = {}, with = check},
  scope:calls{to = "math/rand.Read",    using = {}, with = check},
  scope:calls{to = "math/rand.Shuffle", using = {}, with = check},
}

function check(project, context)
  return result:low{
    name = "insecure-randomness",
    description = "Use of math/rand (non-cryptographic PRNG). Not suitable for tokens, keys, nonces, or security decisions — use crypto/rand. (CWE-338)",
    cwes = {"CWE-338"},
    evidence = {functions = {[context.caller.address] = {
      annotate:at{location = context.caller.call_address, message = "Non-cryptographic randomness (math/rand)."}}}}
  }
end
-- vim: ft=lua
