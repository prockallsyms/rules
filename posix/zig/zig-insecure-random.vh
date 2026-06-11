author = "vulhunt-dev"
name = "zig-insecure-random"
platform = "posix-binary"
architecture = "*:*:*"

-- Ported from zig/lang/security/insecure-random. Zig's non-cryptographic PRNGs
-- (Xoshiro256 = DefaultPrng, Xoroshiro128, Pcg, Isaac64, SplitMix64, RomuTrio)
-- are inlined as defined functions but remain reachable as CALL targets, so we
-- match the calls to their generator step (.next/.fill). The CSPRNG is
-- Random.ChaCha (DefaultCsprng) and is intentionally excluded. (CWE-338)
scopes = {
  scope:calls{to = "Random.Xoshiro256.next",    using = {}, with = check},
  scope:calls{to = "Random.Xoshiro256.fill",    using = {}, with = check},
  scope:calls{to = "Random.Xoroshiro128.next",  using = {}, with = check},
  scope:calls{to = "Random.Xoroshiro128.fill",  using = {}, with = check},
  scope:calls{to = "Random.Pcg.next",           using = {}, with = check},
  scope:calls{to = "Random.Pcg.fill",           using = {}, with = check},
  scope:calls{to = "Random.Isaac64.next",       using = {}, with = check},
  scope:calls{to = "Random.Isaac64.refill",     using = {}, with = check},
  scope:calls{to = "Random.RomuTrio.next",      using = {}, with = check},
}

function check(project, context)
  return result:low{
    name = "insecure-random",
    description = "Use of a non-cryptographic Zig PRNG (std.Random.DefaultPrng / Xoshiro256 / Pcg / Isaac64 / ...). Not suitable for keys, tokens, nonces, or security decisions — use std.Random.DefaultCsprng (ChaCha) or std.crypto.random. (CWE-338)",
    cwes = {"CWE-338"},
    evidence = {functions = {[context.caller.address] = {
      annotate:at{location = context.caller.call_address, message = "Non-cryptographic PRNG generation step."}}}}
  }
end
-- vim: ft=lua
