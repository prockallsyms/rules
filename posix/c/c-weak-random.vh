author = "prockallsyms"
name = "c-insecure-randomness"
platform = "posix-binary"
architecture = "*:*:*"

-- Consolidated from gitlab c_random_rule-*, 0xdea/itermalum raptor-insecure-api-rand.
-- Non-cryptographic PRNGs; insecure if used for security-sensitive values. (CWE-338/CWE-330)
scopes = {
  scope:calls{to = "rand",    using = {}, with = check},
  scope:calls{to = "srand",   using = {}, with = check},
  scope:calls{to = "random",  using = {}, with = check},
  scope:calls{to = "srandom", using = {}, with = check},
  scope:calls{to = "drand48", using = {}, with = check},
  scope:calls{to = "lrand48", using = {}, with = check},
  scope:calls{to = "mrand48", using = {}, with = check},
  scope:calls{to = "nrand48", using = {}, with = check},
  scope:calls{to = "erand48", using = {}, with = check},
  scope:calls{to = "jrand48", using = {}, with = check},
  scope:calls{to = "seed48",  using = {}, with = check},
  scope:calls{to = "lcong48", using = {}, with = check},
  scope:calls{to = "initstate", using = {}, with = check},
  scope:calls{to = "setstate",  using = {}, with = check},
}

function check(project, context)
  return result:low{
    name = "insecure-randomness",
    description = "Use of a non-cryptographic PRNG (rand/random/*rand48). Not suitable for tokens, keys, nonces, or any security decision. (CWE-338/CWE-330)",
    cwes = {"CWE-338", "CWE-330"},
    evidence = {functions = {[context.caller.address] = {
      annotate:at{location = context.caller.call_address,
        message = "Non-cryptographic randomness source."}
    }}}
  }
end
-- vim: ft=lua
