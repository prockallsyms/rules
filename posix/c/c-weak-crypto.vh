author = "prockallsyms"
name = "c-weak-crypto-primitive"
platform = "posix-binary"
architecture = "*:*:*"

-- Consolidated from gitlab c_crypto_rule-*. Broken/weak cipher primitives via
-- OpenSSL EVP selectors and crypt(3). (CWE-327)
scopes = {
  scope:calls{to = "EVP_rc4",         using = {}, with = check},
  scope:calls{to = "EVP_rc4_40",      using = {}, with = check},
  scope:calls{to = "EVP_des_cbc",     using = {}, with = check},
  scope:calls{to = "EVP_des_ecb",     using = {}, with = check},
  scope:calls{to = "EVP_des_ede",     using = {}, with = check},
  scope:calls{to = "EVP_des_ede3",    using = {}, with = check},
  scope:calls{to = "EVP_rc2_cbc",     using = {}, with = check},
  scope:calls{to = "EVP_rc2_ecb",     using = {}, with = check},
  scope:calls{to = "crypt",           using = {}, with = check},
  scope:calls{to = "crypt_r",         using = {}, with = check},
}

function check(project, context)
  return result:medium{
    name = "weak-crypto-primitive",
    description = "Use of a broken or weak cryptographic primitive (DES/3DES/RC2/RC4 via OpenSSL EVP, or crypt(3)). (CWE-327)",
    cwes = {"CWE-327"},
    evidence = {functions = {[context.caller.address] = {
      annotate:at{location = context.caller.call_address,
        message = "Weak/broken cipher primitive."}
    }}}
  }
end
-- vim: ft=lua
