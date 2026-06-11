author = "prockallsyms"
name = "go-weak-crypto-primitive"
platform = "posix-binary"
architecture = "*:*:*"

-- Ported from lang use-of-md5/sha1/DES/rc4, sha224-hash. Go retains
-- package-qualified symbols, so weak crypto/hash primitives resolve directly.
-- (CWE-327/CWE-328)
scopes = {
  scope:calls{to = "crypto/md5.New",  using = {}, with = check},
  scope:calls{to = "crypto/md5.Sum",  using = {}, with = check},
  scope:calls{to = "crypto/sha1.New", using = {}, with = check},
  scope:calls{to = "crypto/sha1.Sum", using = {}, with = check},
  scope:calls{to = "crypto/des.NewCipher",           using = {}, with = check},
  scope:calls{to = "crypto/des.NewTripleDESCipher",  using = {}, with = check},
  scope:calls{to = "crypto/rc4.NewCipher",           using = {}, with = check},
  scope:calls{to = "crypto/sha256.New224", using = {}, with = check},
  scope:calls{to = "crypto/sha256.Sum224", using = {}, with = check},
}

function check(project, context)
  return result:medium{
    name = "weak-crypto-primitive",
    description = "Use of a weak/broken cryptographic primitive (MD5/SHA-1/DES/3DES/RC4/SHA-224). (CWE-327/CWE-328)",
    cwes = {"CWE-327", "CWE-328"},
    evidence = {functions = {[context.caller.address] = {
      annotate:at{location = context.caller.call_address, message = "Weak crypto/hash primitive."}}}}
  }
end
-- vim: ft=lua
