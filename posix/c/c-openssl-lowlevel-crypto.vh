author = "prockallsyms"
name = "c-openssl-lowlevel-weak-crypto"
platform = "posix-binary"
architecture = "*:*:*"
-- OpenSSL low-level (non-EVP) weak primitives. (CWE-327/CWE-328/CWE-338)
scopes = {
  scope:calls{to="MD5_Init",using={},with=c}, scope:calls{to="MD4_Init",using={},with=c},
  scope:calls{to="SHA1_Init",using={},with=c},
  scope:calls{to="RC4_set_key",using={},with=c}, scope:calls{to="RC4",using={},with=c},
  scope:calls{to="DES_set_key",using={},with=c}, scope:calls{to="DES_ecb_encrypt",using={},with=c},
  scope:calls{to="DES_ncbc_encrypt",using={},with=c}, scope:calls{to="BF_set_key",using={},with=c},
  scope:calls{to="RAND_pseudo_bytes",using={},with=c},
}
function c(project,context) return result:medium{name="openssl-lowlevel-weak-crypto",
  description="OpenSSL low-level weak primitive (MD4/MD5/SHA1/RC4/DES/Blowfish/RAND_pseudo_bytes). (CWE-327/328/338)",
  cwes={"CWE-327","CWE-328"}, evidence={functions={[context.caller.address]={annotate:at{location=context.caller.call_address,message="weak low-level crypto"}}}}} end
