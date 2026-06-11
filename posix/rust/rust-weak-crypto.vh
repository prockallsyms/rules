author = "vulhunt-dev"
name = "rust-weak-crypto"
platform = "posix-binary"
architecture = "*:*:*"
-- RustCrypto weak hashes (md2/md4/md5/sha1) + weak ciphers (DES/3DES/RC4) + small RSA.
-- v0-mangled; match crate+type fragments. (CWE-327/CWE-328)
scopes = scope:functions{
  target = {matching = "3Md2|3Md4|3Md5|4Sha1|3Des|3Rc4|8TdesEde3|13RsaPrivateKey", kind = "symbol"},
  with = check }
function check(project, context)
  return result:medium{name="rust-weak-crypto",
    description="RustCrypto weak primitive (MD2/MD4/MD5/SHA1 hash, DES/3DES/RC4 cipher, or small RSA key). (CWE-327/CWE-328)",
    cwes={"CWE-327","CWE-328"}, evidence={functions={[context.address]={annotate:prototype "weak crypto"}}}} end
