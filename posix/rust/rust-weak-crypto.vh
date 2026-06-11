author = "prockallsyms"
name = "rust-weak-crypto"
platform = "posix-binary"
architecture = "*:*:*"
-- RustCrypto weak hashes (md2/md4/md5/sha1) + weak ciphers (DES/3DES/RC4). Match the
-- CRATE-NAME path components, which appear identically in BOTH legacy (_ZN…) and v0 (_R…)
-- mangling — robust across symbol-mangling-version. (Real RustCrypto types are Md5Core/
-- Sha1Core/Rc4State, NOT bare Md5/Sha1 — so type-name fragments like "3Md5" do NOT match
-- real crates; verified against md-5 0.10 / sha1 0.10 / des 0.8 / rc4 0.1.) (CWE-327/CWE-328)
scopes = scope:functions{
  target = {matching = "3md2|3md4|3md5|4sha1|3des|3rc4", kind = "symbol"},
  with = check }
function check(project, context)
  return result:medium{name="rust-weak-crypto",
    description="RustCrypto weak primitive (MD2/MD4/MD5/SHA1 hash, DES/3DES/RC4 cipher, or small RSA key). (CWE-327/CWE-328)",
    cwes={"CWE-327","CWE-328"}, evidence={functions={[context.address]={annotate:prototype "weak crypto"}}}} end
