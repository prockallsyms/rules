author = "prockallsyms"
name = "cpp-qt-weak-hash"
platform = "posix-binary"
architecture = "*:*:*"
-- QCryptographicHash with a weak algorithm (Md4/Md5/Sha1). The algorithm is an enum
-- argument; presence flags the call for review (precise enum-arg refinement pending an
-- app sample). Mangled: QCryptographicHash::hash / ctor. (CWE-327/CWE-328)
scopes = scope:functions{
  target = {matching = "18QCryptographicHash(4hashE|C[12]E)", kind = "symbol"},
  with = check
}
function check(project, context)
  return result:low{
    name = "qt-cryptographic-hash",
    description = "Use of QCryptographicHash — verify the algorithm is not Md4/Md5/Sha1 (weak). (CWE-327/CWE-328)",
    cwes = {"CWE-327", "CWE-328"},
    evidence = {functions = {[context.address] = {annotate:prototype "QCryptographicHash"}}}}
end
