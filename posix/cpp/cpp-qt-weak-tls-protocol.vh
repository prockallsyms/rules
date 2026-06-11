author = "prockallsyms"
name = "cpp-qt-weak-tls-protocol"
platform = "posix-binary"
architecture = "*:*:*"
-- QSslConfiguration::setProtocol / QSslSocket::setProtocol — selecting SslV2/SslV3/
-- TlsV1_0/TlsV1_1/AnyProtocol is weak. SslProtocol is an enum arg; presence flags for
-- review (enum-arg refinement pending an app sample). (CWE-326/CWE-327)
scopes = scope:functions{
  target = {matching = "(17QSslConfiguration|10QSslSocket)11setProtocolE", kind = "symbol"},
  with = check
}
function check(project, context)
  return result:low{
    name = "qt-tls-protocol",
    description = "QSsl[Configuration|Socket]::setProtocol — verify it is not SslV3/TlsV1_0/TlsV1_1/AnyProtocol (weak TLS). (CWE-326/CWE-327)",
    cwes = {"CWE-326", "CWE-327"},
    evidence = {functions = {[context.address] = {annotate:prototype "Qt setProtocol"}}}}
end
