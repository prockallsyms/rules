author = "vulhunt-dev"
name = "cpp-grpc-insecure-credentials"
platform = "posix-binary"
architecture = "*:*:*"
-- gRPC InsecureServerCredentials/InsecureChannelCredentials are FREE FUNCTIONS that
-- create transport credentials with NO TLS/auth -> plaintext, unauthenticated RPC.
-- Pure symbol-presence (no arg needed); ABI-stable Itanium names. (CWE-319/CWE-306)
scopes = scope:functions{
  target = {matching = "Insecure(Server|Channel)Credentials", kind = "symbol"},
  with = check
}
function check(project, context)
  return result:high{
    name = "grpc-insecure-credentials",
    description = "gRPC Insecure{Server,Channel}Credentials: transport has no TLS and no authentication. (CWE-319/CWE-306)",
    cwes = {"CWE-319", "CWE-306"},
    evidence = {functions = {[context.address] = {annotate:prototype "gRPC insecure credentials"}}}}
end
