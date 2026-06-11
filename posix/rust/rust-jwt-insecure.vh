author = "prockallsyms"
name = "rust-jwt-insecure-verification"
platform = "posix-binary"
architecture = "*:*:*"
-- jsonwebtoken signature verification disabled. (CWE-347)
scopes = scope:functions{
  target = {matching = "insecure_disable_signature_validation|insecure_decode|dangerous_insecure_decode", kind = "symbol"}, with = check }
function check(project, context)
  return result:high{name="rust-jwt-insecure-verification",
    description="jsonwebtoken signature verification disabled (insecure_disable_signature_validation / insecure_decode). (CWE-347)",
    cwes={"CWE-347"}, evidence={functions={[context.address]={annotate:prototype "JWT verification disabled"}}}} end
