author = "prockallsyms"
name = "rust-tls-verification-disabled"
platform = "posix-binary"
architecture = "*:*:*"
-- TLS cert/host verification disabled across crates: reqwest/native-tls danger_accept_*
-- (incl. the renamed tls_danger_accept_*), openssl set_verify_callback, rustls custom
-- verifier. Distinctive method names → match directly. (CWE-295)
scopes = scope:functions{
  target = {matching = "danger_accept_invalid_certs|danger_accept_invalid_hostnames|tls_danger_accept_invalid|set_verify_callback|with_custom_certificate_verifier|set_certificate_verifier", kind = "symbol"},
  with = check }
function check(project, context)
  return result:high{name="rust-tls-verification-disabled",
    description="Rust TLS certificate/hostname verification disabled (reqwest/native-tls danger_accept_*, openssl set_verify_callback, or rustls custom verifier). (CWE-295)",
    cwes={"CWE-295"}, evidence={functions={[context.address]={annotate:prototype "TLS verification disabled"}}}} end
