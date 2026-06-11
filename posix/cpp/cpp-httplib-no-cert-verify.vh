author = "prockallsyms"
name = "cpp-httplib-no-cert-verify"
platform = "posix-binary"
architecture = "*:*:*"
-- cpp-httplib Client::enable_server_certificate_verification(false) disables TLS cert
-- verification. (CWE-295)
scopes = scope:calls{to = "_ZN7httplib6Client38enable_server_certificate_verificationEb", using = {}, with = check}
function check(project, context)
  local b = context.inputs[2]   -- this=1, bool=2
  if b ~= nil and b:is_const() and b.constant ~= nil and b.constant:is_zero() then
    return result:high{name="httplib-no-cert-verify",
      description="cpp-httplib enable_server_certificate_verification(false) — TLS cert verification disabled. (CWE-295)",
      cwes={"CWE-295"}, evidence={functions={[context.caller.address]={annotate:at{location=context.caller.call_address,message="cert verification disabled"}}}}}
  end
end
