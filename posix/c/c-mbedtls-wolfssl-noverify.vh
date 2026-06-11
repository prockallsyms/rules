author = "prockallsyms"
name = "c-embedded-tls-no-verify"
platform = "posix-binary"
architecture = "*:*:*"
-- Embedded TLS cert verification disabled: mbedtls_ssl_conf_authmode(NONE=0/OPTIONAL=1),
-- wolfSSL_CTX_set_verify(SSL_VERIFY_NONE=0). (CWE-295)
scopes = {
  scope:calls{to="mbedtls_ssl_conf_authmode", using={}, with=mbed},
  scope:calls{to="wolfSSL_CTX_set_verify",     using={}, with=wolf},
  scope:calls{to="wolfSSL_set_verify",         using={}, with=wolf},
}
local function fire(context,msg) return result:high{name="embedded-tls-no-verify",
  description="Embedded TLS certificate verification disabled ("..msg.."). (CWE-295)", cwes={"CWE-295"},
  evidence={functions={[context.caller.address]={annotate:at{location=context.caller.call_address,message=msg}}}}} end
function mbed(p,context) local m=context.inputs[2]  -- authmode < REQUIRED(2)
  if m~=nil and m:is_const() and m.constant~=nil and (m.constant < BitVec.from_integer(2,m.constant:bits())) then
    return fire(context,"mbedtls authmode below REQUIRED") end end
function wolf(p,context) local m=context.inputs[2]
  if m~=nil and m:is_const() and m.constant~=nil and m.constant:is_zero() then
    return fire(context,"wolfSSL SSL_VERIFY_NONE") end end
