author = "prockallsyms"
name = "c-tls-verification-disabled"
platform = "posix-binary"
architecture = "*:*:*"

-- Higher-signal: inspect the constant arguments to detect TLS peer/cert
-- verification being explicitly disabled (not mere API presence).
--  * OpenSSL: SSL_CTX_set_verify / SSL_set_verify with mode == SSL_VERIFY_NONE (0)
--  * curl: curl_easy_setopt(.., CURLOPT_SSL_VERIFYPEER|VERIFYHOST, 0)
-- (CWE-295)
scopes = {
  scope:calls{to = "SSL_CTX_set_verify", using = {}, with = check_openssl},
  scope:calls{to = "SSL_set_verify",     using = {}, with = check_openssl},
  scope:calls{to = "curl_easy_setopt",   using = {}, with = check_curl},
}

local CURLOPT_SSL_VERIFYPEER = 64
local CURLOPT_SSL_VERIFYHOST = 81

local function const_eq(operand, n)
  local c = operand.constant
  if c == nil then return false end
  return c == BitVec.from_integer(n, c:bits())
end

local function finding(context, msg)
  return result:high{
    name = "tls-verification-disabled",
    description = "TLS certificate/peer verification is explicitly disabled, exposing connections to man-in-the-middle attacks. (CWE-295)",
    cwes = {"CWE-295"},
    evidence = {functions = {[context.caller.address] = {
      annotate:at{location = context.caller.call_address, message = msg}
    }}}
  }
end

-- SSL[_CTX]_set_verify(ctx, mode, cb): mode is the 2nd argument (inputs[2]).
function check_openssl(project, context)
  local mode = context.inputs[2]
  if mode == nil or not mode:is_const() then return end
  if mode.constant ~= nil and mode.constant:is_zero() then
    return finding(context, "Verification mode is SSL_VERIFY_NONE — certificate validation disabled.")
  end
end

-- curl_easy_setopt(handle, option, value): option=inputs[2], value=inputs[3].
function check_curl(project, context)
  local opt = context.inputs[2]
  local val = context.inputs[3]
  if opt == nil or val == nil then return end
  if not (const_eq(opt, CURLOPT_SSL_VERIFYPEER) or const_eq(opt, CURLOPT_SSL_VERIFYHOST)) then return end
  if val:is_const() and val.constant ~= nil and val.constant:is_zero() then
    return finding(context, "CURLOPT_SSL_VERIFY* set to 0 — TLS verification disabled.")
  end
end
-- vim: ft=lua
