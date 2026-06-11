author = "vulhunt-dev"
name = "c-weak-tls-version"
platform = "posix-binary"
architecture = "*:*:*"

-- Operand-based: flag explicit selection of an obsolete TLS/SSL protocol
-- version. (CWE-326/CWE-327)
--  * OpenSSL: SSL[_CTX]_set_min/max_proto_version(ctx, V) where V < TLS1_2
--    (SSL3_VERSION=0x300, TLS1_VERSION=0x301, TLS1_1_VERSION=0x302; 0 = no floor).
--  * curl: curl_easy_setopt(.., CURLOPT_SSLVERSION, V) where V selects <= TLSv1.1.
scopes = {
  scope:calls{to = "SSL_CTX_set_min_proto_version", using = {}, with = check_openssl},
  scope:calls{to = "SSL_CTX_set_max_proto_version", using = {}, with = check_openssl},
  scope:calls{to = "SSL_set_min_proto_version",     using = {}, with = check_openssl},
  scope:calls{to = "SSL_set_max_proto_version",     using = {}, with = check_openssl},
  scope:calls{to = "curl_easy_setopt",              using = {}, with = check_curl},
}

local TLS1_2_VERSION = 0x0303
local CURLOPT_SSLVERSION = 32
-- curl enum values <= TLSv1.1 (CURL_SSLVERSION_*): TLSv1=1, SSLv2=2, SSLv3=3,
-- TLSv1_0=4, TLSv1_1=5. (6=TLSv1_2, 7=TLSv1_3 are acceptable.)
local CURL_WEAK = {1, 2, 3, 4, 5}

local function const_val(operand)
  if operand == nil or not operand:is_const() then return nil end
  return operand.constant
end

local function const_eq(operand, n)
  local c = const_val(operand); if c == nil then return false end
  return c == BitVec.from_integer(n, c:bits())
end

local function finding(context, msg)
  return result:medium{
    name = "weak-tls-version",
    description = "An obsolete TLS/SSL protocol version is explicitly selected, weakening transport security. (CWE-326/CWE-327)",
    cwes = {"CWE-326", "CWE-327"},
    evidence = {functions = {[context.caller.address] = {
      annotate:at{location = context.caller.call_address, message = msg}
    }}}
  }
end

-- SSL[_CTX]_set_{min,max}_proto_version(ctx, version): version = inputs[2].
function check_openssl(project, context)
  local v = const_val(context.inputs[2])
  if v == nil then return end
  -- weak if version < TLS1_2 (covers SSL3/TLS1.0/TLS1.1 and 0 = "no minimum")
  if v < BitVec.from_integer(TLS1_2_VERSION, v:bits()) then
    return finding(context, "Minimum/maximum protocol version is below TLS 1.2.")
  end
end

-- curl_easy_setopt(handle, option, value): option=inputs[2], value=inputs[3].
function check_curl(project, context)
  if not const_eq(context.inputs[2], CURLOPT_SSLVERSION) then return end
  local val = context.inputs[3]
  for _, w in ipairs(CURL_WEAK) do
    if const_eq(val, w) then
      return finding(context, "CURLOPT_SSLVERSION selects TLS 1.1 or older.")
    end
  end
end
-- vim: ft=lua
