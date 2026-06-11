author = "vulhunt-dev"
name = "c-tls-missing-hostname-verification"
platform = "posix-binary"
architecture = "*:*:*"
-- Absence heuristic: binary enables OpenSSL peer verification (SSL[_CTX]_set_verify) but
-- NEVER calls a hostname check (X509_check_host / X509_VERIFY_PARAM_set1_host/ip) →
-- chain verified but hostname not, allowing MITM with any valid cert. (CWE-295)
scopes = scope:project{with=check}
function check(project, context)
  local setv = project:functions_where(function(f) return f:has_call("SSL_CTX_set_verify") or f:has_call("SSL_set_verify") end)
  if #setv == 0 then return end
  local host = project:functions_where(function(f)
    return f:has_call("X509_check_host") or f:has_call("X509_check_ip") or f:has_call("X509_check_ip_asc")
        or f:has_call("X509_VERIFY_PARAM_set1_host") or f:has_call("X509_VERIFY_PARAM_set1_ip") end)
  if #host > 0 then return end
  local f = setv[1]
  return result:medium{name="tls-missing-hostname-verification",
    description="OpenSSL peer verification enabled but no hostname check (X509_check_host / set1_host) anywhere — cert chain verified, hostname not. (CWE-295)",
    cwes={"CWE-295"}, evidence={functions={[f.address]={annotate:prototype "sets SSL verify but never checks hostname"}}}}
end
