author = "vulhunt-dev"
name = "c-libssh2-no-hostkey-check"
platform = "posix-binary"
architecture = "*:*:*"
-- Absence heuristic: libssh2 authenticates (userauth_*) but NEVER verifies the host key
-- (libssh2_knownhost_check/checkp) → accepts any host key (MITM). (CWE-295/CWE-322)
scopes = scope:project{with=check}
function check(project, context)
  local auth = project:functions_where(function(f)
    return f:has_call("libssh2_userauth_password") or f:has_call("libssh2_userauth_publickey_fromfile_ex")
        or f:has_call("libssh2_userauth_publickey") end)
  if #auth == 0 then return end
  local kh = project:functions_where(function(f)
    return f:has_call("libssh2_knownhost_check") or f:has_call("libssh2_knownhost_checkp") end)
  if #kh > 0 then return end
  local f = auth[1]
  return result:high{name="libssh2-no-hostkey-check",
    description="libssh2 authentication without host-key verification (libssh2_knownhost_check) — accepts any host key (MITM). (CWE-295/CWE-322)",
    cwes={"CWE-295","CWE-322"}, evidence={functions={[f.address]={annotate:prototype "ssh auth without known-host check"}}}}
end
