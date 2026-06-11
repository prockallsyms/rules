author = "vulhunt-dev"
name = "c-sqlite-load-extension-enabled"
platform = "posix-binary"
architecture = "*:*:*"
-- sqlite3_enable_load_extension(db, 1) lets SQL load arbitrary shared objects → RCE if
-- queries are attacker-influenced. (CWE-94)
scopes = { scope:calls{to="sqlite3_enable_load_extension", using={}, with=check} }
function check(p,context) local on=context.inputs[2]
  if on~=nil and on:is_const() and on.constant~=nil and not on.constant:is_zero() then
    return result:medium{name="sqlite-load-extension-enabled",
      description="sqlite3_enable_load_extension(db, 1) — SQL can load arbitrary extensions (RCE surface). (CWE-94)",
      cwes={"CWE-94"}, evidence={functions={[context.caller.address]={annotate:at{location=context.caller.call_address,message="extension loading enabled"}}}}}
  end
end
