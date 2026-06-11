author = "vulhunt-dev"
name = "cpp-boost-dangerous"
platform = "posix-binary"
architecture = "*:*:*"
-- Boost.Asio TLS verify disabled (set_verify_mode(verify_none=0)) [operand], and
-- Boost.Serialization input archives over untrusted data [presence]. (CWE-295/CWE-502)
scopes = {
  scope:calls{to = "_ZN5boost4asio3ssl7context15set_verify_modeEi", using = {}, with = check_verify},
  scope:functions{target = {matching = "7archive1[0-9]+(text|binary|xml)_iarchive", kind = "symbol"}, with = check_deser},
}
function check_verify(project, context)
  local m = context.inputs[2]   -- this=1, mode=2
  if m ~= nil and m:is_const() and m.constant ~= nil and m.constant:is_zero() then
    return result:high{name="boost-asio-no-verify",
      description="boost::asio::ssl::context::set_verify_mode(verify_none) — TLS peer verification disabled. (CWE-295)",
      cwes={"CWE-295"}, evidence={functions={[context.caller.address]={annotate:at{location=context.caller.call_address,message="verify_none"}}}}}
  end
end
function check_deser(project, context)
  return result:medium{name="boost-unsafe-deserialization",
    description="Boost.Serialization input archive (text/binary/xml_iarchive) — deserializing untrusted data is unsafe. (CWE-502)",
    cwes={"CWE-502"}, evidence={functions={[context.address]={annotate:prototype "boost iarchive"}}}}
end
