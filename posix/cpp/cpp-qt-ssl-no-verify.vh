author = "vulhunt-dev"
name = "cpp-qt-ssl-verification-disabled"
platform = "posix-binary"
architecture = "*:*:*"

-- Ported from cpp qt-ssl-verification-disabled. QSslSocket::setPeerVerifyMode with
-- VerifyNone(0) or QueryPeer(1) disables certificate verification (MITM). C++ enum
-- args ARE readable as constant operands (unlike Go), so this is a precise
-- operand check, not mere presence. (CWE-295)
-- Mangled (ABI-stable): _ZN10QSslSocket17setPeerVerifyModeENS_14PeerVerifyModeE
--   PeerVerifyMode: VerifyNone=0, QueryPeer=1, VerifyPeer=2, AutoVerifyPeer=3
-- CONFIRMED: this exact mangled name is present in real Qt6 libQt6Network.so.6
-- (the enum-arg signature is stable across Qt versions). Operand logic (mode<2)
-- validated on the stub; not yet against a real app that passes a constant mode.
scopes = {
  scope:calls{to = "_ZN10QSslSocket17setPeerVerifyModeENS_14PeerVerifyModeE", using = {}, with = check},
  scope:calls{to = "_ZN21QSslConfiguration17setPeerVerifyModeENS_14PeerVerifyModeE", using = {}, with = check},
}

local QSslSocket_VerifyPeer = 2

-- instance method: inputs[1]=this, inputs[2]=mode enum
function check(project, context)
  local mode = context.inputs[2]
  if mode == nil or not mode:is_const() or mode.constant == nil then return end
  -- insecure if mode < VerifyPeer (i.e. VerifyNone or QueryPeer)
  if mode.constant < BitVec.from_integer(QSslSocket_VerifyPeer, mode.constant:bits()) then
    return result:high{
      name = "qt-ssl-verification-disabled",
      description = "QSslSocket/QSslConfiguration peer-verify mode set to VerifyNone/QueryPeer — TLS certificate verification disabled, enabling man-in-the-middle attacks. (CWE-295)",
      cwes = {"CWE-295"},
      evidence = {functions = {[context.caller.address] = {
        annotate:at{location = context.caller.call_address, message = "Peer verification disabled (mode < VerifyPeer)."}}}}
    }
  end
end
-- vim: ft=lua
