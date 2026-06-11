author = "vulhunt-dev"
name = "c-curl-insecure-options"
platform = "posix-binary"
architecture = "*:*:*"
-- Additional dangerous curl_easy_setopt options (beyond VERIFYPEER/HOST/SSLVERSION):
-- CURLOPT_SSL_VERIFYSTATUS=0, CURLOPT_PROXY_SSL_VERIFYPEER/HOST=0, CURLOPT_USE_SSL=NONE. (CWE-295/CWE-319)
scopes = { scope:calls{to="curl_easy_setopt", using={}, with=check} }
local OPTS = {[2194]=true,[5247]=true,[5248]=true,[119]=true}  -- VERIFYSTATUS, PROXY_VERIFYPEER/HOST, USE_SSL
local function const_eq(op,n) if op==nil or not op:is_const() or op.constant==nil then return false end
  return op.constant == BitVec.from_integer(n, op.constant:bits()) end
local function const_zero(op) return op~=nil and op:is_const() and op.constant~=nil and op.constant:is_zero() end
function check(p,context)
  local opt=context.inputs[2]; local val=context.inputs[3]
  if opt==nil or not opt:is_const() or opt.constant==nil then return end
  local matched=false
  for n,_ in pairs(OPTS) do if const_eq(opt,n) then matched=true break end end
  if matched and const_zero(val) then
    return result:medium{name="curl-insecure-option",
      description="curl_easy_setopt disables a TLS verification/transport-security option (VERIFYSTATUS/PROXY verify/USE_SSL). (CWE-295/CWE-319)",
      cwes={"CWE-295","CWE-319"}, evidence={functions={[context.caller.address]={annotate:at{location=context.caller.call_address,message="insecure curl option = 0"}}}}}
  end
end
