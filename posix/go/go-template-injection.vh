author = "vulhunt-dev"
name = "go-text-template-injection"
platform = "posix-binary"
architecture = "*:*:*"
-- text/template.Parse (NOT html/template) does no contextual auto-escaping. Parsing a
-- template built from untrusted input is SSTI; rendering to HTML is XSS. (CWE-1336/CWE-79)
scopes = scope:calls{to="text/template.(*Template).Parse", using={}, with=c}
function c(project, context)
  -- html/template wraps text/template and calls this internally; flagging an
  -- html/template user (the SAFE choice) is a false positive. Skip call sites
  -- inside the template packages themselves -- genuine user code calls from main.*.
  local cn = context.caller.name
  if cn ~= nil and (cn:find("html/template", 1, true) or cn:find("text/template", 1, true)) then return end
  return result:medium{name="go-text-template-injection",
  description="text/template.Parse -- no contextual escaping (unlike html/template); untrusted template text is SSTI, untrusted HTML output is XSS. (CWE-1336/CWE-79)",
  cwes={"CWE-1336","CWE-79"}, evidence={functions={[context.caller.address]={annotate:at{location=context.caller.call_address,message="text/template parse (no escaping)"}}}}} end
