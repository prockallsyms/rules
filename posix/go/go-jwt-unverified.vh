author = "prockallsyms"
name = "go-jwt-unverified-parse"
platform = "posix-binary"
architecture = "*:*:*"
-- golang-jwt ParseUnverified (v4/v5) decodes a token WITHOUT checking the signature --
-- auth bypass if the claims are then trusted. (CWE-347)
scopes = {
  scope:calls{to="github.com/golang-jwt/jwt/v5.(*Parser).ParseUnverified", using={}, with=c},
  scope:calls{to="github.com/golang-jwt/jwt/v4.(*Parser).ParseUnverified", using={}, with=c},
}
function c(project, context) return result:high{name="go-jwt-unverified-parse",
  description="golang-jwt ParseUnverified -- token signature is NOT verified; trusting these claims is an auth bypass. (CWE-347)",
  cwes={"CWE-347"}, evidence={functions={[context.caller.address]={annotate:at{location=context.caller.call_address,message="JWT parsed without signature verification"}}}}} end
