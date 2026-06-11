author = "prockallsyms"
name = "go-deprecated-jwt-go"
platform = "posix-binary"
architecture = "*:*:*"
-- Presence of the unmaintained github.com/dgrijalva/jwt-go (CVE-2020-26160: aud claim
-- bypass). Superseded by github.com/golang-jwt/jwt. (CWE-1104). One annotation per init.
scopes = scope:functions{ target = {matching = "dgrijalva/jwt-go\\.init$", kind = "symbol"}, with = c }
function c(project, context) return result:medium{name="go-deprecated-jwt-go",
  description="Binary links the deprecated/vulnerable github.com/dgrijalva/jwt-go (CVE-2020-26160). Migrate to github.com/golang-jwt/jwt. (CWE-1104)",
  cwes={"CWE-1104"}, evidence={functions={[context.address]={annotate:prototype "deprecated jwt-go"}}}} end
