author = "vulhunt-dev"
name = "go-untrusted-deserialization"
platform = "posix-binary"
architecture = "*:*:*"
-- Decoding untrusted data with encoding/gob or gopkg.in/yaml.v2 -- resource exhaustion /
-- type-confusion / object-graph attacks if the input is attacker-controlled. (CWE-502)
-- yaml.Unmarshal exported wrapper inlines; the surviving worker is the package unmarshal.
scopes = {
  scope:calls{to="encoding/gob.(*Decoder).Decode", using={}, with=c},
  scope:calls{to="gopkg.in/yaml%2ev2.unmarshal", using={}, with=c},
  scope:calls{to="gopkg.in/yaml%2ev2.Unmarshal", using={}, with=c},
}
function c(project, context) return result:low{name="go-untrusted-deserialization",
  description="Deserialization of possibly-untrusted data (encoding/gob Decode or yaml.v2 Unmarshal) -- DoS / type-confusion if input is attacker-controlled. (CWE-502)",
  cwes={"CWE-502"}, evidence={functions={[context.caller.address]={annotate:at{location=context.caller.call_address,message="untrusted deserialization"}}}}} end
