author = "vulhunt-dev"
name = "cpp-poco-dangerous"
platform = "posix-binary"
architecture = "*:*:*"
-- POCO: weak hash engines (MD5/SHA1) [presence], Process::launch [presence], and
-- Net::Context construction [presence/review for VERIFY_NONE]. (CWE-327/CWE-78/CWE-295)
scopes = {
  scope:functions{target = {matching = "4Poco9MD5Engine|4Poco10SHA1Engine", kind = "symbol"}, with = wc},
  scope:functions{target = {matching = "4Poco7Process6launch", kind = "symbol"}, with = pc},
  scope:functions{target = {matching = "4Poco3Net7ContextC[12]E", kind = "symbol"}, with = tc},
}
function wc(p,context) return result:medium{name="poco-weak-hash",
  description="POCO MD5Engine/SHA1Engine — weak hash. (CWE-327/CWE-328)", cwes={"CWE-327"},
  evidence={functions={[context.address]={annotate:prototype "POCO weak hash"}}}} end
function pc(p,context) return result:medium{name="poco-process-launch",
  description="Poco::Process::launch — external process execution; verify args not attacker-controlled. (CWE-78)", cwes={"CWE-78"},
  evidence={functions={[context.address]={annotate:prototype "Poco::Process::launch"}}}} end
function tc(p,context) return result:low{name="poco-tls-context",
  description="Poco::Net::Context constructed — verify VerificationMode is not VERIFY_NONE. (CWE-295)", cwes={"CWE-295"},
  evidence={functions={[context.address]={annotate:prototype "Poco::Net::Context"}}}} end
