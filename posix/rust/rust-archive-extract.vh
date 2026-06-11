author = "prockallsyms"
name = "rust-archive-extraction"
platform = "posix-binary"
architecture = "*:*:*"
-- Archive extraction (tar::Archive::unpack / Entry::unpack_in / zip::ZipArchive::extract)
-- — path traversal / zip-slip if destination is unsanitized (recent CVEs). (CWE-22/CWE-59)
-- Real symbols carry a generic param between type and method ("Archive$LT$R$GT$6unpack"),
-- so the contiguous "7Archive6unpack" form does NOT match — anchor on crate+module then
-- the verb. Verified against tar 0.4 / zip 0.6.
scopes = scope:functions{
  target = {matching = "3tar7archive.*6unpack|3tar5entry.*unpack|3zip4read.*7extract", kind = "symbol"}, with = check }
function check(project, context)
  return result:medium{name="rust-archive-extraction",
    description="Archive extraction (tar/zip) — verify destination path sanitization (zip-slip / symlink escape). (CWE-22/CWE-59)",
    cwes={"CWE-22","CWE-59"}, evidence={functions={[context.address]={annotate:prototype "archive extract"}}}} end
