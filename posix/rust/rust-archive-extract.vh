author = "prockallsyms"
name = "rust-archive-extraction"
platform = "posix-binary"
architecture = "*:*:*"
-- Archive extraction (tar::Archive::unpack / Entry::unpack_in / zip::ZipArchive::extract)
-- — path traversal / zip-slip if destination is unsanitized (recent CVEs). (CWE-22/CWE-59)
scopes = scope:functions{
  target = {matching = "7Archive6unpack|5Entry9unpack_in|10ZipArchive7extract|13unpack_in_raw", kind = "symbol"}, with = check }
function check(project, context)
  return result:medium{name="rust-archive-extraction",
    description="Archive extraction (tar/zip) — verify destination path sanitization (zip-slip / symlink escape). (CWE-22/CWE-59)",
    cwes={"CWE-22","CWE-59"}, evidence={functions={[context.address]={annotate:prototype "archive extract"}}}} end
