author = "vulhunt-dev"
name = "c-insecure-temp-file"
platform = "posix-binary"
architecture = "*:*:*"

-- Consolidated from gitlab c_tmpfile_rule-*, raptor-insecure-api-mktemp-*.
-- Predictable / racy temporary-file creation. (CWE-377)
scopes = {
  scope:calls{to = "mktemp",  using = {}, with = check},
  scope:calls{to = "tmpnam",  using = {}, with = check},
  scope:calls{to = "tempnam", using = {}, with = check},
  scope:calls{to = "tmpfile", using = {}, with = check},
}

function check(project, context)
  return result:low{
    name = "insecure-temp-file",
    description = "Use of a predictable/racy temporary-file API (mktemp/tmpnam/tempnam/tmpfile). Prefer mkstemp. (CWE-377)",
    cwes = {"CWE-377"},
    evidence = {functions = {[context.caller.address] = {
      annotate:at{location = context.caller.call_address,
        message = "Insecure temporary-file creation (TOCTOU / predictable name)."}
    }}}
  }
end
-- vim: ft=lua
