author = "prockallsyms"
name = "c-insecure-file-operation"
platform = "posix-binary"
architecture = "*:*:*"

-- Consolidated from gitlab c_race_rule-* / c_misc_rule-*. File operations that
-- are classic TOCTOU / permission / symlink hazards. (CWE-367/CWE-732/CWE-59)
-- (bare fopen/open/stat are intentionally excluded as too common for presence.)
scopes = {
  scope:calls{to = "chmod",      using = {}, with = check},
  scope:calls{to = "fchmod",     using = {}, with = check},
  scope:calls{to = "chown",      using = {}, with = check},
  scope:calls{to = "fchown",     using = {}, with = check},
  scope:calls{to = "lchown",     using = {}, with = check},
  scope:calls{to = "umask",      using = {}, with = check},
  scope:calls{to = "mkfifo",     using = {}, with = check},
  scope:calls{to = "mknod",      using = {}, with = check},
  scope:calls{to = "access",     using = {}, with = check},
  scope:calls{to = "readlink",   using = {}, with = check},
  scope:calls{to = "readlinkat", using = {}, with = check},
  scope:calls{to = "chroot",     using = {}, with = check},
}

function check(project, context)
  return result:low{
    name = "insecure-file-operation",
    description = "File operation prone to TOCTOU races, weak permissions, or symlink attacks (chmod/chown/access/readlink/mkfifo/etc). Verify the path cannot be swapped between check and use. (CWE-367/CWE-732)",
    cwes = {"CWE-367", "CWE-732"},
    evidence = {functions = {[context.caller.address] = {
      annotate:at{location = context.caller.call_address,
        message = "Race/permission-sensitive file operation."}
    }}}
  }
end
-- vim: ft=lua
