author = "prockallsyms"
name = "c-unbounded-string-copy"
platform = "posix-binary"
architecture = "*:*:*"

-- Consolidated from the (highly redundant) strcpy/strcat family rules across
-- gitlab c_buffer_rule-*, itermalum/0xdea raptor-insecure-api-strcpy-*, lang.
-- Unbounded / easily-misused string copy & concat. (CWE-120/CWE-676)
scopes = {
  scope:calls{to = "strcpy",  using = {}, with = check},
  scope:calls{to = "strcat",  using = {}, with = check},
  scope:calls{to = "stpcpy",  using = {}, with = check},
  scope:calls{to = "strncpy", using = {}, with = check},
  scope:calls{to = "strncat", using = {}, with = check},
  scope:calls{to = "stpncpy", using = {}, with = check},
  scope:calls{to = "wcscpy",  using = {}, with = check},
  scope:calls{to = "wcscat",  using = {}, with = check},
  scope:calls{to = "wcsncpy", using = {}, with = check},
  scope:calls{to = "wcsncat", using = {}, with = check},
  scope:calls{to = "wcpcpy",  using = {}, with = check},
  scope:calls{to = "wcpncpy", using = {}, with = check},
  -- BSD/embedded-prevalent bounded copies (still truncate / mis-size easily)
  scope:calls{to = "strlcpy", using = {}, with = check},
  scope:calls{to = "strlcat", using = {}, with = check},
  scope:calls{to = "strscpy", using = {}, with = check},
}

function check(project, context)
  return result:low{
    name = "unbounded-string-copy",
    description = "Use of an easily-misused C string copy/concat function. strcpy/strcat are unbounded; the strn*/wcs* variants frequently truncate or leave the destination non-NUL-terminated. (CWE-120/CWE-676)",
    cwes = {"CWE-120", "CWE-676"},
    evidence = {functions = {[context.caller.address] = {
      annotate:at{location = context.caller.call_address,
        message = "String copy/concat with no reliable destination-bound guarantee."}
    }}}
  }
end
-- vim: ft=lua
