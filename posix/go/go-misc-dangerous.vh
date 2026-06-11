author = "prockallsyms"
name = "go-dangerous-stdlib-use"
platform = "posix-binary"
architecture = "*:*:*"

-- Ported from lang reflect-makefunc, unsafe-reflect-by-name, insecure-module-used,
-- telnet-request, fs-directory-listing, pprof-debug-exposure, doublestar-glob.
-- Call-presence of dangerous/risky stdlib & library entry points. (CWE-470/CWE-242)
-- NOTE: net/http.FileServer was dropped — it inlines on optimized Go builds and
-- leaves no symbol (verified). reflect/cgi/doublestar validated on verify_go.elf.
scopes = {
  scope:calls{to = "reflect.MakeFunc",          using = {}, with = check_reflect},
  scope:calls{to = "reflect.Value.MethodByName",using = {}, with = check_reflect},
  scope:calls{to = "reflect.Value.FieldByName", using = {}, with = check_reflect},
  scope:calls{to = "net/http/cgi.Serve",        using = {}, with = check_cgi},
  scope:calls{to = "github.com/bmatcuk/doublestar.Glob",     using = {}, with = check_glob},
  scope:calls{to = "github.com/bmatcuk/doublestar/v4.Glob",  using = {}, with = check_glob},
}

function check_reflect(project, context)
  return result:low{
    name = "dynamic-reflection",
    description = "Dynamic reflection (reflect.MakeFunc / MethodByName / FieldByName). If the name/type derives from untrusted input it can invoke unintended code. (CWE-470)",
    cwes = {"CWE-470"},
    evidence = {functions = {[context.caller.address] = {annotate:at{location = context.caller.call_address, message = "Dynamic reflection."}}}}
  }
end
function check_fs(project, context)
  return result:low{
    name = "http-directory-listing",
    description = "http.FileServer exposes a directory tree (directory listing / path traversal risk if rooted at sensitive paths). (CWE-548)",
    cwes = {"CWE-548"},
    evidence = {functions = {[context.caller.address] = {annotate:at{location = context.caller.call_address, message = "http.FileServer directory exposure."}}}}
  }
end
function check_cgi(project, context)
  return result:medium{
    name = "insecure-cgi-module",
    description = "net/http/cgi is considered insecure/legacy. (CWE-1104)",
    cwes = {"CWE-1104"},
    evidence = {functions = {[context.caller.address] = {annotate:at{location = context.caller.call_address, message = "Insecure CGI module."}}}}
  }
end
function check_glob(project, context)
  return result:low{
    name = "uncontrolled-glob",
    description = "doublestar.Glob can perform uncontrolled filesystem traversal if the pattern is untrusted. (CWE-22)",
    cwes = {"CWE-22"},
    evidence = {functions = {[context.caller.address] = {annotate:at{location = context.caller.call_address, message = "Uncontrolled glob traversal."}}}}
  }
end
-- vim: ft=lua
