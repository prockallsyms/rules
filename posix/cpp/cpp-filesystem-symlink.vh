author = "prockallsyms"
name = "cpp-filesystem-symlink-follow"
platform = "posix-binary"
architecture = "*:*:*"

-- Ported from lang directory-iterator-follows-symlinks / copy-file-no-symlink-handling.
-- C++ library symbols are Itanium-mangled and the engine does not demangle, so we
-- regex-match the stable mangled segments (`<len>filesystem<len>directory_iterator`).
-- std::filesystem directory iteration / copy follow symlinks by default. (CWE-59)
scopes = scope:functions{
  target = {matching = "filesystem[0-9]+directory_iterator|filesystem[0-9]+copy_file", kind = "symbol"},
  with = check
}

function check(project, context)
  return result:low{
    name = "filesystem-symlink-follow",
    description = "Use of std::filesystem directory_iterator / copy_file, which follow symbolic links by default — a symlink-traversal hazard when operating on attacker-controlled paths. Pass directory_options::skip_... / copy_options::skip_symlinks. (CWE-59)",
    cwes = {"CWE-59"},
    evidence = {functions = {[context.address] = {
      annotate:prototype "std::filesystem directory traversal"
    }}}
  }
end
-- vim: ft=lua
