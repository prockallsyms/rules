author = "prockallsyms"
name = "c-discouraged-memory-api"
platform = "posix-binary"
architecture = "*:*:*"

-- alloca: unbounded stack growth -> stack-clash/overflow if size is attacker
-- influenced. valloc/memalign/pvalloc: obsolete allocators. (CWE-770/CWE-676)
scopes = {
  scope:calls{to = "alloca",   using = {}, with = check},
  scope:calls{to = "valloc",   using = {}, with = check},
  scope:calls{to = "pvalloc",  using = {}, with = check},
  scope:calls{to = "memalign", using = {}, with = check},
}

function check(project, context)
  return result:low{
    name = "discouraged-memory-api",
    description = "Use of a discouraged allocator. alloca() grows the stack with no failure mode (stack-clash risk if the size is attacker-influenced); valloc/pvalloc/memalign are obsolete. (CWE-770)",
    cwes = {"CWE-770"},
    evidence = {functions = {[context.caller.address] = {
      annotate:at{location = context.caller.call_address,
        message = "Discouraged allocator (alloca/valloc/pvalloc/memalign)."}
    }}}
  }
end
-- vim: ft=lua
