author = "vulhunt-dev"
name = "rust-dangerous-ffi"
platform = "posix-binary"
architecture = "*:*:*"
-- Dangerous FFI via raw libc C symbols (system/dlopen/exec*/mprotect/setuid) reached
-- through Rust extern blocks or the nix/libc crates (which wrap these same libc symbols,
-- so the unmangled import is what surfaces). [scope:calls — unmangled]. (CWE-78/CWE-114/CWE-250)
scopes = {
  scope:calls{to="system",using={},with=cc}, scope:calls{to="dlopen",using={},with=cc},
  scope:calls{to="execve",using={},with=cc}, scope:calls{to="execvp",using={},with=cc},
  scope:calls{to="mprotect",using={},with=cc}, scope:calls{to="setuid",using={},with=cc},
}
function cc(project, context) return result:medium{name="rust-dangerous-ffi",
  description="Raw libc FFI (system/dlopen/exec/mprotect) — command exec / library load / W^X. (CWE-78/CWE-114)",
  cwes={"CWE-78","CWE-114"}, evidence={functions={[context.caller.address]={annotate:at{location=context.caller.call_address,message="dangerous libc FFI"}}}}} end
