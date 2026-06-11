author = "vulhunt-dev"
name = "cpp-protobuf-untrusted-parse"
platform = "posix-binary"
architecture = "*:*:*"
-- protobuf parse of untrusted wire data (ParseFromString/Array, MergeFromString). DoS /
-- type-confusion surface; verify size/recursion limits + Any.UnpackTo handling. (CWE-502/CWE-400)
scopes = scope:functions{
  target = {matching = "1[0-9]+(ParseFromString|ParseFromArray|MergeFromString)", kind = "symbol"},
  with = check
}
function check(project, context)
  return result:low{name="protobuf-untrusted-parse",
    description="protobuf message parse — verify the input is trusted and limits are set. (CWE-502/CWE-400)",
    cwes={"CWE-502","CWE-400"}, evidence={functions={[context.address]={annotate:prototype "protobuf parse"}}}}
end
