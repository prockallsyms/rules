author = "vulhunt-dev"
name = "go-redis-server-side-eval"
platform = "posix-binary"
architecture = "*:*:*"
-- go-redis Eval/EvalSha run a server-side Lua script. If the script body is built from
-- untrusted input it is code injection on the Redis server. (CWE-94). The exported
-- (*Client).Eval wrapper inlines; the surviving worker is cmdable.eval.
scopes = {
  scope:calls{to="github.com/redis/go-redis/v9.cmdable.eval", using={}, with=c},
  scope:calls{to="github.com/redis/go-redis/v9.(*Client).Eval", using={}, with=c},
}
function c(project, context) return result:medium{name="go-redis-server-side-eval",
  description="go-redis Eval/EvalSha executes a server-side Lua script -- injection if the script body is untrusted. (CWE-94)",
  cwes={"CWE-94"}, evidence={functions={[context.caller.address]={annotate:at{location=context.caller.call_address,message="Redis server-side Lua eval"}}}}} end
