author = "prockallsyms"
name = "c-libarchive-unsafe-extract"
platform = "posix-binary"
architecture = "*:*:*"
-- archive_read_extract / archive_write_disk_set_options with extract flags MISSING the
-- security bits → path traversal / zip-slip. REAL libarchive values (archive.h, verified
-- 3.6.2): SECURE_SYMLINKS=0x100, SECURE_NODOTDOT=0x200 (0x40/0x80 are FFLAGS/XATTR). (CWE-22/CWE-59)
scopes = {
  scope:calls{to="archive_read_extract",           using={}, with=f3},  -- a,entry,flags
  scope:calls{to="archive_write_disk_set_options", using={}, with=f2},  -- a,flags
}
local function unsafe(op)
  if op==nil or not op:is_const() or op.constant==nil then return false end
  local c=op.constant; local function missing(n) return c:band(BitVec.from_integer(n,c:bits())):is_zero() end
  return missing(0x100) or missing(0x200)   -- missing SECURE_SYMLINKS or SECURE_NODOTDOT
end
local function fire(context) return result:medium{name="libarchive-unsafe-extract",
  description="libarchive extraction without SECURE_SYMLINKS/SECURE_NODOTDOT — path traversal / symlink escape (zip-slip). (CWE-22/CWE-59)",
  cwes={"CWE-22","CWE-59"}, evidence={functions={[context.caller.address]={annotate:at{location=context.caller.call_address,message="missing secure-extract flags"}}}}} end
function f3(p,context) if unsafe(context.inputs[3]) then return fire(context) end end
function f2(p,context) if unsafe(context.inputs[2]) then return fire(context) end end
