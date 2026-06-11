author = "vulhunt-dev"
name = "cpp-untrusted-file-parse"
platform = "posix-binary"
architecture = "*:*:*"
-- OpenCV / libtorrent parsing untrusted files (images/models/.torrent) — historical
-- memory-safety surface. (CWE-20/CWE-502)
scopes = scope:functions{
  target = {matching = "imread|bdecode|readNetFrom|torrent_info", kind = "symbol"},
  with = check
}
function check(project, context)
  return result:info{name="untrusted-file-parse",
    description="OpenCV/libtorrent untrusted-file parse — verify input is trusted/sandboxed. (CWE-20)",
    cwes={"CWE-20"}, evidence={functions={[context.address]={annotate:prototype "untrusted file parse"}}}}
end
