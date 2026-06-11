author = "prockallsyms"
name = "c-decompression-bomb"
platform = "posix-binary"
architecture = "*:*:*"
-- Decompression without an output cap → decompression bomb / resource exhaustion. (CWE-409/CWE-400)
scopes = {
  scope:calls{to="inflate",using={},with=c}, scope:calls{to="uncompress",using={},with=c},
  scope:calls{to="gzread",using={},with=c}, scope:calls{to="gzgets",using={},with=c},
  scope:calls{to="BZ2_bzDecompress",using={},with=c}, scope:calls{to="lzma_stream_decoder",using={},with=c},
}
function c(project,context) return result:low{name="decompression-bomb",
  description="Decompression routine (zlib/bzip2/xz) — verify an output-size cap exists to prevent a decompression bomb. (CWE-409/CWE-400)",
  cwes={"CWE-409"}, evidence={functions={[context.caller.address]={annotate:at{location=context.caller.call_address,message="unbounded decompression?"}}}}} end
