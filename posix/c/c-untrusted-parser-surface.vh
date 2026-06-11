author = "vulhunt-dev"
name = "c-untrusted-media-parser"
platform = "posix-binary"
architecture = "*:*:*"
-- Untrusted-file parsing surface (libtiff/libpng/libjpeg/expat) — memory-unsafety
-- attack surface; inventory/review. (CWE-20)
scopes = {
  scope:calls{to="TIFFReadRGBAImage",using={},with=c}, scope:calls{to="TIFFReadRGBATile",using={},with=c},
  scope:calls{to="TIFFReadRGBATileExt",using={},with=c}, scope:calls{to="TIFFReadEncodedStrip",using={},with=c},
  scope:calls{to="TIFFReadEncodedTile",using={},with=c}, scope:calls{to="png_read_image",using={},with=c},
  scope:calls{to="png_read_png",using={},with=c}, scope:calls{to="jpeg_read_scanlines",using={},with=c},
  scope:calls{to="jpeg_read_header",using={},with=c}, scope:calls{to="XML_Parse",using={},with=c},
  scope:calls{to="XML_ParseBuffer",using={},with=c},
}
function c(project,context) return result:info{name="untrusted-media-parser",
  description="Untrusted-input media/XML parser (libtiff/libpng/libjpeg/expat) — historical memory-safety surface; verify input is trusted/sandboxed. (CWE-20)",
  cwes={"CWE-20"}, evidence={functions={[context.caller.address]={annotate:at{location=context.caller.call_address,message="untrusted parser sink"}}}}} end
