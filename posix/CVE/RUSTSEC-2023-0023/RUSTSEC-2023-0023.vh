author = "prockallsyms"
name = "RUSTSEC-2023-0023"
platform = "posix-binary"
architecture = "*:*:*"
signatures = {project = "openssl", from = "0.9.7", to = "0.10.48"}

-- RUSTSEC-2023-0023 / GHSA-9qwg-crg9-m2vc: the rust `openssl` crate before 0.10.48
-- (sfackler/rust-openssl) allowed arbitrary file read (CWE-22 / CWE-20) through its
-- `SubjectAlternativeName` builder and `ExtendedKeyUsage::other` API. Both builders
-- accumulated user-supplied strings and, at `build()` time, joined them into a single
-- comma-separated value string that was passed verbatim to OpenSSL's FFI
-- `X509V3_EXT_nconf_nid`. That C function runs OpenSSL's config-file/mini-language parser,
-- which honours directives such as `file:/path` and `@/path` (read file contents) and
-- `@section`. An attacker who could influence the argument to `dns()`/`email()`/`uri()`/
-- `other()` could inject those directives and read arbitrary files during certificate
-- construction.
--
-- Fix (PR #1854, commits 482575b "Resolve an injection vulnerability in SAN creation" +
-- 332311b "Resolve an injection vulnerability in EKU creation", released in 0.10.48):
-- the string-building / `X509V3_EXT_nconf_nid` path was removed entirely. SAN now builds a
-- GENERAL_NAME stack via `GENERAL_NAME_new` + `ASN1_STRING_set`, EKU builds an ASN1_OBJECT
-- stack via `OBJ_txt2obj` (Asn1Object::from_str), and both are emitted through the new
-- `X509Extension::new_internal` -> `ffi::X509V3_EXT_i2d` (takes a pre-built C structure,
-- never parses the value string).
--
-- DISCRIMINATOR -- module-level FFI-function presence (NOT a bare symbol-version key, and
-- NOT call-presence). Why not call-presence: in the vendored static build the FFI functions
-- are reached through GOT slots filled by R_X86_64_RELATIVE relocations and emitted as
-- `call *0xNNN(%rip)` (e.g. .got slot -> X509V3_EXT_nconf_nid); there is no direct
-- `call <X509V3_EXT_nconf_nid>` instruction, and `context:has_call("X509V3_EXT_nconf_nid")`
-- probed FALSE in both `SubjectAlternativeName::build` and `X509Extension::new_nid`, so the
-- engine does not resolve those GOT-indirect calls into named targets.
--
-- Instead the fix's call-target swap is observable through linker dead-code-elimination:
-- the vulnerable `X509V3_EXT_nconf_nid` config-parser call site is the ONLY thing that pulls
-- that FFI function into the binary, and the patched `X509V3_EXT_i2d` call site is the only
-- thing that pulls i2d in. Probed live with project:functions{matching=...,kind="symbol"}:
--    VULN 0.10.47:    X509V3_EXT_nconf_nid PRESENT, X509V3_EXT_i2d ABSENT
--    PATCHED 0.10.48: X509V3_EXT_nconf_nid ABSENT,  X509V3_EXT_i2d PRESENT
-- (GENERAL_NAME_new is present in BOTH builds -- libcrypto references it internally -- so it
-- is NOT used.) The `SubjectAlternativeName...build` symbol exists in BOTH builds (Rust v0,
-- matched by readable segments), so the finding anchors on the real vulnerable function in
-- either build.
--
-- Telnetd / fire-when-fix-absent: FIRE when the config-parser FFI is linked
-- (X509V3_EXT_nconf_nid present AND X509V3_EXT_i2d absent); stay SILENT (return nil) when the
-- structured-data FFI is present (X509V3_EXT_i2d) or the parser FFI is gone -> >= 0.10.48.

scopes = scope:functions{
  target = {matching = "SubjectAlternativeName.*build", kind = "symbol"},
  with = check
}

function check(project, context)
  -- single-form project:functions; nil when no function with that symbol exists.
  local function has_fn(sym)
    local f = project:functions{matching = sym, kind = "symbol"}
    return f ~= nil
  end

  local nconf = has_fn("X509V3_EXT_nconf_nid")  -- vulnerable config-parser FFI
  local i2d   = has_fn("X509V3_EXT_i2d")         -- fix's structured-data FFI

  -- Fix present (>= 0.10.48): the structured-data emitter is linked, or the config parser
  -- has been dead-code-eliminated. Either way the vulnerable parse path is gone -> silent.
  if i2d or not nconf then
    return
  end

  return result:high{
    name = "RUSTSEC-2023-0023",
    description = "rust `openssl` crate before 0.10.48: SubjectAlternativeName::build and ExtendedKeyUsage::build joined user-supplied strings into a comma-separated value and passed it to the OpenSSL FFI `X509V3_EXT_nconf_nid`, OpenSSL's config-file/mini-language parser, which interprets `file:/path` and `@/path` directives -- allowing an attacker who controls a dns()/email()/uri()/other() argument to read arbitrary files during certificate construction (CWE-22 / CWE-20). The fix (0.10.48) removes the string + X509V3_EXT_nconf_nid path and instead builds GENERAL_NAME / ASN1_OBJECT stacks (GENERAL_NAME_new, OBJ_txt2obj) emitted through X509Extension::new_internal -> ffi::X509V3_EXT_i2d, which never parses the value. This build links the config-parser FFI X509V3_EXT_nconf_nid and does not link X509V3_EXT_i2d, so the vulnerable parse path is present. Upgrade openssl to >= 0.10.48.",
    provenance = {
      kind = "posix.ELF",
      linkage = "project",
      vendor = "sfackler",
      product = "openssl",
      license = "Apache-2.0",
      affected_versions = {">=0.9.7", "<0.10.48"}
    },
    cwes = {"CWE-22", "CWE-20"},
    advisory = "https://rustsec.org/advisories/RUSTSEC-2023-0023.html",
    patch = "https://github.com/sfackler/rust-openssl/commit/482575bca7c0eca7913d5db0c1aa4376e6c1a02d",
    identifiers = {"RUSTSEC-2023-0023", "GHSA-9qwg-crg9-m2vc"},
    references = {
      ["RUSTSEC"] = "https://rustsec.org/advisories/RUSTSEC-2023-0023.html",
      ["GHSA"] = "https://github.com/sfackler/rust-openssl/security/advisories/GHSA-9qwg-crg9-m2vc"
    },
    evidence = {
      functions = {
        [context.address] = {
          annotate:prototype "fn SubjectAlternativeName::build(&self, ctx: &X509v3Context) -> Result<X509Extension, ErrorStack>",
          annotate:at{
            location = context.address,
            message = "SubjectAlternativeName::build (and ExtendedKeyUsage::build) joins user-supplied SAN/EKU strings and passes the value to OpenSSL's config parser X509V3_EXT_nconf_nid (linked here; the 0.10.48 X509V3_EXT_i2d structured-data emitter is absent), which honours `file:`/`@file` directives -> arbitrary file read. Upgrade openssl to >= 0.10.48."
          }
        }
      }
    }
  }
end

--
-- vim: ft=lua
--
