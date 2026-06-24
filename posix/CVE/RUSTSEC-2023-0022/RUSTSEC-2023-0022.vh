author = "vulhunt-pipeline"
name = "RUSTSEC-2023-0022"
platform = "posix-binary"
architecture = "*:*:*"
signatures = {project = "openssl", from = "0.9.7", to = "0.10.48"}

-- RUSTSEC-2023-0022 / GHSA-3gxf-9r58-2ghg: the rust `openssl` crate
-- (sfackler/rust-openssl) before 0.10.48 had `X509NameBuilder::build` return the
-- builder's internal `X509Name` directly (`self.0`), still in OpenSSL's lazily-
-- uninitialised "modified" state. Because `X509Name`/`X509NameRef` are marked
-- `Send + Sync` (via foreign_type_and_impl_send_sync!), a caller may legitimately
-- share that object across threads; the first read triggers OpenSSL's non-thread-safe
-- lazy recomputation of internal encoding/hash state -> a data race / UB (CWE-362).
--
-- Fix (PR #1854, commit 6ced4f305e44df7ca32e478621bf4840b122f1a3, released 0.10.48):
-- `build` now round-trips through DER --
--   X509Name::from_der(&self.0.to_der().unwrap()).unwrap()
-- which forces all lazy state to resolve (`i2d_X509_NAME`) and returns a freshly
-- parsed, fully-initialised name (`d2i_X509_NAME`) with the `modified` flag clear,
-- safe to share. The Send/Sync impls were NOT removed -- the entire fix is in the
-- runtime body of `build`.
--
-- DISCRIMINATOR -- presence/absence of the `X509NameBuilder::build` SYMBOL itself.
-- The vulnerable body is the trivial pass-through `self.0`, which the compiler
-- inlines into its caller at any opt level, so there is NO standalone
-- `<openssl::x509::X509NameBuilder>::build` symbol in a vulnerable (<0.10.48) build.
-- The patched body does real work (Vec alloc + i2d/d2i FFI round-trip + unwrap/panic
-- infra), so it is emitted as its own function symbol. Probed live with
-- project:functions{matching=..., kind="symbol"} (Rust v0; the `::build` demangled
-- form does NOT match the engine matcher -- only the mangled `...X509NameBuilder5build`
-- segment / `X509NameBuilder.*build` does, confirmed by probe):
--    VULN 0.10.47:    X509NameBuilder5build ABSENT  (build inlined)
--    PATCHED 0.10.48: X509NameBuilder5build PRESENT (DER round-trip body)
-- NOT call-presence on i2d_X509_NAME/d2i_X509_NAME: in the vendored static build both
-- FFI functions are linked (libcrypto references them internally) and the calls from
-- `build` are GOT-indirect (`call *0xNNN(%rip)`), which the engine does not resolve to
-- named targets -- so an FFI-presence or has_call check does NOT discriminate here.
--
-- Anchor: scope on `X509NameBuilder::append_entry_by_text`, which is present as its
-- own symbol in BOTH builds (so the finding anchors on a real X509NameBuilder method
-- regardless of version). It does not itself match the `.*build` discriminator regex.
--
-- Telnetd / fire-when-fix-absent: FIRE when the discriminator (the `build` function
-- symbol) is ABSENT (build was inlined as `self.0` -> < 0.10.48); stay SILENT (return
-- nil) when the `build` symbol is PRESENT (the DER round-trip fix is compiled in ->
-- >= 0.10.48).

scopes = scope:functions{
  target = {matching = "X509NameBuilder.*append_entry_by_text", kind = "symbol"},
  with = check
}

function check(project, context)
  -- single-form project:functions; nil when no function with that symbol exists.
  local function has_fn(sym)
    local f = project:functions{matching = sym, kind = "symbol"}
    return f ~= nil
  end

  -- The patched (>= 0.10.48) `build` has a non-trivial DER round-trip body and is
  -- emitted as its own symbol; the vulnerable `self.0` body is inlined away.
  local build_emitted = has_fn("X509NameBuilder.*build")

  -- Fix present: stay silent.
  if build_emitted then
    return
  end

  return result:high{
    name = "RUSTSEC-2023-0022",
    description = "rust `openssl` crate before 0.10.48: X509NameBuilder::build returned the builder's internal X509Name directly (`self.0`) while it was still in OpenSSL's lazily-uninitialised \"modified\" state. X509Name/X509NameRef are marked Send + Sync, so a consumer may share the returned name across threads; the first read then triggers OpenSSL's non-thread-safe lazy recomputation of internal encoding/hash state -> a data race / undefined behaviour (CWE-362). The fix (0.10.48, commit 6ced4f30) makes build() round-trip through DER (X509Name::from_der(&self.0.to_der().unwrap()).unwrap()), forcing all lazy state to resolve and returning a freshly parsed, fully-initialised name safe to share. In this build the vulnerable trivial build() body was inlined (the patched DER round-trip build symbol is absent), so the unsound path is present. Upgrade openssl to >= 0.10.48.",
    provenance = {
      kind = "posix.ELF",
      linkage = "project",
      vendor = "sfackler",
      product = "openssl",
      license = "Apache-2.0",
      affected_versions = {">=0.9.7", "<0.10.48"}
    },
    cwes = {"CWE-362"},
    advisory = "https://rustsec.org/advisories/RUSTSEC-2023-0022.html",
    patch = "https://github.com/sfackler/rust-openssl/commit/6ced4f305e44df7ca32e478621bf4840b122f1a3",
    identifiers = {"RUSTSEC-2023-0022", "GHSA-3gxf-9r58-2ghg"},
    references = {
      ["RUSTSEC"] = "https://rustsec.org/advisories/RUSTSEC-2023-0022.html",
      ["GHSA"] = "https://github.com/sfackler/rust-openssl/security/advisories/GHSA-3gxf-9r58-2ghg"
    },
    evidence = {
      functions = {
        [context.address] = {
          annotate:prototype "fn X509NameBuilder::build(self) -> X509Name",
          annotate:at{
            location = context.address,
            message = "X509NameBuilder::build returns the internal X509Name in OpenSSL's lazily-uninitialised \"modified\" state (the patched DER round-trip build() body is absent here, so build was inlined as `self.0` -> openssl < 0.10.48). Sharing the result across threads (X509Name is Send + Sync) triggers a non-thread-safe lazy recompute inside OpenSSL -> data race (CWE-362). Upgrade openssl to >= 0.10.48."
          }
        }
      }
    }
  }
end

--
-- vim: ft=lua
--
