author = "prockallsyms"
name = "RUSTSEC-2023-0024"
platform = "posix-binary"
architecture = "*:*:*"
signatures = {project = "openssl", from = "0.9.7", to = "0.10.48"}

-- RUSTSEC-2023-0024 / GHSA-6hcf-g6gr-hhcr: the rust `openssl` crate before
-- 0.10.48 (sfackler/rust-openssl) has a NULL pointer dereference (CWE-476) in
-- `X509Extension::new` and `X509Extension::new_nid`. When the caller passes
-- `context: None`, the code did `context.map_or(ptr::null_mut(), X509v3Context::as_ptr)`
-- and forwarded a raw NULL `ctx` pointer to the OpenSSL FFI `X509V3_EXT_nconf` /
-- `X509V3_EXT_nconf_nid`. Several extension types (e.g. crlDistributionPoints,
-- certificatePolicies) unconditionally dereference the context pointer, so a safe
-- Rust caller could crash the process (denial of service) with no unsafe code.
--
-- Upstream fix (PR #1854, commit 78aa9aa, released in 0.10.48): the `None` arm now
-- allocates a stack `X509V3_CTX`, zeroes it (`let mut ctx = mem::zeroed()` ->
-- compiled as a `xorps`/`movaps` stack memset of the ~0x40-byte CTX) and calls
-- `ffi::X509V3_set_ctx(&mut ctx, null, null, null, null, 0)` to initialise it,
-- then passes `&mut ctx` (a valid pointer) instead of NULL. Both `X509Extension::new`
-- and `X509Extension::new_nid` were changed identically.
--
-- WHY NOT whole-binary symbol presence of X509V3_set_ctx (prior, OVERFIT, rejected):
-- that approach only "worked" because the minimal consumer had no other caller of
-- X509V3_set_ctx, so the linker dead-code-eliminated it from the vuln build. On a
-- real binary that also links `x509v3_context` (used by X509Builder /
-- SslContextBuilder / X509ReqBuilder), X509V3_set_ctx is present in BOTH versions
-- and the rule would FALSE-SILENT on the vulnerable build. NOT FAITHFUL.
--
-- WHY NOT has_call/context:calls for X509V3_set_ctx: every FFI call out of
-- X509Extension::new is GOT-indirect (`callq *off(%rip)` -> GOTPCREL slot), so the
-- engine does NOT resolve those into named targets (probed live; all calls in the
-- body are `call *off(%rip)`). The fix's added call is therefore not name-matchable.
--
-- FUNCTION-SCOPED engine-matchable discriminator (verified by objdump on both ELFs,
-- Rust v0 symbols matched by readable segment `X509Extension.*new`):
-- the fix's `mem::zeroed()` of the stack X509V3_CTX compiles, in BOTH changed
-- functions, to a contiguous, position-independent (fixed stack displacements, no
-- RIP-relative / GOT bytes) 23-byte run:
--     0f 57 c0          xorps  %xmm0, %xmm0
--     0f 29 44 24 60    movaps %xmm0, 0x60(%rsp)
--     0f 29 44 24 50    movaps %xmm0, 0x50(%rsp)
--     0f 29 44 24 40    movaps %xmm0, 0x40(%rsp)
--     0f 29 44 24 30    movaps %xmm0, 0x30(%rsp)
-- = `0f57c00f294424600f294424500f294424400f29442430`. This run is the X509V3_CTX
-- stack-zero that immediately precedes the new `X509V3_set_ctx(&mut ctx, null*4, 0)`
-- call (registers zeroed, GOT-indirect call) in BOTH X509Extension::new and
-- X509Extension::new_nid.
--     VULN 0.10.47:    run occurs 0 times  (no CTX is allocated/zeroed; NULL passed)
--     PATCHED 0.10.48: run occurs 2 times  (once in new at 0x17e8fb, once in
--                      new_nid at 0x17eb21 -- both inside the two fixed functions)
-- It is absent from the vuln build even though that build links the SAME vendored
-- static OpenSSL, so it is specific to this fix's codegen, not a generic sequence
-- emitted by x509v3_context or std code.
--
-- Rule model: FIX-PRESENT (telnetd / fire-when-fix-absent). The `X509Extension::new`
-- symbol exists in BOTH builds, so the symbol alone does NOT discriminate; we scope
-- to it (so the finding only arises when the vulnerable extension-builder path is
-- linked) and emit ONLY when the fix's CTX-zeroing run is ABSENT binary-wide. A
-- patched (>= 0.10.48) build contains the run and stays SILENT.

local SCOPE = "X509Extension.*new"
-- mem::zeroed() of the stack X509V3_CTX (xorps + 4x movaps), the fix's CTX init
local FIX_RUN = "0f57c00f294424600f294424500f294424400f29442430"

scopes = scope:functions{
  target = {matching = SCOPE, kind = "symbol"},
  with = check
}

function check(project, context)
  -- project:search_code can RAISE an uncaught Lua error on some ELFs; an
  -- unhandled error aborts the whole scan (zeroes every rule in the dir).
  -- pcall-guard so a failure degrades to "pattern absent" for THIS rule only and
  -- never tears the batch down. Hex MUST be contiguous (no spaces).
  local function safe_search(hex)
    local ok, res = pcall(function() return project:search_code(hex) end)
    return ok and res
  end

  -- Fix-signal: the 0.10.48 X509V3_CTX stack-zero (mem::zeroed()) that precedes the
  -- new X509V3_set_ctx initialiser, present in both fixed functions. If present
  -- anywhere in the code section, this is a patched (>= 0.10.48) build -> silent.
  if safe_search(FIX_RUN) then
    return
  end

  return result:high{
    name = "RUSTSEC-2023-0024",
    description = "rust `openssl` crate before 0.10.48: X509Extension::new and X509Extension::new_nid passed a raw NULL `ctx` pointer to the OpenSSL FFI X509V3_EXT_nconf / X509V3_EXT_nconf_nid when the caller supplied context=None (context.map_or(ptr::null_mut(), ...)). Extension types such as crlDistributionPoints and certificatePolicies unconditionally dereference the context, causing a NULL pointer dereference (CWE-476) and process crash (denial of service) reachable from safe Rust. The fix (0.10.48, commit 78aa9aa) allocates and zero-initialises a stack X509V3_CTX (mem::zeroed) and calls X509V3_set_ctx before forwarding a valid pointer. This build's X509Extension::new/new_nid lacks the fix's X509V3_CTX stack-zero run `0f57c00f294424600f294424500f294424400f29442430`, so the vulnerable NULL-ctx path is present. Upgrade openssl to >= 0.10.48.",
    provenance = {
      kind = "posix.ELF",
      linkage = "project",
      vendor = "sfackler",
      product = "openssl",
      license = "Apache-2.0",
      affected_versions = {">=0.9.7", "<0.10.48"}
    },
    cwes = {"CWE-476"},
    advisory = "https://rustsec.org/advisories/RUSTSEC-2023-0024.html",
    patch = "https://github.com/sfackler/rust-openssl/commit/78aa9aac1aafd2b0e2dabf81d77602e1b18f9d75",
    identifiers = {"RUSTSEC-2023-0024", "GHSA-6hcf-g6gr-hhcr"},
    references = {
      ["RUSTSEC"] = "https://rustsec.org/advisories/RUSTSEC-2023-0024.html",
      ["GHSA"] = "https://github.com/sfackler/rust-openssl/security/advisories/GHSA-6hcf-g6gr-hhcr"
    },
    evidence = {
      functions = {
        [context.address] = {
          annotate:prototype "fn X509Extension::new(conf: Option<&ConfRef>, context: Option<&X509v3Context>, name: &str, value: &str) -> Result<X509Extension, ErrorStack>",
          annotate:at{
            location = context.address,
            message = "X509Extension::new / new_nid forwards a raw NULL ctx pointer to X509V3_EXT_nconf when context=None; extensions that deref the context (crlDistributionPoints, certificatePolicies) crash with a NULL pointer dereference (CWE-476). The 0.10.48 fix's X509V3_CTX stack-zero run `0f57c00f294424600f294424500f294424400f29442430` (mem::zeroed before X509V3_set_ctx) is absent here. Upgrade openssl to >= 0.10.48."
          }
        }
      }
    }
  }
end

--
-- vim: ft=lua
--
