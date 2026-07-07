author = "prockallsyms"
name = "RUSTSEC-2025-0002"
platform = "posix-binary"
architecture = "*:*:*"
signatures = {project = "fast-float2", from = "0.2.0", to = "0.2.2"}

scopes = {
  scope:functions{
    target = {matching = "parse_number", kind = "symbol"},
    using = {},
    with = check
  }
}

-- RUSTSEC-2025-0002 / GHSA-jqcp-xc3v-f446: fast-float2 < 0.2.2 out-of-bounds
-- read / memory exposure (CWE-125). The internal cursor method
-- `AsciiStr::first` (src/common.rs) returned `u8` via an UNCONDITIONAL
-- `unsafe { *self.ptr }` with no non-empty check; callers
-- (`parse_number`, `parse_scientific`, `try_parse_19digits`, the unsafe
-- `ByteSlice::get_first`/`get_at` helpers) relied only on `debug_assert!`
-- guards that are NO-OPs in release builds. On an empty / exhausted-by-sign
-- input the parser dereferences one byte past the slice, leaking adjacent
-- heap/stack memory or crashing. An attacker who controls the float string
-- passed to `fast_float2::parse::<f64,_>` / `parse_partial` can trigger it.
--
-- Fix (v0.2.2, commit 31d1abf7c6 "Remove unsafety for the v0.2.2 release"):
--   * `AsciiStr::first` -> `Option<u8>` with `if self.is_empty() { None }`;
--     the unchecked form renamed `unsafe fn first_unchecked`.
--   * `ByteSlice::get_first`/`get_at` unsafe helpers REMOVED.
--   * `number::parse_number` had its `debug_assert!(!s.is_empty())`
--     PROMOTED to a real runtime guard `if s.is_empty() { return None; }`.
--
-- Binary discriminator (telnetd model; confirmed by objdump diff + engine
-- search_code on both monomorphized `number::parse_number` builds at
-- opt-level=1). `parse_number` is a standalone symbol in BOTH builds, so the
-- rule only ever considers a real fast-float2 parser. The promoted empty-guard
-- is observable at the function prologue:
--   * Vulnerable (0.2.1): prologue `movq %rdi,%rax` is immediately followed by
--     `movzbl (%rsi),%ecx` -- the first byte is loaded with NO preceding length
--     check (the debug_assert compiled to nothing).
--   * Patched (0.2.2): prologue `movq %rdi,%rax` is followed by
--     `testq %rdx,%rdx ; je <return None>` -- the new `if s.is_empty()` runtime
--     guard tests the slice length BEFORE any load.
-- The contiguous byte sequence
--   48 89 f8  48 85 d2  0f 84            (movq %rdi,%rax ; testq %rdx,%rdx ; je)
-- is PRESENT exactly once in the patched binary (the parse_number empty-guard)
-- and ABSENT from the vulnerable build (verified: 1 vs 0 occurrences across the
-- whole ELF). Present-in-patched fix-signature: if the guard byte pattern is
-- found, the build carries the 0.2.2 empty-check (patched) -> return nil
-- (silent). If absent, `parse_number` loads the first byte with no length guard
-- -- the < 0.2.2 unchecked-read structure -> vulnerable -> fire.

function check(project, context)
  -- project:search_code can RAISE a Lua error on some ELFs; an unhandled error aborts
  -- the whole scan. Wrap in pcall so a search failure degrades to "pattern not present"
  -- for THIS rule only and never tears the batch down.
  local function safe_search(hex)
    local ok, res = pcall(function() return project:search_code(hex) end)
    return ok and res
  end

  -- The 0.2.2 fix promotes `parse_number`'s debug_assert to a real
  -- `if s.is_empty() { return None }` guard, compiled as
  -- `movq %rdi,%rax ; testq %rdx,%rdx ; je`. Its presence means patched.
  if safe_search("4889f84885d20f84") then
    return
  end

  return result:high{
    name = "RUSTSEC-2025-0002",
    description = "fast-float2 < 0.2.2: the float parser's internal cursor `AsciiStr::first` dereferences `self.ptr` (`unsafe { *self.ptr }`) with no non-empty check, guarded only by release-stripped `debug_assert!`s. `number::parse_number` (reached from `fast_float2::parse::<f64,_>` / `parse_partial`) loads the first input byte with no length guard (the 0.2.2 `if s.is_empty() { return None }` empty-check prologue `testq %rdx,%rdx ; je` is absent in this build), so a crafted empty / sign-exhausted input drives a one-byte out-of-bounds read past the slice, exposing adjacent heap/stack memory or crashing (CWE-125, memory exposure).",
    provenance = {
      kind = "posix.ELF",
      linkage = "project",
      vendor = "Alexhuszagh",
      product = "fast-float2",
      license = "MIT OR Apache-2.0",
      affected_versions = {"<0.2.2"}
    },
    cwes = {"CWE-125"},
    advisory = "https://rustsec.org/advisories/RUSTSEC-2025-0002.html",
    patch = "https://github.com/Alexhuszagh/fast-float-rust/commit/31d1abf7c6",
    identifiers = {"RUSTSEC-2025-0002", "GHSA-jqcp-xc3v-f446"},
    references = {
      ["RUSTSEC"] = "https://rustsec.org/advisories/RUSTSEC-2025-0002.html",
      ["GHSA"] = "https://github.com/advisories/GHSA-jqcp-xc3v-f446"
    },
    evidence = {
      functions = {
        [context.address] = {
          annotate:at{
            location = context.address,
            message = "`number::parse_number` loads the first input byte with no empty-length guard (the 0.2.2 `if s.is_empty() { return None }` prologue `testq %rdx,%rdx ; je` is absent); `AsciiStr::first`'s unchecked `unsafe { *self.ptr }` reads one byte past the slice on empty / sign-exhausted input (OOB read / memory exposure)."
          }
        }
      }
    }
  }
end

--
-- vim: ft=lua
--
