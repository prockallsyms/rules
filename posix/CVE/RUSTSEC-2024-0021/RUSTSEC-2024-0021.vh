author = "prockallsyms"
name = "RUSTSEC-2024-0021"
platform = "posix-binary"
architecture = "*:*:*"
signatures = {project = "eyre", from = "0.6.11", to = "0.6.12"}

scopes = {
  scope:functions{
    target = {matching = "context_drop_rest", kind = "symbol"},
    using = {},
    with = check
  }
}

-- RUSTSEC-2024-0021 / GHSA-4v52-7q2x-v4xj: eyre >=0.6.9, <0.6.12
-- `Report::downcast` type confusion (CWE-843) -> memory corruption.
--
-- A `Report` produced via `wrap_err`/`WrapErr` is internally a
-- `ContextError<D, E>` (D = the context message type, E = the wrapped error).
-- `Report::downcast::<T>()` reads out the requested half (D or E) with
-- `ptr::read` (transferring ownership to the caller) and then calls the vtable
-- function `object_drop_rest` -> `eyre::error::context_drop_rest::<D, E>` to drop
-- the remaining `ErrorImpl` box. The already-moved-out field must be suppressed
-- from that drop by wrapping it in `ManuallyDrop<_>` at the cast site.
--
-- The bug (eyre/src/error.rs, introduced 0.6.9): both cast sites used the WRONG
-- type parameter --
--   downcasted-to-D branch:  cast to ErrorImpl<ContextError<ManuallyDrop<E>, E>>
--   downcasted-to-E branch:  cast to ErrorImpl<ContextError<E, ManuallyDrop<E>>>
-- i.e. `E` where `D` was required. When `D` and `E` differ in size/alignment or
-- in their `Drop` glue, the remaining field is then dropped with the wrong type
-- and/or at the wrong memory offset -- a type confusion that drops `E` as if it
-- were `D` (or reads at a layout computed for the wrong `ManuallyDrop` prefix),
-- causing use-after-free / heap corruption / segfault.
--
-- Fix (commit 770ac3fa1435eae3b166a4b072053360e38a0575, PR eyre-rs/eyre#143,
-- v0.6.12): the two cast sites are corrected to the true layout --
--   downcasted-to-D branch:  ErrorImpl<ContextError<ManuallyDrop<D>, E>>
--   downcasted-to-E branch:  ErrorImpl<ContextError<D, ManuallyDrop<E>>>
-- so the moved-out half is `ManuallyDrop`-suppressed at its real position and the
-- surviving half is dropped with the correct type at the correct offset.
--
-- Discriminator (telnetd model; verified live on both real ELFs at opt-level=1,
-- symbols retained; v0 `_R...` symbols are matched DEMANGLED). The corrected casts
-- force the compiler to monomorphize drop glue over a `ManuallyDrop`-wrapped
-- `ContextError` -- e.g.
--   core::ptr::drop_in_place::<eyre::error::ContextError<D, ManuallyDrop<E>>>
-- This `ContextError< ... ManuallyDrop ... >` drop_in_place symbol is emitted ONLY
-- by the fixed (>=0.6.12) build. The vulnerable (0.6.11) build, whose casts never
-- name a `ManuallyDrop`-wrapped `ContextError` of the right shape, emits NO
-- `ManuallyDrop`-bearing `ContextError` drop glue at all. Confirmed live:
--   vuln 0.6.11:    context_drop_rest present, ContextError<..ManuallyDrop..> = ABSENT
--   patched 0.6.12: context_drop_rest present, ContextError<..ManuallyDrop..> = PRESENT
--
-- We anchor on `eyre::error::context_drop_rest::<D, E>` (present in BOTH builds, so
-- the rule only ever considers a real `wrap_err`-wrapped `Report::downcast` path).
-- If a `ContextError< ... ManuallyDrop ... >` drop_in_place symbol exists, this
-- build carries the 0.6.12 layout fix -> patched -> return nil (silent). If it is
-- absent, the wrong-type cast still stands -> vulnerable -> fire.

function check(project, context)
  -- Fix-signal: the 0.6.12 corrected cast monomorphizes drop glue over a
  -- `ManuallyDrop`-wrapped `ContextError`. Its presence means the type-confusion
  -- in `context_drop_rest` has been fixed -> not vulnerable.
  if project:functions({matching = "ContextError.*ManuallyDrop", kind = "symbol"}) then
    return
  end

  return result:high{
    name = "RUSTSEC-2024-0021",
    description = "eyre >=0.6.9, <0.6.12: `Report::downcast` type confusion (CWE-843) -> memory corruption. A `Report` built via `wrap_err`/`WrapErr` is a `ContextError<D, E>`; `Report::downcast::<T>()` `ptr::read`s out one half (transferring ownership) then calls the vtable `object_drop_rest` -> `eyre::error::context_drop_rest::<D, E>` to drop the remaining `ErrorImpl`, suppressing the moved-out field with `ManuallyDrop<_>`. The vulnerable cast sites used the WRONG type parameter (`ManuallyDrop<E>`/`E` where `D` was required), so when `D` and `E` differ in size or `Drop` behavior the surviving field is dropped with the wrong type and/or at the wrong offset -- a type confusion causing use-after-free / heap corruption / segfault. This build's `context_drop_rest` has no `ContextError< ... ManuallyDrop ... >` drop glue, so the 0.6.12 cast-layout fix (commit 770ac3fa) is absent -- the wrong-type drop still stands.",
    provenance = {
      kind = "posix.ELF",
      linkage = "project",
      vendor = "eyre-rs",
      product = "eyre",
      license = "MIT OR Apache-2.0",
      affected_versions = {">=0.6.9, <0.6.12"}
    },
    cwes = {"CWE-843"},
    advisory = "https://rustsec.org/advisories/RUSTSEC-2024-0021.html",
    patch = "https://github.com/eyre-rs/eyre/commit/770ac3fa1435eae3b166a4b072053360e38a0575",
    identifiers = {"RUSTSEC-2024-0021", "GHSA-4v52-7q2x-v4xj"},
    references = {
      ["RUSTSEC"] = "https://rustsec.org/advisories/RUSTSEC-2024-0021.html",
      ["GHSA"] = "https://github.com/advisories/GHSA-4v52-7q2x-v4xj"
    },
    evidence = {
      functions = {
        [context.address] = {
          annotate:at{
            location = context.address,
            message = "`eyre::error::context_drop_rest::<D, E>` (the `object_drop_rest` vtable fn reached by `Report::downcast` on a `wrap_err`-wrapped report). This build emits no `ContextError< ... ManuallyDrop ... >` drop glue, so the 0.6.12 cast-layout fix is absent: the moved-out half is suppressed with the wrong type parameter and the surviving half is dropped at the wrong type/offset -- type confusion -> memory corruption."
          }
        }
      }
    }
  }
end

--
-- vim: ft=lua
--
