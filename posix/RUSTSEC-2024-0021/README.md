# RUSTSEC-2024-0021 — rust/eyre | downcast wrong-type drop (CWE-843)

| | |
|---|---|
| **Library** | `eyre` |
| **Aliases** | GHSA-4v52-7q2x-v4xj |
| **CWE** | CWE-843 |
| **Affected / fixed** | `>= 0.6.11` … fixed in `0.6.12` |
| **Rule** | [`RUSTSEC-2024-0021.vh`](./RUSTSEC-2024-0021.vh) |

## Summary

In `eyre` versions 0.6.9 through 0.6.11, the `Report::downcast` function is unsound due to a
type-parameter mistake in the internal helper `context_drop_rest`. When a user calls
`report.downcast::<T>()` on a `Report` that was created via `wrap_err` (i.e., a `ContextError<D,
E>` where `D` is a message type and `E` is the underlying error), the helper responsible for
dropping the non-downcasted half of the struct was parameterised with the wrong type. Specifically,
when downcasting to `D`, the code marked the `msg` field as `ManuallyDrop` using `E`'s type
instead of `D`'s; and when downcasting to `E`, it used `E` for the `msg` field instead of `D`.
This is a **type confusion** bug (CWE-843): the drop glue for the remaining field ran the wrong
type's `Drop` implementation, or ran `Drop` at an incorrect memory offset when `D` and `E` differ
in size. The impact is **memory corruption** (potential use-after-free, heap corruption, segfault)
or resource leaks when `D` or `E` have non-trivial `Drop` implementations. The bug was introduced
in 0.6.9 and fixed in 0.6.12.

## Detection discriminator

This engine has no library-version gate, so the rule proves the **vulnerable code structure** and is silent on the patched build.

Anchor scope: `eyre::error::context_drop_rest` (present in BOTH builds → rule only
considers a real `wrap_err`-wrapped `Report::downcast` path).

Fix-signal symbol (present ONLY in patched 0.6.12):
`project:functions({matching = "ContextError.*ManuallyDrop", kind = "symbol"})`

The 0.6.12 fix (commit 770ac3fa, PR #143) corrects the two cast sites in
`context_drop_rest<D,E>` from the wrong type param to the true layout
`ContextError<ManuallyDrop<D>, E>` / `ContextError<D, ManuallyDrop<E>>`. That
corrected cast forces the compiler to emit drop glue monomorphized over a
`ManuallyDrop`-wrapped `ContextError`, e.g. (demangled):
  `core::ptr::drop_in_place::<eyre::error::ContextError<eyre_downcast_poc::MyMsg, core::mem::manually_drop::ManuallyDrop<eyre_downcast_poc::MyError>>>`

The vulnerable 0.6.11 build emits NO `ManuallyDrop`-bearing `ContextError` symbol at
all (its wrong-type casts never name that shape). Confirmed live via a probe rule:
  vuln 0.6.11:    probe hits = "cdr,dip"            (NO ManuallyDrop / ctx_md)
  patched 0.6.12: probe hits = "cdr,dip,MD,ctx_md"  (ManuallyDrop present)

Rule logic (telnetd model): scope context_drop_rest; if the
`ContextError.*ManuallyDrop` fix-signal symbol exists → patched → return nil (silent);
else → vulnerable → fire result:high (CWE-843).

## Reproducing the test binaries

Minimal consumer that calls `Report::downcast` and exercises `context_drop_rest` with differing
`D` and `E` types (non-trivial drop, different sizes):

**`Cargo.toml`:**
```toml
[package]
name = "eyre-downcast-poc"
version = "0.1.0"
edition = "2021"

[dependencies]
# Pin vulnerable version:
eyre = "=0.6.11"
# For fixed version, change to:
# eyre = "=0.6.12"
```

**`src/main.rs`:**
```rust
use eyre::{Report, WrapErr};

// D: message type — use a type with a non-trivial drop and different size from E
#[derive(Debug)]
struct MyMsg(String);  // size = 24 bytes (String)

impl std::fmt::Display for MyMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// E: underlying error type — small, different layout from D
#[derive(Debug)]
struct MyError(u8);  // size = 1 byte

impl std::fmt::Display for MyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MyError({})", self.0)
    }
}

impl std::error::Error for MyError {}

fn main() {
    // eyre::set_hook is required; use the default handler
    let _ = eyre::set_hook(Box::new(eyre::DefaultHandler::default_with));

    // Build a wrapped error: ContextError<MyMsg, MyError>
    let base_err: Result<(), MyError> = Err(MyError(42));
    let wrapped: Report = base_err
        .wrap_err(MyMsg("something went wrong".to_string()))
        .unwrap_err();

    // Trigger Report::downcast -> context_drop_rest<MyMsg, MyError>
    // On 0.6.11: context_drop_rest casts to wrong type -> wrong drop -> memory corruption
    // On 0.6.12: fixed cast -> correct drop
    match wrapped.downcast::<MyError>() {
        Ok(e) => println!("downcasted: MyError({})", e.0),
        Err(report) => println!("could not downcast: {}", report),
    }
}
```

**API notes:**
- The public API (`WrapErr`, `Report::downcast`) is identical between 0.6.11 and 0.6.12 — the same
  `src/main.rs` compiles and runs on both. The crash/corruption only manifests on 0.6.11 at runtime
  when `D` and `E` have different sizes or non-trivial `Drop` impls.
- `WrapErr` is the trait providing `.wrap_err()`. It is re-exported from `eyre`. No API changes
  between the two versions.
- The `eyre::set_hook` call is required when the `auto-install` feature is not enabled (the
  default in 0.6.11). In 0.6.12 this is unchanged.
- This is pure Rust with no platform-specific dependencies — builds to x86_64-unknown-linux-gnu
  ELF without modification.

Committed sample artifacts:

```
RUSTSEC-2024-0021/Cargo.lock
RUSTSEC-2024-0021/Cargo.toml
RUSTSEC-2024-0021/eyre-downcast-poc.vuln.elf
RUSTSEC-2024-0021/patched/Cargo.lock
RUSTSEC-2024-0021/patched/Cargo.toml
RUSTSEC-2024-0021/patched/eyre-downcast-poc.patched.elf
RUSTSEC-2024-0021/src/main.rs
```

## Upstream fix

Patch: https://github.com/eyre-rs/eyre/commit/770ac3fa1435eae3b166a4b072053360e38a0575

Merge commit: `770ac3fa1435eae3b166a4b072053360e38a0575`  
PR: https://github.com/eyre-rs/eyre/pull/143  
Source file changed: `eyre/src/error.rs` (+2 / -2)

```diff
@@ -698,13 +698,13 @@ where
     // ptr::read to take ownership of that value.
     if TypeId::of::<D>() == target {
         unsafe {
-            e.cast::<ErrorImpl<ContextError<ManuallyDrop<E>, E>>>()
+            e.cast::<ErrorImpl<ContextError<ManuallyDrop<D>, E>>>()
                 .into_box()
         };
     } else {
         debug_assert_eq!(TypeId::of::<E>(), target);
         unsafe {
-            e.cast::<ErrorImpl<ContextError<E, ManuallyDrop<E>>>>()
+            e.cast::<ErrorImpl<ContextError<D, ManuallyDrop<E>>>>()
                 .into_box()
         };
     }
```

**What the fix changed:**

`context_drop_rest<D, E>` is called after `ptr::read` has already extracted one field's value
(transferring its ownership to the caller). The remaining `ErrorImpl` box must be dropped, but the
already-moved-out field must NOT be dropped again — so it is wrapped in `ManuallyDrop<_>` at the
cast site to suppress its destructor.

The bug: in the `TypeId::of::<D>() == target` branch (we downcasted to `D`, so `msg` was moved
out), the cast was `ErrorImpl<ContextError<ManuallyDrop<E>, E>>` — i.e., it marked the first field
(`msg: D`) as `ManuallyDrop` using `E`'s type instead of `D`'s. This means (a) the layout of the
`ManuallyDrop` wrapper may not match the actual `D` field if `D` and `E` differ in size or
alignment, and (b) the second field `error: E` would be dropped using `E`'s destructor but at a
memory offset computed for a `ManuallyDrop<E>` prefix instead of a `ManuallyDrop<D>` prefix —
wrong offset if `size_of::<D>() != size_of::<E>()`.

Symmetrically in the `else` branch (we downcasted to `E`, so `error` was moved out), the cast was
`ErrorImpl<ContextError<E, ManuallyDrop<E>>>` — wrapping the second field (`error: E`) in
`ManuallyDrop<E>` is correct, but using `E` for the first field (`msg: D`) is wrong; it should be
`D`.

The fix simply corrects both type arguments: `ManuallyDrop<D>` when `D` was moved out, and `D`
(not `E`) as the first field when `E` was moved out. Both branches now correctly reflect the true
memory layout `ContextError<D, E>` with the moved-out half wrapped in `ManuallyDrop`.

## Verification

`RUSTSEC-2024-0021 | created | rust/eyre | downcast wrong-type drop (CWE-843). discriminator=fix-added ManuallyDrop ContextError drop-glue symbol. vuln FIRED, patched SILENT (verified via GHSA — engine drops RUSTSEC ids).`

## Provenance

Generated by the multi-agent CVE-rule pipeline (research → build both versions → binary-observable discriminator → self-verify → independent GATE). Build recipe, discriminator, and scan results above are drawn from the pipeline's research dossier and signature notes for this CVE.

References:

- RUSTSEC: https://rustsec.org/advisories/RUSTSEC-2024-0021.html
- GHSA: https://github.com/advisories/GHSA-4v52-7q2x-v4xj
