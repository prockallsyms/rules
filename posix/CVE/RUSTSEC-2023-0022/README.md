# RUSTSEC-2023-0022 — The `openssl` crate (Rust bindings for libssl/libcrypto) exposed `X509NameBuilder::build` returning an `X509Name` that was unsound to use across threads

| | |
|---|---|
| **Library** | `openssl` |
| **Aliases** | GHSA-3gxf-9r58-2ghg |
| **CWE** | CWE-362 |
| **Affected / fixed** | `>= 0.9.7` … fixed in `0.10.48` |
| **Rule** | [`RUSTSEC-2023-0022.vh`](./RUSTSEC-2023-0022.vh) |

## Summary

The `openssl` crate (Rust bindings for libssl/libcrypto) exposed `X509NameBuilder::build` returning an `X509Name` that was unsound to use across threads. OpenSSL's `X509_NAME` C structure has an internal `modified` flag that causes deferred lazy recomputation of internal state (encoding cache, hash) the first time certain read operations are performed. Because `X509Name` and `X509NameRef` were both marked `Send + Sync` via the `foreign_type_and_impl_send_sync!` macro, a caller could legitimately share the returned object across threads, triggering a data race inside OpenSSL's non-thread-safe lazy-computation path. The bug is CWE-362 (Concurrent Execution Using Shared Resource with Improper Synchronization). Impact: data race / undefined behaviour in multi-threaded consumers using `X509Name` objects freshly built by `X509NameBuilder::build`. Reported by David Benjamin (Google), fixed in openssl 0.10.48.

Aliases: GHSA-3gxf-9r58-2ghg.

## Detection discriminator

This engine has no library-version gate, so the rule proves the **vulnerable code structure** and is silent on the patched build.

PRESENCE of the `X509NameBuilder::build` FUNCTION SYMBOL.

- The vulnerable body (`self.0`) is a trivial move/return that the compiler inlines into
  the caller at all opt levels → there is NO standalone `X509NameBuilder::build` symbol in
  a < 0.10.48 build.
- The patched body does real work (Vec alloc + i2d/d2i FFI DER round-trip + unwrap/panic
  infra) → it is emitted as its own function symbol.

Confirmed live via `nm` and via engine probe `project:functions{matching=..., kind="symbol"}`:

| symbol matcher                       | VULN 0.10.47 | PATCHED 0.10.48 |
|--------------------------------------|--------------|-----------------|
| `X509NameBuilder.*append_entry_by_text` (anchor) | PRESENT | PRESENT |
| `X509NameBuilder.*build` (discriminator)         | ABSENT  | PRESENT |

Matcher form note (Rust v0): the demangled `X509NameBuilder::build` matcher matched NOTHING
in either build; the mangled-segment form `X509NameBuilder.*build` / `X509NameBuilder5build`
matched (false in vuln, true in patched). Probe results:
  VULN:    buildColonColon=false build5=false
  PATCHED: buildColonColon=false build5=true

## Reproducing the test binaries

Minimal consumer that exercises the vulnerable path:

```toml
# Cargo.toml
[dependencies]
openssl = "=0.10.47"   # pin_vulnerable; change to "=0.10.48" for patched
```

```rust
// src/main.rs
use openssl::x509::X509NameBuilder;

fn main() {
    let mut builder = X509NameBuilder::new().unwrap();
    builder.append_entry_by_text("CN", "example.com").unwrap();
    let name = builder.build();  // <-- this is the vulnerable/fixed call site
    // In the vulnerable version, `name` is in "modified" state.
    // Sending it to another thread and calling e.g. name.to_der() races.
    println!("{:?}", name);
}
```

Build requirements: `openssl-sys` requires libssl/libcrypto headers at compile time and a linked libssl at link time. For Linux ELF cross-compilation:
- Install `libssl-dev` (Debian/Ubuntu) or equivalent
- Set `OPENSSL_DIR` or use the `openssl` crate's `vendored` feature:
  ```toml
  openssl = { version = "=0.10.47", features = ["vendored"] }
  ```
  The `vendored` feature bundles OpenSSL source and builds it statically, removing the need for a system OpenSSL install. The same `features = ["vendored"]` line works at both `0.10.47` and `0.10.48` — no API differences between the two versions from the consumer's perspective.

Target: `x86_64-unknown-linux-gnu` (produces ELF — compatible with VulHunt's posix loader).

Committed sample artifacts:

```
RUSTSEC-2023-0022/Cargo.lock
RUSTSEC-2023-0022/Cargo.toml
RUSTSEC-2023-0022/patched/Cargo.lock
RUSTSEC-2023-0022/patched/Cargo.toml
RUSTSEC-2023-0022/patched/rustsec_2023_0022_patched.elf
RUSTSEC-2023-0022/rustsec_2023_0022_vuln.elf
RUSTSEC-2023-0022/src/main.rs
```

## Upstream fix

Patch: https://github.com/sfackler/rust-openssl/commit/6ced4f305e44df7ca32e478621bf4840b122f1a3

Commit: `6ced4f305e44df7ca32e478621bf4840b122f1a3`
PR: https://github.com/sfackler/rust-openssl/pull/1854
File: `openssl/src/x509/mod.rs`

```diff
@@ -1045,7 +1045,10 @@ impl X509NameBuilder {
 
     /// Return an `X509Name`.
     pub fn build(self) -> X509Name {
-        self.0
+        // Round-trip through bytes because OpenSSL is not const correct and
+        // names in a "modified" state compute various things lazily. This can
+        // lead to data-races because OpenSSL doesn't have locks or anything.
+        X509Name::from_der(&self.0.to_der().unwrap()).unwrap()
     }
 }
```

**What the fix changed:** The single-line body `self.0` (returning the builder's internal `X509Name` directly, still in the lazily-uninitialized "modified" state) was replaced with a DER round-trip: `self.0.to_der()` serialises the name via `i2d_X509_NAME` (which forces OpenSSL to resolve all lazy state into canonical bytes), then `X509Name::from_der(…)` deserialises a fresh `X509_NAME` object via `d2i_X509_NAME` that is in a clean, fully-initialised state with the `modified` flag clear. The returned object is therefore safe to share across threads.

Critically, the `Send + Sync` marker impls for `X509Name` / `X509NameRef` were NOT removed; they remain (via the `foreign_type_and_impl_send_sync!` macro) in both the vulnerable and patched versions. The fix is entirely in the runtime body of `build`.

## Provenance

Generated by the multi-agent CVE-rule pipeline (research → build both versions → binary-observable discriminator → self-verify → independent GATE). Build recipe, discriminator, and scan results above are drawn from the pipeline's research dossier and signature notes for this CVE.

References:

- RUSTSEC: https://rustsec.org/advisories/RUSTSEC-2023-0022.html
- GHSA: https://github.com/sfackler/rust-openssl/security/advisories/GHSA-3gxf-9r58-2ghg
