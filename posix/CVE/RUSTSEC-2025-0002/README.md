# RUSTSEC-2025-0002 — rust/fast-float2 | AsciiStr OOB read

| | |
|---|---|
| **Library** | `fast-float2` |
| **Aliases** | GHSA-jqcp-xc3v-f446 |
| **CWE** | CWE-125 |
| **Affected / fixed** | `>= 0.2.0` … fixed in `0.2.2` |
| **Rule** | [`RUSTSEC-2025-0002.vh`](./RUSTSEC-2025-0002.vh) |

## Summary

`fast-float2` (crate `fast-float2`, versions < 0.2.2) exposes a memory-safety bug (CWE-125: Out-of-Bounds Read) in `AsciiStr::first`, an internal cursor method used throughout the float parser. The method unconditionally dereferences `self.ptr` via `unsafe { *self.ptr }` without first checking that the buffer is non-empty. Several callers (`parse_number`, `parse_scientific`, `try_parse_19digits`) invoke `first()` or related helpers (`first_either`, `first_is`) relying only on `debug_assert!` guards — which are stripped in release builds — or on guards that are absent in certain code paths (e.g. `parse_scientific` advances the pointer past `e`/`E` and then calls `first_either` with no length check). Additionally, `ByteSlice::get_first`/`get_at` use `get_unchecked` and `eq_ignore_case` contains `debug_assert!(len >= u.len())` without an actual runtime guard. On an empty or exhausted-by-sign input the parser reads memory past the slice, exposing adjacent heap or stack contents. Impact: an attacker who controls parser input (e.g. network-supplied float strings) can leak memory contents or cause a segmentation fault.

## Detection discriminator

This engine has no library-version gate, so the rule proves the **vulnerable code structure** and is silent on the patched build.

The 0.2.2 fix promotes `parse_number`'s `debug_assert!(!s.is_empty())` to a real runtime
`if s.is_empty() { return None; }`. Observable at the function prologue:
- VULN 0.2.1 prologue:  `48 89 f8` movq %rdi,%rax ; `0f b6 0e` movzbl (%rsi),%ecx
  -> first byte loaded immediately, NO length test (debug_assert compiled to nothing).
- PATCHED 0.2.2 prologue: `48 89 f8` movq %rdi,%rax ; `48 85 d2` testq %rdx,%rdx ; `0f 84 ..` je <None>
  -> the new is_empty() guard tests slice length BEFORE any load.

Contiguous, position-independent byte signature (only the je's 4-byte displacement follows, excluded):
  search_code("4889f84885d20f84")   ( movq %rdi,%rax ; testq %rdx,%rdx ; je )
Raw-byte verification across whole ELF: PATCHED count=1 (at vaddr 0x1c7b0 = parse_number), VULN count=0.

## Reproducing the test binaries

Consumer `Cargo.toml` (same dependency line works for both versions; change `0.2.1` ↔ `0.2.2`):

```toml
[package]
name = "ff2-consumer"
version = "0.1.0"
edition = "2021"

[dependencies]
fast-float2 = "=0.2.1"   # change to "=0.2.2" for patched build
```

Minimal consumer `src/main.rs`:

```rust
fn main() {
    // Empty input: in v0.2.1 this triggers the unchecked first() dereference
    // inside parse_number (called from parse_float via parse_number after
    // parse_float's is_empty guard... but parse_scientific calls first_either
    // without a guard after step()).  A single sign char followed by nothing
    // also exercises the path: parse_number calls s.first() == b'-' on s that
    // may be empty after step.
    //
    // Triggering input for OOB: a lone sign char (step() advances past it,
    // then code calls first() / first_either() on the now-empty AsciiStr).
    let inputs: &[&[u8]] = &[
        b"",          // empty: exercises parse_float empty guard on v0.2.1
        b"-",         // sign + nothing: parse_number calls step() then first()
        b"1e",        // parse_scientific calls step() past 'e' then first_either on empty
        b"1e-",       // parse_scientific steps past 'e', '-', then calls check_first_digit
    ];
    for &input in inputs {
        let result = fast_float2::parse::<f64, _>(input);
        println!("{:?} -> {:?}", input, result);
    }
}
```

**API compatibility between versions:** The public API `fast_float2::parse` and `fast_float2::parse_partial` are identical in signature and semantics between 0.2.1 and 0.2.2. The only internal change is that `AsciiStr::first()` changed return type from `u8` to `Option<u8>`, but this type is not exposed in the public API. No changes to `Cargo.toml` consumer syntax are needed; simply pin to `=0.2.1` or `=0.2.2`.

Cross-compile to x86-64 Linux ELF from macOS:
```
cargo build --release --target x86_64-unknown-linux-musl
```

The crate has no platform-specific dependencies; it is `no_std`-capable and pure Rust. It builds cleanly on x86-64 Linux ELF.

Committed sample artifacts:

```
RUSTSEC-2025-0002/patched-build/Cargo.lock
RUSTSEC-2025-0002/patched-build/Cargo.toml
RUSTSEC-2025-0002/patched/rustsec-2025-0002-patched.elf
RUSTSEC-2025-0002/rustsec-2025-0002-vuln.elf
RUSTSEC-2025-0002/vuln-build/Cargo.lock
RUSTSEC-2025-0002/vuln-build/Cargo.toml
```

## Upstream fix

Patch: https://github.com/Alexhuszagh/fast-float-rust/commit/31d1abf7c6

Repository: `https://github.com/Alexhuszagh/fast-float-rust`
Fix commit: `31d1abf7c6` ("Remove unsafety for the v0.2.2 release.") bumps the version; the actual source changes are in the preceding commits on the same branch, all included in the `v0.2.1..v0.2.2` tag range.

Key hunk from `src/common.rs` (v0.2.1 → v0.2.2):

```diff
-    #[inline]
-    pub fn first(&self) -> u8 {
-        unsafe { *self.ptr }
-    }
-
-    #[inline]
-    pub fn first_is(&self, c: u8) -> bool {
-        self.first() == c
-    }
-
-    #[inline]
-    pub fn first_either(&self, c1: u8, c2: u8) -> bool {
-        let c = self.first();
-        c == c1 || c == c2
-    }
-
-    #[inline]
-    pub fn check_first(&self, c: u8) -> bool {
-        !self.is_empty() && self.first() == c
-    }
-
-    #[inline]
-    pub fn check_first_either(&self, c1: u8, c2: u8) -> bool {
-        !self.is_empty() && (self.first() == c1 || self.first() == c2)
-    }
-
-    #[inline]
-    pub fn check_first_digit(&self) -> bool {
-        !self.is_empty() && self.first().is_ascii_digit()
-    }
+    /// # Safety
+    ///
+    /// Safe if `!self.is_empty()`
+    #[inline]
+    pub unsafe fn first_unchecked(&self) -> u8 {
+        debug_assert!(!self.is_empty(), "attempting to get first value of empty buffer.");
+        unsafe { *self.ptr }
+    }
+
+    #[inline]
+    pub fn first(&self) -> Option<u8> {
+        if self.is_empty() {
+            None
+        } else {
+            // SAFETY: safe since `!self.is_empty()`
+            Some(unsafe { self.first_unchecked() })
+        }
+    }
+
+    #[inline]
+    pub fn first_is(&self, c: u8) -> bool {
+        self.first() == Some(c)
+    }
+
+    #[inline]
+    pub fn first_is2(&self, c1: u8, c2: u8) -> bool {
+        self.first().map_or(false, |c| c == c1 || c == c2)
+    }
+
+    #[inline]
+    pub fn first_is_digit(&self) -> bool {
+        self.first().map_or(false, |c| c.is_ascii_digit())
+    }
```

Additional fix in `src/number.rs` — `parse_number` now has a real early-return guard instead of only a `debug_assert`:

```diff
 pub fn parse_number(s: &[u8]) -> Option<(Number, usize)> {
-    debug_assert!(!s.is_empty());
+    if s.is_empty() {
+        return None;
+    }
```

And the sign-handling rewritten to use the new checked `step_if` so `first()` is never called after step:

```diff
-    if s.first() == b'-' {
+    if s.step_if(b'-') {
         negative = true;
-        if s.step().is_empty() {
+        if s.is_empty() {
             return None;
         }
-    } else if s.first() == b'+' && s.step().is_empty() {
+    } else if s.step_if(b'

*(diff truncated — see upstream patch)*

## Verification

`RUSTSEC-2025-0002 | created | rust/fast-float2 | AsciiStr OOB read. discriminator=byte-pattern of added is_empty guard in parse_number. vuln FIRED, patched SILENT (via GHSA). [byte-pattern codegen-specific]`

## Provenance

Generated by the multi-agent CVE-rule pipeline (research → build both versions → binary-observable discriminator → self-verify → independent GATE). Build recipe, discriminator, and scan results above are drawn from the pipeline's research dossier and signature notes for this CVE.

References:

- RUSTSEC: https://rustsec.org/advisories/RUSTSEC-2025-0002.html
- GHSA: https://github.com/advisories/GHSA-jqcp-xc3v-f446
