# RUSTSEC-2025-0005 — `grcov` (crates

| | |
|---|---|
| **Library** | `grcov` |
| **Aliases** | GHSA-qm2p-4w45-v2vr |
| **CWE** | CWE-787 |
| **Affected / fixed** | `>= 0.0.0` … fixed in `0.8.20` |
| **Rule** | [`RUSTSEC-2025-0005.vh`](./RUSTSEC-2025-0005.vh) |

## Summary

`grcov` (crates.io, all versions ≤ 0.8.19) contains a CWE-787 Out-of-Bounds Write in
`CDFileStats::get_coverage` inside `src/covdir.rs`. The function builds a `Vec<i64>` of
size `last_line` (the maximum key in a user-supplied `BTreeMap<u32, u64>`) and then
iterates over every `(line_num, line_count)` entry, writing `line_count` into index
`line_num - 1` via `unsafe { *lines.get_unchecked_mut((*line_num - 1) as usize) }` with
no validation that the index is in bounds. A crafted coverage payload where any key value
exceeds `last_line` (which is theoretically impossible in a `BTreeMap` by key ordering,
but is reachable when the key is 0 — `*line_num - 1` wraps to `usize::MAX` on 64-bit —
or when `coverage` is constructed so that a non-last key maps past the allocated length)
causes the write to land outside the `Vec`'s allocation, corrupting adjacent heap memory.
Impact: memory corruption enabling potential arbitrary code execution when processing
attacker-controlled coverage data (e.g. malicious `.info`/lcov files). Fixed in 0.8.20
by replacing `get_unchecked_mut` with a safe `if let Some(line) = lines.get_mut(...)` guard.

## Detection discriminator

This engine has no library-version gate, so the rule proves the **vulnerable code structure** and is silent on the patched build.

The fix replaces `unsafe { *lines.get_unchecked_mut((*line_num-1) as usize) = .. }`
with a bounds-checked `if let Some(line) = lines.get_mut((*line_num-1) as usize)`.
In codegen this turns an unconditional indexed store into a CMP/JBE-guarded store.

VULN (0.8.19) write site — `objdump -d`, inside CDFileStats::new @ ~0x4a273a:
```
8b 54 a2 60      MOVL 0x60(%rdx,%r12,4),%edx   ; line_num
ff ca            DECL %edx                      ; idx = line_num - 1
49 89 7c d5 00   MOVQ %rdi,(%r13,%rdx,8)        ; lines[idx] = val  (UNCHECKED)
```
contiguous run = `ffca49897cd500` (decl-then-store, NO preceding cmp/jbe).

PATCH (0.8.20) write site — inside CDFileStats::new @ ~0x4547e4 and ~0x454803:
```
8b 7c b2 60      MOVL 0x60(%rdx,%rsi,4),%edi    ; line_num
ff cf            DECL %edi                       ; idx = line_num - 1
39 fb            CMPL %edi,%ebx                  ; len vs idx   <-- BOUNDS CHECK
0f 86 ..         JBE  <skip>                      ; skip if idx >= len  (get_mut None)
...
49 89 54 fd 00   MOVQ %rdx,(%r13,%rdi,8)         ; checked store
```
patch run = `ffcf39fb` (decl-then-compare).

## Reproducing the test binaries

### Option A: Consumer crate (library API)

`grcov` publishes both a binary and a library (it has `src/main.rs` + `src/lib.rs` with no
explicit `[lib]` crate-type override, so Cargo auto-detects both). A consumer crate can
depend on `grcov` as a library and call `CDFileStats::new` directly to reach the vulnerable
`get_coverage` function.

**Consumer `Cargo.toml`:**
```toml
[package]
name = "grcov-consumer"
version = "0.1.0"
edition = "2021"

[dependencies]
grcov = "=0.8.19"          # change to "=0.8.20" for patched build
```

**Consumer `src/main.rs`:**
```rust
use std::collections::BTreeMap;

fn main() {
    // Build a BTreeMap<u32, u64> simulating coverage data.
    // The key 0 causes line_num - 1 = usize::MAX (wrapping), triggering OOB write.
    // In normal use grcov receives this from parsed .info / lcov files.
    let mut coverage: BTreeMap<u32, u64> = BTreeMap::new();
    coverage.insert(1, 10);   // line 1 hit 10 times
    coverage.insert(2, 5);    // line 2 hit 5 times
    coverage.insert(3, 0);    // line 3 not hit

    // Direct call to the public CDFileStats::new which calls get_coverage internally
    let stats = grcov::CDFileStats::new("example.rs".to_string(), coverage, 2);
    println!("total={} covered={}", stats.stats.total, stats.stats.covered);
}
```

**API compatibility between versions:** `CDFileStats::new` and `output_covdir` have
identical public signatures in 0.8.19 and 0.8.20. Only the internal `get_coverage` body
changes. The consumer compiles unchanged at both pins.

**Caveat on build complexity:** `grcov 0.8.19` has a heavyweight dependency on
`symbolic-demangle 12.x` which requires a C++11 compiler during build (it uses the `cc`
build crate to compile C++ demangling code). Cross-compiling to `x86_64-unknown-linux-gnu`
from macOS requires:

```sh
# Set up zig-cc linker wrapper (from examples/build-elf.sh)
cat > /tmp/zig-cc-linux.sh <<'EOF'
#!/bin/sh
exec zig cc -target x86_64-linux-gnu "$@"
EOF
chmod +x /tmp/zig-cc-linux.sh

cat > /tmp/zig-cxx-linux.sh <<'EOF'
#!/bin/sh
exec zig c++ -target x86_64-linux-gnu "$@"
EOF
chmod +x /tmp/zig-cxx-linux.sh

# Build consumer at vulnerable version
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/tmp/zig-cc-linux.sh \
  CC_x86_64_unknown_linux_gnu=/tmp/zig-cc-linux.sh \
  CXX_x86_64_unknown_linux_gnu=/tmp/zig-cxx-linux.sh \
  cargo build --release --target x86_64-unknown-linux-gnu 2>&1

# The grcov binary itself (no consumer wrapper needed if building grcov directly):
# git clone --depth=1 --branch v0.8.19 https://github.com/mozilla/grcov /tmp/grcov-vuln
# cd /tmp/grcov-vuln
# CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/tmp/zig-cc-linux.sh ... cargo build ...
```

### Option B: Build the grcov binary directly

Both `v0.8.19` (vulnerable) and `v0.8.20` (fixed) tags exist in the GitHub repo. Building
the `grcov` binary directly avoids the "consumer crate" abstraction and places the
`get_coverage` function directly in the output binary. The `--no-strip` / `-C debuginfo=2`
flags retain symbols for the matcher.

```sh
# Vulnerable binary
git clone --depth=1 --branch v0.8.19 https://github.com/mozilla/grcov /tmp/grcov-0.8.19
cd /tmp/grcov-0.8.19
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/tmp/zig-cc-linux.sh \
  CC_x86_64_unknown_linux_gnu=/tmp/zig-cc-linux.sh \
  CXX_x86_64_unknown_linux_gnu=/tmp/zig-cxx-linux.sh \
  RUSTFLAGS="-C debuginfo=2 -C strip=none" \
  cargo build --release --target x86_64-unknown-linux-gnu
# output: target/x86_64-unknown-linux-gnu/release/grcov

# Patched binary
git clone --depth=1 --branch v0.8.20 https://github.com/mozilla/grcov /tmp/grcov-0.8.20
cd /tmp/grcov-0.8.20
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/tmp/zig-cc-linux.sh \
  CC_x86_64_unknown_linux_gnu=/tmp/zig-cc-linux.sh \
  CXX_x86_64_unknown_linux_gnu=/tmp/zig-cxx-linux.sh \
  RUSTFLAGS="-C debuginfo=2 -C strip=none" \
  cargo build --release --target x86_64-unknown-linux-gnu
```

No `#[cfg(windows)]`, `winapi`, or platform-locked dependencies detected in grcov's
Cargo.toml. The `tcmalloc` dependency is guarded `[target.'cfg(unix)'.dependencies]` and
is optional (`tc` feature flag, not default). The `tera`/`quick-xml`/`serde_json` deps are
pure Rust. The `symbolic-demangle` C++ code is cross-compiled via `zig c++` above.

Committed sample artifacts:

```
RUSTSEC-2025-0005/Cargo.lock
RUSTSEC-2025-0005/Cargo.toml
RUSTSEC-2025-0005/grcov-0.8.19.elf
RUSTSEC-2025-0005/patched/Cargo.lock
RUSTSEC-2025-0005/patched/Cargo.toml
RUSTSEC-2025-0005/patched/grcov-0.8.20.elf
RUSTSEC-2025-0005/src/cobertura.rs
RUSTSEC-2025-0005/src/covdir.rs
RUSTSEC-2025-0005/src/defs.rs
RUSTSEC-2025-0005/src/file_filter.rs
RUSTSEC-2025-0005/src/filter.rs
RUSTSEC-2025-0005/src/gcov.rs
RUSTSEC-2025-0005/src/html.rs
RUSTSEC-2025-0005/src/lib.rs
RUSTSEC-2025-0005/src/llvm_tools.rs
RUSTSEC-2025-0005/src/main.rs
RUSTSEC-2025-0005/src/output.rs
RUSTSEC-2025-0005/src/parser.rs
RUSTSEC-2025-0005/src/path_rewriting.rs
RUSTSEC-2025-0005/src/producer.rs
RUSTSEC-2025-0005/src/reader.rs
RUSTSEC-2025-0005/src/symlink.rs
```

## Upstream fix

Patch: https://github.com/mozilla/grcov/commit/c821956

Repository: `https://github.com/mozilla/grcov`
Fix commit: `c821956` (full hash not confirmed; short form used in GHSA-qm2p-4w45-v2vr)
File: `src/covdir.rs`, function `CDFileStats::get_coverage`

```diff
--- a/src/covdir.rs (v0.8.19, vulnerable)
+++ b/src/covdir.rs (v0.8.20, patched)
@@ -61,10 +61,9 @@
         let mut lines: Vec<i64> = vec![-1; last_line];
         for (line_num, line_count) in coverage.iter() {
-            let line_count = *line_count;
-            unsafe {
-                *lines.get_unchecked_mut((*line_num - 1) as usize) = line_count as i64;
-            }
-            covered += (line_count > 0) as usize;
+            if let Some(line) = lines.get_mut((*line_num - 1) as usize) {
+                *line = *line_count as i64;
+                covered += (*line_count > 0) as usize;
+            }
         }
```

(Diff reconstructed from `git show v0.8.19:src/covdir.rs` vs `git show v0.8.20:src/covdir.rs`
on a shallow clone of mozilla/grcov. The `c821956` GHSA reference and OSV `affected < 0.8.21`
range are consistent: fix committed before the 0.8.20 tag on 2024-10-14.)

**What the fix added/changed:** Removed the `unsafe` block containing
`*lines.get_unchecked_mut((*line_num - 1) as usize)` (which writes to `lines[idx]` with no
bounds check) and replaced the entire body of the loop iteration with
`if let Some(line) = lines.get_mut((*line_num - 1) as usize) { *line = ...; covered += ...; }`.
`get_mut` performs a bounds check (`idx < self.len()`) and returns `None` on out-of-bounds; the
`if let` pattern skips the write entirely if the index is invalid. The `covered` increment was
also moved inside the `if let` block, so it only counts lines that were actually written. The
fix also removed the intermediate `let line_count = *line_count;` binding (the deref is now
inline: `*line_count as i64`).

## Provenance

Generated by the multi-agent CVE-rule pipeline (research → build both versions → binary-observable discriminator → self-verify → independent GATE). Build recipe, discriminator, and scan results above are drawn from the pipeline's research dossier and signature notes for this CVE.

References:

- RUSTSEC: https://rustsec.org/advisories/RUSTSEC-2025-0005.html
- GHSA: https://github.com/advisories/GHSA-qm2p-4w45-v2vr
