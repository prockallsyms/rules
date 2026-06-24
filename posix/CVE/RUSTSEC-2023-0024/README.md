# RUSTSEC-2023-0024 — `openssl::x509::X509Extension::new` and `openssl::x509::X509Extension::new_nid` in the `openssl` Rust crate (versions >= 0

| | |
|---|---|
| **Library** | `openssl` |
| **Aliases** | GHSA-6hcf-g6gr-hhcr |
| **CWE** | CWE-476 |
| **Affected / fixed** | `>= 0.9.7` … fixed in `0.10.48` |
| **Rule** | [`RUSTSEC-2023-0024.vh`](./RUSTSEC-2023-0024.vh) |

## Summary

`openssl::x509::X509Extension::new` and `openssl::x509::X509Extension::new_nid` in the `openssl` Rust crate (versions >= 0.9.7, < 0.10.48) passed a raw null pointer as the `ctx` argument to the underlying C functions `X509V3_EXT_nconf` and `X509V3_EXT_nconf_nid` whenever the Rust caller supplied `context: None`. Certain OpenSSL extension types (e.g. `crlDistributionPoints`, `certificatePolicies`) unconditionally dereference the context pointer, producing a null pointer dereference (CWE-476) that terminates the process. Because the function signature accepts `None` as a safe Rust value, a safe caller can trigger the crash without any unsafe code. Impact is denial-of-service in any application that constructs X.509 extensions without a pre-built context. Credit: David Benjamin (Google). Advisory aliases: GHSA-6hcf-g6gr-hhcr.

## Detection discriminator

This engine has no library-version gate, so the rule proves the **vulnerable code structure** and is silent on the patched build.

The prior module-level X509V3_set_ctx symbol-presence discriminator was SAMPLE-OVERFIT:
it only worked because the minimal consumer had no other caller of X509V3_set_ctx (so DCE
removed it from vuln). On a real binary that also links x509v3_context
(X509Builder/SslContextBuilder/X509ReqBuilder), X509V3_set_ctx is present in BOTH versions
and the rule would FALSE-SILENT on vuln. REPLACED.

NEW (function-scoped, holds regardless of what else the binary links):
objdump of X509Extension::new (vuln 0x17d970 / patched 0x17e870) and new_nid shows every
FFI call is GOT-indirect (callq *off(%rip)) -> has_call/context:calls cannot name
X509V3_set_ctx. The fix's `mem::zeroed()` of the stack X509V3_CTX compiles in BOTH changed
functions to a contiguous, position-independent 23-byte run (no RIP-rel/GOT):
    0f 57 c0          xorps  %xmm0,%xmm0
    0f 29 44 24 60    movaps %xmm0,0x60(%rsp)
    0f 29 44 24 50    movaps %xmm0,0x50(%rsp)
    0f 29 44 24 40    movaps %xmm0,0x40(%rsp)
    0f 29 44 24 30    movaps %xmm0,0x30(%rsp)
  = 0f57c00f294424600f294424500f294424400f29442430
This immediately precedes the new X509V3_set_ctx(&mut ctx, null*4, 0) (regs zeroed, GOT call).
  VULN 0.10.47:    0 occurrences (NULL passed straight in; no CTX allocated/zeroed) -> FIRE
  PATCHED 0.10.48: 2 occurrences, vaddr 0x17e8fb (inside new) + 0x17eb21 (inside new_nid),
                   both precisely the two fixed functions -> SILENT
Absent in vuln despite vuln linking the SAME vendored OpenSSL -> specific to this fix's
codegen, not a generic sequence emitted by x509v3_context or std code.
Rule: scope X509Extension.*new; pcall-guarded whole-code search_code(FIX_RUN); fire-when-absent.
Self-test (existing ELFs): vuln FIRED (exit 0), patched SILENT (exit 1).

## Reproducing the test binaries

### Vulnerable consumer (pin 0.10.47)

`Cargo.toml`:
```toml
[package]
name = "rustsec-2023-0024-vuln"
version = "0.1.0"
edition = "2021"

[dependencies]
openssl = { version = "=0.10.47", features = ["vendored"] }

[profile.release]
opt-level = 1
debug = true
strip = false
```

`src/main.rs`:
```rust
use openssl::nid::Nid;
use openssl::x509::X509Extension;

// #[inline(never)] ensures the function body is present and not inlined away
#[inline(never)]
fn make_extension_new() -> Result<X509Extension, openssl::error::ErrorStack> {
    // Pass context=None to trigger the vulnerable code path (null ptr in vuln; zeroed ctx in fixed)
    X509Extension::new(None, None, "basicConstraints", "CA:FALSE")
}

#[inline(never)]
fn make_extension_new_nid() -> Result<X509Extension, openssl::error::ErrorStack> {
    X509Extension::new_nid(None, None, Nid::BASIC_CONSTRAINTS, "CA:FALSE")
}

fn main() {
    // basicConstraints does not require a context so this succeeds on both versions
    // (use "crlDistributionPoints" or "subjectAltName" to actually trigger the crash on vuln)
    let ext = make_extension_new();
    std::hint::black_box(&ext);
    let ext2 = make_extension_new_nid();
    std::hint::black_box(&ext2);
    println!("done");
}
```

### Fixed consumer (pin 0.10.48)

Identical `src/main.rs`. Change `Cargo.toml` dependency to:
```toml
openssl = { version = "=0.10.48", features = ["vendored"] }
```

The API signature is unchanged between 0.10.47 and 0.10.48 — the same call compiles at both pins.

### Cross-compile to Linux ELF (x86_64)

```sh
# Write the zig-cc wrapper
cat > /tmp/zig-cc-linux.sh <<'EOF'
#!/bin/sh
exec zig cc -target x86_64-linux-gnu "$@"
EOF
chmod +x /tmp/zig-cc-linux.sh

# Build vulnerable
cd /path/to/rustsec-2023-0024-vuln
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/tmp/zig-cc-linux.sh \
  cargo build --release --target x86_64-unknown-linux-gnu
# output: target/x86_64-unknown-linux-gnu/release/rustsec-2023-0024-vuln (ELF)

# Build fixed: change Cargo.toml to =0.10.48, repeat
```

Note: `features = ["vendored"]` causes OpenSSL C sources to be compiled in-tree. This is slow (several minutes) and produces a large binary, but ensures the binary links and contains all relevant symbols without a system OpenSSL dependency. Symbols are retained (`strip = false`, `debug = true`).

Committed sample artifacts:

```
RUSTSEC-2023-0024/Cargo.lock
RUSTSEC-2023-0024/Cargo.toml
RUSTSEC-2023-0024/patched/Cargo.lock
RUSTSEC-2023-0024/patched/Cargo.toml
RUSTSEC-2023-0024/patched/rustsec_2023_0024_patched.elf
RUSTSEC-2023-0024/rustsec_2023_0024_vuln.elf
RUSTSEC-2023-0024/src/main.rs
```

## Upstream fix

Patch: https://github.com/sfackler/rust-openssl/commit/78aa9aac1aafd2b0e2dabf81d77602e1b18f9d75

**Repository:** https://github.com/sfackler/rust-openssl  
**Fix PR:** #1854 (merged 2023-03-24)  
**Fix commit:** `78aa9aa` ("Always provide an X509V3Context in X509Extension::new because OpenSSL requires it for some extensions (and segfaults without)")  
**File:** `openssl/src/x509/mod.rs`

### X509Extension::new — before (0.10.47, lines 810-827)

```rust
pub fn new(
    conf: Option<&ConfRef>,
    context: Option<&X509v3Context<'_>>,
    name: &str,
    value: &str,
) -> Result<X509Extension, ErrorStack> {
    let name = CString::new(name).unwrap();
    let value = CString::new(value).unwrap();
    unsafe {
        ffi::init();
        let conf = conf.map_or(ptr::null_mut(), ConfRef::as_ptr);
        let context = context.map_or(ptr::null_mut(), X509v3Context::as_ptr);
        let name = name.as_ptr() as *mut _;
        let value = value.as_ptr() as *mut _;

        cvt_p(ffi::X509V3_EXT_nconf(conf, context, name, value)).map(X509Extension)
    }
}
```

### X509Extension::new — after (0.10.48, lines 814-847)

```rust
pub fn new(
    conf: Option<&ConfRef>,
    context: Option<&X509v3Context<'_>>,
    name: &str,
    value: &str,
) -> Result<X509Extension, ErrorStack> {
    let name = CString::new(name).unwrap();
    let value = CString::new(value).unwrap();
    let mut ctx;
    unsafe {
        ffi::init();
        let conf = conf.map_or(ptr::null_mut(), ConfRef::as_ptr);
        let context_ptr = match context {
            Some(c) => c.as_ptr(),
            None => {
                ctx = mem::zeroed();

                ffi::X509V3_set_ctx(
                    &mut ctx,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    0,
                );
                &mut ctx
            }
        };
        let name = name.as_ptr() as *mut _;
        let value = value.as_ptr() as *mut _;

        cvt_p(ffi::X509V3_EXT_nconf(conf, context_ptr, name, value)).map(X509Extension)
    }
}
```

The identical transformation applies to `X509Extension::new_nid` (vulnerable: lines 836-852; fixed: lines 859-891), replacing `context.map_or(ptr::null_mut(), X509v3Context::as_ptr)` with the same `match`/`mem::zeroed()`/`X509V3_set_ctx` block.

**Precise delta:** The fix REMOVED the one-liner `context.map_or(ptr::null_mut(), X509v3Context::as_ptr)` (which produced a raw null for `None`) and ADDED a `match` arm for `None` that: (1) declares `let mut ctx` outside the `unsafe` block, (2) initializes it with `mem::zeroed()`, (3) calls `ffi::X509V3_set_ctx(&mut ct

*(diff truncated — see upstream patch)*

## Provenance

Generated by the multi-agent CVE-rule pipeline (research → build both versions → binary-observable discriminator → self-verify → independent GATE). Build recipe, discriminator, and scan results above are drawn from the pipeline's research dossier and signature notes for this CVE.

References:

- RUSTSEC: https://rustsec.org/advisories/RUSTSEC-2023-0024.html
- GHSA: https://github.com/sfackler/rust-openssl/security/advisories/GHSA-6hcf-g6gr-hhcr
