# RUSTSEC-2023-0023 — The `openssl` Rust crate (sfackler/rust-openssl) before version 0

| | |
|---|---|
| **Library** | `openssl` |
| **Aliases** | GHSA-9qwg-crg9-m2vc |
| **CWE** | CWE-22, CWE-20 |
| **Affected / fixed** | `>= 0.9.7` … fixed in `0.10.48` |
| **Rule** | [`RUSTSEC-2023-0023.vh`](./RUSTSEC-2023-0023.vh) |

## Summary

The `openssl` Rust crate (sfackler/rust-openssl) before version 0.10.48 allowed arbitrary file
read via its `SubjectAlternativeName` builder and `ExtendedKeyUsage::other` API. Both builder
types accumulated user-supplied strings and, at `build()` time, concatenated them into a
comma-separated value string that was then passed verbatim to OpenSSL's `X509V3_EXT_nconf_nid`
FFI function. That C function uses OpenSSL's mini-language / configuration-file parser, which
honours directives such as `file:/path/to/file` and `@/path/to/file` (reads file contents) and
`@section` (resolves a named section from a loaded conf file). An attacker able to influence the
argument to `dns()`, `email()`, `uri()`, `other()`, etc. could inject these directives and read
arbitrary files from the host filesystem during certificate construction. CWE-20 (Improper Input
Validation) / CWE-73 (External Control of File Name or Path). Alias GHSA-9qwg-crg9-m2vc.

## Detection discriminator

This engine has no library-version gate, so the rule proves the **vulnerable code structure** and is silent on the patched build.

Linker dead-code-elimination ties the FFI function set to the Rust build path:
| symbol                 | VULN 0.10.47 | PATCHED 0.10.48 |
|------------------------|--------------|-----------------|
| X509V3_EXT_nconf_nid   | PRESENT      | ABSENT (DCE'd)  |
| X509V3_EXT_i2d         | ABSENT       | PRESENT         |
| GENERAL_NAME_new       | present      | present (both)  |  <- NOT discriminating

The fix replaced the `X509V3_EXT_nconf_nid` config-parser path with `X509V3_EXT_i2d`
(+ GENERAL_NAME_new constructors / OBJ_txt2obj). Because the vulnerable path is the ONLY
reference to `X509V3_EXT_nconf_nid` in these consumers, the symbol is present iff the build is
vulnerable, and `X509V3_EXT_i2d` is present iff the build is patched. This is a structural
consequence of the fix, not a bare symbol-version key: it is the actual config-parser call site
that the fix removed.

Probed live with project:functions{matching="...", kind="symbol"} (single-form, ~= nil):
- VULN:    nconf=true  i2d=false  gnn=true
- PATCHED: nconf=false i2d=true   gnn=true

## Reproducing the test binaries

Consumer crate for the vulnerable version (`Cargo.toml`):

```toml
[package]
name = "openssl-san-vuln"
version = "0.1.0"
edition = "2021"

[dependencies]
openssl = { version = "=0.10.47", features = ["vendored"] }

[profile.release]
opt-level = 1
debug = true
strip = false
```

The `vendored` feature compiles OpenSSL from source bundled in `openssl-src`, avoiding a need
for a pre-installed system OpenSSL for the cross-compile target.

Consumer `src/main.rs`:

```rust
use openssl::x509::extension::{ExtendedKeyUsage, SubjectAlternativeName};
use openssl::x509::X509;

fn main() {
    // Exercise SubjectAlternativeName::build — the vulnerable API
    let mut builder = X509::builder().unwrap();
    let ctx = builder.x509v3_context(None, None);

    let san = SubjectAlternativeName::new()
        .dns("example.com")
        .email("user@example.com")
        .uri("https://example.com")
        .build(&ctx)
        .unwrap();
    drop(san);

    // Exercise ExtendedKeyUsage::other — the other vulnerable API
    let eku = ExtendedKeyUsage::new()
        .server_auth()
        .other("clientAuth")
        .build()
        .unwrap();
    drop(eku);

    println!("done");
}
```

Cross-compile to Linux ELF with zig-cc linker wrapper:

```sh
cat > /tmp/zig-cc-linux.sh <<'EOF'
#!/bin/sh
exec zig cc -target x86_64-linux-gnu "$@"
EOF
chmod +x /tmp/zig-cc-linux.sh

CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/tmp/zig-cc-linux.sh \
  cargo build --release --target x86_64-unknown-linux-gnu
# output: target/x86_64-unknown-linux-gnu/release/openssl-san-vuln (ELF)
```

For the fixed version, change the dependency pin to `"=0.10.48"`. The public API call
signatures are identical between 0.10.47 and 0.10.48 for `dns()`, `email()`, `uri()`,
`server_auth()`, and `other()` — no source changes needed in the consumer. (Note: `dir_name()`
and `other_name()` on SubjectAlternativeName were deprecated and now panic in 0.10.48; do not
call those in the consumer.)

The same `src/main.rs` builds cleanly at both pins.

Committed sample artifacts:

```
RUSTSEC-2023-0023/Cargo.lock
RUSTSEC-2023-0023/Cargo.toml
RUSTSEC-2023-0023/openssl-san-vuln.elf
RUSTSEC-2023-0023/patched/Cargo.lock
RUSTSEC-2023-0023/patched/Cargo.toml
RUSTSEC-2023-0023/patched/openssl-san-patched.elf
RUSTSEC-2023-0023/src/main.rs
```

## Upstream fix

Patch: https://github.com/sfackler/rust-openssl/commit/482575bca7c0eca7913d5db0c1aa4376e6c1a02d

Fix PR: https://github.com/sfackler/rust-openssl/pull/1854
Fix commits (in order):
- `482575b` — "Resolve an injection vulnerability in SAN creation"
- `332311b` — "Resolve an injection vulnerability in EKU creation"
- `5efceaa` — merge commit into main

### Key hunk — `SubjectAlternativeName::build` (openssl/src/x509/extension.rs)

Vulnerable (0.10.47):
```rust
pub fn build(&self, ctx: &X509v3Context<'_>) -> Result<X509Extension, ErrorStack> {
    let mut value = String::new();
    let mut first = true;
    append(&mut value, &mut first, self.critical, "critical");
    for name in &self.names {
        append(&mut value, &mut first, true, name);
    }
    X509Extension::new_nid(None, Some(ctx), Nid::SUBJECT_ALT_NAME, &value)
}
```

Fixed (0.10.48):
```rust
pub fn build(&self, _ctx: &X509v3Context<'_>) -> Result<X509Extension, ErrorStack> {
    let mut stack = Stack::new()?;
    for item in &self.items {
        let gn = match item {
            RustGeneralName::Dns(s) => GeneralName::new_dns(s.as_bytes())?,
            RustGeneralName::Email(s) => GeneralName::new_email(s.as_bytes())?,
            RustGeneralName::Uri(s) => GeneralName::new_uri(s.as_bytes())?,
            RustGeneralName::Ip(s) => {
                GeneralName::new_ip(s.parse().map_err(|_| ErrorStack::get())?)?
            }
            RustGeneralName::Rid(s) => GeneralName::new_rid(Asn1Object::from_str(s)?)?,
        };
        stack.push(gn)?;
    }
    unsafe {
        X509Extension::new_internal(Nid::SUBJECT_ALT_NAME, self.critical, stack.as_ptr().cast())
    }
}
```

### Key hunk — `ExtendedKeyUsage::build` (openssl/src/x509/extension.rs)

Vulnerable (0.10.47):
```rust
pub fn build(&self) -> Result<X509Extension, ErrorStack> {
    let mut value = String::new();
    let mut first = true;
    append(&mut value, &mut first, self.critical, "critical");
    // ... many append() calls for flags ...
    for other in &self.other {
        append(&mut value, &mut first, true, other);
    }
    X509Extension::new_nid(None, None, Nid::EXT_KEY_USAGE, &value)
}
```

Fixed (0.10.48):
```rust
pub fn build(&self) -> Result<X509Extension, ErrorStack> {
    let mut stack = Stack::new()?;
    for item in &self.items {
        stack.push(Asn1Object::from_str(item)?)?;
    }
    unsafe {
        X509Extension::new_internal(Nid::EXT_KEY_USAGE, self.critical, stack.as_ptr().cast())
    }
}
```

### New helper — `X509Extension::new_internal` (openssl/src/x509/mod.rs, commit 482575b)

```rust
pub(crate) unsafe fn new_internal(
    nid: Nid,
    critical: bool,
    value: *mut c_void,
) -> Result<X509Exten

*(diff truncated — see upstream patch)*

## Provenance

Generated by the multi-agent CVE-rule pipeline (research → build both versions → binary-observable discriminator → self-verify → independent GATE). Build recipe, discriminator, and scan results above are drawn from the pipeline's research dossier and signature notes for this CVE.

References:

- RUSTSEC: https://rustsec.org/advisories/RUSTSEC-2023-0023.html
- GHSA: https://github.com/sfackler/rust-openssl/security/advisories/GHSA-9qwg-crg9-m2vc
