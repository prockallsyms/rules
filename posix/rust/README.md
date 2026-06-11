# Rust portable rulepacks

See `../../triage/RUST-COVERAGE.md`. Rust uses **v0 mangling** (not demangled by the
engine); rules match stable name fragments via
`scope:functions{target={matching="<rust-regex>", kind="symbol"}}`, or unmangled libc
imports via `scope:calls{to="…"}`.

| Pack | technique | sev | validated |
|------|-----------|-----|-----------|
| rust-command-exec | `std::process::Command::new` (mangled frag) | medium | ✅ rstest.elf |
| rust-risky-std | `fs::remove_dir_all`, `TcpListener::bind`, `mem::transmute` | low | ✅ rstest.elf |
| **rust-weak-crypto** | RustCrypto MD2/MD4/MD5/SHA1 + DES/3DES/RC4 + small RSA (type-len frag) | medium | ✅ rstub.elf (5) |
| **rust-tls-disabled** | reqwest/native-tls `danger_accept_*` (+ renamed `tls_danger_accept_*`), openssl `set_verify_callback`, rustls custom verifier | high | ✅ rstub.elf (7) |
| **rust-sql-raw-query** | sqlx `raw_sql` / diesel `sql_query` (bare name) | medium | ✅ rstub.elf (2) |
| **rust-jwt-insecure** | jsonwebtoken `insecure_disable_signature_validation` / `insecure_decode` / `dangerous_insecure_decode` | high | ✅ rstub.elf (2) |
| **rust-archive-extract** | tar `Archive::unpack`/`Entry::unpack_in`, zip `ZipArchive::extract` (zip-slip) | medium | ✅ rstub.elf (2) |
| **rust-ffi-dangerous** | `scope:calls` libc `system`/`dlopen`/`exec*`/`mprotect`/`setuid` (nix/libc wrap these) | medium | ✅ rstub.elf (6) |

The library rules come from `../../triage/LIBRARY-API-CATALOG.md` and were validated on
`examples/rstub.rs` → `rstub.elf` (local modules whose crate/type/method names match the
real crates so v0-mangled symbols match by construction): **24 findings, 0 errors**.

## v0-mangling matching lesson (see RUST-COVERAGE.md for detail)
- **Free functions** → match the **bare final identifier** (`raw_sql`,
  `danger_accept_invalid_certs`). Crate-prefixed `4sqlx7raw_sql` does **not** match.
- **Methods on a type** → match the **contiguous type-with-length / type+method**
  fragment (`3Md5`, `3Des`, `7Archive6unpack`). A crate+type fragment (`3md53Md5`) spans
  a `NtB2_` back-reference and is **not contiguous** → fails.
- **Raw FFI / libc** → `scope:calls{to="<C name>"}` on the unmangled import.

## Build a Rust ELF on macOS (no real toolchain target needed)
```sh
cat > /tmp/zig-cc-linux.sh <<'EOF'
#!/bin/sh
exec zig cc -target x86_64-linux-gnu "$@"
EOF
chmod +x /tmp/zig-cc-linux.sh
rustc --target x86_64-unknown-linux-gnu -C linker=/tmp/zig-cc-linux.sh -g \
  examples/rstub.rs -o examples/rstub.elf
```

## Run
```sh
export BIAS_DATA=/Users/samv/vulhunt-dev/biasdata
vulhunt-ce scan <rust-elf> -d "$BIAS_DATA" -r posix/rust --pretty
```
