# RUSTSEC-2023-0018 — The `remove_dir_all` Rust crate (versions < 0

| | |
|---|---|
| **Library** | `remove_dir_all` |
| **Aliases** | GHSA-mc8h-8q98-g5hr |
| **CWE** | CWE-363, CWE-367, CWE-59 |
| **Affected / fixed** | `>= 0.7.0` … fixed in `0.8.0` |
| **Rule** | [`RUSTSEC-2023-0018.vh`](./RUSTSEC-2023-0018.vh) |

## Summary

The `remove_dir_all` Rust crate (versions < 0.8.0) contained a Time-of-Check Time-of-Use (TOCTOU)
race condition (CWE-363/CWE-367/CWE-59) in its recursive directory deletion functions. An attacker
controlling a target directory could replace interior path components with symlinks between the
traversal check and the deletion syscall, tricking a privileged process into deleting files outside
the intended directory tree (e.g. substituting a subdirectory with a symlink to `/etc`). The
vulnerability mirrors CVE-2022-21658 in the Rust standard library. On UNIX, the pre-fix
`remove_dir_all` was a raw re-export of `std::fs::remove_dir_all`; `remove_dir_contents` used
path-based `fs::read_dir` iteration with no file-descriptor anchoring. The fix rewrote the core
traversal on all platforms to use file-descriptor-relative (`*at`-style) syscalls via the `fs_at`
crate, preventing symlink escapes within the directory tree.

## Detection discriminator

This engine has no library-version gate, so the rule proves the **vulnerable code structure** and is silent on the patched build.

Presence/absence of `fs_at`-namespaced symbols in the ELF.

The 0.8.0 fix (commit 7247a8b) rewrote `remove_dir_all`'s recursive traversal to
file-descriptor-relative `*at`-family syscalls via the NEW `fs_at` crate dependency
(`fs_at::read_dir`, `OpenOptions::open_dir_at` with `O_NOFOLLOW`, `rmdir_at`,
`unlink_at`). `fs_at` does not exist in any pre-0.8.0 Cargo.toml, so:

- VULN 0.7.0 ELF: `nm | grep -c fs_at` = **0**
- PATCHED 0.8.0 ELF: `nm | grep -c fs_at` = **31**

The crate-owned traversal symbol (`14remove_dir_all...`) is present in BOTH builds and
is used as the present-in-both scope anchor (the unix `remove_dir_all` is a bare
`pub use std::fs::remove_dir_all` with no crate symbol, so it is NOT the anchor — the
crate traversal functions `_remove_dir_contents` (0.7.0) / `__impl::remove_dir_contents_recursive`
(0.8.0) carry the `remove_dir_all` namespace and match the scope in both).

## Reproducing the test binaries

Minimal Rust consumer that links the library and calls `remove_dir_contents` so the unix traversal
code is pulled in at both versions:

```toml
# Cargo.toml
[package]
name = "cve-consumer"
version = "0.1.0"
edition = "2021"

[dependencies]
# Vulnerable pin:
remove_dir_all = "=0.7.0"
# Fixed pin (swap for patched build):
# remove_dir_all = "=0.8.0"

[profile.release]
opt-level = 2
debug = false
```

```rust
// src/main.rs
use std::fs;
use remove_dir_all::remove_dir_contents;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "/tmp/test_rda".to_string());
    fs::create_dir_all(&path).ok();
    let _ = remove_dir_contents(&path);
}
```

Cross-compile to Linux x86_64 ELF:

```bash
# via examples/build-elf.sh or directly:
cargo build --release --target x86_64-unknown-linux-musl
# or with the project's cross-compile helper:
bash examples/build-elf.sh
```

**API compatibility between versions:** The `remove_dir_contents(path)` signature is identical in
both 0.7.0 and 0.8.0 — the same source compiles against either pin. The `remove_dir_all(path)`
function is also signature-compatible. No API difference to handle.

**Symbol retention:** Because `remove_dir_contents` is a public API function (not generic-only),
it will not be dead-code-eliminated even with LTO. With `remove_dir_all = "=0.7.0"` the binary
will contain `remove_dir_all::portable::remove_dir_contents` and `remove_dir_all::unix::_remove_dir_contents`. With `=0.8.0` it will contain `remove_dir_all::remove_dir_contents` calling into `fs_at` helpers.

Committed sample artifacts:

```
RUSTSEC-2023-0018/build-patched/Cargo.lock
RUSTSEC-2023-0018/build-patched/Cargo.toml
RUSTSEC-2023-0018/build-vuln/Cargo.lock
RUSTSEC-2023-0018/build-vuln/Cargo.toml
RUSTSEC-2023-0018/patched/remove_dir_all-0.8.0.elf
RUSTSEC-2023-0018/remove_dir_all-0.7.0.elf
```

## Upstream fix

Patch: https://github.com/XAMPPRocky/remove_dir_all/commit/7247a8b6ee59fc99bbb69ca6b3ca4bfd8c809ead

**Repository:** https://github.com/XAMPPRocky/remove_dir_all  
**Fix commit:** `7247a8b6ee59fc99bbb69ca6b3ca4bfd8c809ead`  
**PR:** "Merge pull request from GHSA-mc8h-8q98-g5hr"

### Vulnerable unix path — `src/unix.rs` (deleted in fix)

```rust
// DELETED in 0.8.0 — the entire unix.rs file:
pub fn _remove_dir_contents<P: AsRef<Path>>(path: P) -> Result<(), io::Error> {
    for entry in fs::read_dir(path)? {          // path-based: no fd anchor
        let entry_path = entry?.path();
        remove_file_or_dir_all(&entry_path)?;   // follows resolved path, races here
    }
    Ok(())
}

fn remove_file_or_dir_all<P: AsRef<Path>>(path: P) -> io::Result<()> {
    match fs::remove_file(&path) {
        Err(e) if e.raw_os_error() == Some(libc::EISDIR) =>
            fs::remove_dir_all(&path),          // recurses via stdlib, no fd safety
        r => r,
    }
}
```

### Vulnerable lib.rs re-exports (non-Windows)

```rust
// REMOVED lines from src/lib.rs:
#[cfg(not(windows))]
mod unix;

mod portable;

#[cfg(not(windows))]
pub use std::fs::remove_dir_all;   // unix: pure stdlib re-export, no crate code at all

pub use portable::ensure_empty_dir;
pub use portable::remove_dir_contents;
```

### Fixed `src/_impl.rs` (new in 0.8.0, platform-agnostic including unix)

```rust
// ADDED in 0.8.0 — core traversal uses fs_at fd-relative operations:
fn remove_dir_contents_recursive<I: io::Io>(
    mut d: File,
    debug_root: &PathComponents<'_>,
) -> Result<()> {
    let dirfd = I::duplicate_fd(&mut d)?;
    let mut iter = fs_at::read_dir(&mut d)?;         // fd-relative readdir

    iter.try_for_each(|dir_entry| -> Result<()> {
        // ...
        let mut opts = fs_at::OpenOptions::default();
        opts.read(true)
            .write(fs_at::OpenOptionsWriteMode::Write)
            .follow(false);                           // O_NOFOLLOW — refuse symlinks
        let child_result = opts.open_dir_at(&dirfd, name);  // *at open, anchored to fd
        // ...
        opts.rmdir_at(&dirfd, name)                  // *at rmdir
        // ...
        opts.unlink_at(&dirfd, name)                 // *at unlink
    })?;
    Ok(())
}
```

### Fixed unix.rs (`src/_impl/unix.rs`, new in 0.8.0)

```rust
// ADDED — unix Io trait impl uses O_NOFOLLOW when opening directories:
fn open_dir(p: &Path) -> io::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.read(true);
    options.custom_flags(libc::O_NOFOLLOW);   // key: refuses to follow symlinks
    options.open(p)
}

fn is_eloop(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::ELOOP)     // detects E

*(diff truncated — see upstream patch)*

## Provenance

Generated by the multi-agent CVE-rule pipeline (research → build both versions → binary-observable discriminator → self-verify → independent GATE). Build recipe, discriminator, and scan results above are drawn from the pipeline's research dossier and signature notes for this CVE.

References:

- RUSTSEC: https://rustsec.org/advisories/RUSTSEC-2023-0018.html
- GHSA: https://github.com/advisories/GHSA-mc8h-8q98-g5hr
