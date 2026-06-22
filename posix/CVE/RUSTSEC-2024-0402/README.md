# RUSTSEC-2024-0402 — `hashbrown` version 0

| | |
|---|---|
| **Library** | `hashbrown` |
| **Aliases** | GHSA-wwq9-3cpr-mm53 |
| **CWE** | CWE-345 |
| **Affected / fixed** | `>= 0.15.0` … fixed in `0.15.1` |
| **Rule** | [`RUSTSEC-2024-0402.vh`](./RUSTSEC-2024-0402.vh) |

## Summary

`hashbrown` version 0.15.0 introduced a `borsh` optional feature that provided `BorshSerialize` and `BorshDeserialize` impls for `hashbrown::HashMap`. The `BorshSerialize` implementation iterated over the map's entries in hash-table order — an inherently non-deterministic order dependent on insertion history, hash-seed, and memory layout. This violated Borsh's core canonicity guarantee (same data must always produce identical bytes), which is security-critical in consensus and signing contexts (blockchain, deterministic hashing): two nodes holding logically identical maps could serialize to different byte strings, enabling consensus splits or signature-verification failures. Additionally, the implementation incorrectly serialized the hasher state and used `usize` (platform-dependent size) for the length field instead of the spec-required `u32`. CWE-1 180 (Incorrect Behavior Order: Validate Before Canonicalize). Alias: GHSA-wwq9-3cpr-mm53.

## Detection discriminator

This engine has no library-version gate, so the rule proves the **vulnerable code structure** and is silent on the patched build.

Present-only symbol; the fix REMOVES it.

`borsh::ser::helpers::to_vec` monomorphized over a hashbrown HashMap:
```
borsh::ser::helpers::to_vec::<hashbrown::map::HashMap<i32, i32, ...DetHasher, ...Global>>
```
Engine-matchable (demangled) form: `to_vec.*hashbrown.*HashMap` via `project:functions`.

This monomorphization can only exist if `hashbrown::HashMap: BorshSerialize`, which is ONLY
true with the 0.15.0 borsh-feature impl. In 0.15.1 the impl/feature is deleted (PR #570), so
`borsh::to_vec` cannot be instantiated for a hashbrown HashMap and the symbol cannot exist.

Confirmed live via probe rule (project:functions, engine's actual match forms):
- vuln  : `project:functions("to_vec.*hashbrown.*HashMap")` -> PRESENT
- patch : `project:functions("to_vec.*hashbrown.*HashMap")` -> ABSENT

### Rejected alternative handles
- The impl method `<HashMap as borsh::ser::BorshSerialize>::serialize` exists in the debug
  ELF but the engine keeps it MANGLED (`_RINvX...9hashbrown20external_trait_impls5borsh8hash_map...`)
  and does NOT expose readable `BorshSerialize` / `external_trait_impls` / `hash_map` segments to
  its matcher (all probed: false in both builds). It also inlines away in release builds.
- A bare `borsh` token is unusable: it appears in unrelated consumer symbols (and, before the
  package was renamed, in the package name itself). `Borsh`/`Serialize` (capitalized) do NOT match.

## Reproducing the test binaries

The consumer must enable the `borsh` feature on hashbrown 0.15.0 and call `borsh::to_vec` on a `hashbrown::HashMap` so the `BorshSerialize` impl is monomorphized and linked into the binary.

**Cargo.toml (vulnerable pin):**
```toml
[package]
name = "hashbrown-borsh-consumer"
version = "0.1.0"
edition = "2021"

[dependencies]
hashbrown = { version = "=0.15.0", features = ["borsh"] }
borsh = { version = "1.5.0", features = ["derive"] }
```

**src/main.rs:**
```rust
use hashbrown::HashMap;

fn main() {
    let mut map: HashMap<i32, i32> = HashMap::new();
    map.insert(1, 10);
    map.insert(2, 20);
    map.insert(3, 30);

    // Calls <hashbrown::HashMap<i32,i32,_> as BorshSerialize>::serialize
    // This is the vulnerable function: iterates in non-deterministic hash order.
    let bytes = borsh::to_vec(&map).expect("serialization failed");
    println!("serialized {} bytes", bytes.len());

    // Demonstrate non-canonicity: insert in reverse order, compare bytes
    let mut map2: HashMap<i32, i32> = HashMap::new();
    map2.insert(3, 30);
    map2.insert(2, 20);
    map2.insert(1, 10);
    let bytes2 = borsh::to_vec(&map2).expect("serialization failed");
    if bytes == bytes2 {
        println!("SAME (this run happened to be canonical)");
    } else {
        println!("DIFFERENT bytes for same logical map — non-canonical serialization confirmed");
    }
}
```

**Cross-compile to Linux ELF (using zig-cc linker, symbols retained — no strip):**
```sh
# Write zig-cc wrapper
cat > /tmp/zig-cc-linux.sh <<'EOF'
#!/bin/sh
exec zig cc -target x86_64-linux-gnu "$@"
EOF
chmod +x /tmp/zig-cc-linux.sh

# Build vulnerable (0.15.0)
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/tmp/zig-cc-linux.sh \
  cargo build --target x86_64-unknown-linux-gnu --release
# Output: target/x86_64-unknown-linux-gnu/release/hashbrown-borsh-consumer
# NOTE: use --release but do NOT strip (Cargo default for release does not strip unless [profile.release] strip = true)
# To retain symbols explicitly: add to Cargo.toml:
# [profile.release]
# strip = false
# debug = 1
```

**Patched pin (0.15.1) — API difference:** In 0.15.1, the `borsh` feature does not exist on hashbrown. The consumer `Cargo.toml` must be changed to remove `features = ["borsh"]` from the hashbrown dependency, and `borsh::to_vec(&map)` will fail to compile ("`BorshSerialize` not implemented for `HashMap<i32, i32>`"). To build a comparable 0.15.1 binary, the consumer cannot call `borsh::to_vec` on a hashbrown map at all — the absent impl IS the fix. A patched-version probe binary would simply instantiate a `hashbrown::HashMap` without borsh serialization:

```toml
# Cargo.toml for patched pin
hashbrown = { version = "=0.15.1" }
# borsh dep not needed — no BorshSerialize impl exists
```

The two binaries differ by the presence/absence of the `BorshSerialize::serialize` monomorphized symbol for HashMap.

Committed sample artifacts:

```
RUSTSEC-2024-0402/Cargo.lock
RUSTSEC-2024-0402/Cargo.toml
RUSTSEC-2024-0402/hashbrown-borsh-consumer.elf
RUSTSEC-2024-0402/patched/Cargo.lock
RUSTSEC-2024-0402/patched/Cargo.toml
RUSTSEC-2024-0402/patched/hashbrown-borsh-consumer.elf
RUSTSEC-2024-0402/src/main.rs
```

## Upstream fix

Patch: https://github.com/rust-lang/hashbrown/pull/570

Fix PR: https://github.com/rust-lang/hashbrown/pull/570 ("Revert feat: borsh serde"), merged 2024-10-12.

Two commits land in v0.15.1:

- `6a27e27` — removes the entire borsh source module (81 lines across 3 files)
- `5b8e6d5` — removes the borsh dependency from `Cargo.toml` and README

```diff
diff --git a/src/external_trait_impls/borsh/hash_map.rs b/src/external_trait_impls/borsh/hash_map.rs
deleted file mode 100644
index 8991affbc4..0000000000
--- a/src/external_trait_impls/borsh/hash_map.rs
+++ /dev/null
@@ -1,78 +0,0 @@
-use crate::HashMap;
-
-use borsh::{
-    io::{Read, Result, Write},
-    BorshDeserialize, BorshSerialize,
-};
-
-impl<K: BorshSerialize, V: BorshSerialize, S: BorshSerialize> BorshSerialize for HashMap<K, V, S> {
-    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
-        // assuming hash may have some seed,
-        // as borsh is supposed by default to be deterministic, need to write it down
-        self.hash_builder.serialize(writer)?;
-        // considering A stateless
-        self.len().serialize(writer)?;
-        for kv in self.iter() {
-            kv.serialize(writer)?;
-        }
-        Ok(())
-    }
-}
-
-impl<
-        K: BorshDeserialize + core::hash::Hash + Eq,
-        V: BorshDeserialize,
-        S: BorshDeserialize + core::hash::BuildHasher,
-    > BorshDeserialize for HashMap<K, V, S>
-{
-    fn deserialize_reader<R: Read>(reader: &mut R) -> Result<Self> {
-        let hash_builder = S::deserialize_reader(reader)?;
-        let len = usize::deserialize_reader(reader)?;
-        let mut map = HashMap::with_capacity_and_hasher(len, hash_builder);
-        for _ in 0..len {
-            let (k, v) = <(K, V)>::deserialize_reader(reader)?;
-            map.insert(k, v);
-        }
-        Ok(map)
-    }
-}
diff --git a/src/external_trait_impls/borsh/mod.rs b/src/external_trait_impls/borsh/mod.rs
deleted file mode 100644
index 841e4b1a2e..0000000000
--- a/src/external_trait_impls/borsh/mod.rs
+++ /dev/null
@@ -1 +0,0 @@
-mod hash_map;
diff --git a/src/external_trait_impls/mod.rs b/src/external_trait_impls/mod.rs
index bca8f9770e..ef497836cb 100644
--- a/src/external_trait_impls/mod.rs
+++ b/src/external_trait_impls/mod.rs
@@ -1,5 +1,3 @@
-#[cfg(feature = "borsh")]
-mod borsh;
 #[cfg(feature = "rayon")]
 pub(crate) mod rayon;
 #[cfg(feature = "serde")]
diff --git a/Cargo.toml b/Cargo.toml
index ..
--- a/Cargo.toml
+++ b/Cargo.toml
@@ borsh dependency line @@
-borsh = { version = "1.5.0", default-features = false, optional = true, features = ["derive"]}
```

**What the fix changed:** The fix does NO

*(diff truncated — see upstream patch)*

## Provenance

Generated by the multi-agent CVE-rule pipeline (research → build both versions → binary-observable discriminator → self-verify → independent GATE). Build recipe, discriminator, and scan results above are drawn from the pipeline's research dossier and signature notes for this CVE.

References:

- RUSTSEC: https://rustsec.org/advisories/RUSTSEC-2024-0402.html
- GHSA: https://github.com/advisories/GHSA-wwq9-3cpr-mm53
- fix: https://github.com/rust-lang/hashbrown/pull/570
