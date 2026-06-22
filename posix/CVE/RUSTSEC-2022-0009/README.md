# RUSTSEC-2022-0009 — `libp2p-core` versions `>=0

| | |
|---|---|
| **Library** | `libp2p-core` |
| **Aliases** | GHSA-wc36-xgcc-jwpr |
| **CWE** | CWE-347 |
| **Affected / fixed** | `>= 0.30.0-rc.1` … fixed in `0.30.2` |
| **Rule** | [`RUSTSEC-2022-0009.vh`](./RUSTSEC-2022-0009.vh) |

## Summary

`libp2p-core` versions `>=0.30.0-rc.1` through `<0.30.2` and `0.31.0` failed to verify that the public key used to sign a `SignedEnvelope` matched the `PeerId` embedded in the enclosed `PeerRecord`. The function `PeerRecord::from_signed_envelope` decoded the protobuf payload, extracted the claimed `PeerId` from the record bytes, validated the envelope signature, but never cross-checked that the signing key was the same key that the declared `PeerId` was derived from. An attacker could take a legitimately signed `PeerRecord` from peer A, re-wrap it in a new envelope signed by their own key (peer B), and present it to a node; the node would accept the record as valid for peer A's identity. CWE-347 (Improper Verification of Cryptographic Signature). Alias: GHSA-wc36-xgcc-jwpr.

## Detection discriminator

This engine has no library-version gate, so the rule proves the **vulnerable code structure** and is silent on the patched build.

CALL to `bcmp` REACHABLE FROM `PeerRecord::from_signed_envelope`, present only in the patched build.

The added guard `peer_id != envelope.key.to_peer_id()` compares two PeerId values.
A PeerId wraps a multihash digest; the `!=` lowers to a byte comparison of the two
digest buffers, emitted as a call to libc/compiler-rt `bcmp`. The
`to_peer_id()`/`PeerId::from_public_key` derivation is INLINED into the function
(no named call survives — `context:calls("to_peer_id")`/`"from_public_key")` = 0 in
both), but the equality `bcmp` does survive codegen and is the binary-observable
handle.

Measured via the engine's `context:calls(...)` over the ICFG (which resolves the
indirect PLT call edge to the `bcmp` import), scoped to the real method
(`context.name == "from_signed_envelope"`, excluding monomorphized iterator
helpers/closures the demangled-name regex also matches):

| call from from_signed_envelope | vuln 0.30.0 | patched 0.30.2 |
|--------------------------------|-------------|----------------|
| bcmp                           | 0           | 1              |
| total resolvable calls (TC)    | 5           | 6              |
| to_peer_id / from_public_key   | 0 / 0       | 0 / 0 (inlined)|
| multihash from_bytes / decode  | 1 / 1       | 1 / 1          |

The +1 total call and the bcmp delta are the only engine-observable difference;
all DIRECT (e8) named call targets are byte-identical between the two builds.

## Reproducing the test binaries

Both versions have the same public API for `PeerRecord::from_signed_envelope`; the only runtime difference is whether the mismatched-key check fires.

**Cargo.toml (vulnerable pin):**
```toml
[package]
name = "peer-record-probe"
version = "0.1.0"
edition = "2021"

[dependencies]
libp2p-core = "=0.30.0"
```

**Cargo.toml (patched pin):**
```toml
[dependencies]
libp2p-core = "=0.30.2"
```

**src/main.rs** — minimal consumer that exercises `PeerRecord::from_signed_envelope`:

```rust
use libp2p_core::identity::Keypair;
use libp2p_core::signed_envelope::SignedEnvelope;
use libp2p_core::PeerRecord;

// Domain and payload type constants from the crate
const DOMAIN_SEP: &str = "libp2p-routing-state";
const PAYLOAD_TYPE: &str = "/libp2p/routing-state-record";

fn main() {
    let keypair = Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id();

    // Build a valid PeerRecord and sign it
    let addr: libp2p_core::Multiaddr = "/ip4/127.0.0.1/tcp/1234".parse().unwrap();
    let record = PeerRecord::new(keypair, vec![addr]).expect("valid record");
    let envelope = record.into_signed_envelope();

    // Round-trip: parse back from the signed envelope
    let reconstructed = PeerRecord::from_signed_envelope(envelope)
        .expect("should parse and verify");
    assert_eq!(reconstructed.peer_id(), &peer_id);
    println!("peer id verified: {}", peer_id);
}
```

**Build to Linux ELF (zig-cc linker wrapper):**

```sh
# Create zig-cc linker wrapper
cat > /tmp/zig-cc-linux.sh <<'EOF'
#!/bin/sh
exec zig cc -target x86_64-linux-gnu "$@"
EOF
chmod +x /tmp/zig-cc-linux.sh

# Build (with symbols, no strip)
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/tmp/zig-cc-linux.sh \
  cargo build \
    --target x86_64-unknown-linux-gnu \
    --release
# Output: target/x86_64-unknown-linux-gnu/release/peer-record-probe
# Switch Cargo.toml dependency between =0.30.0 and =0.30.2 to get the two ELFs.
```

**API differences between 0.30.0 and 0.30.2:** None that affect the consumer. `PeerRecord::from_signed_envelope` has the same signature in both versions. The `FromEnvelopeError` enum gains a `MismatchedSignature` variant in 0.30.2 but that is additive. The `SignedEnvelope::key` field becomes `pub(crate)` in 0.30.2 but that is internal. No external API breaks.

**Note on libp2p-core 0.30.0 build requirements:** The crate uses `prost-build` (build-time protobuf codegen) and `ring` (native crypto). The zig-cc wrapper handles the C/C++ compilation for `ring` on Linux targets. Ensure `protoc` is available or that the pre-generated protobuf files are present; libp2p-core 0.30.x ships pre-generated protobuf sources so `protoc` is not strictly required.

Committed sample artifacts:

```
RUSTSEC-2022-0009/Cargo.lock
RUSTSEC-2022-0009/Cargo.toml
RUSTSEC-2022-0009/patched/Cargo.lock
RUSTSEC-2022-0009/patched/Cargo.toml
RUSTSEC-2022-0009/patched/peer-record-probe.patched.elf
RUSTSEC-2022-0009/peer-record-probe.vuln.elf
RUSTSEC-2022-0009/src/main.rs
```

## Upstream fix

Patch: https://github.com/libp2p/rust-libp2p/commit/44d63d8ed4f3e5727c2a38422e79d59147004c75

Fix commit: `44d63d8ed4f3e5727c2a38422e79d59147004c75`
PR: `#2491` ("core/src/: Validate PeerRecord signature matching peer ID")
Authors: Max Inden <mail@max-inden.de>, Marco Munizaga
Date: 2022-02-09

Two files were changed:

**core/src/signed_envelope.rs** — expose the `key` field within the crate:

```diff
diff --git a/core/src/signed_envelope.rs b/core/src/signed_envelope.rs
index a528cb08..73efcc99 100644
--- a/core/src/signed_envelope.rs
+++ b/core/src/signed_envelope.rs
@@ -10,7 +10,7 @@ use unsigned_varint::encode::usize_buffer;
 #[derive(Debug, Clone, PartialEq)]
 pub struct SignedEnvelope {
-    key: PublicKey,
+    pub(crate) key: PublicKey,
     payload_type: Vec<u8>,
     payload: Vec<u8>,
     signature: Vec<u8>,
```

**core/src/peer_record.rs** — add the cross-check immediately after decoding the peer ID:

```diff
diff --git a/core/src/peer_record.rs b/core/src/peer_record.rs
index 18b62d23..54771ba2 100644
--- a/core/src/peer_record.rs
+++ b/core/src/peer_record.rs
@@ -36,6 +36,11 @@ impl PeerRecord {
         let record = peer_record_proto::PeerRecord::decode(payload)?;
 
         let peer_id = PeerId::from_bytes(&record.peer_id)?;
+
+        if peer_id != envelope.key.to_peer_id() {
+            return Err(FromEnvelopeError::MismatchedSignature);
+        }
+
         let seq = record.seq;
         ...
+    /// The signer of the envelope is different than the peer id in the record.
+    MismatchedSignature,
```

**What the fix added:** A single guard block inserted at line ~39 of `from_signed_envelope`, immediately after `PeerId::from_bytes` decodes the record's claimed peer ID. The guard calls `envelope.key.to_peer_id()` — which resolves at runtime to `PeerId::from_public_key(&envelope.key)` via the `From<&PublicKey> for PeerId` impl — and compares the result with the `peer_id` decoded from the protobuf payload. If they differ, the function returns `Err(FromEnvelopeError::MismatchedSignature)` immediately. Before this fix, no such comparison existed: the signing public key was verified (envelope signature check) but never checked against the PeerId in the payload.

The companion change to `signed_envelope.rs` (making `key` `pub(crate)`) was necessary to allow `peer_record.rs` to read `envelope.key` directly; without that, the field was private and the comparison could not be written.

## Provenance

Generated by the multi-agent CVE-rule pipeline (research → build both versions → binary-observable discriminator → self-verify → independent GATE). Build recipe, discriminator, and scan results above are drawn from the pipeline's research dossier and signature notes for this CVE.

References:

- RUSTSEC: https://rustsec.org/advisories/RUSTSEC-2022-0009.html
- GHSA: https://github.com/advisories/GHSA-wc36-xgcc-jwpr
