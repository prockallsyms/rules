author = "vulhunt-pipeline"
name = "RUSTSEC-2022-0009"
platform = "posix-binary"
architecture = "*:*:*"
signatures = {project = "libp2p-core", from = "0.30.0-rc.1", to = "0.30.2"}

-- RUSTSEC-2022-0009 / GHSA-wc36-xgcc-jwpr — libp2p-core improper signature
-- verification (CWE-347). `PeerRecord::from_signed_envelope` decoded the record's
-- claimed PeerId and verified the envelope signature, but NEVER checked that the
-- signing public key actually derives the claimed PeerId. Fix commit 44d63d8e adds:
--     if peer_id != envelope.key.to_peer_id() { return Err(MismatchedSignature) }
--
-- DISCRIMINATOR (verified live against 0.30.0 vuln vs 0.30.2 patched ELFs):
-- the inserted `peer_id != envelope.key.to_peer_id()` comparison compares two
-- multihash digests, which the compiler lowers to a byte comparison — a call to
-- `bcmp` REACHABLE FROM `from_signed_envelope`. The `to_peer_id`/`from_public_key`
-- derivation is inlined (no named call), but the equality `bcmp` survives codegen.
--   vuln 0.30.0:  from_signed_envelope -> bcmp  = 0 calls  (no key/PeerId check)
--   patched 0.30.2: from_signed_envelope -> bcmp = 1 call   (the added guard)
-- The engine resolves this indirect (PLT) call edge; `context:calls("bcmp")` counts it.
--
-- Rust v0 symbols are matched DEMANGLED by the engine; the scope regex
-- `from_signed_envelope` matches the main fn plus monomorphized helpers/closures,
-- so we gate on `context.name == "from_signed_envelope"` (the engine's short name for
-- the real method). FIRE-WHEN-FIX-ABSENT: report the vuln only when bcmp is NOT
-- reachable from the function; return nil (silent) when the patch's bcmp guard is present.
scopes = scope:functions{
  target = {matching = "from_signed_envelope", kind = "symbol"},
  with = check
}

function check(project, context)
  -- Only the real PeerRecord::from_signed_envelope method, not its monomorphized
  -- iterator helpers/closures (which the demangled-name regex also matches).
  if context.name ~= "from_signed_envelope" then return end

  -- Fix signature: the added `peer_id != envelope.key.to_peer_id()` check lowers
  -- to a byte comparison (bcmp) of the two multihash digests, reachable from this fn.
  local ok, fix_calls = pcall(function()
    return context:calls({matching = "bcmp", kind = "symbol"})
  end)

  -- If the patch's comparison is present, this build is fixed -> stay silent.
  if ok and fix_calls and #fix_calls > 0 then
    return
  end

  -- No PeerId/key cross-check present: vulnerable.
  return result:high{
    name = "RUSTSEC-2022-0009",
    description = "libp2p-core >=0.30.0-rc.1 <0.30.2 (and 0.31.0): PeerRecord::from_signed_envelope verifies the SignedEnvelope signature but never checks that the signing public key derives the PeerId embedded in the record, so an attacker can re-wrap a victim's signed PeerRecord in an envelope signed by their own key and have it accepted as the victim's identity (CWE-347, improper signature verification). The fix adds `if peer_id != envelope.key.to_peer_id() { return Err(MismatchedSignature) }`; this build lacks that PeerId-vs-key comparison (no `bcmp` of the derived digests reachable from from_signed_envelope).",
    provenance = {
      kind = "posix.ELF",
      linkage = "project",
      vendor = "libp2p",
      product = "libp2p-core",
      license = "MIT",
      affected_versions = {">=0.30.0-rc.1", "<0.30.2"}
    },
    cwes = {"CWE-347"},
    cvss = cvss:v3_1{
      base = "8.1",
      exploitability = "2.2",
      impact = "5.2",
      vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
    },
    advisory = "https://rustsec.org/advisories/RUSTSEC-2022-0009.html",
    patch = "https://github.com/libp2p/rust-libp2p/commit/44d63d8ed4f3e5727c2a38422e79d59147004c75",
    identifiers = {"RUSTSEC-2022-0009", "GHSA-wc36-xgcc-jwpr"},
    references = {
      ["RUSTSEC"] = "https://rustsec.org/advisories/RUSTSEC-2022-0009.html",
      ["GHSA"] = "https://github.com/advisories/GHSA-wc36-xgcc-jwpr"
    },
    evidence = {
      functions = {
        [context.address] = {
          annotate:prototype "libp2p_core::PeerRecord::from_signed_envelope(SignedEnvelope) -> Result<PeerRecord, FromEnvelopeError>"
        }
      }
    }
  }
end

--
-- vim: ft=lua
--
