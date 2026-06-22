author = "vulhunt-cve-pipeline"
name = "RUSTSEC-2024-0402"
platform = "posix-binary"
architecture = "*:*:*"
signatures = {project = "hashbrown", from = "0.15.0", to = "0.15.1"}

-- RUSTSEC-2024-0402 / GHSA-wwq9-3cpr-mm53 -- hashbrown 0.15.0 borsh feature
-- non-canonical HashMap serialization (CWE-1180).
--
-- hashbrown 0.15.0 introduced an optional `borsh` feature (PR #525) providing
-- `BorshSerialize` / `BorshDeserialize` impls for `hashbrown::HashMap`
-- (src/external_trait_impls/borsh/hash_map.rs). The `BorshSerialize::serialize`
-- impl iterated the map with `self.iter()` -- raw hash-table order, which depends
-- on insertion history, hash seed and memory layout -- and wrote entries in that
-- order. This violates Borsh's canonicity guarantee (identical data MUST encode to
-- identical bytes), which is security-critical in consensus / signing contexts
-- (blockchain, deterministic hashing): two nodes holding logically identical maps
-- can serialize to DIFFERENT byte strings, enabling consensus splits or
-- signature-verification failures. The impl also serialized the hasher state and
-- used platform-dependent `usize` for the length field instead of the spec `u32`.
--
-- Fix (PR #570, v0.15.1) does NOT add a sort: it DELETES the entire borsh module
-- and the `borsh` optional dependency/feature. In 0.15.1 the borsh feature does
-- not exist; no `BorshSerialize` impl for HashMap is compiled, and a consumer
-- cannot call `borsh::to_vec` on a hashbrown::HashMap at all (it fails to compile).
--
-- DISCRIMINATOR (present-only; the fix REMOVES it). Verified live on two real
-- consumer ELFs (debug, symbols retained, cross-compiled x86_64-linux via zig-cc):
--   * vuln  consumer: hashbrown = "=0.15.0", features = ["borsh"], calling
--                     borsh::to_vec(&hashbrown_map).
--   * patch consumer: hashbrown = "=0.15.1" (no borsh feature), calling
--                     borsh::to_vec on a plain Vec (the hashbrown borsh path is
--                     uncompilable) -- a fair SILENT.
-- The `BorshSerialize` impl for HashMap is generic over K/V/S and inlines into the
-- caller in release builds, so the impl method symbol is not a reliable handle.
-- The robust, semantically-grounded handle is borsh's `to_vec` helper monomorphized
-- over a hashbrown HashMap:
--     borsh::ser::helpers::to_vec::<hashbrown::map::HashMap<K, V, S, A>>
-- (engine-demangled match form `to_vec.*hashbrown.*HashMap`). This monomorphization
-- can ONLY exist if `hashbrown::HashMap: BorshSerialize`, i.e. ONLY when the 0.15.0
-- borsh feature impl is present. In 0.15.1 the impl is gone, so `borsh::to_vec`
-- cannot be instantiated for a hashbrown HashMap and this symbol cannot exist.
-- Verified via probe rule (project:functions, engine's actual demangled forms):
--   vuln  : project:functions("to_vec.*hashbrown.*HashMap") -> PRESENT
--   patch : project:functions("to_vec.*hashbrown.*HashMap") -> ABSENT
--
-- NOTE on demangling: the engine matches a MIX of demangled and still-mangled
-- Rust v0 symbols; the readable `BorshSerialize` segment is NOT exposed for the
-- impl method (it stays mangled as `...9hashbrown20external_trait_impls5borsh...`),
-- and a bare `borsh` token also appears in unrelated consumer symbols, so neither
-- is usable. The `to_vec<hashbrown::map::HashMap...>` monomorphization is the only
-- clean, demangled, discriminating handle and was confirmed PRESENT-only.
--
-- Model: scope a common hashbrown HashMap symbol present in BOTH builds (so the
-- rule only fires on a real hashbrown consumer), then FIRE when the
-- borsh-to_vec-over-HashMap monomorphization is PRESENT (vulnerable 0.15.0 borsh
-- path linked); stay SILENT when it is absent (0.15.1, feature removed).

scopes = {
  scope:functions{
    target = {matching = "hashbrown.*HashMap", kind = "symbol"},
    using = {},
    with = check
  }
}

function check(project, context)
  -- Vulnerable signal: borsh::to_vec monomorphized over a hashbrown HashMap. This
  -- exists ONLY when hashbrown's 0.15.0 borsh-feature BorshSerialize impl is present
  -- (it cannot compile in 0.15.1, where the impl/feature were removed).
  local present = project:functions({matching = "to_vec.*hashbrown.*HashMap", kind = "symbol"})
  if present == nil then
    -- borsh serialization of a hashbrown HashMap is not linked -> the 0.15.0 borsh
    -- feature impl is absent (0.15.1 / fix applied) -> not vulnerable -> silent.
    return
  end

  return result:medium{
    name = "RUSTSEC-2024-0402",
    description = "hashbrown 0.15.0 borsh feature: the `BorshSerialize` impl for `hashbrown::HashMap` (src/external_trait_impls/borsh/hash_map.rs) serializes entries in raw hash-table order via `self.iter()`, violating Borsh's canonicity guarantee (CWE-1180): logically identical maps can serialize to different byte strings, enabling consensus splits or signature-verification failures in deterministic-encoding contexts (blockchain/signing). It also serialized the hasher state and used platform-dependent `usize` rather than the spec `u32` for the length field. This binary links `borsh::ser::helpers::to_vec` monomorphized over a `hashbrown::HashMap` -- a symbol that can only exist when the 0.15.0 borsh-feature `BorshSerialize` impl is present. The v0.15.1 fix (PR #570) removed the entire borsh module/feature; upgrade hashbrown to >= 0.15.1 (and stop relying on its borsh impl).",
    provenance = {
      kind = "posix.ELF",
      linkage = "project",
      vendor = "rust-lang",
      product = "hashbrown",
      license = "MIT OR Apache-2.0",
      affected_versions = {"=0.15.0"}
    },
    -- NOTE: CWE-1180 (the advisory's nominal CWE, "Incorrect Behavior Order:
    -- Validate Before Canonicalize") is NOT in this engine's CWE enum and, when
    -- present, silently DROPS the entire finding (verified live). CWE-345
    -- (Insufficient Verification of Data Authenticity) is the accepted, closest
    -- fit: non-canonical serialization undermines deterministic/signed-data
    -- integrity in the consensus/signing contexts this advisory targets.
    cwes = {"CWE-345"},
    advisory = "https://rustsec.org/advisories/RUSTSEC-2024-0402.html",
    patch = "https://github.com/rust-lang/hashbrown/pull/570",
    identifiers = {"RUSTSEC-2024-0402", "GHSA-wwq9-3cpr-mm53"},
    references = {
      ["RUSTSEC"] = "https://rustsec.org/advisories/RUSTSEC-2024-0402.html",
      ["GHSA"] = "https://github.com/advisories/GHSA-wwq9-3cpr-mm53",
      ["fix"] = "https://github.com/rust-lang/hashbrown/pull/570"
    },
    evidence = {
      functions = {
        [context.address] = {
          annotate:at{
            location = context.address,
            message = "This build links `borsh::ser::helpers::to_vec::<hashbrown::map::HashMap<...>>`, which can only be monomorphized when hashbrown's 0.15.0 borsh-feature `BorshSerialize` impl exists. That impl serializes the map in non-canonical hash-table order (RUSTSEC-2024-0402 / GHSA-wwq9-3cpr-mm53, CWE-1180). The fix (hashbrown 0.15.1, PR #570) deletes the borsh feature entirely. Upgrade to >= 0.15.1."
          }
        }
      }
    }
  }
end

--
-- vim: ft=lua
--
