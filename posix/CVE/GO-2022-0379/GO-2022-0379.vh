author = "vulhunt-pipeline"
name = "GO-2022-0379"
platform = "posix-binary"
architecture = "*:*:*"
signatures = {project = "github.com/docker/distribution", from = "2.7.1", to = "2.8.0"}

-- GO-2022-0379 / GHSA-qq97-vm5h-rrhg (CWE-843, type confusion) in the manifest
-- unmarshalling code of github.com/docker/distribution < v2.8.0. The registry
-- dispatches an uploaded manifest body to a closure keyed on the request
-- Content-Type (distribution.UnmarshalManifest, reached from
-- (*manifestHandler).PutManifest). The OCI image-index closure (imageIndexFunc,
-- registered for application/vnd.oci.image.index.v1+json) and the OCI
-- image-manifest closure (ocischemaFunc, registered for
-- application/vnd.oci.image.manifest.v1+json) performed NO structural
-- pre-validation: they called m.UnmarshalJSON(b) directly. A schema-2 manifest
-- (config+layers) presented as an OCI index, or an OCI index (manifests array)
-- presented as an OCI manifest, decodes silently as the opposing type. Because
-- the manifest digest is the SHA-256 of the raw bytes, the same digest can refer
-- to two distinct manifest types depending on the Content-Type the client
-- requests -> digest/type-confusion, undermining content-addressability
-- (integrity bypass / supply-chain confusion).
--
-- The v2.8.0 fix (distribution commit b59a6f8, backported into docker/distribution
-- v2.8.0) inserts a structural guard as the FIRST statement of each closure,
-- BEFORE UnmarshalJSON:
--   * manifest/manifestlist/manifestlist.go: validateIndex(b) -- rejects a body
--     carrying `config`/`layers` ("index: expected index but found manifest").
--   * manifest/ocischema/manifest.go:        validateManifest(b) -- rejects a body
--     carrying `manifests` ("ocimanifest: expected manifest but found index").
-- Each is a NEW named package-level function that calls json.Unmarshal + errors.New;
-- both survive codegen as distinct callable `T` symbols.
--
-- DISCRIMINATOR (fix-added named symbols, telnetd model). Verified with
-- `go tool nm` on registry ELFs built from the v2.7.1 and v2.8.0 tags:
--   vuln  v2.7.1: manifestlist.init.0 present; manifestlist.validateIndex and
--                 ocischema.validateManifest ABSENT from the binary entirely.
--   patch v2.8.0: manifestlist.init.0 present; manifestlist.validateIndex and
--                 ocischema.validateManifest present as `T` symbols, each CALLed
--                 from its registered unmarshal closure before UnmarshalJSON.
-- The closure symbols themselves (init.0.func1/func2) are renumbered between the
-- two builds and the OCI vs Docker manifest-list closures are nearly identical at
-- the call level, so we do NOT scope a closure. Instead we anchor on the package
-- init `manifest/manifestlist.init.0` (single stable symbol present in BOTH builds)
-- and discriminate on GLOBAL presence of the fix's validator symbols via
-- project:functions{kind="symbol"}: fire ONLY when the fix validators are ABSENT
-- (vulnerable); return nil when present (patched -> silent). The engine has no
-- library-version gate, so this structural absence — not the symbol/version — is
-- what proves the vulnerable build.

scopes = scope:functions{
  target = {matching = "manifest/manifestlist\\.init\\.0$", kind = "symbol"},
  with = check
}

function check(project, context)
  -- Fix signature: the two new structural validators added in v2.8.0. Either one
  -- present means the patched OCI manifest/index pre-validation is compiled in.
  local validate_index = project:functions({
    matching = "manifest/manifestlist\\.validateIndex$",
    kind = "symbol"
  })
  local validate_manifest = project:functions({
    matching = "manifest/ocischema\\.validateManifest$",
    kind = "symbol"
  })

  if validate_index ~= nil or validate_manifest ~= nil then
    -- patched (>= v2.8.0): OCI index/manifest bodies are structurally validated
    -- before UnmarshalJSON -> type confusion rejected -> not vulnerable
    return
  end

  return result:high{
    name = "GO-2022-0379",
    description = "github.com/docker/distribution < v2.8.0: type-confusion (CWE-843) in OCI manifest unmarshalling. The closures registered for application/vnd.oci.image.index.v1+json (imageIndexFunc) and application/vnd.oci.image.manifest.v1+json (ocischemaFunc), reached via distribution.UnmarshalManifest from the registry manifest PUT handler, call UnmarshalJSON directly with no structural pre-validation. A schema-2 manifest (config+layers) sent as an OCI image-index, or an OCI index (manifests array) sent as an OCI image-manifest, decodes silently as the opposing type; since the digest is the SHA-256 of the raw bytes, one digest can resolve to two distinct manifest types depending on the requested Content-Type, breaking content-addressability (integrity bypass / digest confusion). The v2.8.0 fix adds the validateIndex / validateManifest structural guards before UnmarshalJSON; neither validator symbol is present in this binary, so the unvalidated type-confusion path is reachable.",
    provenance = {
      kind = "posix.ELF",
      linkage = "project",
      vendor = "docker",
      product = "distribution",
      license = "Apache-2.0",
      affected_versions = {"<2.8.0"}
    },
    cwes = {"CWE-843"},
    cvss = cvss:v3_1{
      base = "5.3",
      exploitability = "3.9",
      impact = "1.4",
      vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
    },
    advisory = "https://pkg.go.dev/vuln/GO-2022-0379",
    patch = "https://github.com/distribution/distribution/commit/b59a6f827947f9e0e67df0cfb571046de4733586",
    identifiers = {"GO-2022-0379", "GHSA-qq97-vm5h-rrhg"},
    references = {
      ["Go"] = "https://pkg.go.dev/vuln/GO-2022-0379",
      ["GHSA"] = "https://github.com/advisories/GHSA-qq97-vm5h-rrhg"
    },
    evidence = {
      functions = {
        [context.address] = {
          annotate:prototype "func init() // manifest/manifestlist: registers imageIndexFunc for application/vnd.oci.image.index.v1+json",
          annotate:at{
            location = context.address,
            message = "The OCI manifest/index unmarshal closures registered by this package init call UnmarshalJSON with no structural type check. The v2.8.0 fix's validators `manifest/manifestlist.validateIndex` and `manifest/ocischema.validateManifest` are absent from this binary, so a manifest body presented with the wrong OCI Content-Type is parsed as the opposing type (digest/type confusion, CWE-843)."
          }
        }
      }
    }
  }
end

--
-- vim: ft=lua
