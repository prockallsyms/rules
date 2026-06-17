# GO-2022-0379 — fix-added validators validateIndex/validateManifest absent in v2

| | |
|---|---|
| **Library** | `github.com/docker/distribution` |
| **Aliases** | GHSA-qq97-vm5h-rrhg |
| **CWE** | CWE-843 |
| **Affected / fixed** | `>= 2.7.1` … fixed in `2.8.0` |
| **Rule** | [`GO-2022-0379.vh`](./GO-2022-0379.vh) |

## Summary

GO-2022-0379 (GHSA-qq97-vm5h-rrhg) is a type-confusion vulnerability (CWE-843) in the
manifest unmarshalling code of `github.com/docker/distribution` before v2.8.0. When a
container registry receives a manifest payload over HTTP, it dispatches to a registered
unmarshal function keyed on the `Content-Type` header. The vulnerability is that the OCI
image-index unmarshal function (`imageIndexFunc`, registered for
`application/vnd.oci.image.index.v1+json`) and the OCI image-manifest unmarshal function
(`ocischemaFunc`, registered for `application/vnd.oci.image.manifest.v1+json`) performed
no structural pre-validation: a manifest body could be presented with the wrong Content-Type
and it would be parsed silently as the opposing type. A schema-2 manifest (with `config` +
`layers` fields) sent as an OCI image-index, or an OCI index (with a `manifests` array) sent
as an OCI image-manifest, would decode successfully, producing a mistyped object in the
registry. This enables digest-confusion attacks: the same digest (SHA-256 of the raw bytes)
could refer to two logically distinct manifest types depending on which Content-Type the
client requests, undermining the content-addressability guarantee of the registry. Impact:
integrity bypass / supply-chain confusion in container image distribution; no memory safety
impact, no RCE.

## Detection discriminator

This engine has no library-version gate, so the rule proves the **vulnerable code structure** and is silent on the patched build.

The v2.8.0 fix adds two NEW named package-level validator functions, called as the
first statement of the OCI manifest/index unmarshal closures before UnmarshalJSON:
- `github.com/docker/distribution/manifest/manifestlist.validateIndex`
- `github.com/docker/distribution/manifest/ocischema.validateManifest`

Both survive codegen as distinct `T` symbols (each calls json.Unmarshal + errors.New,
non-inlinable). They are ABSENT from the vulnerable v2.7.1 binary entirely and PRESENT
in v2.8.0.

`go tool nm` (registry built from cmd/registry):
```
# vuln v2.7.1
go tool nm registry-v2.7.1 | grep -E 'validateIndex|validateManifest'   -> (none)
go tool nm registry-v2.7.1 | grep -E 'manifestlist\.init\.0$'            -> 8a8520 T ...manifestlist.init.0
# patch v2.8.0
go tool nm registry-v2.8.0 | grep -E 'validateIndex|validateManifest'
  -> 8a9700 T ...manifest/manifestlist.validateIndex
  -> 8aa960 T ...manifest/ocischema.validateManifest
```

`go tool objdump` confirms the call-site change (patched manifestlist imageIndexFunc
closure init.0.func2 callees include `...manifestlist.validateIndex` before
`(*DeserializedManifestList).UnmarshalJSON`; vuln closures call only UnmarshalJSON).

## Reproducing the test binaries

Both v2.7.1 and v2.8.0 have no top-level `go.mod`; they are built in GOPATH mode with the
in-repo `vendor/` tree. The build pattern is identical to CVE-2017-11468 and CVE-2023-2253
(see `examples/cve-samples/`).

### Vulnerable: v2.7.1

```sh
export GOPATH=$(mktemp -d)
mkdir -p "$GOPATH/src/github.com/docker"
git clone --depth=1 --branch v2.7.1 \
    https://github.com/docker/distribution.git \
    "$GOPATH/src/github.com/docker/distribution"
cd "$GOPATH/src/github.com/docker/distribution"
GO111MODULE=off GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -o registry-v2.7.1 ./cmd/registry/
```

### Patched: v2.8.0

```sh
export GOPATH=$(mktemp -d)
mkdir -p "$GOPATH/src/github.com/docker"
git clone --depth=1 --branch v2.8.0 \
    https://github.com/docker/distribution.git \
    "$GOPATH/src/github.com/docker/distribution"
cd "$GOPATH/src/github.com/docker/distribution"
GO111MODULE=off GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -o registry-v2.8.0 ./cmd/registry/
```

**API call path:** `distribution.UnmarshalManifest(mediaType, body)` in
`registry/handlers/manifests.go:308`. The handler imports both
`manifest/manifestlist` and `manifest/ocischema` (lines 11-12), whose `init()` functions
register the vulnerable/patched closures. The entrypoint is `cmd/registry/main.go` (package
main) which calls `registry.NewApp(ctx, config)` -> `handlers.NewApp` which wires the HTTP
routes including the manifest PUT handler.

**Triggering input:** A PUT request to the registry at
`/v2/<name>/manifests/<tag>` with
`Content-Type: application/vnd.oci.image.index.v1+json` but a body that is a schema-2
manifest (containing `config` and `layers` fields) — or vice versa. In v2.7.1 this is parsed
without error; in v2.8.0 `validateIndex` rejects it with an error.

**API compatibility:** The function signature of `distribution.UnmarshalManifest` is
identical across v2.7.1 and v2.8.0; no API differences between the two versions.

**Symbol verification (expected):**
```
go tool nm registry-v2.7.1 | grep "validateIndex\|validateManifest"
# → (no output)

go tool nm registry-v2.8.0 | grep "validateIndex\|validateManifest"
# → github.com/docker/distribution/manifest/manifestlist.validateIndex
# → github.com/docker/distribution/manifest/ocischema.validateManifest
```

Committed sample artifacts:

```
GO-2022-0379/BUILD.md
GO-2022-0379/patched/registry-v2.8.0
GO-2022-0379/registry-v2.7.1
```

## Upstream fix

Patch: https://github.com/distribution/distribution/commit/b59a6f827947f9e0e67df0cfb571046de4733586

Fix commit: `b59a6f827947f9e0e67df0cfb571046de4733586` (in `distribution/distribution` v3,
backported into `docker/distribution` v2.8.0 tag).

```diff
diff --git a/manifest/manifestlist/manifestlist.go b/manifest/manifestlist/manifestlist.go
index 55c0224..9cc2fc1 100644
--- a/manifest/manifestlist/manifestlist.go
+++ b/manifest/manifestlist/manifestlist.go
@@ -54,6 +54,9 @@ func init() {

 	imageIndexFunc := func(b []byte) (distribution.Manifest, distribution.Descriptor, error) {
+		if err := validateIndex(b); err != nil {
+			return nil, distribution.Descriptor{}, err
+		}
 		m := new(DeserializedManifestList)
 		err := m.UnmarshalJSON(b)
 		if err != nil {
@@ -221,3 +224,23 @@ func (m DeserializedManifestList) Payload() (string, []byte, error) {
 	return mediaType, m.canonical, nil
 }
+
+type unknownDocument struct {
+	Config interface{} `json:"config,omitempty"`
+	Layers interface{} `json:"layers,omitempty"`
+}
+
+func validateIndex(b []byte) error {
+	var doc unknownDocument
+	if err := json.Unmarshal(b, &doc); err != nil {
+		return err
+	}
+	if doc.Config != nil || doc.Layers != nil {
+		return errors.New("index: expected index but found manifest")
+	}
+	return nil
+}
```

```diff
diff --git a/manifest/ocischema/manifest.go b/manifest/ocischema/manifest.go
index 968de6e..e76e490 100644
--- a/manifest/ocischema/manifest.go
+++ b/manifest/ocischema/manifest.go
@@ -22,6 +22,9 @@ func init() {
 	ocischemaFunc := func(b []byte) (distribution.Manifest, distribution.Descriptor, error) {
+		if err := validateManifest(b); err != nil {
+			return nil, distribution.Descriptor{}, err
+		}
 		m := new(DeserializedManifest)
 		err := m.UnmarshalJSON(b)
 		if err != nil {
@@ -122,3 +125,22 @@ func (m DeserializedManifest) Payload() (string, []byte, error) {
 	return v1.MediaTypeImageManifest, m.canonical, nil
 }
+
+type unknownDocument struct {
+	Manifests interface{} `json:"manifests,omitempty"`
+}
+
+func validateManifest(b []byte) error {
+	var doc unknownDocument
+	if err := json.Unmarshal(b, &doc); err != nil {
+		return err
+	}
+	if doc.Manifests != nil {
+		return errors.New("ocimanifest: expected manifest but found index")
+	}
+	return nil
+}
```

**What the fix added:** Two new validation functions — `validateIndex` (in
`manifest/manifestlist/manifestlist.go`) and `validateManifest` (in
`manifest/ocischema/manifest.go`) — are each called as the first statement inside the
respective registered unmarshal closure, BEFORE `m.UnmarshalJSON(b)`.

- `validateIndex` partially unmarshals the raw JSON into a probe struct that checks for
  `config` or `layers` fie

*(diff truncated — see upstream patch)*

## Verification

```
- vuln  registry-v2.7.1 : FIRED (GHSA-qq97-vm5h-rrhg)
- patch registry-v2.8.0 : SILENT
(query via GHSA alias — engine drops the GO- id string from findings.)
```

## Provenance

Generated by the multi-agent CVE-rule pipeline (research → build both versions → binary-observable discriminator → self-verify → independent GATE). Build recipe, discriminator, and scan results above are drawn from the pipeline's research dossier and signature notes for this CVE.

References:

- Go: https://pkg.go.dev/vuln/GO-2022-0379
- GHSA: https://github.com/advisories/GHSA-qq97-vm5h-rrhg
