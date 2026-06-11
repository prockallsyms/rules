# Community-contributed VulHunt rules

VulHunt (`.vh`) rules for scanning compiled binaries, organized by target platform.

## Layout

```
posix/         POSIX/ELF rules
  CVE-*.vh       per-CVE detections
  c/             C dangerous-API + operand/dataflow packs
  cpp/           C++ (Qt, boost, POCO, gRPC, protobuf, …)
  go/            Go stdlib + library packs (jwt, sql, template, redis, …)
  rust/          Rust crate packs (crypto, TLS, jwt, sql, archive, FFI, …)
  zig/           Zig packs
uefi/          UEFI firmware rules
```

The language packs under `posix/` are ported from popular SAST rulesets and detect
dangerous/risky API usage that survives compilation to the binary (call presence,
constant-argument operand checks, call-ordering, and Weggli-on-decompiled patterns).
Each language directory has its own `README.md` describing the packs and how they were
validated.

## Running

```sh
export BIAS_DATA=/path/to/biasdata
# scan with one language pack
vulhunt-ce scan <elf> -d "$BIAS_DATA" -r posix/c --pretty
# or load a whole platform tree recursively (rules self-filter by platform/arch)
vulhunt-ce scan <elf> -d "$BIAS_DATA" -r posix --pretty
```
