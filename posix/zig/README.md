# Zig portable rulepacks

See `../../triage/ZIG-COVERAGE.md`. Of the 8 Zig SAST rules, 6 are inherently
source-only (compile-time builtins `@ptrCast`/`@cImport`/`@intToPtr`, error syntax
`catch unreachable`, secrets-regex). One is shipped:

| Pack | technique | validated |
|------|-----------|-----------|
| zig-insecure-random | call-site match on non-crypto PRNG steps (Random.Xoshiro256/Pcg/Isaac64/… `.next`/`.fill`) | ✅ fires on examples/zigdanger.elf (3 hits) |

Key detail: Zig inlines the PRNG so the generator functions aren't registered as
*named functions* (scope:functions misses them), but they remain reachable as
**call targets** — so the rule uses `scope:calls` with the exact dotted symbols.
The secure CSPRNG (`Random.ChaCha`) is intentionally excluded.

`std.process.Child` (command-exec) is deferred — Zig 0.16 moved spawning to the
`std.Io` interface and the symbol surface is unstable across releases.

## Build a Zig test binary
```sh
zig build-exe -target x86_64-linux-gnu -O Debug -femit-bin=zigdanger.elf zigdanger.zig
```
(`-O Debug` keeps symbols; release inlines/strips more.)
