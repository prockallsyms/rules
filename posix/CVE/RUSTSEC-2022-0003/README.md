# RUSTSEC-2022-0003 — autonomous run halted on CVE #1 — 2 pipeline defects found+fixed (stripped samples; rodata-string discriminator unmatchable)

| | |
|---|---|
| **Aliases** | GHSA-p2g9-94wh-65c2 |
| **CWE** | CWE-79, CWE-116 |
| **Rule** | [`RUSTSEC-2022-0003.vh`](./RUSTSEC-2022-0003.vh) |

## Summary

The `ammonia::clean_text` function in ammonia versions 3.0.0 through 3.1.2 contained an incorrect character-to-HTML-entity mapping for the Form Feed character (FF, U+000C / `\x0C`). The developer mixed up FF with CR when reading an ASCII table: the `'\r'` (Carriage Return, `\x0D`) arm was mapped to `"&#12;"` (the decimal entity for `\x0C`), leaving the actual Form Feed character unescaped and passing through verbatim. Because HTML5 treats Form Feed as ASCII whitespace — a character that ends an unquoted HTML attribute value — an attacker who could inject a `\x0C` byte into the input of `clean_text` could break out of an unquoted attribute context and inject arbitrary HTML. CWE-116 (Improper Encoding or Escaping of Output). The alias is GHSA-p2g9-94wh-65c2.

## Detection discriminator

This engine has no library-version gate, so the rule proves the **vulnerable code structure** and is silent on the patched build.

NONE — no engine-matchable binary discriminator found.

### Why no discriminator

The fix adds one new escape handler (for char `\x0C`, Form Feed) to the `clean_text` match
dispatch table. In the compiled release binary, this manifests as:

1. **Jump table delta (`.rodata` only):** The jump table at `.rodata` is updated so the `\x0C`
   slot (index 12 in the dispatch table) points to a new handler instead of the default
   pass-through arm. The jump table is in `.rodata`, not in `.text`. The VulHunt engine's
   `project:search_code(<hex>)` matches CODE only — it errors "code outside any function"
   if the match hits `.rodata`. There is no `search_string` primitive.

2. **Rodata string delta:** The string `"&#13;"` (5 bytes: `26 23 31 33 3b`) is present in the
   patched binary but absent in the vulnerable binary. This is the single byte-level observable
   difference. However, it is pure `.rodata` data — no engine API can match it.

3. **Function body code bytes:** After correcting for the PIE segment load bias (text segment:
   file_offset=0x194f0, vaddr=0x1a4f0), the function bodies DO differ (581 of 928 bytes
   differ). However, ALL differing bytes are inside RIP-relative displacement fields of
   `leaq rbx, [rip+disp32]` instructions that load string pointers. The 3-byte opcode prefix
   `48 8d 1d` is identical; only the 4-byte displacement suffix differs. These displacement
   values depend on where the rodata strings are placed (which moved because `"&#13;"` was
   inserted into the escape table). No position-independent instruction byte sequence is
   unique to one build.

4. **Call presence/count:** Both versions have identical call structure (same 8 named call
   targets: `__rust_alloc_error_handler`, `__rust_no_alloc_shim_is_unstable_v2`,
   `__rust_alloc`, `memcpy`, `do_reserve_and_handle` x2, `__rust_dealloc`, `_Unwind_Resume`).
   The `push_str` for escape strings is fully inlined as a `memcpy` call; there is exactly
   ONE `memcpy` call site in both builds (the inline expansion at `0x1a949` / `0x1a8e9`).

5. **Code-byte count delta:** The instruction `movl $5, %r12d; leaq rbx, [rip+...]`
   (bytes `41 bc 05 00 00 00 48 8d 1d`) occurs 6 times in the vulnerable function and 7 times
   in the patched function. However, this is a COUNT discriminator: both build's `clean_text`
   contain at least one instance of this pattern, so `project:search_code(...)` returns
   "found" on BOTH. The VulHunt engine has no "count occurrences" primitive and
   `search_code` returns only the first match.

6. **Decompiler API:** `project:decompile()` is unavailable in vulhunt-ce (returns
   "decompiler extension API unavailable"). Weggli structural queries over decompiled pseudocode
   are therefore not accessible.

### Summary of engine primitive coverage

| Discriminator type             | Present in binary? | Engine primitive        | Matchable? |
|-------------------------------|-------------------|-------------------------|-----------|
| `"&#13;"` string in `.rodata` | YES (patched only) | `search_code` (code-only) | NO       |
| Jump table delta in `.rodata`  | YES               | `search_code` (code-only) | NO       |
| Call presence/absence          | NO delta          | `context:has_call/:calls` | N/A      |
| `push_str` operand string      | Only via rodata ptr | `pre_call_string` (requires decompiler) | NO |
| Code byte PRESENCE diff        | NO unique sequence | `fn:matches`/`search_code` | NO     |
| Code byte COUNT diff (6 vs 7)  | YES               | No count primitive        | NO       |
| Decompiled source query        | Would show `== 12` | `project:decompile` (unavailable) | NO |

**Conclusion:** The only observable code/binary difference between the two `clean_text`
implementations is the count of `movl $5, %r12d; leaq rbx` instruction sequences (6 vs 7),
driven by the additional escape handler. The canonical distinguishing signal is the rodata
string `"&#13;"` — absent in vulnerable, present in patched — which is not matchable by any
current VulHunt engine primitive (code-only `search_code`, no `search_string` API).

This CVE is **BLOCKED** for VulHunt Phase 1 rule authoring. Unblocking requires either:
- A `project:search_bytes(<hex>)` or `search_string(<str>)` rodata primitive in the engine, OR
- The decompiler extension (`project:decompile()`) which would expose the missing `== 12`
  branch via a Weggli structural query.

## Reproducing the test binaries

Add to `Cargo.toml` (vulnerable):
```toml
[dependencies]
ammonia = "=3.1.2"
```

For the patched version:
```toml
[dependencies]
ammonia = "=3.1.3"
```

Minimal consumer (`src/main.rs`) that calls `clean_text` on attacker-style input containing a Form Feed byte:

```rust
fn main() {
    // \x0c is the Form Feed character — the dangerous byte
    // In vulnerable 3.1.2 it passes through unescaped;
    // in 3.1.3 it is replaced with &#12;
    let user_input = "hello\x0cworld";
    let sanitized = ammonia::clean_text(user_input);
    // Simulate embedding in unquoted HTML attribute (the vulnerable pattern)
    let html = format!("<div title={}>content</div>", sanitized);
    println!("{}", html);
    // 3.1.2 prints: <div title=hello\x0cworld>content</div>  <- FF breaks attribute
    // 3.1.3 prints: <div title=hello&#12;world>content</div> <- safe
}
```

The API `ammonia::clean_text` has the same signature (`fn clean_text(src: &str) -> String`) in both 3.1.2 and 3.1.3; no API differences between the two versions. The crate builds with stable Rust (MSRV bumped from 1.41.1 to 1.48.0 in 3.1.3, which is inconsequential for modern toolchains).

Committed sample artifacts:

```
RUSTSEC-2022-0003/patched/rustsec-2022-0003-patched.elf
RUSTSEC-2022-0003/rustsec-2022-0003-vuln.elf
```

## Upstream fix

Patch: https://github.com/rust-ammonia/ammonia/commit/6c7bf22907a75d1bbaed52e4f7dd9716f5e6f737

Fix commit: `6c7bf22907a75d1bbaed52e4f7dd9716f5e6f737` (merged into v3.1.3 via PR #147).

```diff
diff --git a/src/lib.rs b/src/lib.rs
index 8f9fc96..c1fada5 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -143,7 +143,8 @@ pub fn clean_text(src: &str) -> String {
             ' ' => "&#32;",
             '\t' => "&#9;",
             '\n' => "&#10;",
-            '\r' => "&#12;",
+            '\x0c' => "&#12;",
+            '\r' => "&#13;",
             // a spec-compliant browser will perform this replacement anyway, but the middleware might not
             '\0' => "&#65533;",
```

**What the fix changed:** The single match arm `'\r' => "&#12;"` was replaced with two arms:

1. `'\x0c' => "&#12;"` — the Form Feed character (U+000C) now correctly maps to the decimal entity `&#12;`.
2. `'\r' => "&#13;"` — Carriage Return (U+000D) now correctly maps to `&#13;`.

Before the fix, the match arm was keyed on `'\r'` (`\x0D`) but produced `"&#12;"` (the entity for `\x0C`). This meant:
- `\r` was escaped (but to the wrong entity, `&#12;` instead of `&#13;`).
- `\x0C` (Form Feed) fell through to the default `_` arm and was passed through **verbatim** — unescaped.

Since HTML5 parsers treat Form Feed as whitespace that terminates an unquoted attribute value, a `\x0C` byte in attacker-controlled input would silently break attribute context, enabling attribute or tag injection. The fix adds the missing `'\x0c'` arm before the `'\r'` arm so FF is now escaped.

## Verification

`RUSTSEC-2022-0003 | PAUSED | autonomous run halted on CVE #1 — 2 pipeline defects found+fixed (stripped samples; rodata-string discriminator unmatchable). Re-validate before resuming.`

## Provenance

Generated by the multi-agent CVE-rule pipeline (research → build both versions → binary-observable discriminator → self-verify → independent GATE). Build recipe, discriminator, and scan results above are drawn from the pipeline's research dossier and signature notes for this CVE.

References:

- RUSTSEC: https://rustsec.org/advisories/RUSTSEC-2022-0003.html
- GHSA: https://github.com/advisories/GHSA-p2g9-94wh-65c2
