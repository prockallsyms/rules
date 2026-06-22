author = "Binarly"
name = "RUSTSEC-2022-0003"
platform = "posix-binary"
architecture = "*:*:*"

-- Anchor on ammonia's clean_text being linked. The Rust mangled symbol carries a
-- per-version crate-hash prefix (_RNvCs<hash>_7ammonia10clean_text) that differs
-- between 3.1.2 and 3.1.3, so we match on the stable, version-independent path
-- segments "7ammonia10clean_text" (present in BOTH builds -> check runs in both).
scopes = scope:functions{
  target = {matching = "7ammonia10clean_text", kind = "symbol"},
  with = check
}

function check(project, context)
  -- Discriminator (ABSENT-IN-VULNERABLE / PRESENT-IN-PATCHED):
  -- The 3.1.3 fix added the escape-table arm '\r' => "&#13;", introducing the
  -- HTML decimal-entity literal "&#13;" (bytes 26 23 31 33 3b) into .rodata.
  -- The vulnerable 3.1.2 build maps '\r' to the WRONG entity "&#12;" and has no
  -- branch for Form Feed ('\x0c'), so "&#13;" never appears in its binary.
  --
  -- PATCHED  : "&#13;" present  -> fix applied -> return nothing (SILENT).
  -- VULNERABLE: "&#13;" absent  -> Form Feed passes through unescaped -> finding.
  if project:search_string("&#13;", "ascii") then
    return
  end

  return result:high{
    name = "RUSTSEC-2022-0003",
    description = "ammonia 3.0.0..3.1.2 ammonia::clean_text maps Carriage Return ('\\r') to the wrong HTML entity \"&#12;\" and never escapes Form Feed ('\\x0c'). Because HTML5 treats Form Feed as whitespace that terminates an unquoted attribute value, an attacker-controlled \\x0c byte passed through clean_text can break out of an unquoted attribute context and inject arbitrary HTML.",
    provenance = {
      kind = "posix.ELF",
      linkage = "static",
      vendor = "rust-ammonia",
      product = "ammonia",
      license = "MIT OR Apache-2.0",
      affected_versions = {">=3.0.0", "<3.1.3"}
    },
    cwes = {"CWE-79", "CWE-116"},
    identifiers = {"RUSTSEC-2022-0003", "GHSA-p2g9-94wh-65c2"},
    references = {
      ["RUSTSEC"] = "https://rustsec.org/advisories/RUSTSEC-2022-0003.html",
      ["GHSA"] = "https://github.com/advisories/GHSA-p2g9-94wh-65c2"
    },
    patch = "https://github.com/rust-ammonia/ammonia/commit/6c7bf22907a75d1bbaed52e4f7dd9716f5e6f737",
    source = "https://github.com/rust-ammonia/ammonia",
    evidence = {
      functions = {
        [context.address] = {
          annotate:prototype "fn ammonia::clean_text(src: &str) -> String",
          annotate:at{
            location = context.address,
            message = "This is ammonia::clean_text. Its char escape table maps '\\r' to the wrong entity \"&#12;\" and has no arm for Form Feed ('\\x0c'); the absence of the \"&#13;\" literal in this binary confirms the unpatched (pre-3.1.3) escape table, so Form Feed reaches output unescaped and can terminate an unquoted HTML attribute."
          }
        }
      }
    }
  }
end

--
-- vim: ft=lua
--
