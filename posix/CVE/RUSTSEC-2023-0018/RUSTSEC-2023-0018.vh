author = "vulhunt-pipeline"
name = "RUSTSEC-2023-0018"
platform = "posix-binary"
architecture = "*:*:*"
signatures = {project = "remove_dir_all", from = "0.7.0", to = "0.8.0"}

-- RUSTSEC-2023-0018 / GHSA-mc8h-8q98-g5hr: the `remove_dir_all` Rust crate < 0.8.0
-- has a TOCTOU / symlink-following race (CWE-363/CWE-367/CWE-59) in its recursive
-- directory removal. On unix, pre-fix traversal used path-based `fs::read_dir(path)`
-- + `fs::remove_file(path)` (re-resolved at every step, no fd anchor); an attacker who
-- controls the target tree can swap an interior component for a symlink between the
-- check and the deletion syscall, causing a privileged caller to delete files outside
-- the intended tree (mirrors CVE-2022-21658). The unix `remove_dir_all` itself is a bare
-- `pub use std::fs::remove_dir_all` (no crate symbol), so we do not anchor on it; we
-- anchor on the crate-owned `remove_dir_all` traversal functions present in BOTH builds.
--
-- Fix (commit 7247a8b6ee59fc99bbb69ca6b3ca4bfd8c809ead, released 0.8.0) rewrote the
-- core traversal on ALL platforms to use file-descriptor-relative `*at`-family syscalls
-- via the NEW `fs_at` crate (`fs_at::read_dir`, `open_dir_at` with O_NOFOLLOW,
-- `rmdir_at`, `unlink_at`). The `fs_at` dependency does not exist in any pre-0.8.0
-- Cargo.toml, so a binary linked against a vulnerable `remove_dir_all` carries ZERO
-- `fs_at`-namespaced symbols, while any 0.8.0+ binary carries them (verified by nm:
-- 0 fs_at symbols in the 0.7.0 ELF, 31 in the 0.8.0 ELF; both retain the crate-owned
-- `remove_dir_all` traversal symbol).
--
-- Binary discriminator (verified live with the engine's own project:functions view):
--   VULN 0.7.0:  scope `remove_dir_all` matches; project:functions("fs_at") == nil.
--   PATCH 0.8.0: scope `remove_dir_all` matches; project:functions("fs_at") ~= nil.
--
-- telnetd model: scope the present-in-both `remove_dir_all` crate symbol. The engine has
-- no library-version gate, so we discriminate STRUCTURALLY: if any `fs_at`-namespaced
-- symbol is present, the 0.8.0 fd-relative rewrite is compiled in -> return nil (silent).
-- Otherwise the crate still ships the path-based unix traversal -> vulnerable.

local SCOPE = "remove_dir_all"
local FIX_MARKER = "fs_at"

scopes = {
  scope:functions{
    target = {matching = SCOPE, kind = "symbol"},
    using = {},
    with = check
  }
}

function check(project, context)
  local fns = project:functions({matching = SCOPE, kind = "symbol", all = true})
  if type(fns) ~= "table" or #fns == 0 then
    return
  end

  -- Fix present (>= 0.8.0): the fd-relative rewrite links the NEW `fs_at` crate, so
  -- `fs_at`-namespaced symbols exist in the binary. Single-form ~= nil check.
  local fixed = project:functions({matching = FIX_MARKER, kind = "symbol"})
  if fixed ~= nil then
    return
  end

  return result:high{
    name = "RUSTSEC-2023-0018",
    description = "remove_dir_all Rust crate < 0.8.0: TOCTOU / symlink-following race (CWE-363/CWE-367/CWE-59) in recursive directory removal. On unix the pre-0.8.0 traversal (remove_dir_contents / ensure_empty_dir / the unix _remove_dir_contents helper) used path-based fs::read_dir(path) and fs::remove_file(path), re-resolving each path component at every step with no file-descriptor anchor. An attacker who controls the target directory tree can replace an interior component with a symlink between the directory walk and the deletion syscall, causing a privileged caller to delete files outside the intended tree (mirrors CVE-2022-21658). The 0.8.0 fix (commit 7247a8b) rewrites traversal to file-descriptor-relative *at syscalls via the new fs_at crate (fs_at::read_dir, open_dir_at with O_NOFOLLOW, rmdir_at, unlink_at). This binary links the crate-owned remove_dir_all traversal but carries NO fs_at-namespaced symbols, so the path-based vulnerable traversal is still compiled in (vulnerable < 0.8.0). Upgrade remove_dir_all to >= 0.8.0.",
    provenance = {
      kind = "posix.ELF",
      linkage = "project",
      vendor = "XAMPPRocky",
      product = "remove_dir_all",
      license = "MIT",
      affected_versions = {"<0.8.0"}
    },
    cwes = {"CWE-363", "CWE-367", "CWE-59"},
    cvss = cvss:v3_1{
      base = "7.0",
      exploitability = "1.0",
      impact = "5.9",
      vector = "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"
    },
    advisory = "https://rustsec.org/advisories/RUSTSEC-2023-0018.html",
    patch = "https://github.com/XAMPPRocky/remove_dir_all/commit/7247a8b6ee59fc99bbb69ca6b3ca4bfd8c809ead",
    identifiers = {"RUSTSEC-2023-0018", "GHSA-mc8h-8q98-g5hr"},
    references = {
      ["RUSTSEC"] = "https://rustsec.org/advisories/RUSTSEC-2023-0018.html",
      ["GHSA"] = "https://github.com/advisories/GHSA-mc8h-8q98-g5hr"
    },
    evidence = {
      functions = {
        [context.address] = {
          annotate:prototype "remove_dir_all crate traversal (remove_dir_contents / ensure_empty_dir) -- path-based, no fd anchor (< 0.8.0)",
          annotate:at{
            location = context.address,
            message = "remove_dir_all crate-owned recursive traversal is present but the binary carries NO fs_at-namespaced symbols, so the pre-0.8.0 path-based fs::read_dir / fs::remove_file traversal (no file-descriptor anchoring) is compiled in. An attacker who can swap an interior path component for a symlink during the walk can escape the target tree (TOCTOU / symlink-following, CWE-363/367/59). Upgrade remove_dir_all to >= 0.8.0 (fd-relative *at traversal via the fs_at crate)."
          }
        }
      }
    }
  }
end

--
-- vim: ft=lua
--
