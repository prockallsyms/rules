author = "prockallsyms"
name = "RUSTSEC-2025-0005"
platform = "posix-binary"
architecture = "*:*:*"
signatures = {project = "grcov", from = "0.0.0", to = "0.8.20"}

-- RUSTSEC-2025-0005 / GHSA-qm2p-4w45-v2vr -- CWE-787 (Out-of-Bounds Write) in
-- grcov <= 0.8.19.
--
-- `grcov::covdir::CDFileStats::get_coverage` (src/covdir.rs) builds a
-- `Vec<i64>` of length `last_line` and then, for each (line_num, line_count)
-- entry of a caller-supplied `BTreeMap<u32, u64>`, writes line_count into index
-- `line_num - 1` via:
--     unsafe { *lines.get_unchecked_mut((*line_num - 1) as usize) = line_count as i64; }
-- with NO bounds check. A `line_num` of 0 makes `*line_num - 1` wrap to
-- usize::MAX (unsigned), so the write lands far outside the Vec allocation,
-- corrupting adjacent heap memory -- a CWE-787 OOB write reachable from the
-- public API `CDFileStats::new` / `output_covdir` when processing
-- attacker-controlled coverage data.
--
-- The fix (commit c821956, v0.8.20) replaces the unchecked write with a
-- bounds-checked `if let Some(line) = lines.get_mut((*line_num - 1) as usize)`.
-- `get_mut` performs `idx < len` and skips the write when out of bounds.
--
-- get_coverage is NOT a separate symbol: in both release ELFs it is inlined
-- into `grcov::covdir::CDFileStats::new` (the only remaining covdir symbols are
-- CDFileStats::new and ::to_json). The structural delta lives inside ::new.
--
-- Engine-matchable discriminator (verified by `objdump -d` of CDFileStats::new
-- on both ELFs; Rust v0 symbols matched in demangled, readable form):
--   VULN  (0.8.19) write site -- unconditional indexed store, NO compare:
--       8b 54 a2 60        MOVL  0x60(%rdx,%r12,4),%edx   ; line_num
--       ff ca              DECL  %edx                     ; idx = line_num - 1
--       49 89 7c d5 00     MOVQ  %rdi,(%r13,%rdx,8)       ; lines[idx] = val (UNCHECKED)
--     = the contiguous run `ff ca 49 89 7c d5 00` (decl-then-store, no cmp/jbe).
--   PATCH (0.8.20) write site -- get_mut bounds check before the store:
--       8b 7c b2 60        MOVL  0x60(%rdx,%rsi,4),%edi   ; line_num
--       ff cf              DECL  %edi                     ; idx = line_num - 1
--       39 fb              CMPL  %edi,%ebx                 ; len vs idx  <-- BOUNDS CHECK
--       0f 86 ..           JBE   <skip>                    ; skip write if idx >= len
--       ... 49 89 54 fd 00 MOVQ  %rdx,(%r13,%rdi,8)        ; checked store
--     = the run `ff cf 39 fb` (decl-then-compare).
--
-- Whole-binary byte-run occurrences (Python .count over the raw ELF):
--   VULN run  `ffca49897cd500` : 1x in 0.8.19, 0x in 0.8.20  (binary-unique to vuln)
--   PATCH run `ffcf39fb`       : 0x in 0.8.19, 2x in 0.8.20
-- So the vulnerable unchecked-write run is itself a binary-unique positive
-- signal of the unpatched code.
--
-- Rule model: VULN-PRESENT pattern (match it directly). The symbol
-- `CDFileStats::new` exists in both builds (no version gate), so we scope to it
-- -- ensuring the covdir/get_coverage path is actually linked -- and emit ONLY
-- when the unchecked-write run is present binary-wide. A patched (>= 0.8.20)
-- build replaces it with the bounds-checked store and stays SILENT.

local SCOPE = "covdir.*CDFileStats.*new"
local VULN_RUN = "ffca49897cd500"

scopes = {
  scope:functions{
    target = {matching = SCOPE, kind = "symbol"},
    using = {},
    with = check
  }
}

function check(project, context)
  -- project:search_code can RAISE an uncaught Lua error on some ELFs; an
  -- unhandled error aborts the whole scan (zeroes every rule in the dir).
  -- pcall-guard so a failure degrades to "pattern absent" for THIS rule only.
  -- Hex MUST be contiguous (no spaces).
  local function safe_search(hex)
    local ok, res = pcall(function() return project:search_code(hex) end)
    return ok and res
  end

  -- Vuln-signal: the unchecked indexed write `DECL idx ; MOVQ val,(base+idx*8)`
  -- with no preceding bounds compare. Unique to grcov <= 0.8.19 (0x in 0.8.20,
  -- where get_mut inserts a CMP/JBE before the store). Absent -> patched build.
  if not safe_search(VULN_RUN) then
    return
  end

  return result:high{
    name = "RUSTSEC-2025-0005",
    description = "grcov <= 0.8.19: Out-of-Bounds Write (CWE-787) in `grcov::covdir::CDFileStats::get_coverage`. The function allocates a `Vec<i64>` of length `last_line` then writes each coverage entry into index `line_num - 1` via `unsafe { *lines.get_unchecked_mut((*line_num - 1) as usize) = line_count as i64; }` with no bounds check. A `line_num` of 0 makes `line_num - 1` wrap to usize::MAX, so the write lands outside the Vec allocation and corrupts adjacent heap memory -- reachable from the public `CDFileStats::new` / `output_covdir` API when processing attacker-controlled coverage data. get_coverage is inlined into `CDFileStats::new`; this build contains the unchecked decl-then-store instruction run `ffca49897cd500` (DECL idx ; MOVQ val,(base+idx*8) with no preceding CMP/JBE bounds check), which is unique to the unpatched code (0 occurrences in 0.8.20). The fix (commit c821956, v0.8.20) replaces get_unchecked_mut with a bounds-checked `if let Some(line) = lines.get_mut(...)`. Upgrade grcov to >= 0.8.20.",
    provenance = {
      kind = "posix.ELF",
      linkage = "project",
      vendor = "mozilla",
      product = "grcov",
      license = "MPL-2.0",
      affected_versions = {"<=0.8.19"}
    },
    cwes = {"CWE-787"},
    advisory = "https://rustsec.org/advisories/RUSTSEC-2025-0005.html",
    patch = "https://github.com/mozilla/grcov/commit/c821956",
    identifiers = {"GHSA-qm2p-4w45-v2vr", "RUSTSEC-2025-0005"},
    references = {
      ["RUSTSEC"] = "https://rustsec.org/advisories/RUSTSEC-2025-0005.html",
      ["GHSA"] = "https://github.com/advisories/GHSA-qm2p-4w45-v2vr"
    },
    evidence = {
      functions = {
        [context.address] = {
          annotate:at{
            location = context.address,
            message = "grcov::covdir::CDFileStats::get_coverage (inlined into CDFileStats::new) writes coverage values into `lines[line_num - 1]` via an UNCHECKED `get_unchecked_mut`; line_num 0 wraps the index to usize::MAX -> out-of-bounds heap write (CWE-787). The unchecked decl-then-store run `ffca49897cd500` (no preceding bounds CMP/JBE) is present, identifying grcov <= 0.8.19. The v0.8.20 fix (commit c821956) adds a get_mut bounds check. Upgrade grcov to >= 0.8.20."
          }
        }
      }
    }
  }
end

--
-- vim: ft=lua
--
