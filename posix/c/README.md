# C portable rulepacks (consolidated from SAST triage)

Themed VulHunt rules ported from `../sast-rules/c`, consolidating the highly
redundant per-sink SAST rules into one rule per theme (see `../../triage/C-TRIAGE.md`).
POSIX/ELF only; Windows-API sinks (StrCpy*, LoadLibrary*, CreateProcess*,
Impersonate*) are deferred to a future `windows-binary` pack.

## Rules & validation

15 consolidated packs covering 122 source rules (see `../../triage/C-COVERAGE.md`).
Validated against `examples/danger*.c.elf` (x86_64 ELF via `zig cc`).

| Rule | Kind | Sev | Validated |
|------|------|-----|-----------|
| c-command-exec | call presence: system/popen/exec* | medium | ✅ system, popen, execl |
| c-string-overflow | call presence: strcpy/strcat/strn*/wcs* | low | ✅ strcpy, strcat |
| c-unbounded-input | call presence: gets/scanf (+`__isoc99_*`) | medium | ✅ gets, scanf→__isoc99_scanf |
| c-weak-random | call presence: rand/random/*rand48 | low | ✅ rand, srand |
| c-temp-file-race | call presence: mktemp/tmpnam/tempnam/tmpfile | low | ✅ mktemp, tmpnam |
| c-weak-crypto | call presence: EVP_des*/rc4/rc2, crypt | medium | ✅ EVP_rc4, EVP_des_cbc |
| c-insecure-file-ops | call presence: chmod/chown/access/readlink/mkfifo | low | ✅ 6/6 in user fn |
| c-obsolete-apis | call presence: usleep/vfork/getpass/getlogin/strtok | info | ✅ 6/6 |
| c-discouraged-memory | call presence: alloca/valloc/memalign | low | ✅ memalign |
| c-unchecked-numeric | call presence: atoi/atol/atof | info | ✅ atoi |
| c-embedded-sinks | call presence: CAN/FOTA/nRF-AT | low/med | ⚠️ unvalidated (no firmware) |
| **c-format-string** | **operand: format arg not compile-time const** | high | ✅ flags `printf(user)`, spares `printf("%s",u)` & `sprintf(b,"name=%s",x)` |
| **c-tls-no-verify** | **operand: const == VERIFY_NONE / 0** | high | ✅ flags NONE & VERIFYPEER=0; spares PEER & VERIFYHOST=2 |
| **c-weak-tls-version** | **operand: const proto < TLS 1.2** | medium | ✅ flags TLS1.0 & SSLv3; spares TLS1.2 |
| **c-memset-misuse** | **operand: length const == 0** | medium | ✅ flags `memset(p,0,0)`, spares `memset(p,0,16)` |
| **c-tainted-input-flow** | **dataflow heuristic: source→sink, ordered** | medium | ✅ flags recv/getenv→strcpy/system, no FP |
| **c-use-after-free** | **Weggli on decompiled C (`extensions="decompiler"`)** | high | ✅ flags double_free/use_after_free, spares freed_ok (realloc) |
| **c-alloc-size-overflow** | **Weggli on decompiled C** | medium | ✅ flags `malloc(x*y)` (mul_alloc); multiply survives decompilation |
| c-openssl-lowlevel-crypto | call presence: MD5_Init/SHA1_Init/RC4/DES/BF/RAND_pseudo_bytes | medium | ✅ libstub (8) |
| c-untrusted-parser-surface | call presence: libtiff/png/jpeg/expat parse | info | ✅ libstub (4) |
| c-decompression-bomb | call presence: inflate/uncompress/gz* | low | ✅ libstub (2) |
| **c-libxml2-xxe** | **operand: parse flags & NOENT/DTDLOAD/HUGE** | high | ✅ libstub (flags NOENT/DTDLOAD; spares 0) |
| **c-curl-insecure-options** | **operand: opt∈{VERIFYSTATUS,PROXY,USE_SSL} & val=0** | medium | ✅ libstub (3) |
| **c-mbedtls-wolfssl-noverify** | **operand: authmode<REQUIRED / VERIFY_NONE** | high | ✅ libstub (spares REQUIRED) |
| **c-sqlite-load-extension** | **operand: enable_load_extension(,1)** | medium | ✅ libstub (spares 0) |
| **c-libarchive-unsafe-extract** | **operand: extract flags missing SECURE bits** | medium | ✅ libstub (spares secure flags) |
| c-tls-missing-hostname-check | **absence**: set_verify w/o X509_check_host | medium | ✅ fires absencetest, spares libstub |
| c-libssh2-no-hostkey-check | **absence**: userauth w/o knownhost_check | high | ✅ fires absencetest, spares libstub |

### Library API rules (from `../../triage/LIBRARY-API-CATALOG.md`)
The block above (c-openssl-lowlevel through c-libssh2-no-hostkey) ports the C library
catalog: OpenSSL low-level, libxml2 XXE, curl extra options, mbedTLS/wolfSSL, SQLite,
libarchive, zlib, image codecs, libssh2. Validated via `examples/libstub.c` (stub
signatures matching real libs) + `examples/absencetest.c`. Const-arg rules use BitVec
band/comparison on the flag/enum operand; absence rules use `project:functions_where`.
| **c-privilege-drop-order** | **ordering: setuid before setgid** | medium | ✅ flags `drop_bad`, spares `drop_ok` |

The operand + dataflow-heuristic packs are the high-signal differentiators over
grep/flawfinder: they read call-argument operands (`context.inputs[i]:is_const()`,
`.constant:is_zero()`, `.constant == BitVec.from_integer(n, bits)`, `<`) or use
call co-occurrence + ordering (`project:functions_where` + `f:calls()` address
ordering) — flagging only the actually-insecure use, not mere API presence.

17 packs cover **133 of 252** source rules (53%). Remaining deferred (61) need
operand-origin taint or same-object tracking (UAF/double-free/unchecked-return/
size-relational); see `../../triage/C-COVERAGE.md`.

## Known characteristic: static-runtime noise
Presence rules also match dangerous calls inside statically-linked runtime/libc
code (e.g. `zig cc` bundles `Io.Threaded.posixExecvPath` which calls `execve`).
For dynamically-linked targets libc is external (only app call-sites match); for
static binaries/firmware this is real noise — future work: filter library
functions via FLIRT or symbol-namespace heuristics.

## Run
```sh
export BIAS_DATA=/Users/samv/vulhunt-dev/biasdata
vulhunt-ce scan <elf> -d "$BIAS_DATA" -r posix/c --pretty
```
