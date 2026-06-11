# C++ portable rulepacks

See `../../triage/CPP-COVERAGE.md`. **C++ is mostly covered by `ports/c`** — its
libc / `extern "C"` surface compiles to the same unmangled symbols, so the C
command-exec / string-overflow / format-string / weak-crypto / etc. rules fire
directly on C++ binaries (validated on `examples/cppdanger.elf`).

This directory holds only C++-**specific** rules:

| Pack | technique | validated |
|------|-----------|-----------|
| cpp-filesystem-symlink | C++-mangled `scope:functions` regex on std::filesystem directory_iterator/copy_file | ✅ cppdanger.elf |
| **cpp-qt-command-injection** | Qt QProcess exec — dual mode: mangled-prefix `scope:functions` (libs/static) + exact-mangled `scope:calls` (app imports) | ✅ qtdanger.elf (8 hits) |
| **cpp-qt-ssl-no-verify** | Qt QSslSocket setPeerVerifyMode — **operand**: enum const < VerifyPeer | ✅ qtdanger.elf (flags VerifyNone) |
| **cpp-grpc-insecure-credentials** | gRPC Insecure{Server,Channel}Credentials (free fns, presence) | ✅ grpcstub.elf (2) |
| **cpp-qt-weak-hash** | QCryptographicHash (Md4/Md5/Sha1) presence/review | ✅ **real libQt6Core** (3) |
| **cpp-qt-weak-tls-protocol** | QSsl[Config\|Socket]::setProtocol (SslV3/TLS1.0/1.1) presence/review | ✅ **real libQt6Network** (2) |

| **cpp-qt-additional-sinks** | QSqlQuery::exec(QString)/QProcess::startCommand/QWebEnginePage::runJavaScript | medium | ✅ **real libQt6Sql** (exec) + cppstub |
| **cpp-boost-dangerous** | asio set_verify_mode(verify_none) **operand** + Serialization iarchive presence | high/med | ✅ cppstub (spares verify_peer) |
| **cpp-poco-dangerous** | MD5Engine/SHA1Engine, Process::launch, Net::Context presence | med | ✅ cppstub (4) |
| **cpp-protobuf-untrusted-parse** | ParseFromString/Array presence | low | ✅ cppstub |
| **cpp-libpqxx-raw-query** | transaction_base::exec(string) presence | medium | ✅ cppstub |
| **cpp-httplib-no-cert-verify** | enable_server_certificate_verification(false) **operand** | high | ✅ cppstub |
| **cpp-untrusted-parse** | cv::imread/lt::bdecode presence | info | ✅ cppstub |

These library rules come from `../../triage/LIBRARY-API-CATALOG.md` (per-language top-10
risky libs + dangerous APIs). Validated via `examples/cppstub.cpp` (ABI-faithful stubs)
+ real `libQt6Sql/Core/Network`. **Matching note:** vulhunt exposes a **simplified C++
name** (final identifier, e.g. `InsecureServerCredentials`, `imread`) alongside the
mangled form — for short namespaces (`cv`/`lt`) only the simple name resolved, so **match
the simple unique name** when possible; use mangled `<len><class><len><method>` fragments
only when the simple name is too generic (`exec`/`launch`). const-arg rules use
`scope:calls` with the exact mangled symbol + `inputs[2]` operand (this=inputs[1]).

### Hunting Qt without a demangler or the real Qt libs
Itanium C++ mangling is ABI-stable: `QProcess::execute` is always
`_ZN8QProcess7executeE<params>`. The `8QProcess7execute` class::method prefix is
identical across Qt 5/6 and independent of the parameter overload, so a regex on
that prefix hunts genuine Qt binaries. The Qt rules were validated against a
**stub** (`examples/qtdanger.cpp`) whose mangled symbols match real Qt by
construction. C++ enum/int args ARE readable as constant operands (confirmed:
`setPeerVerifyMode(VerifyNone)` → `inputs[2].constant == 0`), so Qt config checks
can be precise — unlike Go.

## Run (combine with the C packs for full C++ coverage)
`-r` takes a single directory (multiple `-r` flags are rejected) and is loaded
recursively. For full C++ coverage, point it at a tree containing both the C and
C++ packs — e.g. keep `ports/c` and `ports/cpp` under a shared parent and scan that,
or symlink the cpp rules into the C dir:
```sh
export BIAS_DATA=/Users/samv/vulhunt-dev/biasdata
vulhunt-ce scan <cpp-elf> -d "$BIAS_DATA" -r posix --pretty   # ports/ contains both c/ and cpp/
```
