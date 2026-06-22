# GO-2023-2153 — gRPC-Go's HTTP/2 server transport did not enforce the `MaxConcurrentStreams` limit against actual handler goroutine execution

| | |
|---|---|
| **Library** | `google.golang.org/grpc` |
| **Aliases** | GHSA-m425-mq94-257g, CVE-2023-44487 |
| **CWE** | CWE-400 |
| **Affected / fixed** | `>= 1.58.0` … fixed in `1.58.3` |
| **Rule** | [`GO-2023-2153.vh`](./GO-2023-2153.vh) |

## Summary

gRPC-Go's HTTP/2 server transport did not enforce the `MaxConcurrentStreams` limit against actual handler goroutine execution. An attacker could send HTTP/2 requests then immediately cancel them with RST_STREAM frames before the server could respond, allowing the server to launch an unbounded number of concurrent method handler goroutines despite any configured stream concurrency ceiling. Because RST_STREAM resets the stream before `HEADERS`-based flow control could gate new requests, the server kept spawning goroutines with no cap. This is CWE-400 (Uncontrolled Resource Consumption / Rapid Reset), and it directly enables denial-of-service through goroutine and memory exhaustion. The advisory aliases are GHSA-m425-mq94-257g and CVE-2023-44487.

## Detection discriminator

This engine has no library-version gate, so the rule proves the **vulnerable code structure** and is silent on the patched build.

Scope: function symbol `grpc.(*Server).serveStreams` (present in both builds -> vuln-shape anchor).
Fix signal: presence of the symbol `grpc.(*atomicSemaphore).acquire` (the blocking counting
semaphore added by the fix; channel-receive -> never inlined -> always a real symbol).

Rule fires (vulnerable) when `(*atomicSemaphore).acquire` symbol is ABSENT.
Rule silent (patched) when it is PRESENT.

This is a clean fix-symbol-presence discriminator: serveStreams alone fires on both
(symbol-only, useless); the acquire/release/newHandlerQuota symbols are entirely absent
from v1.58.2 and present in v1.58.3. We test the project:functions handle `~= nil` (never iterate).

Symbol regex (unanchored, escape Go literal dots/parens/stars):
  scope:   grpc\.\(\*Server\)\.serveStreams$
  fix sym: grpc\.\(\*atomicSemaphore\)\.acquire$

## Reproducing the test binaries

The committed sample links the **real vulnerable package** (no stubs). Minimal consumer (`main.go`):

```go
// main.go
package main

import (
	"net"

	"google.golang.org/grpc"
)

// keep forces the linker to retain the symbol even with optimizations
//
//go:noinline
func keep(s *grpc.Server) { s.Serve(nil) }

func main() {
	s := grpc.NewServer()
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	keep(s)
	_ = lis
}
```

Pinned dependency (vulnerable build): `require google.golang.org/grpc v1.58.2` — the patched build uses the fixed version. Build each with:

```bash
GOOS=linux GOARCH=amd64 go build -o consumer .
```

Committed sample artifacts:

```
GO-2023-2153/consumer_vuln
GO-2023-2153/go.mod
GO-2023-2153/go.sum
GO-2023-2153/main.go
GO-2023-2153/patched/consumer_fixed
GO-2023-2153/patched/go.mod
GO-2023-2153/patched/go.sum
GO-2023-2153/patched/main.go
```

## Upstream fix

Patch: https://github.com/grpc/grpc-go/commit/f2180b4d5403d2210b30b93098eb7da31c05c721

Fix commit: `f2180b4d5403d2210b30b93098eb7da31c05c721`  
PR: https://github.com/grpc/grpc-go/pull/6703  
Author: Doug Fawley, merged 2023-10-10.

### server.go — key hunks

```diff
-type serverWorkerData struct {
-	st     transport.ServerTransport
-	wg     *sync.WaitGroup
-	stream *transport.Stream
-}
-
 // Server is a gRPC server to serve RPC requests.
 type Server struct {
 	...
-	serverWorkerChannel chan *serverWorkerData
+	serverWorkerChannel chan func()
 }
```

```diff
 var defaultServerOptions = serverOptions{
+	maxConcurrentStreams:  math.MaxUint32,
 	maxReceiveMessageSize: defaultServerMaxReceiveMessageSize,
```

```diff
 func MaxConcurrentStreams(n uint32) ServerOption {
+	if n == 0 {
+		n = math.MaxUint32
+	}
 	return newFuncServerOption(func(o *serverOptions) {
```

```diff
 func (s *Server) serveStreams(st transport.ServerTransport) {
 	defer st.Close(errors.New("finished serving streams for the server transport"))
 	var wg sync.WaitGroup

+	streamQuota := newHandlerQuota(s.opts.maxConcurrentStreams)
 	st.HandleStreams(func(stream *transport.Stream) {
 		wg.Add(1)
+
+		streamQuota.acquire()
+		f := func() {
+			defer streamQuota.release()
+			defer wg.Done()
+			s.handleStream(st, stream)
+		}
+
 		if s.opts.numServerWorkers > 0 {
-			data := &serverWorkerData{st: st, wg: &wg, stream: stream}
 			select {
-			case s.serverWorkerChannel <- data:
+			case s.serverWorkerChannel <- f:
 				return
 			default:
 			}
 		}
-		go func() {
-			defer wg.Done()
-			s.handleStream(st, stream, s.traceInfo(st, stream))
-		}()
+		go f()
 	})
 	wg.Wait()
 }

-func (s *Server) handleSingleStream(data *serverWorkerData) {
-	defer data.wg.Done()
-	s.handleStream(data.st, data.stream, s.traceInfo(data.st, data.stream))
-}
```

```diff
+// atomicSemaphore implements a blocking, counting semaphore.
+type atomicSemaphore struct {
+	n    atomic.Int64
+	wait chan struct{}
+}
+
+func (q *atomicSemaphore) acquire() {
+	if q.n.Add(-1) < 0 {
+		<-q.wait
+	}
+}
+
+func (q *atomicSemaphore) release() {
+	if q.n.Add(1) <= 0 {
+		q.wait <- struct{}{}
+	}
+}
+
+func newHandlerQuota(n uint32) *atomicSemaphore {
+	a := &atomicSemaphore{wait: make(chan struct{}, 1)}
+	a.n.Store(int64(n))
+	return a
+}
```

### What the fix changed

The fix added a blocking counting semaphore (`atomicSemaphore`) initialized to `maxConcurrentStreams`. At the top of each new-stream callback in `serveStreams`, `streamQuota.acquire()` is called synchronously (blocking the accept loop if quota is exhausted) and `streamQuota.release()` is deferred in the handler closure. This ensures that at most `maxC

*(diff truncated — see upstream patch)*

## Provenance

Generated by the multi-agent CVE-rule pipeline (research → build both versions → binary-observable discriminator → self-verify → independent GATE). Build recipe, discriminator, and scan results above are drawn from the pipeline's research dossier and signature notes for this CVE.

References:

- Go: https://pkg.go.dev/vuln/GO-2023-2153
- GHSA: https://github.com/advisories/GHSA-m425-mq94-257g
