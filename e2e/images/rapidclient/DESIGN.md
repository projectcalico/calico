# Design: multi-mode `rapidclient` e2e utility binary

## Goal

Turn the existing single-purpose `rapidclient` e2e image into a **multi-mode Go
binary** dispatched by a `MODE` env var, and **port the `k8s-e2e-dataplane-server`**
(currently a Flask + socat image in `tigera/k8s-e2e/images/flask`) into it as a
new `server` mode.

Primary motivations:

1. **Fix the arm64 gap.** `calico/k8s-e2e-dataplane-server:stable` is published
   **amd64-only** (verified: single-arch manifest). On arm64 clusters (azr-aks
   ARM lane) the server container runs the amd64 binary and crashes instantly
   (exitCode 255), so every `Packet Size Verification` spec fails — chronic for
   6+ weeks. An in-repo Go binary built via Calico's `buildx` gets arm64 for free.
2. **Remove an external dependency.** The packet-size server source lives outside
   the monorepo (`tigera/k8s-e2e`) and is pinned to a floating `:stable` tag,
   which is how the arm64 regression went unnoticed. Bringing it in-repo puts it
   under the same review/build/multi-arch guarantees as other code.
3. **Establish a reusable pattern.** A mode-dispatched utility image lets future
   e2e helpers be added as new modes instead of new external images.

## Non-goals

- Re-implementing third-party upstream test images (agnhost, test-webserver,
  iperf3, socat, netshoot). Those stay as upstream references in `images.go`;
  they are already multi-arch and not Calico-owned.
- Changing the `Packet Size Verification` test logic or what it asserts. This is
  a like-for-like server replacement; the suite must pass unchanged on amd64 and
  newly pass on arm64.
- Changing the client (maglev) invocation. The `docker run … -url … -port …`
  call in `maglev.go` must keep working verbatim.
- Pinning image tags to digests / changing the tagging scheme. Noted as a future
  hardening (see Open questions), not in scope here.
- Deleting anything in `tigera/k8s-e2e`. We stop *referencing* the flask image;
  retiring it there is a separate follow-up.

## Approach

### Dispatch (decided: default-client + `MODE=server`)

`main.go` reads the `MODE` env var and dispatches through a **mode registry**:

- `MODE` unset/empty → **`client`** mode (backward-compatible default; preserves
  the existing flag interface and the `maglev.go` invocation with zero change).
- `MODE=server` → `server` mode (the ported dataplane server), injected by the
  packet_size pod customizer.
- Unknown `MODE` → exit non-zero with a clear error listing registered modes.

Each mode owns its **own `flag.FlagSet`** parsed from `os.Args[1:]`, so modes
have independent flag/arg surfaces. This is the "general multi-tool framework"
shape (decided), kept minimal: a registry + interface now, only `client` and
`server` implemented. Adding a mode later = one `registerMode` call in an
`init()`.

### Package layout (`e2e/images/rapidclient/`, name kept)

```
main.go        # dispatch: read MODE (default "client"), look up mode, run
mode.go        # Mode interface + registry (registerMode / lookupMode / modeNames)
client.go      # client mode: today's rapidclient logic, registered via init()
server.go      # server mode: HTTP /length//post// + UDP echo, registered via init()
server_test.go # unit tests for server endpoints + UDP echo
Dockerfile     # unchanged (FROM scratch; ENTRYPOINT ["/rapidclient"])
Makefile       # CHANGED: multi-arch buildx manifest push (amd64 + arm64)
README.md      # updated to document modes
```

Image name, dir name, quay repo (`quay.io/tigeradev/rapidclient`), CI push job,
and the `change_in('/e2e/images/rapidclient/*.go')` trigger all stay as-is.

### `images.go` change

```go
// RapidClient (client mode, default) — unchanged ref.
RapidClient      = "quay.io/tigeradev/rapidclient"
// PacketSizeServer now points at the SAME image; server mode is selected by
// the MODE=server env the packet_size pod customizer sets.
PacketSizeServer = "quay.io/tigeradev/rapidclient"
```

The `// Source: tigera/k8s-e2e/images/flask.` comment is replaced with a pointer
to `e2e/images/rapidclient/server.go`.

### `packet_size.go` change

`withPacketSizeServer` currently swaps the image, nils args, and sets the
readiness path to `/length/1`. Add the mode env:

```go
func withPacketSizeServer(pod *v1.Pod) {
    for i := range pod.Spec.Containers {
        pod.Spec.Containers[i].Image = images.PacketSizeServer
        pod.Spec.Containers[i].Args  = nil
        pod.Spec.Containers[i].Env   = append(pod.Spec.Containers[i].Env,
            v1.EnvVar{Name: "MODE", Value: "server"})
        if rp := pod.Spec.Containers[i].ReadinessProbe; rp != nil && rp.HTTPGet != nil {
            rp.HTTPGet.Path = "/length/1"
        }
    }
}
```

`PORT` is left unset → server defaults to 5000 (matches `packetServerPort` and
the container port already in the base conncheck server pod).

### Multi-arch build (the actual bug fix)

**Current state** (verbatim, so the diff is unambiguous).
`e2e/images/rapidclient/Makefile`:

```makefile
include ../../../metadata.mk
PACKAGE_NAME=github.com/projectcalico/calico/e2e/images/rapidclient
include ../../../lib.Makefile
QUAY_REGISTRY ?= quay.io/tigeradev
TAG_NAME ?= $(shell git branch --show-current)

bin/rapidclient: main.go
	mkdir -p bin
	$(DOCKER_RUN) -e CGO_ENABLED=0 $(CALICO_BUILD) go build -o $@ -ldflags "-s -w" .

image: bin/rapidclient
	docker buildx build --load --platform=linux/$(ARCH) --pull \
		--build-arg BINARY_PATH=bin/rapidclient -f Dockerfile \
		-t $(QUAY_REGISTRY)/rapidclient:$(TAG_NAME) .

publish: image
	docker push $(QUAY_REGISTRY)/rapidclient:$(TAG_NAME)
	@if [ "$(TAG_NAME)" = "master" ]; then \
		docker tag  ...:$(TAG_NAME) ...:latest; docker push ...:latest; fi
```

`Dockerfile`: `FROM scratch` / `COPY ${BINARY_PATH} /rapidclient` /
`ENTRYPOINT ["/rapidclient"]`. CGO is already disabled, so the binary is static
and `FROM scratch` is correct — no Dockerfile change needed for the binary
itself (only inputs change).

CI: `.semaphore/push-images/e2e-test.yml` already logs into quay
(`quay-tigeradev-hashrelease` secret) in its prologue and runs
`make -C e2e publish-test-images CONFIRM=true` (which calls this Makefile's
`publish`). Triggered by `change_in('/e2e/images/rapidclient/*.go')` in
`.semaphore/semaphore.yml`. **Authentication and the publish job already exist** —
we are not adding CI wiring, only changing the Makefile to emit a manifest list.

**The defect:** `image` uses `--load --platform=linux/$(ARCH)` (default
`ARCH=amd64`) — a single-arch image loaded locally, so the published tag is
amd64-only. That is the arm64 bug.

**Change** — build both arch binaries and push one **manifest list**:

```makefile
ARCHES = amd64 arm64

bin/rapidclient-%:
	mkdir -p bin
	$(DOCKER_RUN) -e CGO_ENABLED=0 -e GOARCH=$* $(CALICO_BUILD) \
		go build -o $@ -ldflags "-s -w" .

# Dockerfile takes BINARY_PATH; buildx selects the right per-arch binary via
# TARGETARCH. Build all platforms in one manifest and --push (cannot --load a
# multi-platform build).
publish: $(addprefix bin/rapidclient-,$(ARCHES))
	docker buildx build --platform=$(subst $(space),$(comma),$(addprefix linux/,$(ARCHES))) \
		--push --pull -f Dockerfile \
		-t $(QUAY_REGISTRY)/rapidclient:$(TAG_NAME) .
	@if [ "$(TAG_NAME)" = "master" ]; then \
		docker buildx imagetools create -t $(QUAY_REGISTRY)/rapidclient:latest \
			$(QUAY_REGISTRY)/rapidclient:$(TAG_NAME); fi
```

The `Dockerfile` gains a `TARGETARCH` arg so buildx copies the matching binary:
`ARG TARGETARCH` / `COPY bin/rapidclient-${TARGETARCH} /rapidclient`. (Confirm
the exact lib.Makefile multi-arch idiom during implementation — Calico already
has `ARCHES`/manifest helpers in `lib.Makefile`; prefer reusing them over the
hand-rolled `subst` above if a helper exists.)

**Regression guard:** after publish, assert the tag is a manifest list with both
platforms — `docker buildx imagetools inspect $(QUAY_REGISTRY)/rapidclient:$(TAG_NAME)`
must list `linux/amd64` and `linux/arm64`; fail the target otherwise. This is the
specific check that stops a silent regression to single-arch.

This Makefile change is what resolves the arm64 failure; everything else just
makes the server available to build in the first place.

## Interfaces / data shapes

### Mode registry (`mode.go`)

```go
type Mode interface {
    Name() string
    // Run parses its own flags from args and executes. Returns an error;
    // main() maps non-nil to a non-zero exit.
    Run(args []string) error
}

func registerMode(m Mode)          // called from each mode's init()
func lookupMode(name string) (Mode, bool)
func modeNames() []string          // for the unknown-mode error message
```

`main()`:
```go
mode := os.Getenv("MODE")
if mode == "" { mode = "client" }   // back-compat default
m, ok := lookupMode(mode)
if !ok { fatalf("unknown MODE %q; known modes: %v", mode, modeNames()) }
if err := m.Run(os.Args[1:]); err != nil { log.Fatal(err) }
```

### `client` mode (`client.go`) — behaviour preserved exactly

Flags (unchanged): `-url` (required), `-port` (default 12345), `-timeout`
(30s), `-v`. Single GET from a fixed source port with `SO_REUSEADDR` and
keep-alives disabled; prints the response body. Identical to today's `main.go`.

The only consumer is `maglev.go:594`, which runs it on an **external node**:

```go
cmd := fmt.Sprintf("sudo docker run --rm --net=host %s -url http://%s/shell?cmd=hostname -port %d",
    images.RapidClient, ep, m.maglevConfig.SourcePort)
```

`MODE` is unset here → defaults to `client` → flags parse exactly as today. **No
change to `maglev.go`.** (Note: the `/shell?cmd=hostname` URL is an endpoint on
the *maglev backend* being load-balanced, not on our `server` mode — client mode
is a generic HTTP GET tool and is agnostic to it.)

### `server` mode (`server.go`) — ported contract

Listens on `PORT` (env, default 5000). TCP HTTP and UDP echo on the **same port
number**. Port comes from `PORT` env only — the `-p=`/`--port=` CLI override the
old flask `runme.sh` accepted is **intentionally not replicated** (no consumer
passes it; `withPacketSizeServer` sets `Args = nil`). This is the single
deliberate functional difference from the python version.

**Dual-stack (decided, no fallback):** bind each listener to the unspecified
address so Linux serves both IPv4 and v4-mapped IPv6 from one socket, matching
flask's `host="::"`:
- HTTP: `net.Listen("tcp", ":"+port)` then `http.Serve`.
- UDP: `net.ListenPacket("udp", ":"+port)`.

On Linux these bind dual-stack by default (`IPV6_V6ONLY=0`), which is all the
test needs (it connects via IPv4 pod IP / ClusterIP / NodePort, and IPv6 in
dual-stack configs). We do **not** implement a two-socket fallback unless a
concrete CI failure proves the single socket insufficient — keeping the
implementation deterministic. If that ever happens, the fix is two listeners
(`0.0.0.0` + `[::]` with `IPV6_V6ONLY=1`); recorded here so the option isn't
re-litigated.

**Invalid `PORT`:** non-numeric or out-of-range (`<1` or `>65535`) → log and
exit non-zero immediately (visible pod `Failed`, not a silent hang).

HTTP endpoints (must match what `packet_size.go` drives):

| Route | Method | Response | Status |
|---|---|---|---|
| `/` | GET | static non-empty string (sanity) | 200 |
| `/length/{N}` | GET | exactly **N whitespace-free bytes** (N≥1) | 200 |
| `/length/{N}` | GET | empty body when `N==0` | 200 |
| `/length/{N}` | GET | `N` non-integer or `<0` | 400 |
| `/post` | POST | the request body's byte count, as a decimal string | 200 |
| `/post` | GET | static help string (parity with flask) | 200 |
| anything else | any | not-found | 404 |

**`/length/{N}` body — pinned charset.** Emit N bytes by repeating the fixed
36-byte alphabet `abcdefghijklmnopqrstuvwxyz0123456789` and truncating to N. This
alphabet is **whitespace-free**, so the test's `len(strings.TrimSpace(body))`
equals N. Content is otherwise irrelevant (the suite asserts only length —
verified in `packet_size.go`), but the charset is pinned so the unit test is
exact and a future content-sensitive test would be a deliberate change, not an
accident. Write all N bytes in the response and set `Content-Length` (no chunked
framing surprises); `http.Server` is concurrent by default — no extra handling.

**`/post` — count, don't buffer.** Stream the body with
`n, _ := io.Copy(io.Discard, r.Body)` and return `strconv.FormatInt(n, 10)`.
This avoids holding the (up to 10000-byte) body in memory and reports the exact
received byte count (equivalent to flask's `request.content_length` for the
curl-set Content-Length the test uses).

**UDP echo.** Loop: `n, addr, _ := pc.ReadFrom(buf)`, then
`pc.WriteTo(buf[:n], addr)` — echo exactly the `n` bytes read (never the whole
buffer). Use a 65535-byte `buf` (full UDP payload space; test payloads are
`< MTU`, so never truncated; flask used socat `-b 10000`). Datagrams larger than
the buffer would be truncated by the kernel — out of range for this test, noted
as the cap.

A single read→write goroutine is used instead of socat's `fork` (per-peer
handler). This is **correct for any number of peers** — each datagram is echoed
to its own source `addr`, and the reused `buf` is race-free because one goroutine
reads then writes it sequentially. The only thing `fork` adds is parallelism
across simultaneous senders, which doesn't affect echo correctness or the
reply source port (both reply from the bound port, the thing NodePort/ClusterIP
conntrack keys on).

**Caveat if `packet_size` is ever made concurrent** (a likely future speedup —
the suite currently fires probes serially): a single goroutine drains
`SO_RCVBUF` slower than parallel handlers, so a concurrent burst can overflow the
kernel receive buffer and *silently drop* datagrams → missing echoes. Today this
is harmless because the test is serial and wraps the UDP check in
`Eventually(30s, 1s)`, which retries transient loss. If you parallelise the
probes and see drops, harden the server with: (1)
`pc.(*net.UDPConn).SetReadBuffer(...)` to absorb bursts, and (2) goroutine-per-
datagram echo — **copying `buf[:n]` first**
(`d := append([]byte(nil), buf[:n]...); go pc.WriteTo(d, addr)`), because the
shared buffer is reused on the next `ReadFrom`; skipping the copy reintroduces a
data race. This caveat is also recorded at `serveUDP` in `server.go`.

Readiness/liveness, port, and `restartPolicy: Never` are inherited unchanged
from the base conncheck server pod; the customizer only overrides image, args,
the `MODE=server` env, and the readiness path (`/length/1`). No probe-timing
changes.

### Test assertions this server must satisfy (from `packet_size.go`)

- **GET** (`packetTestViaConncheck`, line 284): `len(strings.TrimSpace(out)) == length`.
  ⇒ The N-byte body **must contain no leading/trailing whitespace**, or TrimSpace
  shortens it and the check fails. (This is exactly why the flask lorem corpus is
  one whitespace-free run-on string.) The Go generator emits N bytes drawn from a
  whitespace-free charset (e.g. repeating `a–z0–9`).
- **POST** (line 301): `strconv.Atoi(strings.TrimSpace(out)) == length`, where the
  client posts `strings.Repeat("X", length)`. ⇒ return the byte count of the
  received body. Use bytes actually read (robust) — equals Content-Length here.
- **UDP** (line 323): `strings.TrimSpace(out) == payload`, payload =
  `generateUDPPayload(length)` (digits `0–9`, no whitespace). ⇒ pure echo.

Readiness: `/length/1` must 200 with a 1-byte body.

## Edge cases & failure modes

- **Whitespace in `/length` output** → breaks GET length assertion. Mitigation:
  whitespace-free charset; unit test asserts `len(TrimSpace(body)) == N` for
  several N including 1, 10, MTU-ish, 10000.
- **`/length/0` or non-integer `{N}`** → flask would `int("abc")` 500. Match by
  returning 400 on parse failure; `N=0` returns empty body (200). Document; tests
  never send these but be defensive.
- **Large GET (10000 bytes)** → must not be truncated by any default write
  limits; stream/write fully.
- **UDP datagram larger than read buffer** → would truncate the echo and fail the
  equality check. 65535 buffer covers all test sizes; document the cap.
- **Dual-stack binding** → on some kernels `[::]` won't accept IPv4 unless
  `IPV6_V6ONLY=0`. Go's `net.Listen("tcp", ":5000")` already binds dual-stack via
  IPv4-mapped addresses on Linux; verify both UDP and TCP accept v4 and v6. If a
  single dual-stack socket is unreliable, fall back to two listeners (`0.0.0.0`
  and `[::]`). Decide during implementation; note in README.
- **Port already in use / bind failure** → log and exit non-zero promptly so the
  pod goes `Failed` visibly (current behaviour) rather than hanging.
- **`MODE=server` but stray args present** → server mode ignores all args (does
  not fatal). The flask wrapper parsed a `-p=`/`--port=` arg; that override is
  intentionally dropped (see the server-mode section) — `PORT` env is the only
  port knob.
- **Multi-arch manifest regression** → add a guard/check that the published image
  is a manifest list with both `amd64` and `arm64` (e.g. assert in the Makefile
  publish step or a CI check) so this can't silently regress to single-arch again.

## Testing

- **Unit (`server_test.go`)**, vanilla `go test` (no Ginkgo — new package):
  - `GET /length/{N}` returns N bytes with `len(TrimSpace(body)) == N` for
    N ∈ {1, 10, 1400, 10000}.
  - `POST /post` with a body of K `X`s returns `"K"`.
  - UDP echo returns the exact datagram for a digit payload.
  - unknown `MODE` → error; empty `MODE` → client selected (dispatch test).
- **Integration**: the existing `Packet Size Verification` suite is the real
  proof. Must stay green on amd64 (gcp-kubeadm/aws-kubeadm) and newly pass on
  arm64 (azr-aks ARM). No new e2e test needed; the change is covered by an
  existing suite that currently fails on arm64.

## Migration / rollout

1. Land the multi-mode binary + multi-arch Makefile; CI publishes
   `quay.io/tigeradev/rapidclient` as a manifest list.
2. Repoint `images.PacketSizeServer` and add `MODE=server` in the customizer in
   the **same PR** (so the suite switches to the in-repo server atomically).
3. Verify packet_size on an arm64 azr-aks run goes green; confirm amd64 unaffected.
4. Follow-up (separate): drop the flask image from `tigera/k8s-e2e`; consider
   pinning the image tag.

## Explicitly out of scope (matching the disposable-test-server scope)

The flask server had none of these and the replacement intentionally doesn't add
them: TLS/HTTPS, request-body size limits (POST is streamed, not buffered — no
OOM risk), graceful shutdown / signal handling (pod is killed, `restartPolicy:
Never`), metrics/structured logging beyond startup + fatal logs, and rate
limiting/concurrency caps (`http.Server`'s default per-connection goroutines are
sufficient). If a future need arises it's a deliberate extension, not a gap here.

## Follow-ups (deliberately not in this change)

1. **Tag pinning.** `images.go` consumes a floating tag (`:latest`/branch). The
   arm64 rot was masked partly by a floating, unpinned, external tag. Pinning the
   e2e utility image to an immutable tag/digest with a documented bump process is
   worthwhile hardening, but **deferred** — multi-arch publishing alone fixes the
   reported bug. Tracked as a separate change.
2. **Retire the flask image.** Once this lands and packet_size is green on arm64,
   drop `images/flask` from `tigera/k8s-e2e` (it will be unreferenced).

(Resolved during review and folded into the body: dual-stack binding decision;
`/length` charset pinned; multi-arch Makefile/CI mechanics made concrete;
`maglev.go` invocation quoted to verify "zero change". Doc home: this file,
`e2e/images/rapidclient/DESIGN.md`.)
