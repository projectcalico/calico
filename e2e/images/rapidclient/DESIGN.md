# Design: multi-mode `rapidclient` e2e utility binary

## Goal

`rapidclient` is a multi-mode Go binary for e2e tests, dispatched by a `MODE`
environment variable. It hosts two modes:

- `client` — a minimal HTTP client that forces source-port reuse (used by the
  maglev consistent-hashing tests).
- `server` — the datapath test server (HTTP length/echo endpoints + UDP echo)
  used by the `Packet Size Verification` suite.

The image is built as a **multi-arch manifest list** (`amd64` + `arm64`) and
published to `quay.io/tigeradev/rapidclient`.

Motivations:

1. **arm64 coverage.** The `server` mode replaces the external
   `calico/k8s-e2e-dataplane-server:stable` image, which is published amd64-only.
   On arm64 clusters (e.g. the azr-aks ARM lane) the amd64 server binary crashes
   on start (exitCode 255) and every `Packet Size Verification` spec fails. An
   in-repo Go binary built via Calico's `buildx` is multi-arch by construction.
2. **No external dependency.** The datapath server source lives in-repo rather
   than in `tigera/k8s-e2e` behind a floating `:stable` tag, so it is covered by
   the same review/build/multi-arch guarantees as the rest of the code.
3. **A reusable pattern.** Mode dispatch lets future e2e helpers be added as new
   modes of one image instead of new external images.

## Non-goals

- Re-implementing third-party upstream test images (agnhost, test-webserver,
  iperf3, socat, netshoot). They remain upstream references in `images.go`;
  they are already multi-arch and not Calico-owned.
- Altering `Packet Size Verification` test logic or assertions. `server` mode is
  a like-for-like replacement of the flask server.
- Altering the maglev client invocation. The `docker run … -url … -port …` call
  in `maglev.go` is unchanged except for its image ref (now via
  `RapidClientImage()`).
- Digest-pinning the published image. CI runs against a per-lane tag loaded onto
  the nodes (see *Image delivery to test nodes*); pinning the published `:latest`
  to an immutable digest is separate future hardening.
- Deleting `tigera/k8s-e2e/images/flask`. This binary stops *referencing* the
  flask image; retiring it there is a follow-up.

## Design

### Mode dispatch

`main.go` reads `MODE` and dispatches through a small registry:

- `MODE` unset/empty → `client` (backward-compatible default; the maglev
  invocation and the old flag interface work unchanged).
- `MODE=server` → `server`, set by the packet-size pod customizer.
- Unknown `MODE` → exit non-zero with an error listing the registered modes.

Each mode owns its own `flag.FlagSet` parsed from `os.Args[1:]`, so modes have
independent flag/arg surfaces. The framework is deliberately minimal — a registry
plus a `Mode` interface, with only `client` and `server` implemented. A new mode
is one `registerMode` call in an `init()`.

```go
type Mode interface {
    Name() string
    // Run parses its own flags from args and executes. main() maps a non-nil
    // return to a non-zero exit.
    Run(args []string) error
}

func registerMode(m Mode)
func lookupMode(name string) (Mode, bool)
func modeNames() []string   // for the unknown-mode error
```

```go
// main()
mode := os.Getenv("MODE")
if mode == "" { mode = "client" }
m, ok := lookupMode(mode)
if !ok { fatalf("unknown MODE %q; known modes: %v", mode, modeNames()) }
if err := m.Run(os.Args[1:]); err != nil { log.Fatal(err) }
```

### Package layout

```
main.go        # dispatch: read MODE (default "client"), look up mode, run
mode.go        # Mode interface + registry (registerMode / lookupMode / modeNames)
client.go      # client mode, registered via init()
server.go      # server mode: HTTP /length//post/ + UDP echo, registered via init()
server_test.go # unit tests for server endpoints + UDP echo
Dockerfile     # FROM scratch; TARGETARCH selects the per-arch binary
Makefile       # multi-arch manifest build/publish + ut/ci
README.md      # documents the modes
```

The image name, directory, quay repo, and the `change_in('/e2e/images/rapidclient/*.go')`
CI trigger are unchanged.

### One image, two modes (`images.go`)

Both consumers use the same image, so a single env-aware helper composes the ref
and reports whether the image was loaded onto the nodes (see *Image delivery*):

```go
const rapidClientRepo = "quay.io/tigeradev/rapidclient"

// RapidClientImage returns the image ref and whether it was pre-loaded onto the
// test nodes (RAPIDCLIENT_TAG set by a CI lane) rather than pulled from quay.
func RapidClientImage() (ref string, preloaded bool) {
    if tag := os.Getenv("RAPIDCLIENT_TAG"); tag != "" {
        return rapidClientRepo + ":" + tag, true
    }
    return rapidClientRepo + ":latest", false
}
```

Consumers:

- `packet_size.go` — `withPacketSizeServer` sets the server pod's image, clears
  `Args`, adds `MODE=server`, and sets the readiness path to `/length/1`. When
  `preloaded`, it sets `ImagePullPolicy: Never` so a missing/failed load fails
  loudly instead of masking with a stale published image. `PORT` is left unset,
  so the server defaults to 5000 (matching the base conncheck server pod's
  container port).
- `maglev.go` — runs `client` mode on the external node via
  `sudo docker run … -url … -port …`. `MODE` is unset, so it defaults to `client`
  and the flags parse as before; only the image ref changes.

### `server` mode contract

Listens on `PORT` (env, default 5000), serving TCP HTTP and UDP echo on the
**same port number**. `PORT` is the only port knob — the `-p=`/`--port=` CLI
override the old flask wrapper accepted is intentionally not replicated (no
consumer passes it; `withPacketSizeServer` clears `Args`). A non-numeric or
out-of-range `PORT` logs and exits non-zero immediately (visible pod `Failed`,
not a silent hang).

**Dual-stack (single socket).** Each listener binds the unspecified address
(`net.Listen("tcp", ":"+port)`, `net.ListenPacket("udp", ":"+port)`). On Linux
this serves both IPv4 and v4-mapped IPv6 from one socket (`IPV6_V6ONLY=0`),
matching flask's `host="::"`, which is all the suite needs (it connects via IPv4
pod IP / ClusterIP / NodePort, plus IPv6 in dual-stack configs). There is
deliberately no two-socket fallback; if a concrete CI failure ever proves one
socket insufficient, the fix is two listeners (`0.0.0.0` + `[::]` with
`IPV6_V6ONLY=1`).

HTTP endpoints (must satisfy what `packet_size.go` drives):

| Route | Method | Response | Status |
|---|---|---|---|
| `/` | GET | static non-empty string (sanity) | 200 |
| `/length/{N}` | GET | exactly **N whitespace-free bytes** (N≥1) | 200 |
| `/length/{N}` | GET | empty body when `N==0` | 200 |
| `/length/{N}` | GET | `N` non-integer or `<0` | 400 |
| `/post` | POST | received body's byte count, as a decimal string | 200 |
| `/post` | GET | static help string (flask parity) | 200 |
| anything else | any | not found | 404 |

- **`/length/{N}` charset.** N bytes are emitted by repeating the fixed 36-byte
  alphabet `abcdefghijklmnopqrstuvwxyz0123456789` and truncating. It is
  whitespace-free, so the suite's `len(strings.TrimSpace(body)) == N` holds. The
  full N bytes are written with `Content-Length` set (no chunked framing). Pinning
  the charset keeps the unit test exact and makes any future content-sensitive
  test a deliberate change.
- **`/post`.** The body is streamed with `io.Copy(io.Discard, r.Body)` and the
  count returned via `strconv.FormatInt`, so a 10 000-byte body is never buffered
  and the reported count is the exact bytes received.
- **UDP echo.** A single read→write loop: `n, addr, _ := pc.ReadFrom(buf)` then
  `pc.WriteTo(buf[:n], addr)`, echoing exactly the `n` bytes read from a
  65535-byte buffer (full UDP payload space; test payloads are `< MTU`). One
  goroutine is correct for any number of peers — each datagram is echoed to its
  own source `addr`, replies leave from the bound port (what NodePort/ClusterIP
  conntrack keys on), and the reused buffer is race-free because one goroutine
  reads then writes sequentially. `fork`-style per-peer parallelism (as in socat)
  is unnecessary for echo correctness.
  - *Concurrency caveat (documented at `serveUDP`):* the suite fires probes
    serially and wraps the UDP check in `Eventually`. If it is ever parallelised,
    a single goroutine can drain `SO_RCVBUF` slower than a concurrent burst
    arrives and silently drop datagrams. The remedy then is
    `SetReadBuffer(...)` plus goroutine-per-datagram echo that **copies `buf[:n]`
    first** (the shared buffer is reused on the next `ReadFrom`).

Readiness/liveness, port, and `restartPolicy: Never` are inherited from the base
conncheck server pod; the customizer overrides only image, args, the `MODE=server`
env, and the readiness path.

### `client` mode contract

Flags: `-url` (required), `-port` (default 12345), `-timeout` (30s), `-v`. It
performs a single GET from a fixed source port with `SO_REUSEADDR` and keep-alives
disabled, and prints the response body. The only consumer is `maglev.go`, which
runs it on the external node; `MODE` is unset there so `client` is selected. The
`/shell?cmd=hostname` URL in that invocation is an endpoint on the maglev backend
being load-balanced, not on `server` mode — `client` is a generic HTTP GET tool.

### Multi-arch image build

`Dockerfile` is `FROM scratch` with `ARG TARGETARCH` /
`COPY bin/rapidclient-${TARGETARCH} /rapidclient`, so one Dockerfile produces
every platform. Per-arch static binaries are built with `CGO_ENABLED=0` and
`GOARCH=$*` (clean cross-compilation, correct for `FROM scratch`).

- `ARCHES := amd64 arm64` — assigned unconditionally because `lib.Makefile`
  already sets a four-arch default; `?=` would leave `publish` building
  `ppc64le`/`s390x` too. amd64-only is the bug this image fixes.
- `publish` builds all `ARCHES` into a single manifest list and `--push`es it
  (a multi-platform build cannot `--load`). A post-publish guard inspects the
  pushed tag and fails unless it is a manifest list covering every arch in
  `ARCHES` — this is what stops a silent regression to single-arch. On `master`
  the tag is retagged to `:latest` via `buildx imagetools create`.
- `image` builds a single-arch image locally (`--load`) for development.
- Unit tests run via `ut` (repo convention; `lib.Makefile`'s `test: ut fv st`
  aggregates it, and `fv`/`st` are no-ops for this image) and `ci`. They execute
  in CI through the dedicated **"E2E images"** Semaphore block
  (`.semaphore/semaphore.yml.d/blocks/20-e2e-images.yml`).

Publishing to quay is done by the existing `.semaphore/push-images/e2e-test.yml`
job (authenticated via the `quay-tigeradev-hashrelease` secret), triggered by the
`change_in('/e2e/images/rapidclient/*.go')` rule.

### Image delivery to test nodes

Fork PR builds have no registry push credential, so the image built *from the PR
under test* cannot be pushed to quay for nodes to pull; a `:latest` reference
would silently run the previously-published image. Each CI lane that exercises the
image therefore builds it from PR source and loads it directly onto its nodes,
pinning the exact tag via `RAPIDCLIENT_TAG` (pods use `ImagePullPolicy: Never`).

- **gcp-kubeadm** (`.semaphore/end-to-end/scripts/phases/load_images.sh`): builds
  `rapidclient:pr-<N>`, `docker save`s it once, `ctr -n k8s.io images import`s it
  onto every worker node's containerd and `docker load`s it onto the external
  node, then exports `RAPIDCLIENT_TAG` (forwarded into the e2e container via
  `K8S_E2E_DOCKER_EXTRA_FLAGS`). Runs only when `RUN_LOCAL_TESTS` and
  `PROVISIONER=gcp-kubeadm` (it depends on the CRC terraform outputs + SSH key);
  otherwise it no-ops.
- **kind** (`e2e-test-bpf`, the sig-calico BPF lane that runs packet-size): builds
  `rapidclient:kind-e2e`, `kind load docker-image`s it into the kind nodes, and
  `docker load`s it into the external node's inner docker daemon (a `dind`
  container). `RAPIDCLIENT_TAG=kind-e2e` is exported by the root `Makefile` so the
  ginkgo process inherits it. The non-BPF `e2e-test` lane (`kind.yaml` focus
  `Conformance && sig-calico`) does not run packet-size, and the CNP lane uses a
  separate test binary, so only `e2e-test-bpf` is wired.

When `RAPIDCLIENT_TAG` is unset — other providers, scheduled hashrelease runs,
local dev — `RapidClientImage()` reports `preloaded=false` and the published
`:latest` is used with the default pull policy.

## Edge cases & failure modes

- **Whitespace in `/length` output** breaks the GET length assertion. Mitigated by
  the whitespace-free charset; the unit test asserts `len(TrimSpace(body)) == N`
  for N ∈ {1, 10, 1400, 10000}.
- **`/length/0` or non-integer `{N}`.** `N==0` returns an empty 200; a parse
  failure returns 400 (flask would 500). The suite never sends these; the server
  is defensive.
- **Large GET (10 000 bytes)** is written in full — no default write-limit
  truncation.
- **UDP datagram larger than the 65535-byte buffer** would truncate the echo.
  Out of range for the suite; documented as the cap.
- **Bind failure / port in use** logs and exits non-zero so the pod goes `Failed`
  visibly rather than hanging.
- **`MODE=server` with stray args** is tolerated (server mode ignores args); the
  dropped `-p=`/`--port=` override is by design.
- **Manifest-list regression** is caught by the post-publish guard asserting the
  tag covers every arch in `ARCHES`.
- **Missing node load with `RAPIDCLIENT_TAG` set** surfaces immediately as
  `ErrImageNeverPull` (pods use `PullNever`) rather than a silent stale pull.

## Testing

- **Unit (`server_test.go`, plain `go test`):** `GET /length/{N}` returns N bytes
  with `len(TrimSpace(body)) == N` for N ∈ {1, 10, 1400, 10000}; `POST /post` with
  K `X`s returns `"K"`; UDP echo returns the exact datagram; dispatch tests cover
  unknown `MODE` (error) and empty `MODE` (client selected). Run in CI via the
  "E2E images" block.
- **Integration:** the existing `Packet Size Verification` suite is the real
  proof — it must stay green on amd64 (gcp-kubeadm / aws-kubeadm, kind BPF) and
  newly pass on arm64 (azr-aks ARM). No new e2e test is added.

## Rollout & follow-ups

- The multi-mode binary, multi-arch publish, `RapidClientImage()` switch, and the
  per-lane image loads land together so the packet-size suite runs against the
  PR-built server atomically, without a registry push.
- **Follow-up — retire the flask image.** Once packet-size is green on arm64, drop
  `images/flask` from `tigera/k8s-e2e` (it becomes unreferenced).
- **Follow-up — digest-pin the published image.** Non-gcp-kubeadm and scheduled
  runs still consume the floating published `:latest`; pinning it to an immutable
  digest with a documented bump process is worthwhile hardening.
