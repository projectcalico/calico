// Copyright (c) 2026 Tigera, Inc. All rights reserved.

// Package localregistry is a single-process registry facade for a kind cluster.
//
// It replaces the "run one registry:2 container per upstream" model. Every
// constraint that model imposed — one container per upstream, credentials
// frozen into a container's env, a proxy that can't be pushed to — is a
// property of the registry:2 image, not of the problem. This package owns
// the registry code, so those constraints don't apply.
//
// One HTTP server serves every upstream. The trick that makes that possible
// is containerd's mirror behaviour: when a node pulls gcr.io/foo/bar and its
// hosts.toml points gcr.io at this facade, containerd sends
//
//	GET /v2/foo/bar/manifests/<ref>?ns=gcr.io
//
// The registry host is stripped from the path but preserved in the ns query
// parameter. The facade routes on ns, so the same endpoint transparently
// backs gcr.io, quay.io, docker.io, ... at once. (See the containerd docs on
// registry hosts, and Spegel, which relies on the same ns parameter.)
//
// Two request outcomes:
//
//   - Overridden ref (see Override): the facade serves the locally-built
//     image and never contacts the upstream. This wins even under
//     imagePullPolicy: Always, because containerd resolves the manifest
//     through the facade and the facade answers before anyone reaches
//     upstream. That is the "force: use what I gave you" operation.
//   - Everything else: lazy pull-through. On the first request for a ref the
//     facade pulls it from the real upstream (named by ns) using the host's
//     live docker keychain — so a rotated gcloud/registry token is picked up
//     on the next miss, no container recreate — caches it, and serves it.
//     Layer blobs are cached on disk (Config.CacheDir) and reused across
//     runs and across upstreams.
//
// The facade runs in-process in the test/tool binary; there is no registry
// container at all. kind nodes reach it over the kind docker network's
// gateway address (see ConfigureNodes).
package localregistry

import (
	"context"
	"fmt"
	stdlog "log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"

	"github.com/projectcalico/calico/lib/std/log"
)

// Defaults applied to a zero-value Config.
const (
	// DefaultPort is the host port the facade listens on. 5001, not 5000,
	// to dodge macOS AirPlay — harmless on Linux, consistent everywhere.
	DefaultPort = 5001
	// DefaultKindNetwork is the docker network kind creates for a cluster.
	DefaultKindNetwork = "kind"
)

// Config configures the facade. Zero values pick sensible defaults.
type Config struct {
	// Port is the host port the facade listens on. Default DefaultPort.
	Port int
	// CacheDir is where pulled layer blobs are cached on disk. Blobs are
	// content-addressed, so the cache is reused across runs and shared
	// across upstreams. Default: a "kind-mirror" dir under os.TempDir().
	CacheDir string
	// KindNetwork is the docker network whose gateway the kind nodes use to
	// reach the facade. Default DefaultKindNetwork ("kind").
	KindNetwork string
	// InsecureUpstream makes pull-through talk plaintext HTTP to upstreams.
	// For tests and local dev against an http registry only; real upstreams
	// are https and this must stay false.
	InsecureUpstream bool
}

// Registry is the running registry. Create it with Start; shut it down with
// Stop.
type Registry struct {
	cfg Config
	log log.Logger

	// internal is the actual blob/manifest store (a go-containerregistry
	// registry). It listens on loopback only and is never exposed to nodes;
	// the facade populates it and reverse-proxies node requests to it.
	internal     *http.Server
	internalURL  *url.URL
	internalHost string
	proxy        *httputil.ReverseProxy

	// public is the node-facing listener.
	public     *http.Server
	publicAddr string // actual bound address (host:port), useful when Port is 0

	keychain authn.Keychain

	mu     sync.Mutex
	cached map[string]bool // key(ns, repo, ref) -> present in the internal store
}

// Start brings up the facade: an internal store on loopback and the public
// node-facing listener. The caller owns shutdown via Stop (typically
// t.Cleanup). On error Start cleans up after itself and returns a nil Registry.
func Start(ctx context.Context, cfg Config) (*Registry, error) {
	// Port 0 means "let the OS pick a free port" (see Config.Port). Callers
	// that need a port stable across facade restarts pass one explicitly;
	// DefaultPort is the conventional choice.
	if cfg.CacheDir == "" {
		cfg.CacheDir = fmt.Sprintf("%s/kind-mirror", os.TempDir())
	}
	if cfg.KindNetwork == "" {
		cfg.KindNetwork = DefaultKindNetwork
	}
	if err := os.MkdirAll(cfg.CacheDir, 0o755); err != nil {
		return nil, fmt.Errorf("create cache dir %s: %w", cfg.CacheDir, err)
	}

	f := &Registry{
		cfg:      cfg,
		log:      log.With("component", "kind-mirror"),
		keychain: authn.DefaultKeychain,
		cached:   map[string]bool{},
	}

	// Internal store: disk-backed blobs (persist across runs), in-memory
	// manifests (tiny; rebuilt on demand — the expensive layer blobs are the
	// thing that must persist, and they do).
	blobs := ggcrregistry.NewDiskBlobHandler(cfg.CacheDir)
	// Route the registry's HTTP access log through our logger at Debug level.
	// Otherwise go-containerregistry writes it straight to os.Stderr, bypassing
	// lib/std/log and spamming the caller's output regardless of how they've
	// configured logging.
	accessLog := stdlog.New(logWriter{log: f.log.With("stream", "registry-access")}, "", 0)
	internalHandler := ggcrregistry.New(
		ggcrregistry.WithBlobHandler(blobs),
		ggcrregistry.Logger(accessLog),
	)
	iln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen (internal): %w", err)
	}
	f.internalHost = iln.Addr().String()
	f.internalURL = &url.URL{Scheme: "http", Host: f.internalHost}
	f.proxy = httputil.NewSingleHostReverseProxy(f.internalURL)
	f.internal = &http.Server{Handler: internalHandler, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = f.internal.Serve(iln) }()

	// Public listener: bind all interfaces so kind nodes can reach it via
	// the docker network gateway.
	pln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", cfg.Port))
	if err != nil {
		_ = f.internal.Close()
		return nil, fmt.Errorf("listen (public :%d): %w", cfg.Port, err)
	}
	f.publicAddr = pln.Addr().String()
	f.public = &http.Server{Handler: f, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = f.public.Serve(pln) }()

	f.log.Info("registry facade started",
		"port", cfg.Port,
		"cacheDir", cfg.CacheDir,
		"internal", f.internalHost,
	)
	return f, nil
}

// Addr is the address the public (node-facing) listener bound to. With
// Config.Port left 0 the port is chosen by the OS; this reports the real one.
func (f *Registry) Addr() string { return f.publicAddr }

// Cached returns the (ns, repo, ref) keys the facade has served — pulled
// through from an upstream or pinned via Override. Useful in tests to assert
// a client's pull actually routed through the facade.
func (f *Registry) Cached() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	keys := make([]string, 0, len(f.cached))
	for k := range f.cached {
		keys = append(keys, k)
	}
	return keys
}

// ServeHTTP implements the facade. It rewrites the ns-scoped request path to
// a namespaced repo in the internal store, lazily populates that repo from
// the upstream on a manifest miss, then reverse-proxies to the internal
// store which does the real OCI protocol work.
func (f *Registry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ns := r.URL.Query().Get("ns")
	repo, kind, ref, ok := parseRepoRequest(r.URL.Path)

	// Not a per-image request (e.g. the /v2/ version ping) or no namespace:
	// pass straight through to the internal store unchanged.
	if !ok || ns == "" {
		f.serveInternal(w, r, r.URL.Path)
		return
	}

	// On a manifest read, make sure the (namespaced) repo is populated —
	// either from a prior Override or by pulling from the upstream now.
	if kind == "manifests" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		if err := f.ensure(r.Context(), ns, repo, ref); err != nil {
			f.log.Warn("pull-through failed", "ns", ns, "repo", repo, "ref", ref, "error", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
	}

	// Blobs pulled for that manifest are already present under the same
	// namespaced repo, so blob requests just proxy through.
	f.serveInternal(w, r, fmt.Sprintf("/v2/%s/%s/%s/%s", safeNS(ns), repo, kind, ref))
}

// serveInternal reverse-proxies the request to the internal store under the
// given (already-rewritten) path, dropping only the ns query parameter the
// internal store doesn't understand. Other query parameters are preserved —
// a push's blob-upload PUT carries ?digest=..., and stripping the whole query
// would break it.
func (f *Registry) serveInternal(w http.ResponseWriter, r *http.Request, path string) {
	q := r.URL.Query()
	q.Del("ns")
	r.URL.Path = path
	r.URL.RawQuery = q.Encode()
	f.proxy.ServeHTTP(w, r)
}

// ensure guarantees the (ns, repo, ref) manifest and its blobs are present
// in the internal store. Overridden refs are already present and marked, so
// this is a no-op for them — that is what makes an override beat upstream.
// Otherwise it pulls from the real upstream (named by ns) with the host's
// live keychain and pushes into the internal store; disk-cached blobs are
// not re-fetched.
func (f *Registry) ensure(ctx context.Context, ns, repo, ref string) error {
	k := key(ns, repo, ref)
	f.mu.Lock()
	present := f.cached[k]
	f.mu.Unlock()
	if present {
		return nil
	}

	// The in-memory map is only a fast path. The authoritative "do I already
	// have this?" is the internal store itself — which also covers manifests
	// put there out-of-band: a shell override pushed with `docker push`/crane,
	// or content from a previous process. If it's there, serve it and do NOT
	// pull through, so an override is never clobbered by the upstream (this is
	// what makes a pushed override stick, even under imagePullPolicy: Always).
	if f.existsInternal(ctx, ns, repo, ref) {
		f.mu.Lock()
		f.cached[k] = true
		f.mu.Unlock()
		return nil
	}

	upstream := joinRef("", ns, repo, ref)
	internal := joinRef(f.internalHost, safeNS(ns), repo, ref)
	f.log.Info("pull-through", "upstream", upstream, "internal", internal)

	img, err := crane.Pull(upstream, f.pullOpts(ctx)...)
	if err != nil {
		return fmt.Errorf("pull %s: %w", upstream, err)
	}
	if err := crane.Push(img, internal, f.pushOpts(ctx)...); err != nil {
		return fmt.Errorf("cache %s: %w", internal, err)
	}

	f.mu.Lock()
	f.cached[k] = true
	f.mu.Unlock()
	return nil
}

// existsInternal reports whether a manifest is already present in the internal
// store, via a HEAD to its loopback endpoint. A non-200 (typically 404) or any
// error means "not present" — the caller then pulls through.
func (f *Registry) existsInternal(ctx context.Context, ns, repo, ref string) bool {
	manifestURL := fmt.Sprintf("%s/v2/%s/%s/manifests/%s", f.internalURL.String(), safeNS(ns), repo, ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, manifestURL, nil)
	if err != nil {
		return false
	}
	// Accept every manifest type so content negotiation never 406s a present
	// manifest into looking absent.
	req.Header.Set("Accept", "*/*")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// Stop shuts the facade down. Idempotent.
func (f *Registry) Stop() error {
	if f == nil {
		return nil
	}
	var firstErr error
	if f.public != nil {
		if err := f.public.Close(); err != nil {
			firstErr = err
		}
	}
	if f.internal != nil {
		if err := f.internal.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (f *Registry) pullOpts(ctx context.Context) []crane.Option {
	opts := []crane.Option{crane.WithContext(ctx), crane.WithAuthFromKeychain(f.keychain)}
	if f.cfg.InsecureUpstream {
		opts = append(opts, crane.Insecure)
	}
	return opts
}

func (f *Registry) pushOpts(ctx context.Context) []crane.Option {
	// The internal store is plaintext http on loopback, so push is insecure.
	return []crane.Option{crane.WithContext(ctx), crane.Insecure}
}

// logWriter adapts an io.Writer onto lib/std/log so the go-containerregistry
// access log (a stdlib *log.Logger) flows through our logger at Debug level
// instead of straight to stderr. Each Write is one already-formatted log line.
type logWriter struct{ log log.Logger }

func (w logWriter) Write(p []byte) (int, error) {
	w.log.Debug(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
