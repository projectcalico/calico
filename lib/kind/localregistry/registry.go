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
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"golang.org/x/sync/singleflight"

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
	// ExtraAuthConfigPath, if set and readable, is a docker config.json whose
	// `auths` supplement the host keychain (authn.DefaultKeychain) — e.g. a
	// fetched enterprise pull secret — so private upstream pulls work without
	// the user editing their own ~/.docker/config.json. A missing or
	// unparseable file is ignored (the facade falls back to the host keychain).
	ExtraAuthConfigPath string
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

	// sf coalesces concurrent ensureManifest / ensureBlob calls for the
	// same (ns, repo, ref) — containerd fires many parallel GETs across
	// nodes and pods, and without dedup each one would spawn its own
	// full pull-through.
	sf singleflight.Group

	// repoOverrides maps a repository leaf (last path segment, e.g. "calico")
	// to a local image served for EVERY ns/tag of that repo — a tag-agnostic
	// override (see OverrideRepoFromDaemon), applied lazily in pullManifest.
	repoOverrides map[string]v1.Image
}

// detachContext returns a context whose values are inherited from parent
// but whose cancellation is not — so an in-flight pull-through survives
// containerd's client timeout closing the incoming HTTP request. The
// pull instead runs under its own pullTimeout, and the caller MUST
// defer the returned cancel to release the timer as soon as the pull
// completes (otherwise every request leaks a live timer for pullTimeout).
func detachContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), pullTimeout)
}

const pullTimeout = 10 * time.Minute

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

	// The facade authenticates to upstreams with the host docker keychain
	// (live, so rotated gcloud/registry tokens are picked up). An optional
	// extra config (e.g. a fetched enterprise pull secret) is layered on so
	// private upstreams work without the user editing their own ~/.docker.
	keychain := authn.Keychain(authn.DefaultKeychain)
	if extra := loadExtraKeychain(cfg.ExtraAuthConfigPath); extra != nil {
		keychain = authn.NewMultiKeychain(authn.DefaultKeychain, extra)
	}

	f := &Registry{
		cfg:           cfg,
		log:           log.With("component", "kind-mirror"),
		keychain:      keychain,
		cached:        map[string]bool{},
		repoOverrides: map[string]v1.Image{},
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

// ServeHTTP is the facade. It rewrites ns-scoped paths to namespaced repos
// in the internal store, populates them on first miss, then reverse-proxies
// the request. Pull-through is split per request kind — manifest bytes on
// a manifest miss, one blob on a blob miss — so no single request holds
// the connection open for the whole image transfer (the old flow pulled
// every layer inside the manifest HEAD, tripping containerd's mirror
// response_header_timeout on Kibana / Elasticsearch). Overrides remain
// whole-image pushes (override.go) — local builds, no time cost.
func (f *Registry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ns := r.URL.Query().Get("ns")
	repo, kind, ref, ok := parseRepoRequest(r.URL.Path)

	// Not a per-image request (e.g. the /v2/ version ping) or no namespace:
	// pass straight through to the internal store unchanged.
	if !ok || ns == "" {
		f.serveInternal(w, r, r.URL.Path)
		return
	}

	switch {
	case kind == "manifests" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		// Populate on HEAD too — the manifest is a few KB either way.
		pullCtx, cancel := detachContext(r.Context())
		err := f.ensureManifest(pullCtx, ns, repo, ref)
		cancel()
		if err != nil {
			f.log.Warn("manifest pull-through failed", "ns", ns, "repo", repo, "ref", ref, "error", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
	case kind == "blobs" && r.Method == http.MethodGet:
		// GET only — a HEAD on a missing blob stays cheap (404 from
		// the internal store); the follow-up GET triggers the pull.
		pullCtx, cancel := detachContext(r.Context())
		err := f.ensureBlob(pullCtx, ns, repo, ref)
		cancel()
		if err != nil {
			f.log.Warn("blob pull-through failed", "ns", ns, "repo", repo, "digest", ref, "error", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
	}

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

// ensureManifest puts the (ns, repo, ref) manifest into the internal store
// if it isn't there yet. Overridden refs are already present, so this
// no-ops for them (that's how an override beats upstream). Otherwise it
// pulls just the manifest bytes from ns with the host's keychain — blobs
// come later via ensureBlob when containerd asks for them.
func (f *Registry) ensureManifest(ctx context.Context, ns, repo, ref string) error {
	k := key(ns, repo, ref)
	f.mu.Lock()
	present := f.cached[k]
	f.mu.Unlock()
	if present {
		return nil
	}
	// Coalesce concurrent callers on the same manifest — containerd fires
	// parallel HEADs from every node and pod.
	_, err, _ := f.sf.Do("m:"+k, func() (any, error) {
		return nil, f.pullManifest(ctx, ns, repo, ref, k)
	})
	return err
}

func (f *Registry) pullManifest(ctx context.Context, ns, repo, ref, k string) error {
	// Re-check under singleflight: the previous holder may have populated
	// it while we waited.
	f.mu.Lock()
	if f.cached[k] {
		f.mu.Unlock()
		return nil
	}
	f.mu.Unlock()

	// A tag-agnostic repo override wins over the upstream for every tag of that
	// repo: materialize the local image under the exact ref the node asked for.
	// This is what lets a build be swapped in for an image whose tag isn't known
	// ahead of time (e.g. an operator picks the version at deploy time).
	f.mu.Lock()
	override := f.repoOverrides[repoLeaf(repo)]
	f.mu.Unlock()
	if override != nil {
		internal := joinRef(f.internalHost, safeNS(ns), repo, ref)
		if err := crane.Push(override, internal, f.pushOpts(ctx)...); err != nil {
			return fmt.Errorf("store repo override %s: %w", internal, err)
		}
		f.mu.Lock()
		f.cached[k] = true
		f.mu.Unlock()
		f.log.Info("repo override", "upstream", joinRef("", ns, repo, ref), "internal", internal)
		return nil
	}

	// The in-memory map is only a fast path. The authoritative "do I already
	// have this?" is the internal store itself — which also covers manifests
	// put there out-of-band: a shell override pushed with `docker push`/crane,
	// or content from a previous process. If it's there, serve it and do NOT
	// pull through, so an override is never clobbered by the upstream (this is
	// what makes a pushed override stick, even under imagePullPolicy: Always).
	if f.manifestExistsInternal(ctx, ns, repo, ref) {
		f.mu.Lock()
		f.cached[k] = true
		f.mu.Unlock()
		return nil
	}

	upstream := joinRef("", ns, repo, ref)
	f.log.Info("manifest pull-through", "upstream", upstream)

	upstreamRef, err := name.ParseReference(upstream, f.upstreamNameOpts()...)
	if err != nil {
		return fmt.Errorf("parse upstream %s: %w", upstream, err)
	}
	desc, err := remote.Get(upstreamRef, f.remoteOpts(ctx)...)
	if err != nil {
		return fmt.Errorf("fetch manifest %s: %w", upstream, err)
	}

	// If this is a manifest list / OCI image index, recursively pull
	// its child manifests BEFORE PUTing the index — ggcr's internal
	// registry rejects an index whose referenced manifests aren't
	// present with 404. Child blobs still pull lazily via ensureBlob
	// on the containerd GETs that follow.
	if isIndex(desc.MediaType) {
		if err := f.ensureIndexChildren(ctx, ns, repo, desc.Manifest); err != nil {
			return fmt.Errorf("populate index children for %s: %w", upstream, err)
		}
	}

	// PUT the manifest under the safeNS'd repo. Referenced blobs come
	// later on containerd's per-blob GETs, which ensureBlob handles.
	putURL := fmt.Sprintf("%s/v2/%s/%s/manifests/%s", f.internalURL.String(), safeNS(ns), repo, ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, putURL, bytes.NewReader(desc.Manifest))
	if err != nil {
		return fmt.Errorf("build manifest PUT: %w", err)
	}
	req.Header.Set("Content-Type", string(desc.MediaType))
	req.ContentLength = int64(len(desc.Manifest))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("push manifest to internal: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("push manifest to internal: status %d", resp.StatusCode)
	}

	f.mu.Lock()
	f.cached[k] = true
	f.mu.Unlock()
	return nil
}

// ensureBlob puts the blob at (ns, repo, digest) into the internal store
// if it isn't there yet. Fast path if an Override's crane.Push (or a prior
// ensureBlob) already put it there. Otherwise: one blob, one HTTP transfer —
// containerd's per-request timeout never blocks on unrelated layers.
func (f *Registry) ensureBlob(ctx context.Context, ns, repo, digest string) error {
	if f.blobExistsInternal(ctx, ns, repo, digest) {
		return nil
	}
	_, err, _ := f.sf.Do("b:"+ns+"|"+repo+"|"+digest, func() (any, error) {
		return nil, f.pullBlob(ctx, ns, repo, digest)
	})
	return err
}

func (f *Registry) pullBlob(ctx context.Context, ns, repo, digest string) error {
	// Re-check under singleflight in case the previous holder populated
	// this blob while we waited.
	if f.blobExistsInternal(ctx, ns, repo, digest) {
		return nil
	}

	upstream := joinRef("", ns, repo, digest)
	digestRef, err := name.NewDigest(upstream, f.upstreamNameOpts()...)
	if err != nil {
		return fmt.Errorf("parse blob digest %s: %w", upstream, err)
	}

	// remote.Layer + WriteLayer stream the body — no local buffering.
	layer, err := remote.Layer(digestRef, f.remoteOpts(ctx)...)
	if err != nil {
		return fmt.Errorf("fetch blob %s: %w", upstream, err)
	}
	internalRepoRef := fmt.Sprintf("%s/%s/%s", f.internalHost, safeNS(ns), repo)
	internalRepo, err := name.NewRepository(internalRepoRef, f.internalNameOpts()...)
	if err != nil {
		return fmt.Errorf("parse internal repo %s: %w", internalRepoRef, err)
	}
	if err := remote.WriteLayer(internalRepo, layer, f.pushRemoteOpts(ctx)...); err != nil {
		return fmt.Errorf("push blob %s to internal: %w", digest, err)
	}
	return nil
}

// manifestExistsInternal HEADs the loopback manifest endpoint. Any non-200
// (typically 404) means "not present" — the caller pulls through.
func (f *Registry) manifestExistsInternal(ctx context.Context, ns, repo, ref string) bool {
	u := fmt.Sprintf("%s/v2/%s/%s/manifests/%s", f.internalURL.String(), safeNS(ns), repo, ref)
	return f.internalHEAD(ctx, u, "*/*")
}

// blobExistsInternal is the /blobs/<digest> counterpart.
func (f *Registry) blobExistsInternal(ctx context.Context, ns, repo, digest string) bool {
	u := fmt.Sprintf("%s/v2/%s/%s/blobs/%s", f.internalURL.String(), safeNS(ns), repo, digest)
	return f.internalHEAD(ctx, u, "*/*")
}

// internalHEAD returns whether the loopback endpoint answered 200; any
// error is treated as "not present".
func (f *Registry) internalHEAD(ctx context.Context, url, accept string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", accept)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// isIndex reports whether mt names a manifest list / OCI image index —
// the multi-arch "one manifest referencing per-arch manifests" case.
func isIndex(mt types.MediaType) bool {
	switch mt {
	case types.OCIImageIndex, types.DockerManifestList:
		return true
	}
	return false
}

// ensureIndexChildren parses raw index bytes and recursively populates
// each referenced child manifest so the subsequent index PUT succeeds
// against ggcr's registry (which rejects an index whose referenced
// manifests aren't present with 404).
func (f *Registry) ensureIndexChildren(ctx context.Context, ns, repo string, indexBytes []byte) error {
	var idx struct {
		Manifests []struct {
			Digest string `json:"digest"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(indexBytes, &idx); err != nil {
		return fmt.Errorf("parse index: %w", err)
	}
	for _, m := range idx.Manifests {
		if m.Digest == "" {
			continue
		}
		if err := f.ensureManifest(ctx, ns, repo, m.Digest); err != nil {
			return fmt.Errorf("child manifest %s: %w", m.Digest, err)
		}
	}
	return nil
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

// loadExtraKeychain builds an authn.Keychain over the static `auths` in a
// docker config.json at path. Returns nil (the caller then uses only the host
// keychain) when path is empty, the file is absent, it doesn't parse, or it
// yields no usable credential — so wiring it in is always safe. Entries whose
// key normalises to an empty host, or that carry no credential material, are
// skipped so they can't shadow the host keychain with an empty AuthConfig.
func loadExtraKeychain(path string) authn.Keychain {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var dc struct {
		Auths map[string]struct {
			Auth          string `json:"auth"`
			Username      string `json:"username"`
			Password      string `json:"password"`
			IdentityToken string `json:"identitytoken"`
			RegistryToken string `json:"registrytoken"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(b, &dc); err != nil {
		return nil
	}
	auths := make(map[string]authn.AuthConfig, len(dc.Auths))
	for reg, a := range dc.Auths {
		host := registryHost(reg)
		ac := authn.AuthConfig{
			Auth:          a.Auth,
			Username:      a.Username,
			Password:      a.Password,
			IdentityToken: a.IdentityToken,
			RegistryToken: a.RegistryToken,
		}
		if host == "" || ac == (authn.AuthConfig{}) {
			continue
		}
		auths[host] = ac
	}
	if len(auths) == 0 {
		return nil
	}
	return staticKeychain(auths)
}

// registryHost normalises a docker-config auths key — which may be a bare host
// ("quay.io") or a legacy URL ("https://quay.io/v1/") — to the host that
// authn.Resource.RegistryStr reports, so lookups match.
func registryHost(key string) string {
	k := strings.TrimPrefix(key, "https://")
	k = strings.TrimPrefix(k, "http://")
	if i := strings.IndexByte(k, '/'); i >= 0 {
		k = k[:i]
	}
	return k
}

// staticKeychain resolves credentials from a fixed registry-host -> AuthConfig
// map (e.g. one parsed from a pull-secret file).
type staticKeychain map[string]authn.AuthConfig

func (s staticKeychain) Resolve(res authn.Resource) (authn.Authenticator, error) {
	if ac, ok := s[res.RegistryStr()]; ok {
		return authn.FromConfig(ac), nil
	}
	return authn.Anonymous, nil
}

func (f *Registry) pushOpts(ctx context.Context) []crane.Option {
	// The internal store is plaintext http on loopback, so push is insecure.
	return []crane.Option{crane.WithContext(ctx), crane.Insecure}
}

// remoteOpts is the remote-package counterpart of the old crane pullOpts —
// ensureManifest / ensureBlob use remote directly so they can pull a single
// manifest or blob without walking the whole image graph.
func (f *Registry) remoteOpts(ctx context.Context) []remote.Option {
	return []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(f.keychain),
	}
}

// pushRemoteOpts is the remote counterpart of pushOpts. name.Insecure lives
// on internalNameOpts, not here — WriteLayer picks it up from the Repository.
func (f *Registry) pushRemoteOpts(ctx context.Context) []remote.Option {
	return []remote.Option{remote.WithContext(ctx)}
}

// upstreamNameOpts parses real upstreams (gcr.io/…, docker.io/…) as https;
// name.Insecure only for the test-only InsecureUpstream toggle.
func (f *Registry) upstreamNameOpts() []name.Option {
	if f.cfg.InsecureUpstream {
		return []name.Option{name.Insecure}
	}
	return nil
}

// internalNameOpts forces plaintext HTTP — the loopback store binds
// http-only.
func (f *Registry) internalNameOpts() []name.Option {
	return []name.Option{name.Insecure}
}

// logWriter adapts an io.Writer onto lib/std/log so the go-containerregistry
// access log (a stdlib *log.Logger) flows through our logger at Debug level
// instead of straight to stderr. Each Write is one already-formatted log line.
type logWriter struct{ log log.Logger }

func (w logWriter) Write(p []byte) (int, error) {
	w.log.Debug(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
