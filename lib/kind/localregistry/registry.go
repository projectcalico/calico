// Copyright (c) 2026 Tigera, Inc. All rights reserved.

// Package localregistry runs a Docker registry container on the host
// and exposes it to a kind cluster as a containerd mirror. This is
// the image-loading strategy for lib/kind.
//
// The local registry:
//
//   - Uses Docker's standard pull pipeline (containerd → registry over
//     HTTP), matching production behaviour rather than mutating
//     imagePullPolicy to Never.
//   - Layer-caches across runs: an image whose base layers haven't
//     changed only re-transfers the changed bits on push and pull.
//   - Persists across container removal. Blobs are stored on a docker
//     named volume (default "kind-registry-data") mounted at
//     /var/lib/registry. The container can be deleted and recreated
//     and the cached image content survives. To wipe entirely the
//     operator runs `docker volume rm kind-registry-data` after Stop.
//   - Survives kind cluster teardowns. The registry container can be
//     left running (Persist=true) to avoid the recreate cost between
//     test runs.
//   - Can serve images to multiple concurrent kind clusters in
//     parallel — useful when running tests across versions.
//
// The cost: containerd has to be told about the registry at cluster-
// creation time via containerdConfigPatches, and the registry
// container has to be connected to the kind docker network. Both are
// handled by this package; the caller wires them together.
//
// Usage:
//
//	reg, err := localregistry.Setup(ctx, localregistry.Config{})
//	if err != nil { t.Fatal(err) }
//	t.Cleanup(func() { reg.Stop() })
//
//	cl, err := kind.Up(ctx, kind.Config{
//	    ContainerdConfigPatches: reg.ContainerdConfigPatches(),
//	})
//	if err != nil { t.Fatal(err) }
//
//	// Attach the registry to kind's docker network now that it exists.
//	if err := reg.Attach(ctx, "kind"); err != nil { t.Fatal(err) }
//
//	// Pre-populate the registry with images the cluster will pull.
//	for _, img := range []string{"calico/node:v3.30.1", "calico/cni:v3.30.1"} {
//	    if _, err := reg.Push(ctx, img); err != nil { t.Fatal(err) }
//	}
//
// Pod specs and manifests then reference images as `localhost:<port>/<image>`.
// For images whose paths don't match (e.g. third-party operator manifests
// that embed quay.io URLs), the caller either rewrites the manifest or
// configures additional containerd mirrors.
package localregistry

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	"sigs.k8s.io/kind/pkg/cluster/nodes"
	"sigs.k8s.io/kind/pkg/cluster/nodeutils"

	"github.com/projectcalico/calico/lib/std/log"
)

// Defaults applied to a zero-value Config.
const (
	DefaultPort        = 5001 // host port. 5001 not 5000 to avoid macOS AirPlay.
	DefaultName        = "kind-registry"
	DefaultImage       = "registry:2"
	DefaultKindNetwork = "kind"
	DefaultVolumeName  = "kind-registry-data" // docker named volume mounted at /var/lib/registry.
	registryInsidePort = 5000                 // the registry process listens on 5000 inside the container.
	registryDataPath   = "/var/lib/registry"  // where registry:2 stores blobs inside the container.
)

// Config configures Setup. Zero values pick sensible defaults; set what
// you need to override.
type Config struct {
	// Port is the host port to publish the registry on (127.0.0.1:Port).
	// Default DefaultPort (5001).
	Port int
	// Name is the docker container name. Reusing an existing container
	// with the same name is an explicit feature — set deliberately for
	// cross-run persistence. Default DefaultName ("kind-registry").
	Name string
	// Image is the registry image to run. Default DefaultImage
	// ("registry:2"). Pinning to a digest is recommended in CI.
	Image string
	// KindNetwork is the docker network kind creates for the cluster.
	// Default DefaultKindNetwork ("kind").
	KindNetwork string
	// VolumeName is the docker named volume mounted at the registry's
	// storage path (/var/lib/registry). The volume outlives container
	// removal — pushed images survive `docker rm` of the container
	// and reappear on the next `docker run` against the same volume.
	// Default DefaultVolumeName ("kind-registry-data"). To wipe the
	// cache, the operator runs `docker volume rm <VolumeName>` after
	// Stop.
	VolumeName string
	// ProxyRemoteURL, when set, runs the registry in pull-through
	// proxy mode against the given upstream. Images not present in
	// the local cache are fetched from the upstream on first request
	// and stored on the volume; subsequent requests hit the cache.
	// Use this to avoid pre-pushing every image the cluster will
	// pull — point the proxy at the registry your manifests reference
	// (e.g. "https://quay.io") and pair with a matching upstream
	// mirror entry passed to ContainerdConfigPatches.
	//
	// Limitation: registry:2 supports exactly one upstream per
	// container. To proxy multiple upstream registries, run more
	// than one localregistry instance.
	ProxyRemoteURL string
	// ProxyUsername / ProxyPassword are the upstream credentials the
	// pull-through proxy uses when fetching from ProxyRemoteURL (passed as
	// REGISTRY_PROXY_USERNAME / REGISTRY_PROXY_PASSWORD). Needed for private
	// upstreams (e.g. gcr.io with "oauth2accesstoken" + a gcloud token);
	// leave empty for anonymous upstreams (quay.io, docker.io, k8s). Only
	// used when ProxyRemoteURL is set.
	ProxyUsername string
	ProxyPassword string
	// Persist, when true, leaves the registry container running on
	// Stop(). The volume persists either way (see VolumeName); Persist
	// just controls whether the container itself stays up between
	// runs. Recommended for local dev. In CI you typically want
	// Persist=false (container is recreated per job) plus the default
	// volume (so layer cache carries across jobs that share the
	// machine).
	Persist bool
}

// Handle is the lifecycle handle returned by Setup. Stop is idempotent
// and safe to call from deferred cleanup even if Setup failed partway.
type Handle struct {
	cfg Config
	log log.Logger
}

// Setup ensures a registry container is running. If one with the same
// name already exists, Setup reuses it (starting it if stopped). The
// registry is NOT yet attached to the kind network — call Attach after
// kind.Up returns.
func Setup(ctx context.Context, cfg Config) (*Handle, error) {
	if cfg.Port == 0 {
		cfg.Port = DefaultPort
	}
	if cfg.Name == "" {
		cfg.Name = DefaultName
	}
	if cfg.Image == "" {
		cfg.Image = DefaultImage
	}
	if cfg.KindNetwork == "" {
		cfg.KindNetwork = DefaultKindNetwork
	}
	if cfg.VolumeName == "" {
		cfg.VolumeName = DefaultVolumeName
	}

	h := &Handle{cfg: cfg, log: log.With("component", "local-registry")}

	exists, running, err := h.status(ctx)
	if err != nil {
		return nil, err
	}
	switch {
	case !exists:
		h.log.Info("creating registry container",
			"name", cfg.Name,
			"port", cfg.Port,
			"image", cfg.Image,
		)
		if err := h.create(ctx); err != nil {
			return nil, err
		}
	case !running:
		h.log.Info("starting existing container", "name", cfg.Name)
		if err := h.start(ctx); err != nil {
			return nil, err
		}
	default:
		h.log.Info("reusing already-running container", "name", cfg.Name)
	}

	return h, nil
}

// Attach connects the registry container to a docker network. Must be
// called AFTER kind.Up creates the network (typically "kind"). Idempotent
// — repeated calls against an already-attached registry are silently
// ignored. A missing network is also silently ignored so callers can
// invoke Attach speculatively before they know the cluster is up.
func (h *Handle) Attach(ctx context.Context, network string) error {
	if h == nil {
		return nil
	}
	out, err := dockerOut(ctx, "network", "connect", network, h.cfg.Name)
	if err == nil {
		h.log.Info("attached to docker network", "name", h.cfg.Name, "network", network)
		return nil
	}
	msg := strings.TrimSpace(out)
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "already exists"), strings.Contains(lower, "endpoint with name"):
		return nil
	case strings.Contains(lower, "not found"), strings.Contains(lower, "no such network"):
		h.log.Info("docker network not present yet — skipping attach", "network", network)
		return nil
	}
	return fmt.Errorf("docker network connect %s %s: %s: %w", network, h.cfg.Name, msg, err)
}

// ContainerdConfigPatches returns the containerd config_path setup kind
// needs to enable per-host registry configuration. After kind.Up returns,
// call ConfigureNodes to drop the hosts.toml files into that directory —
// without those files no pulls actually route through this registry.
//
// Background: containerd 2.x (used by kindest/node images built by kind
// v0.27 and later) dropped support for the legacy
// [plugins."io.containerd.grpc.v1.cri".registry.mirrors.X] stanza inside
// /etc/containerd/config.toml. The replacement is the config_path +
// hosts.toml split documented at
// https://github.com/containerd/containerd/blob/main/docs/hosts.md.
// Older kindest/node images (built by kind v0.26 and earlier, e.g.
// kindest/node:v1.30.x) still honor the legacy stanza, but this format
// works for both, so it's the safe default.
func (h *Handle) ContainerdConfigPatches() []string {
	if h == nil {
		return nil
	}
	return []string{
		`[plugins."io.containerd.grpc.v1.cri".registry]
  config_path = "/etc/containerd/certs.d"`,
	}
}

// ConfigureNodes writes a hosts.toml into each kind node redirecting
// pulls for localhost:<Port> (and any upstreamMirrors supplied) to this
// registry. Must be called AFTER kind.Up created the nodes AND Attach
// connected the registry to the kind docker network — otherwise the
// nodes can't reach the registry by host name and the writes are
// pointless. Safe to re-run.
//
// upstreamMirrors are extra registry hosts whose pulls should also go
// through this local registry. Pair with localregistry.Config.ProxyRemoteURL
// to make the registry transparently proxy a single upstream. registry:2
// only supports one proxy upstream per container, so multi-upstream
// mirroring requires multiple localregistry instances.
func (h *Handle) ConfigureNodes(ctx context.Context, kindNodes []nodes.Node, upstreamMirrors ...string) error {
	if h == nil {
		return nil
	}
	endpoint := fmt.Sprintf("http://%s:%d", h.cfg.Name, registryInsidePort)
	hostsTOML := fmt.Sprintf("[host.%q]\n", endpoint)

	targets := make([]string, 0, 1+len(upstreamMirrors))
	targets = append(targets, fmt.Sprintf("localhost:%d", h.cfg.Port))
	targets = append(targets, upstreamMirrors...)

	for _, n := range kindNodes {
		for _, t := range targets {
			dir := "/etc/containerd/certs.d/" + t
			if err := n.Command("mkdir", "-p", dir).Run(); err != nil {
				return fmt.Errorf("mkdir %s on %s: %w", dir, n, err)
			}
			if err := nodeutils.WriteFile(n, dir+"/hosts.toml", hostsTOML); err != nil {
				return fmt.Errorf("write hosts.toml in %s on %s: %w", dir, n, err)
			}
		}
	}
	h.log.Info("Wrote containerd hosts.toml on kind nodes.",
		"nodes", len(kindNodes),
		"targets", targets,
	)
	return nil
}

// Push pulls sourceRef from its upstream registry (using the local
// docker keychain for auth), then pushes it to this local registry
// under a normalised path. Returns the new ref that pods/manifests
// should use.
//
// Example: Push("quay.io/tigera/operator:v1.32.0") returns
// "localhost:5001/tigera/operator:v1.32.0".
func (h *Handle) Push(ctx context.Context, sourceRef string) (string, error) {
	if h == nil {
		return "", fmt.Errorf("nil registry handle")
	}
	target := h.LocalRef(sourceRef)
	h.log.Info("push image", "source", sourceRef, "target", target)
	img, err := crane.Pull(sourceRef, crane.WithContext(ctx))
	if err != nil {
		return "", fmt.Errorf("pull %s: %w", sourceRef, err)
	}
	if err := crane.Push(img, target, crane.WithContext(ctx), crane.Insecure); err != nil {
		return "", fmt.Errorf("push %s: %w", target, err)
	}
	return target, nil
}

// LocalRef rewrites an arbitrary image reference into the path this
// registry serves it under. Does not push.
func (h *Handle) LocalRef(sourceRef string) string {
	if h == nil {
		return sourceRef
	}
	return fmt.Sprintf("localhost:%d/%s", h.cfg.Port, stripUpstreamPrefix(sourceRef))
}

// Port returns the host port the registry is published on. Useful for
// callers that want to construct refs themselves without going through
// LocalRef.
func (h *Handle) Port() int { return h.cfg.Port }

// Stop tears down the registry container unless Config.Persist was set,
// in which case the container is left running for the next test run.
// Idempotent.
func (h *Handle) Stop() error {
	if h == nil {
		return nil
	}
	if h.cfg.Persist {
		h.log.Info("leaving registry running (Persist=true)", "name", h.cfg.Name)
		return nil
	}
	h.log.Info("removing registry container", "name", h.cfg.Name)
	if out, err := dockerOut(context.Background(), "rm", "-f", h.cfg.Name); err != nil {
		return fmt.Errorf("docker rm %s: %s: %w", h.cfg.Name, strings.TrimSpace(out), err)
	}
	return nil
}

// status reports whether the named container exists and whether it's
// currently running. A missing container is not an error — that's the
// "needs to be created" case.
func (h *Handle) status(ctx context.Context) (exists, running bool, err error) {
	out, err := dockerOut(ctx, "inspect", "-f", "{{.State.Running}}", h.cfg.Name)
	if err == nil {
		return true, strings.TrimSpace(out) == "true", nil
	}
	// Different docker versions case this differently:
	// "No such object: …" / "no such object: …" / "No such container: …"
	if strings.Contains(strings.ToLower(out), "no such") {
		return false, false, nil
	}
	return false, false, fmt.Errorf("docker inspect %s: %s: %w", h.cfg.Name, strings.TrimSpace(out), err)
}

// create runs the registry container fresh. Publishes only on
// 127.0.0.1 — no external exposure. Mounts the named volume so
// blobs survive container removal. When ProxyRemoteURL is set,
// passes the upstream URL through as the proxy target.
func (h *Handle) create(ctx context.Context) error {
	args := []string{"run", "-d", "--restart=always",
		"-p", fmt.Sprintf("127.0.0.1:%d:%d", h.cfg.Port, registryInsidePort),
		"-v", fmt.Sprintf("%s:%s", h.cfg.VolumeName, registryDataPath),
		"--name", h.cfg.Name,
	}
	if h.cfg.ProxyRemoteURL != "" {
		args = append(args, "-e", "REGISTRY_PROXY_REMOTEURL="+h.cfg.ProxyRemoteURL)
		if h.cfg.ProxyUsername != "" {
			args = append(args, "-e", "REGISTRY_PROXY_USERNAME="+h.cfg.ProxyUsername)
		}
		if h.cfg.ProxyPassword != "" {
			args = append(args, "-e", "REGISTRY_PROXY_PASSWORD="+h.cfg.ProxyPassword)
		}
	}
	args = append(args, h.cfg.Image)
	out, err := dockerOut(ctx, args...)
	if err != nil {
		return fmt.Errorf("docker run %s: %s: %w", h.cfg.Name, strings.TrimSpace(out), err)
	}
	return nil
}

func (h *Handle) start(ctx context.Context) error {
	if out, err := dockerOut(ctx, "start", h.cfg.Name); err != nil {
		return fmt.Errorf("docker start %s: %s: %w", h.cfg.Name, strings.TrimSpace(out), err)
	}
	return nil
}

// dockerOut runs `docker <args...>` and returns combined output (stdout
// + stderr) so we can match error messages to known idempotent cases.
func dockerOut(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return string(out), err
}

// stripUpstreamPrefix normalises an image reference by removing the
// upstream registry host and the `library/` namespace docker.io
// applies to single-name images. The result is the path the local
// registry should serve the image at.
//
//	docker.io/library/redis:7   → redis:7
//	docker.io/calico/node:v3    → calico/node:v3
//	quay.io/tigera/operator:v1  → tigera/operator:v1
//	gcr.io/google/foo:bar       → google/foo:bar
func stripUpstreamPrefix(ref string) string {
	// Identify if the first segment looks like a registry host
	// (contains a "." or a ":"). If so, drop it.
	if i := strings.IndexByte(ref, '/'); i > 0 {
		first := ref[:i]
		if strings.ContainsAny(first, ".:") {
			ref = ref[i+1:]
		}
	}
	// docker.io's single-name images live under library/
	ref = strings.TrimPrefix(ref, "library/")
	return ref
}
