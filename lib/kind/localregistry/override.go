// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package localregistry

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Override pins a local image as the answer for an upstream ref. After this
// call, whenever the cluster pulls upstreamRef the facade serves img and
// never contacts the upstream — regardless of the pod's imagePullPolicy.
//
// upstreamRef is the reference as the cluster asks for it, e.g.
// "quay.io/calico/node:v3.30.1" or "docker.io/calico/node:latest". It must
// name a tag, not a digest: a digest is content-addressed, so "serve
// different content under the same digest" is a contradiction.
//
// This is the low-level form. Most callers want the OverrideFrom* helpers.
func (f *Registry) Override(ctx context.Context, upstreamRef string, img v1.Image) error {
	reg, repo, ref, isDigest := splitRef(upstreamRef)
	if isDigest {
		return fmt.Errorf("override target %q is a digest; overrides must target a tag", upstreamRef)
	}
	internal := joinRef(f.internalHost, safeNS(reg), repo, ref)
	f.log.Info("override", "upstream", upstreamRef, "internal", internal)
	if err := crane.Push(img, internal, f.pushOpts(ctx)...); err != nil {
		return fmt.Errorf("store override %s: %w", internal, err)
	}
	// Mark present so pull-through never overwrites it with the upstream.
	f.mu.Lock()
	f.cached[key(reg, repo, ref)] = true
	f.mu.Unlock()
	return nil
}

// OverrideFromDaemon pins a locally-built docker image (a tag as `docker
// images` shows it, e.g. "calico/node:latest-amd64") as the answer for
// upstreamRef. This is the common dev path: build an image, point the ref
// the cluster pulls at your build.
//
//	mir.OverrideFromDaemon(ctx, "quay.io/calico/node:v3.30.1", "calico/node:latest-amd64")
func (f *Registry) OverrideFromDaemon(ctx context.Context, upstreamRef, localDockerRef string) error {
	tar, err := os.CreateTemp("", "kind-mirror-*.tar")
	if err != nil {
		return fmt.Errorf("temp file: %w", err)
	}
	tar.Close()
	defer os.Remove(tar.Name())

	// Reuse the docker CLI (already a hard dependency of kind) to snapshot
	// the daemon image to a tarball crane can read.
	out, err := exec.CommandContext(ctx, "docker", "save", "-o", tar.Name(), localDockerRef).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker save %s: %s: %w", localDockerRef, strings.TrimSpace(string(out)), err)
	}
	return f.OverrideFromTarball(ctx, upstreamRef, tar.Name())
}

// OverrideFromTarball pins an image from a `docker save` / OCI tarball as the
// answer for upstreamRef.
func (f *Registry) OverrideFromTarball(ctx context.Context, upstreamRef, tarPath string) error {
	img, err := crane.Load(tarPath)
	if err != nil {
		return fmt.Errorf("load tarball %s: %w", tarPath, err)
	}
	return f.Override(ctx, upstreamRef, img)
}

// --- ref helpers ---------------------------------------------------------

// key is the cache/override identity for a (registry, repo, reference)
// triple. registry is the ns as containerd sends it, kept verbatim (not
// normalised) so an Override keyed on "docker.io/..." matches the ns=docker.io
// containerd actually requests.
func key(registry, repo, ref string) string {
	return registry + "|" + repo + "|" + ref
}

// safeNS turns a registry host (the ns value, e.g. "gcr.io" or, in tests,
// "127.0.0.1:5001") into a token usable as a repository path segment in the
// internal store: the ':' of a host:port is illegal in an OCI repo name. The
// raw ns is still used for the upstream pull and for cache keys — only the
// internal storage path is sanitised.
func safeNS(ns string) string {
	return strings.ReplaceAll(ns, ":", "_")
}

// joinRef builds an image reference. host is the registry host to prepend
// (the internal store's host, or "" for the bare upstream ref crane resolves
// itself). A digest reference (contains ':') is joined with '@', a tag with
// ':'.
func joinRef(host, registry, repo, ref string) string {
	sep := ":"
	if strings.Contains(ref, ":") { // sha256:… — a digest, not a tag
		sep = "@"
	}
	name := registry + "/" + repo
	if host != "" {
		name = host + "/" + name
	}
	return name + sep + ref
}

// splitRef decomposes an image reference into its registry host, repository
// path, and identifier (tag or digest). The registry host is preserved
// exactly as given — no docker.io→index.docker.io normalisation — so keys
// line up with containerd's ns parameter. A missing registry defaults to
// "docker.io" (the ns containerd uses for Docker Hub).
func splitRef(ref string) (registry, repo, identifier string, isDigest bool) {
	name := ref
	identifier = "latest"

	if at := strings.LastIndex(ref, "@"); at != -1 {
		name, identifier, isDigest = ref[:at], ref[at+1:], true
	} else if colon := strings.LastIndex(ref, ":"); colon > strings.LastIndex(ref, "/") {
		// A colon after the last slash is a tag separator (a colon inside an
		// earlier path segment would be a registry port, which we leave alone).
		name, identifier = ref[:colon], ref[colon+1:]
	}

	if i := strings.IndexByte(name, '/'); i > 0 && (strings.ContainsAny(name[:i], ".:") || name[:i] == "localhost") {
		registry, repo = name[:i], name[i+1:]
	} else {
		registry, repo = "docker.io", name
	}
	return registry, repo, identifier, isDigest
}

// parseRepoRequest splits a registry v2 API path of the form
// /v2/<repo>/manifests/<ref> or /v2/<repo>/blobs/<ref> into its parts. repo
// may contain slashes. ok is false for paths that aren't per-image requests
// (e.g. the /v2/ version ping), which the caller passes through untouched.
func parseRepoRequest(path string) (repo, kind, ref string, ok bool) {
	const prefix = "/v2/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", "", false
	}
	rest := path[len(prefix):]
	for _, k := range []string{"manifests", "blobs"} {
		marker := "/" + k + "/"
		if i := strings.LastIndex(rest, marker); i != -1 {
			return rest[:i], k, rest[i+len(marker):], true
		}
	}
	return "", "", "", false
}
