// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package localregistry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
)

// startUpstream stands up a throwaway OCI registry and returns its host
// (host:port, no scheme) — a stand-in for gcr.io/quay.io in a hermetic test.
func startUpstream(t *testing.T) (host string, srv *httptest.Server) {
	t.Helper()
	srv = httptest.NewServer(ggcrregistry.New())
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://"), srv
}

// pushRandom pushes a fresh random image to host/repoTag and returns it.
func pushRandom(t *testing.T, host, repoTag string) v1.Image {
	t.Helper()
	img, err := random.Image(1024, 2)
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}
	if err := crane.Push(img, host+"/"+repoTag, crane.Insecure); err != nil {
		t.Fatalf("push %s/%s: %v", host, repoTag, err)
	}
	return img
}

// manifestDigestVia fetches a manifest through the facade the way containerd
// would — with the origin registry in the ns query parameter — and returns
// the digest of the bytes served.
func manifestDigestVia(t *testing.T, facadeAddr, ns, repo, ref string) string {
	t.Helper()
	// Addr() reports 0.0.0.0:port; dial loopback.
	_, port, err := net.SplitHostPort(facadeAddr)
	if err != nil {
		t.Fatalf("split facade addr %q: %v", facadeAddr, err)
	}
	url := "http://127.0.0.1:" + port + "/v2/" + repo + "/manifests/" + ref + "?ns=" + ns
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d: %s", url, resp.StatusCode, body)
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func mustDigest(t *testing.T, img v1.Image) string {
	t.Helper()
	d, err := img.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	return d.String()
}

func startRegistry(t *testing.T) *Registry {
	t.Helper()
	f, err := Start(context.Background(), Config{
		Port:             0, // OS-assigned; avoids clashing on a fixed port
		CacheDir:         t.TempDir(),
		InsecureUpstream: true, // test upstreams are plaintext http
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = f.Stop() })
	return f
}

// TestNamespaceRouting proves one facade serves multiple upstreams: two
// registries hosting *different* images under the *same* repo path are told
// apart purely by the ns parameter.
func TestNamespaceRouting(t *testing.T) {
	hostA, _ := startUpstream(t)
	hostB, _ := startUpstream(t)
	imgA := pushRandom(t, hostA, "team/app:v1")
	imgB := pushRandom(t, hostB, "team/app:v1")

	f := startRegistry(t)

	if got, want := manifestDigestVia(t, f.Addr(), hostA, "team/app", "v1"), mustDigest(t, imgA); got != want {
		t.Errorf("ns=%s served %s, want upstream A image %s", hostA, got, want)
	}
	if got, want := manifestDigestVia(t, f.Addr(), hostB, "team/app", "v1"), mustDigest(t, imgB); got != want {
		t.Errorf("ns=%s served %s, want upstream B image %s", hostB, got, want)
	}
}

// TestOverrideBeatsUpstream proves an override is served instead of the
// upstream image — and that no upstream contact happens, by taking the
// upstream down before the request.
func TestOverrideBeatsUpstream(t *testing.T) {
	host, srv := startUpstream(t)
	upstreamImg := pushRandom(t, host, "team/app:v2")

	override, err := random.Image(2048, 3) // distinct content
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}

	f := startRegistry(t)
	if err := f.Override(context.Background(), host+"/team/app:v2", override); err != nil {
		t.Fatalf("Override: %v", err)
	}

	// Kill the upstream: a correct override must not need it.
	srv.Close()

	got := manifestDigestVia(t, f.Addr(), host, "team/app", "v2")
	if want := mustDigest(t, override); got != want {
		t.Errorf("served %s, want override %s", got, want)
	}
	if got == mustDigest(t, upstreamImg) {
		t.Errorf("served the upstream image; override did not win")
	}
}

// TestShellPushOverride proves the no-code override path: pushing an image to
// the facade under the upstream host as the first path segment — exactly what
//
//	docker push localhost:<port>/quay.io/calico/node:v1
//
// does — is served back when a node pulls that upstream ref, and pull-through
// does not clobber it. The upstream "example.com" is never reachable here, so
// a served 200 with the pushed digest can only mean the override won (a
// pull-through attempt would fail instead).
func TestShellPushOverride(t *testing.T) {
	f := startRegistry(t)

	override, err := random.Image(2048, 3)
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}

	_, port, err := net.SplitHostPort(f.Addr())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	// The first path segment is the upstream host, matching the ns a node
	// will later resolve with.
	pushRef := "127.0.0.1:" + port + "/example.com/team/app:v5"
	if err := crane.Push(override, pushRef, crane.Insecure); err != nil {
		t.Fatalf("push override %s: %v", pushRef, err)
	}

	got := manifestDigestVia(t, f.Addr(), "example.com", "team/app", "v5")
	if want := mustDigest(t, override); got != want {
		t.Errorf("served %s, want pushed override %s", got, want)
	}
}

// TestOverrideRejectsDigest guards the documented constraint: you cannot
// override a digest ref (content-addressed, so serving different bytes is a
// contradiction).
func TestOverrideRejectsDigest(t *testing.T) {
	f := startRegistry(t)
	img, _ := random.Image(64, 1)
	err := f.Override(context.Background(),
		"quay.io/team/app@sha256:"+strings.Repeat("a", 64), img)
	if err == nil {
		t.Fatal("expected error overriding a digest ref, got nil")
	}
}
