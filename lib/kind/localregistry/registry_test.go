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
	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
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
	defer func() { _ = resp.Body.Close() }()
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

// TestRepoOverrideServesEveryTag proves a tag-agnostic repo override (the
// pre-load path, registered before any specific tag is known) is served for
// EVERY tag of a matching repository — including a tag never pushed upstream —
// and that it does not leak to a non-matching repo leaf. The override is set
// directly here; OverrideRepoFromDaemon's only extra step is `docker save`,
// which a unit test can't exercise hermetically.
func TestRepoOverrideServesEveryTag(t *testing.T) {
	host, srv := startUpstream(t)
	pushRandom(t, host, "tigera/calico:v1")            // a real upstream tag
	otherImg := pushRandom(t, host, "tigera/other:v1") // an unrelated repo

	override, err := random.Image(4096, 2) // distinct content
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}

	f := startRegistry(t)
	f.mu.Lock()
	f.repoOverrides["calico"] = override
	f.mu.Unlock()

	// A non-matching repo leaf still comes from upstream — the override must not
	// leak to it.
	if got, want := manifestDigestVia(t, f.Addr(), host, "tigera/other", "v1"), mustDigest(t, otherImg); got != want {
		t.Errorf("tigera/other served %s, want upstream %s (override leaked to a non-matching repo)", got, want)
	}

	// Kill the upstream: the override must be served without contacting it, for
	// both an upstream-known tag and a tag that was never pushed.
	srv.Close()
	want := mustDigest(t, override)
	for _, ref := range []string{"v1", "v999-never-pushed"} {
		if got := manifestDigestVia(t, f.Addr(), host, "tigera/calico", ref); got != want {
			t.Errorf("tigera/calico:%s served %s, want override %s", ref, got, want)
		}
	}
}

// TestRepoOverrideYieldsToExistingContent proves a tag-agnostic repo override
// does NOT clobber content already in the internal store (an explicit or
// shell-pushed override, or content from a previous process) -- that would break
// the "an existing override beats upstream" contract. The repo override only
// stands in for the upstream pull-through, so it applies to tags the store
// doesn't already answer.
func TestRepoOverrideYieldsToExistingContent(t *testing.T) {
	f := startRegistry(t)

	// A shell-pushed exact override for one tag of a matching-leaf repo.
	shellImg, err := random.Image(2048, 3)
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}
	_, port, err := net.SplitHostPort(f.Addr())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	if err := crane.Push(shellImg, "127.0.0.1:"+port+"/example.com/team/calico:v1", crane.Insecure); err != nil {
		t.Fatalf("shell push: %v", err)
	}

	// A repo override for the same leaf ("calico"), with distinct content.
	repoImg, err := random.Image(4096, 2)
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}
	f.mu.Lock()
	f.repoOverrides["calico"] = repoImg
	f.mu.Unlock()

	// The shell-pushed tag serves the shell push, not the repo override.
	if got, want := manifestDigestVia(t, f.Addr(), "example.com", "team/calico", "v1"), mustDigest(t, shellImg); got != want {
		t.Errorf("v1 served %s, want shell push %s (repo override clobbered existing content)", got, want)
	}
	// A different, never-pushed tag of the same repo still gets the repo override.
	if got, want := manifestDigestVia(t, f.Addr(), "example.com", "team/calico", "v2-new"), mustDigest(t, repoImg); got != want {
		t.Errorf("v2-new served %s, want repo override %s", got, want)
	}
}

// TestOverrideRepoFromDaemonRejectsBadLeaf guards the leaf contract: a
// multi-segment or empty leaf is rejected up front (it would silently never
// match a repository's last segment), before any docker save.
func TestOverrideRepoFromDaemonRejectsBadLeaf(t *testing.T) {
	f := startRegistry(t)
	for _, leaf := range []string{"", "tigera/calico"} {
		if err := f.OverrideRepoFromDaemon(context.Background(), leaf, "irrelevant:latest"); err == nil {
			t.Errorf("OverrideRepoFromDaemon(leaf=%q) = nil, want error", leaf)
		}
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

// TestPullThroughMultiArchIndex proves ensureManifest handles a real
// multi-arch image: pushing an OCI image index whose referenced child
// manifests aren't yet in the internal store used to 404 the index PUT
// (ggcr's registry rejects an index whose children are missing). The
// facade must recursively populate each child before PUTing the index.
func TestPullThroughMultiArchIndex(t *testing.T) {
	host, _ := startUpstream(t)

	// Build a two-arch OCI image index; push to the upstream.
	imgA, err := random.Image(1024, 2)
	if err != nil {
		t.Fatalf("random.Image A: %v", err)
	}
	imgB, err := random.Image(1024, 2)
	if err != nil {
		t.Fatalf("random.Image B: %v", err)
	}
	idx := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: imgA, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}},
		mutate.IndexAddendum{Add: imgB, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64"}}},
	)
	ref, err := name.ParseReference(host+"/team/multi:v1", name.Insecure)
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	if err := remote.WriteIndex(ref, idx); err != nil {
		t.Fatalf("push index: %v", err)
	}

	f := startRegistry(t)
	got := manifestDigestVia(t, f.Addr(), host, "team/multi", "v1")
	want, err := idx.Digest()
	if err != nil {
		t.Fatalf("index digest: %v", err)
	}
	if got != want.String() {
		t.Errorf("index served %s, want %s", got, want.String())
	}
}
