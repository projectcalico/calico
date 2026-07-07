// Copyright (c) 2026 Tigera, Inc. All rights reserved.

//go:build kindfv

// This is an FV test: it builds a real kind cluster and drives real
// containerd, so it needs docker and is excluded from the default UT run.
// Run it with:
//
//	go test -tags kindfv -run TestMirrorPullThrough -timeout 10m ./...
package kind_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	kindexec "sigs.k8s.io/kind/pkg/exec"

	"github.com/projectcalico/calico/lib/kind"
	"github.com/projectcalico/calico/lib/kind/localregistry"
)

// TestMirrorPullThrough proves the end-to-end wiring: a kind node's containerd
// is pointed at the in-process facade for docker.io, and a real `crictl pull`
// inside the node routes through the facade (which fetches from the real
// upstream and caches it). This exercises ContainerdConfigPatches +
// ConfigureNodes + the ns-routing path against real infrastructure — the part
// the hermetic unit test can't reach.
func TestMirrorPullThrough(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	// 1. Start the facade (in-process, no container).
	mir, err := localregistry.Start(ctx, localregistry.Config{
		CacheDir:    t.TempDir(),
		KindNetwork: "kind",
	})
	if err != nil {
		t.Fatalf("localregistry.Start: %v", err)
	}
	defer func() { _ = mir.Stop() }()

	// 2. Bring up a single-node cluster wired to the facade at creation time.
	cl, err := kind.Up(ctx, kind.Config{
		Name:     "mirror-fv",
		NumNodes: 1,
		// Default to the lib's pinned image; allow a cached one locally to
		// skip the ~1GB cold pull (e.g. KIND_NODE_IMAGE=kindest/node:v1.34.3).
		NodeImage:               os.Getenv("KIND_NODE_IMAGE"),
		ContainerdConfigPatches: mir.ContainerdConfigPatches(),
	})
	if err != nil {
		t.Fatalf("kind.Up: %v", err)
	}
	defer func() { _ = cl.Down() }()

	// 3. Point docker.io at the facade on every node.
	kindNodes, err := cl.Provider().ListNodes(cl.Name)
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(kindNodes) == 0 {
		t.Fatal("cluster reported no nodes")
	}
	if err := mir.ConfigureNodes(ctx, kindNodes, "docker.io"); err != nil {
		t.Fatalf("ConfigureNodes: %v", err)
	}

	// 4. Pull a small public image from inside the node. If the mirror wiring
	//    works, containerd resolves docker.io through the facade.
	const image = "docker.io/library/busybox:1.36"
	out, err := kindexec.CombinedOutputLines(kindNodes[0].Command("crictl", "pull", image))
	if err != nil {
		t.Fatalf("crictl pull %s on %s failed: %v\n%s", image, kindNodes[0], err, strings.Join(out, "\n"))
	}

	// 5. Confirm the pull actually routed through the facade.
	if !cachedContains(mir.Cached(), "docker.io", "library/busybox") {
		t.Fatalf("node pull did not route through the facade; cached keys: %v", mir.Cached())
	}
	t.Logf("pulled %s through the facade; cached keys: %v", image, mir.Cached())
}

func cachedContains(keys []string, ns, repo string) bool {
	prefix := ns + "|" + repo + "|"
	for _, k := range keys {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}
