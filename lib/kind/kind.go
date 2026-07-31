// Copyright (c) 2026 Tigera, Inc. All rights reserved.

// Package kind owns the kind cluster lifecycle. The shape is pure-Go
// (no make, no shell-out) so failure attribution is clean and the test
// runs identically in CI and on a developer machine.
package kind

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/kind/pkg/apis/config/v1alpha4"
	"sigs.k8s.io/kind/pkg/cluster"

	"github.com/projectcalico/calico/lib/std/log"
)

// DefaultNodeImage pins the Kubernetes version used by the cluster when
// Config.NodeImage is empty. Picked to match a version kind currently
// ships; bump with the kind release. Exported so callers can detect
// "what would the default be" without re-invoking Up.
//
// Currently kindest/node:v1.33.7 — the highest 1.33.x release published by
// kind v0.31.0. localregistry now emits the containerd 2.x-compatible
// config_path + hosts.toml setup, so newer kindest/node images that ship
// containerd 2.x (kind v0.27+) work too.
// To bump, look up the digest from the kind release notes — they pin
// per-k8s digests there and require @sha256 to guarantee the release-built
// image.
const DefaultNodeImage = "kindest/node:v1.33.7@sha256:d26ef333bdb2cbe9862a0f7c3803ecc7b4303d8cea8e814b481b09949d353040"

// DefaultNetworking is the Calico-friendly networking config applied when
// Config.Networking is a zero-valued struct: IPv4-only, default CNI off so
// a CNI like Calico can install its own, and Calico's conventional default
// pod subnet. Callers that want different networking pass a populated
// Networking struct and lib/kind uses it verbatim.
var DefaultNetworking = v1alpha4.Networking{
	IPFamily:          v1alpha4.IPv4Family,
	DisableDefaultCNI: true,
	PodSubnet:         "192.168.0.0/16",
}

// Config carries the knobs tests and tools typically tweak.
type Config struct {
	// Name is the kind cluster name. Default: "kind-cluster".
	Name string
	// NumNodes is total nodes (1 control-plane + (NumNodes-1) workers).
	// Default: 2 (one CP + one worker — enough for cross-node pod tests).
	NumNodes int
	// KubeconfigPath is where the cluster's kubeconfig is written. Default:
	// $TMPDIR/kind-<name>.kubeconfig.
	KubeconfigPath string
	// ContainerdConfigPatches is forwarded to kind's v1alpha4.Cluster
	// config. Use this to wire in registry mirrors — typically the
	// patches returned by localregistry.Handle.ContainerdConfigPatches.
	// Each entry is a TOML fragment that kind appends to the
	// /etc/containerd/config.toml on every node.
	ContainerdConfigPatches []string
	// NodeImage overrides the kind node image (kindest/node:vX.Y.Z[@digest]).
	// Default: DefaultNodeImage. Set this to test against a different
	// Kubernetes version without touching the lib.
	NodeImage string
	// Networking overrides the kind v1alpha4 Networking config. A zero
	// value falls back to DefaultNetworking (Calico-friendly). Set this
	// to use kind's default CNI, dual-stack IP, alternate pod/service
	// CIDRs, etc.
	Networking v1alpha4.Networking
	// KubeadmConfigPatches is forwarded to kind. Use this for kubeadm-level
	// tweaks (e.g. extra apiServer certSANs).
	KubeadmConfigPatches []string
}

// Cluster is a brought-up kind cluster the test suite owns.
type Cluster struct {
	Name           string
	KubeconfigPath string
	provider       *cluster.Provider
	clientset      *kubernetes.Clientset
}

// Clientset exposes the underlying typed kubernetes client.
func (cl *Cluster) Clientset() *kubernetes.Clientset { return cl.clientset }

// Provider exposes the underlying kind provider (for callers that need to
// drive operations sigs.k8s.io/kind exposes only on Provider, e.g.
// ListNodes).
func (cl *Cluster) Provider() *cluster.Provider { return cl.provider }

// Up creates the kind cluster and writes the kubeconfig. On success the
// caller owns teardown via Down (typically t.Cleanup); on error Up cleans
// up after itself and returns a nil Cluster, so a non-nil error always
// means there is nothing left to clean up. Up brings up a bare cluster
// only — with the default networking no CNI is installed; the caller
// drives whatever comes next.
func Up(ctx context.Context, c Config) (*Cluster, error) {
	if c.Name == "" {
		c.Name = "kind-cluster"
	}
	if c.NumNodes <= 0 {
		c.NumNodes = 2
	}
	if c.KubeconfigPath == "" {
		c.KubeconfigPath = filepath.Join(os.TempDir(), c.Name+".kubeconfig")
	}

	nodeImage := c.NodeImage
	if nodeImage == "" {
		nodeImage = DefaultNodeImage
	}

	networking := c.Networking
	if networking == (v1alpha4.Networking{}) {
		networking = DefaultNetworking
	}

	logger := log.With("component", "kind")
	logger.Info("Creating kind cluster.",
		"name", c.Name,
		"nodes", c.NumNodes,
		"image", nodeImage,
		"kubeconfig", c.KubeconfigPath,
	)

	prov := cluster.NewProvider(cluster.ProviderWithLogger(kindLoggerAdapter{logger: logger}))

	kc := &v1alpha4.Cluster{
		Networking:              networking,
		Nodes:                   []v1alpha4.Node{{Role: v1alpha4.ControlPlaneRole, Image: nodeImage}},
		ContainerdConfigPatches: c.ContainerdConfigPatches,
		KubeadmConfigPatches:    c.KubeadmConfigPatches,
	}
	for i := 1; i < c.NumNodes; i++ {
		kc.Nodes = append(kc.Nodes, v1alpha4.Node{Role: v1alpha4.WorkerRole, Image: nodeImage})
	}

	logger = logger.With("name", c.Name)

	// Best-effort destroy if a previous run left the cluster around.
	logger.Info("Removing any pre-existing cluster (no-op if absent).")

	if err := prov.Delete(c.Name, c.KubeconfigPath); err != nil {
		logger.Warn("Failed to delete pre-existing cluster, continuing with creation.", "error", err)
	}

	logger.Info("Creating cluster (this typically takes 60-120s).")
	start := time.Now()
	// Don't pass CreateWithWaitForReady — it waits on kube-system pods to
	// go Ready, which can't happen until a CNI is up. With the default
	// networking (DisableDefaultCNI) no CNI is installed, so that wait
	// would hang. Create returns once the apiserver is responsive, which
	// is all the caller needs before installing one.
	if err := prov.Create(c.Name,
		cluster.CreateWithV1Alpha4Config(kc),
		cluster.CreateWithKubeconfigPath(c.KubeconfigPath),
	); err != nil {
		return nil, fmt.Errorf("create kind cluster %q: %w", c.Name, err)
	}
	logger.Info("Cluster ready.", "elapsed", time.Since(start).Round(time.Second))

	cl := &Cluster{
		Name:           c.Name,
		KubeconfigPath: c.KubeconfigPath,
		provider:       prov,
	}

	// Build a clientset and expose it on Cluster (via the Clientset
	// accessor) so callers can talk to the apiserver directly. The cluster
	// is already up by this point, so on failure tear it back down and
	// return a nil Cluster — a non-nil error from Up always means there is
	// nothing left for the caller to clean up (matching the Create failure
	// above).
	restCfg, err := clientcmd.BuildConfigFromFlags("", c.KubeconfigPath)
	if err != nil {
		_ = cl.Down()
		return nil, fmt.Errorf("load kubeconfig %s: %w", c.KubeconfigPath, err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		_ = cl.Down()
		return nil, fmt.Errorf("build clientset: %w", err)
	}
	cl.clientset = cs

	return cl, nil
}

// Down deletes the kind cluster. Idempotent — safe to call from t.Cleanup
// even if Up failed partway.
func (cl *Cluster) Down() error {
	if cl == nil || cl.Name == "" {
		return nil
	}
	prov := cl.provider
	if prov == nil {
		prov = cluster.NewProvider()
	}
	return prov.Delete(cl.Name, cl.KubeconfigPath)
}

// LoadExisting wraps an already-running kind cluster as a *Cluster without
// creating one. The kubeconfig must exist and the cluster must be reachable.
// Use this when a long-lived kind cluster is being re-used across processes
// (e.g. a dev loop) and the lifecycle methods on Cluster — e.g. Down — are
// needed against it. Callers manage their own image-loading strategy
// (e.g. lib/kind/localregistry).
func LoadExisting(name, kubeconfigPath string) (*Cluster, error) {
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	restCfg, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig %s: %w", kubeconfigPath, err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("build clientset: %w", err)
	}
	return &Cluster{
		Name:           name,
		KubeconfigPath: kubeconfigPath,
		provider:       cluster.NewProvider(),
		clientset:      cs,
	}, nil
}
