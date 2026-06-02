// Copyright (c) 2026 Tigera, Inc. All rights reserved.

// Package kind owns the kind cluster lifecycle: bringing up a kind cluster and tearing it down. The shape is
// pure-Go (no make, no shell-out) so failure attribution is clean and the
// test runs identically in CI and on a developer machine.
package kind

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/kind/pkg/apis/config/v1alpha4"
	"sigs.k8s.io/kind/pkg/cluster"

	"github.com/projectcalico/calico/lib/kind/imagepuller"
)

// kindNodeImage pins the Kubernetes version used by the cluster. Picked
// to match a version kind currently ships; bump with the kind release.
const kindNodeImage = "kindest/node:v1.30.6@sha256:b6d08db72079ba5ae1f4a88a09025c0a904af3b52387643c285442afb05ab994"

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
	// ImageCacheDir is where pulled image tarballs are persisted between
	// test runs. Default: $XDG_CACHE_HOME/kind/images (or
	// ~/.cache/kind/images). Override with
	// KIND_IMAGE_CACHE_DIR. Persistence is the whole point — first
	// run pulls, every subsequent run reuses.
	ImageCacheDir string
	// DisableImagePuller turns the imagePullPolicy=Never webhook off
	// entirely. Useful when iterating on a scenario locally, or when
	// the caller is using the localregistry subpackage to serve images
	// instead. Default: false (webhook enabled).
	DisableImagePuller bool
	// ContainerdConfigPatches is forwarded to kind's v1alpha4.Cluster
	// config. Use this to wire in registry mirrors — typically the
	// patches returned by localregistry.Handle.ContainerdConfigPatches.
	// Each entry is a TOML fragment that kind appends to the
	// /etc/containerd/config.toml on every node.
	ContainerdConfigPatches []string
}

// Cluster is a brought-up kind cluster the test suite owns.
type Cluster struct {
	Name           string
	KubeconfigPath string
	provider       *cluster.Provider
	clientset      *kubernetes.Clientset

	// Image-pull machinery. Nil when DisableImagePuller is set.
	puller *imagepuller.Handle
}

// Up creates the kind cluster and writes the kubeconfig. Caller is
// responsible for calling Down (typically via t.Cleanup). Calico is NOT
// installed by Up; call InstallCalicoOSS separately so the install step
// is observable in the test trace.
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

	logger := log.WithField("component", "kind")
	logger.WithFields(log.Fields{
		"name":       c.Name,
		"nodes":      c.NumNodes,
		"image":      kindNodeImage,
		"kubeconfig": c.KubeconfigPath,
	}).Info("creating kind cluster")

	prov := cluster.NewProvider(cluster.ProviderWithLogger(kindLoggerAdapter{entry: logger}))

	// kind config: disable default CNI so Calico's CNI takes over; use
	// Calico's default pod CIDR so the IPPool the operator installs lines
	// up with what kind hands out.
	kc := &v1alpha4.Cluster{
		Networking: v1alpha4.Networking{
			IPFamily:          v1alpha4.IPv4Family,
			DisableDefaultCNI: true,
			PodSubnet:         "192.168.0.0/16",
		},
		Nodes:                   []v1alpha4.Node{{Role: v1alpha4.ControlPlaneRole, Image: kindNodeImage}},
		ContainerdConfigPatches: c.ContainerdConfigPatches,
	}
	for i := 1; i < c.NumNodes; i++ {
		kc.Nodes = append(kc.Nodes, v1alpha4.Node{Role: v1alpha4.WorkerRole, Image: kindNodeImage})
	}

	// Best-effort destroy if a previous run left the cluster around.
	logger.WithField("name", c.Name).Info("removing any pre-existing cluster (no-op if absent)")
	_ = prov.Delete(c.Name, c.KubeconfigPath)

	logger.WithField("name", c.Name).Info("creating cluster (this typically takes 60-120s)")
	start := time.Now()
	// Don't pass CreateWithWaitForReady — that waits on kube-system pods
	// to go Ready, which can't happen until CNI is up, and CNI is the
	// thing the next step (InstallCalicoOSS) installs. Create returns
	// when the apiserver is responsive, which is all we need before we
	// drop the operator manifests on it.
	if err := prov.Create(c.Name,
		cluster.CreateWithV1Alpha4Config(kc),
		cluster.CreateWithKubeconfigPath(c.KubeconfigPath),
	); err != nil {
		return nil, fmt.Errorf("create kind cluster %q: %w", c.Name, err)
	}
	logger.WithFields(log.Fields{
		"name":    c.Name,
		"elapsed": time.Since(start).Round(time.Second),
	}).Info("cluster ready")

	cl := &Cluster{
		Name:           c.Name,
		KubeconfigPath: c.KubeconfigPath,
		provider:       prov,
	}

	// Build a clientset for in-cluster operations (webhook install, pod
	// delete-and-recreate). Even with the puller disabled we want the
	// clientset on Cluster for future tools.
	restCfg, err := clientcmd.BuildConfigFromFlags("", c.KubeconfigPath)
	if err != nil {
		return cl, fmt.Errorf("load kubeconfig %s: %w", c.KubeconfigPath, err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return cl, fmt.Errorf("build clientset: %w", err)
	}
	cl.clientset = cs

	if !c.DisableImagePuller {
		h, err := imagepuller.Setup(ctx, imagepuller.Config{
			Clientset: cs,
			Loader:    cl,
			CacheDir:  c.ImageCacheDir,
		})
		if err != nil {
			return cl, fmt.Errorf("setup image puller: %w", err)
		}
		cl.puller = h
	}

	return cl, nil
}

// Down deletes the kind cluster. Idempotent — safe to call from t.Cleanup
// even if Up failed partway. Stops the image-puller machinery (if any)
// before tearing the cluster down.
func (cl *Cluster) Down() error {
	if cl == nil || cl.Name == "" {
		return nil
	}
	cl.puller.Stop()
	prov := cl.provider
	if prov == nil {
		prov = cluster.NewProvider()
	}
	return prov.Delete(cl.Name, cl.KubeconfigPath)
}
