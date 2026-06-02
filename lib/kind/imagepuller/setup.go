// Copyright (c) 2026 Tigera, Inc. All rights reserved.

// Package imagepuller wires a "never-pull" admission webhook against a
// kind cluster: pods are mutated to imagePullPolicy=Never, an in-process
// goroutine pulls the requested images via the local Docker daemon, the
// images are loaded as archives onto every kind node, and the now-stuck
// pods are recreated so they can start against the loaded image.
//
// The puller is one strategy for "make sure kind nodes have the images
// they need without re-pulling on every test run." Other strategies
// (e.g. a local registry the kind cluster is configured to use) can
// live as siblings of this package.
//
// Setup is the single entry point callers (typically the kind package)
// use; it returns a Handle whose Stop method tears down the webhook
// server and detaches the MutatingWebhookConfiguration.
package imagepuller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
)

// Config is the input to Setup. Loader is the kind-cluster-side adapter
// (typically the kind.Cluster value) that knows how to load image
// archives onto nodes and recycle pods after pulls land. CacheDir
// defaults to $XDG_CACHE_HOME/kind/images (or ~/.cache/kind/images) and
// is overridable via the KIND_IMAGE_CACHE_DIR env var.
type Config struct {
	Clientset *kubernetes.Clientset
	Loader    Loader
	CacheDir  string
}

// Handle is the puller's lifecycle handle. Stop is idempotent and safe
// to call from a deferred cleanup even if Setup failed partway.
type Handle struct {
	stop context.CancelFunc
}

// Stop tears down the webhook server, cancels the puller goroutine,
// and unblocks any in-flight pulls. Idempotent.
func (h *Handle) Stop() {
	if h == nil || h.stop == nil {
		return
	}
	h.stop()
	h.stop = nil
}

// Setup resolves the cache directory, starts the puller goroutine, runs
// the in-process mutating-webhook HTTP server, and registers the
// MutatingWebhookConfiguration against the apiserver. The webhook
// server runs in a background context detached from boot — Setup's
// caller typically cancels its boot context immediately on return,
// which would kill the webhook before any test pod is admitted.
//
// The MutatingWebhookConfiguration install itself uses boot — if the
// caller's deadline has already expired by the time Setup reaches that
// step, the call fails fast rather than waiting on an unbounded API
// call.
func Setup(boot context.Context, cfg Config) (*Handle, error) {
	logger := log.WithField("component", "image-puller")
	cacheDir, err := resolveCacheDir(cfg.CacheDir)
	if err != nil {
		return nil, err
	}
	logger.WithField("dir", cacheDir).Info("cache directory resolved")

	ctx, cancel := context.WithCancel(context.Background())
	h := &Handle{stop: cancel}

	puller, err := newPuller(ctx, cacheDir, cfg.Loader)
	if err != nil {
		h.Stop()
		return nil, err
	}

	_, port, caPEM, err := startImageWebhook(ctx, puller)
	if err != nil {
		h.Stop()
		return nil, err
	}

	if err := installNeverPullWebhook(boot, cfg.Clientset, port, caPEM); err != nil {
		h.Stop()
		return nil, fmt.Errorf("install MutatingWebhookConfiguration: %w", err)
	}
	logger.WithField("port", port).Info("webhook installed")
	return h, nil
}

// resolveCacheDir picks the cache directory, honouring (in priority
// order) explicit Config.CacheDir, KIND_IMAGE_CACHE_DIR env var,
// $XDG_CACHE_HOME/kind/images, ~/.cache/kind/images.
func resolveCacheDir(explicit string) (string, error) {
	if v := os.Getenv("KIND_IMAGE_CACHE_DIR"); v != "" {
		return v, nil
	}
	if explicit != "" {
		return explicit, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate user cache dir: %w", err)
	}
	return filepath.Join(base, "kind", "images"), nil
}
