// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package kind

import (
	"context"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/kind/pkg/cluster/nodeutils"
)

// LoadImageArchives pushes each tar onto every kind node. Implements
// the archivedImageLoader interface the imagePuller dispatches against.
// Errors per-archive are logged but don't abort the rest — a missing or
// corrupt tar shouldn't block the larger run.
func (cl *Cluster) LoadImageArchives(ctx context.Context, archivePaths ...string) error {
	if cl == nil || cl.provider == nil {
		return fmt.Errorf("cluster has no provider")
	}
	nodes, err := cl.provider.ListNodes(cl.Name)
	if err != nil {
		return fmt.Errorf("list kind nodes: %w", err)
	}
	logger := log.WithField("component", "kind-loader")
	for _, path := range archivePaths {
		f, err := os.Open(path)
		if err != nil {
			logger.WithError(err).WithField("path", path).Warn("open archive")
			continue
		}
		for _, node := range nodes {
			// Each node needs its own read of the file (LoadImageArchive
			// consumes the reader), so seek back to start each iteration.
			if _, err := f.Seek(0, 0); err != nil {
				logger.WithError(err).WithField("path", path).Warn("seek archive")
				break
			}
			if err := nodeutils.LoadImageArchive(node, f); err != nil {
				logger.WithError(err).WithFields(log.Fields{"path": path, "node": node.String()}).Warn("load archive onto node")
			}
		}
		_ = f.Close()
	}
	return nil
}

// HandlePodImagesPulled deletes the pod (and any siblings sharing its
// labels in the same namespace) with grace=0 so the owning controller
// recreates it. After the recreation kubelet finds the now-loaded image
// locally and the pod can come up under imagePullPolicy=Never.
//
// Why DeleteCollection by label: the admitted pod object may have a
// generated name we'd race to look up; matching on labels is what the
// original go-tools impl did and what gives the deployment controller
// the simplest path to a clean re-create.
func (cl *Cluster) HandlePodImagesPulled(ctx context.Context, pod *corev1.Pod) error {
	if cl == nil || cl.clientset == nil {
		return nil
	}
	if len(pod.Labels) == 0 {
		// Nothing safe to select on; skip the restart and let kubelet
		// retry on its own backoff.
		return nil
	}
	grace := int64(0)
	return cl.clientset.CoreV1().Pods(pod.Namespace).DeleteCollection(
		ctx,
		metav1.DeleteOptions{GracePeriodSeconds: &grace},
		metav1.ListOptions{LabelSelector: labels.SelectorFromSet(pod.Labels).String()},
	)
}
