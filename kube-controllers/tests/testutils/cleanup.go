// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package testutils

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// CleanupOptions controls the behavior of CleanupAllResources.
type CleanupOptions struct {
	// DeletePodsBeforeNodes causes pods to be deleted with GracePeriodSeconds=0
	// before nodes. This avoids orphaned pod GC delays (~50s) when a
	// kube-controller-manager is running in the test.
	DeletePodsBeforeNodes bool

	// KeepDefaultConfigs preserves FelixConfigurations and BGPConfigurations
	// named "default" during cleanup.
	KeepDefaultConfigs bool
}

// CleanupAllResources deletes all test resources between specs. Pass nil for any
// client that isn't available in the test suite. All list/delete errors are logged
// rather than silently discarded, and delete errors are treated as best-effort since
// the resource may already be gone.
func CleanupAllResources(
	ctx context.Context,
	k8sClient kubernetes.Interface,
	calicoClient client.Interface,
	bc api.Client,
	opts CleanupOptions,
) {
	if k8sClient != nil {
		// Delete pods before nodes if requested, to avoid orphan GC delays.
		if opts.DeletePodsBeforeNodes {
			cleanupK8sPods(ctx, k8sClient)
		}

		cleanupK8sNodes(ctx, k8sClient)

		if !opts.DeletePodsBeforeNodes {
			cleanupK8sPods(ctx, k8sClient)
		}

		cleanupK8sServices(ctx, k8sClient)
		CleanupK8sNetworkPolicies(ctx, k8sClient)
		cleanupK8sDaemonSets(ctx, k8sClient)
		CleanupK8sNamespaces(ctx, k8sClient)
	}

	// IPAM resources must use DeleteKVP in KDD mode.
	if bc != nil {
		cleanupIPAMResource(ctx, bc, model.BlockListOptions{}, "IPAMBlock")
		cleanupIPAMResource(ctx, bc, model.BlockAffinityListOptions{}, "IPAMAffinity")
		cleanupIPAMResource(ctx, bc, model.IPAMHandleListOptions{}, "IPAMHandle")
	}

	if calicoClient != nil {
		cleanupCalicoNodes(ctx, calicoClient)
		cleanupIPPools(ctx, calicoClient)
		cleanupHostEndpoints(ctx, calicoClient)
		cleanupWorkloadEndpoints(ctx, calicoClient)
		CleanupCalicoNetworkPolicies(ctx, calicoClient)
		cleanupFelixConfigurations(ctx, calicoClient, opts.KeepDefaultConfigs)
		cleanupBGPPeers(ctx, calicoClient)
		cleanupBGPConfigurations(ctx, calicoClient, opts.KeepDefaultConfigs)

		if _, err := calicoClient.KubeControllersConfiguration().Delete(ctx, "default", options.DeleteOptions{}); err != nil {
			log.WithError(err).Debug("Failed to delete KubeControllersConfiguration during cleanup")
		}
	}
}

func cleanupK8sNodes(ctx context.Context, k8sClient kubernetes.Interface) {
	nodes, err := k8sClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		log.WithError(err).Warn("Failed to list k8s nodes during cleanup")
		return
	}
	for _, node := range nodes.Items {
		if err := k8sClient.CoreV1().Nodes().Delete(ctx, node.Name, metav1.DeleteOptions{}); err != nil {
			log.WithError(err).WithField("node", node.Name).Debug("Failed to delete k8s node during cleanup")
		}
	}
	if len(nodes.Items) > 0 {
		waitForDeletion(10*time.Second, 500*time.Millisecond, func() (bool, error) {
			nl, err := k8sClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
			if err != nil {
				return false, err
			}
			return len(nl.Items) == 0, nil
		})
	}
}

func cleanupK8sPods(ctx context.Context, k8sClient kubernetes.Interface) {
	zero := int64(0)
	nsList, err := k8sClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		log.WithError(err).Warn("Failed to list namespaces for pod cleanup")
		return
	}
	for _, ns := range nsList.Items {
		pods, err := k8sClient.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil || len(pods.Items) == 0 {
			continue
		}
		if err := k8sClient.CoreV1().Pods(ns.Name).DeleteCollection(ctx, metav1.DeleteOptions{GracePeriodSeconds: &zero}, metav1.ListOptions{}); err != nil {
			log.WithError(err).WithField("namespace", ns.Name).Warn("Failed to delete pods during cleanup")
		}
		waitForDeletion(30*time.Second, 500*time.Millisecond, func() (bool, error) {
			pods, err := k8sClient.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
			if err != nil {
				return false, err
			}
			return len(pods.Items) == 0, nil
		})
	}
}

func cleanupK8sServices(ctx context.Context, k8sClient kubernetes.Interface) {
	nsList, err := k8sClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		log.WithError(err).Warn("Failed to list namespaces for service cleanup")
		return
	}
	for _, ns := range nsList.Items {
		svcs, err := k8sClient.CoreV1().Services(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil || len(svcs.Items) == 0 {
			continue
		}
		for i := range svcs.Items {
			if svcs.Items[i].Name == "kubernetes" {
				continue
			}
			if err := k8sClient.CoreV1().Services(ns.Name).Delete(ctx, svcs.Items[i].Name, metav1.DeleteOptions{}); err != nil {
				log.WithError(err).WithField("service", svcs.Items[i].Name).Debug("Failed to delete service during cleanup")
			}
		}
	}
}

func CleanupK8sNetworkPolicies(ctx context.Context, k8sClient kubernetes.Interface) {
	nsList, err := k8sClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		log.WithError(err).Warn("Failed to list namespaces during cleanup")
		return
	}
	for _, ns := range nsList.Items {
		npList, err := k8sClient.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, np := range npList.Items {
			if err := k8sClient.NetworkingV1().NetworkPolicies(ns.Name).Delete(ctx, np.Name, metav1.DeleteOptions{}); err != nil {
				log.WithError(err).WithField("policy", np.Name).Debug("Failed to delete NetworkPolicy during cleanup")
			}
		}
	}
}

func cleanupK8sDaemonSets(ctx context.Context, k8sClient kubernetes.Interface) {
	dsList, err := k8sClient.AppsV1().DaemonSets(metav1.NamespaceSystem).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.WithError(err).Warn("Failed to list DaemonSets during cleanup")
		return
	}
	for i := range dsList.Items {
		if err := k8sClient.AppsV1().DaemonSets(metav1.NamespaceSystem).Delete(ctx, dsList.Items[i].Name, metav1.DeleteOptions{}); err != nil {
			log.WithError(err).WithField("daemonset", dsList.Items[i].Name).Debug("Failed to delete DaemonSet during cleanup")
		}
	}
}

func CleanupK8sNamespaces(ctx context.Context, k8sClient kubernetes.Interface) {
	nsList, err := k8sClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		log.WithError(err).Warn("Failed to list namespaces during cleanup")
		return
	}
	var deleted []string
	for _, ns := range nsList.Items {
		if ns.Name == "default" || ns.Name == "kube-system" || ns.Name == "kube-public" || ns.Name == "kube-node-lease" {
			continue
		}
		if err := k8sClient.CoreV1().Namespaces().Delete(ctx, ns.Name, metav1.DeleteOptions{}); err != nil {
			log.WithError(err).WithField("namespace", ns.Name).Debug("Failed to delete namespace during cleanup")
		} else {
			deleted = append(deleted, ns.Name)
		}
	}
	for _, name := range deleted {
		n := name
		waitForDeletion(30*time.Second, 500*time.Millisecond, func() (bool, error) {
			_, err := k8sClient.CoreV1().Namespaces().Get(ctx, n, metav1.GetOptions{})
			if k8serrors.IsNotFound(err) {
				return true, nil
			}
			return false, err
		})
	}
}

func cleanupIPAMResource(ctx context.Context, bc api.Client, listOpts model.ListInterface, resourceType string) {
	kvps, err := bc.List(ctx, listOpts, "")
	if err != nil {
		log.WithError(err).WithField("resource", resourceType).Warn("Failed to list IPAM resources during cleanup")
		return
	}
	for _, kvp := range kvps.KVPairs {
		if _, err := bc.DeleteKVP(ctx, kvp); err != nil {
			log.WithError(err).WithField("resource", resourceType).Debug("Failed to delete IPAM resource during cleanup")
		}
	}
}

func cleanupCalicoNodes(ctx context.Context, c client.Interface) {
	nodes, err := c.Nodes().List(ctx, options.ListOptions{})
	if err != nil {
		log.WithError(err).Warn("Failed to list Calico nodes during cleanup")
		return
	}
	for _, node := range nodes.Items {
		if _, err := c.Nodes().Delete(ctx, node.Name, options.DeleteOptions{}); err != nil {
			log.WithError(err).WithField("node", node.Name).Debug("Failed to delete Calico node during cleanup")
		}
	}
}

func cleanupIPPools(ctx context.Context, c client.Interface) {
	pools, err := c.IPPools().List(ctx, options.ListOptions{})
	if err != nil {
		log.WithError(err).Warn("Failed to list IP pools during cleanup")
		return
	}
	var deleted []string
	for _, pool := range pools.Items {
		if _, err := c.IPPools().Delete(ctx, pool.Name, options.DeleteOptions{}); err != nil {
			log.WithError(err).WithField("pool", pool.Name).Debug("Failed to delete IP pool during cleanup")
		} else {
			deleted = append(deleted, pool.Name)
		}
	}
	for _, name := range deleted {
		n := name
		waitForDeletion(30*time.Second, 500*time.Millisecond, func() (bool, error) {
			_, err := c.IPPools().Get(ctx, n, options.GetOptions{})
			if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
				return true, nil
			}
			return false, err
		})
	}
}

func cleanupHostEndpoints(ctx context.Context, c client.Interface) {
	heps, err := c.HostEndpoints().List(ctx, options.ListOptions{})
	if err != nil {
		log.WithError(err).Warn("Failed to list host endpoints during cleanup")
		return
	}
	for _, hep := range heps.Items {
		if _, err := c.HostEndpoints().Delete(ctx, hep.Name, options.DeleteOptions{}); err != nil {
			log.WithError(err).WithField("hep", hep.Name).Debug("Failed to delete host endpoint during cleanup")
		}
	}
}

func cleanupFelixConfigurations(ctx context.Context, c client.Interface, keepDefault bool) {
	fcs, err := c.FelixConfigurations().List(ctx, options.ListOptions{})
	if err != nil {
		log.WithError(err).Warn("Failed to list FelixConfigurations during cleanup")
		return
	}
	for _, fc := range fcs.Items {
		if keepDefault && fc.Name == "default" {
			continue
		}
		if _, err := c.FelixConfigurations().Delete(ctx, fc.Name, options.DeleteOptions{}); err != nil {
			log.WithError(err).WithField("config", fc.Name).Debug("Failed to delete FelixConfiguration during cleanup")
		}
	}
}

func cleanupBGPPeers(ctx context.Context, c client.Interface) {
	peers, err := c.BGPPeers().List(ctx, options.ListOptions{})
	if err != nil {
		log.WithError(err).Warn("Failed to list BGP peers during cleanup")
		return
	}
	for _, peer := range peers.Items {
		if _, err := c.BGPPeers().Delete(ctx, peer.Name, options.DeleteOptions{}); err != nil {
			log.WithError(err).WithField("peer", peer.Name).Debug("Failed to delete BGP peer during cleanup")
		}
	}
}

func cleanupBGPConfigurations(ctx context.Context, c client.Interface, keepDefault bool) {
	bcs, err := c.BGPConfigurations().List(ctx, options.ListOptions{})
	if err != nil {
		log.WithError(err).Warn("Failed to list BGP configurations during cleanup")
		return
	}
	for _, bc := range bcs.Items {
		if keepDefault && bc.Name == "default" {
			continue
		}
		if _, err := c.BGPConfigurations().Delete(ctx, bc.Name, options.DeleteOptions{}); err != nil {
			log.WithError(err).WithField("config", bc.Name).Debug("Failed to delete BGP configuration during cleanup")
		}
	}
}

func cleanupWorkloadEndpoints(ctx context.Context, c client.Interface) {
	weps, err := c.WorkloadEndpoints().List(ctx, options.ListOptions{})
	if err != nil {
		log.WithError(err).Warn("Failed to list workload endpoints during cleanup")
		return
	}
	for _, wep := range weps.Items {
		if _, err := c.WorkloadEndpoints().Delete(ctx, wep.Namespace, wep.Name, options.DeleteOptions{}); err != nil {
			log.WithError(err).WithField("wep", wep.Name).Debug("Failed to delete workload endpoint during cleanup")
		}
	}
}

func CleanupCalicoNetworkPolicies(ctx context.Context, c client.Interface) {
	nsList, err := c.NetworkPolicies().List(ctx, options.ListOptions{})
	if err != nil {
		log.WithError(err).Warn("Failed to list Calico NetworkPolicies during cleanup")
		return
	}
	for _, np := range nsList.Items {
		if _, err := c.NetworkPolicies().Delete(ctx, np.Namespace, np.Name, options.DeleteOptions{}); err != nil {
			log.WithError(err).WithField("policy", np.Name).Debug("Failed to delete Calico NetworkPolicy during cleanup")
		}
	}
}

// waitForDeletion polls until checkGone returns true or the timeout expires.
func waitForDeletion(timeout, interval time.Duration, checkGone func() (bool, error)) {
	deadline := time.After(timeout)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-deadline:
			log.Warn("Timed out waiting for resource deletion during cleanup")
			return
		case <-ticker.C:
			gone, err := checkGone()
			if err != nil {
				log.WithError(err).Debug("Error checking resource deletion")
			}
			if gone {
				return
			}
		}
	}
}
