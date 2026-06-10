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

package infrastructure

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// TyphaHierarchy is a set of Typha containers running in election-driven
// hierarchical mode (WS-C).  Exactly one becomes the leader (running the real
// datastore syncers); the rest are followers that source from the leader.
//
// Discovery model: all Typhas run in pure roleManaged mode (HierarchyEnabled +
// LeaderElectionEnabled, no static UpstreamAddr).  The FV harness creates a
// headless Kubernetes Service named after the lease ("calico-typha-leader") and
// maintains an EndpointSlice pointing to the current leader's IP.  Typhas
// discover the leader's address by listing that Service's EndpointSlice, exactly
// as they would in a real cluster — without requiring the containers to be real
// Kubernetes pods.
//
// After KillLeader the winning follower promotes in-process (no restart needed),
// starts real datastore syncers, and keeps serving its Felix clients.  The FV
// then calls SetLeader to update the EndpointSlice so any remaining followers
// can re-connect.
type TyphaHierarchy struct {
	infra   DatastoreInfra
	options TopologyOptions
	hOpts   HierarchyOptions

	// Leader is the Typha currently designated as the upstream/leader.  Nil
	// until SetLeader is called.
	Leader *Typha
	// Followers are the non-leader Typhas.
	Followers []*Typha
	// All holds every Typha (leader + followers) for teardown.
	All []*Typha
	// podNames maps each Typha container to its TYPHA_PODNAME, needed for
	// WaitForLeader identity matching after entries are removed from All.
	podNames map[*Typha]string

	leaseName      string
	leaseNamespace string
}

// HierarchyOptions configures RunTyphaHierarchy.
type HierarchyOptions struct {
	// NumTyphas is the total number of Typha instances to run (>=2 for a
	// meaningful hierarchy).
	NumTyphas int
	// LeaseName / LeaseNamespace name the leader-election Lease.  Defaults:
	// "calico-typha-leader" / "kube-system".
	LeaseName      string
	LeaseNamespace string
}

// RunTyphaHierarchy starts NumTyphas Typha containers in roleManaged hierarchy
// mode (HierarchyEnabled + LeaderElectionEnabled, no static UpstreamAddr).  It
// creates a headless K8s Service so that followers can discover the leader via
// the standard EndpointSlice path once SetLeader has been called.
//
// Each Typha gets a distinct TYPHA_PODNAME so the Lease identities differ.
func RunTyphaHierarchy(infra DatastoreInfra, options TopologyOptions, hOpts HierarchyOptions) *TyphaHierarchy {
	if hOpts.NumTyphas < 1 {
		hOpts.NumTyphas = 1
	}
	if hOpts.LeaseName == "" {
		hOpts.LeaseName = "calico-typha-leader"
	}
	if hOpts.LeaseNamespace == "" {
		hOpts.LeaseNamespace = "kube-system"
	}

	h := &TyphaHierarchy{
		infra:          infra,
		options:        options,
		hOpts:          hOpts,
		leaseName:      hOpts.LeaseName,
		leaseNamespace: hOpts.LeaseNamespace,
		podNames:       make(map[*Typha]string),
	}

	// Create the headless Service used for leader discovery before starting
	// any Typha so the containers see it immediately on first boot.
	h.ensureLeaderService()

	for i := 0; i < hOpts.NumTyphas; i++ {
		podName := fmt.Sprintf("typha-fv-%d", i)
		t := h.runTypha(podName)
		h.All = append(h.All, t)
		h.podNames[t] = podName
	}
	return h
}

// runTypha starts a single Typha container in roleManaged mode (no static
// UpstreamAddr).  All instances contend for the leader Lease; once one wins it
// starts real datastore syncers, and the others discover its IP via the leader
// Service EndpointSlice and connect upstream.
func (h *TyphaHierarchy) runTypha(podName string) *Typha {
	extraEnv := map[string]string{
		"TYPHA_HIERARCHYENABLED":      "true",
		"TYPHA_LEADERELECTIONENABLED": "true",
		"TYPHA_DATASTORETYPE":         "kubernetes",
		"TYPHA_PODNAME":               podName,
		"TYPHA_PODNAMESPACE":          h.hOpts.LeaseNamespace,
		"TYPHA_LEASENAME":             h.hOpts.LeaseName,
		"TYPHA_LEASENAMESPACE":        h.hOpts.LeaseNamespace,
		// The leader Service used by followers for upstream discovery.
		"TYPHA_LEADERSERVICENAME": h.hOpts.LeaseName,
		// Speed up election in tests.
		"TYPHA_LEADERELECTIONDURATION": "4",
		"TYPHA_LEADERRENEWDEADLINE":    "3",
		"TYPHA_LEADERRETRYPERIOD":      "1",
		"TYPHA_ROLETRANSITIONDEBOUNCE": "1",
	}
	return RunTyphaWithEnv(h.infra, h.options, extraEnv)
}

// SetLeader records leader as the current leader and updates the headless
// Service EndpointSlice to point to its IP so followers can connect upstream.
// Unlike the old static-upstream approach this does NOT restart followers —
// they are already in roleManaged mode and will re-query the EndpointSlice on
// their next discovery cycle.
func (h *TyphaHierarchy) SetLeader(leader *Typha) {
	h.Leader = leader
	var followers []*Typha
	for _, t := range h.All {
		if t != leader {
			followers = append(followers, t)
		}
	}
	h.Followers = followers

	log.WithFields(log.Fields{
		"leaderIP": leader.IP,
		"service":  h.hOpts.LeaseName,
	}).Info("Updating leader EndpointSlice for Typha hierarchy.")
	h.updateLeaderEndpointSlice(leader.IP)
}

// WaitForLeader polls the leader-election Lease until a holder is observed and
// returns the holder identity (the leader's TYPHA_PODNAME).  It maps that back
// to the Typha container via the podNames map.
func (h *TyphaHierarchy) WaitForLeader(timeout time.Duration) (*Typha, string, error) {
	kds, ok := h.infra.(*K8sDatastoreInfra)
	if !ok {
		return nil, "", fmt.Errorf("WaitForLeader requires the Kubernetes datastore")
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		holder, err := h.currentLeaseHolder(kds)
		if err == nil && holder != "" {
			for _, t := range h.All {
				if h.podNames[t] == holder {
					return t, holder, nil
				}
			}
			// Holder observed but no matching live container (e.g. the killed leader's
			// Lease hasn't expired yet).  Keep polling.
			log.WithField("holder", holder).Debug("WaitForLeader: holder has no matching live container; polling.")
		}
		time.Sleep(250 * time.Millisecond)
	}
	return nil, "", fmt.Errorf("timed out waiting for a leader to be elected")
}

// currentLeaseHolder reads the holder identity from the leader-election Lease.
func (h *TyphaHierarchy) currentLeaseHolder(kds *K8sDatastoreInfra) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lease, err := kds.K8sClient.CoordinationV1().Leases(h.leaseNamespace).Get(ctx, h.leaseName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	if lease.Spec.HolderIdentity == nil {
		return "", nil
	}
	return *lease.Spec.HolderIdentity, nil
}

// KillLeader stops the current leader container, simulating a leader pod being
// deleted.  A new leader will be elected within ~LeaseDuration.  After calling
// this, call WaitForLeader to discover the new leader, then SetLeader to update
// the EndpointSlice so followers can reconnect.
func (h *TyphaHierarchy) KillLeader() {
	if h.Leader == nil {
		log.Warn("KillLeader called but no leader designated.")
		return
	}
	log.Info("Killing Typha hierarchy leader to force re-election.")
	h.Leader.Stop()
	// Remove the killed leader from All and podNames so subsequent WaitForLeader
	// only maps back to live containers.
	var remaining []*Typha
	for _, t := range h.All {
		if t == h.Leader {
			delete(h.podNames, t)
			continue
		}
		remaining = append(remaining, t)
	}
	h.All = remaining
	h.Followers = nil // will be repopulated by the next SetLeader call
	h.Leader = nil
}

// Stop tears down all Typha containers in the hierarchy.
func (h *TyphaHierarchy) Stop() {
	for _, t := range h.All {
		t.Stop()
	}
}

// ensureLeaderService creates the headless K8s Service used by followers to
// discover the leader via EndpointSlice.  The Service name matches the lease
// name so no additional configuration is needed on the Typha side (the default
// LeaderServiceName equals the LeaseName).
func (h *TyphaHierarchy) ensureLeaderService() {
	kds, ok := h.infra.(*K8sDatastoreInfra)
	if !ok {
		return
	}
	ctx := context.Background()
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      h.hOpts.LeaseName,
			Namespace: h.hOpts.LeaseNamespace,
		},
		Spec: corev1.ServiceSpec{
			// Headless service — no cluster IP.
			ClusterIP: "None",
			Ports: []corev1.ServicePort{{
				Name:       "calico-typha",
				Port:       5473,
				TargetPort: intstr.FromInt(5473),
				Protocol:   corev1.ProtocolTCP,
			}},
		},
	}
	_, err := kds.K8sClient.CoreV1().Services(h.hOpts.LeaseNamespace).Create(ctx, svc, metav1.CreateOptions{})
	if err != nil && !apierrs.IsAlreadyExists(err) {
		log.WithError(err).Warn("Failed to create leader headless Service; discovery may not work.")
	}
}

// updateLeaderEndpointSlice replaces (or creates) the EndpointSlice for the
// leader Service so followers can discover the new leader IP.
func (h *TyphaHierarchy) updateLeaderEndpointSlice(leaderIP string) {
	kds, ok := h.infra.(*K8sDatastoreInfra)
	if !ok {
		return
	}
	ctx := context.Background()
	port := int32(5473)
	portName := "calico-typha"
	proto := corev1.ProtocolTCP
	ready := true

	eps := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      h.hOpts.LeaseName + "-fv",
			Namespace: h.hOpts.LeaseNamespace,
			Labels: map[string]string{
				discoveryv1.LabelServiceName: h.hOpts.LeaseName,
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports: []discoveryv1.EndpointPort{{
			Name:     &portName,
			Port:     &port,
			Protocol: &proto,
		}},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses: []string{leaderIP},
			Conditions: discoveryv1.EndpointConditions{
				Ready: &ready,
			},
		}},
	}

	existing, err := kds.K8sClient.DiscoveryV1().EndpointSlices(h.hOpts.LeaseNamespace).
		Get(ctx, eps.Name, metav1.GetOptions{})
	if apierrs.IsNotFound(err) {
		_, err = kds.K8sClient.DiscoveryV1().EndpointSlices(h.hOpts.LeaseNamespace).
			Create(ctx, eps, metav1.CreateOptions{})
	} else if err == nil {
		eps.ResourceVersion = existing.ResourceVersion
		_, err = kds.K8sClient.DiscoveryV1().EndpointSlices(h.hOpts.LeaseNamespace).
			Update(ctx, eps, metav1.UpdateOptions{})
	}
	if err != nil {
		log.WithError(err).Warn("Failed to update leader EndpointSlice; follower discovery may be delayed.")
	}
}
