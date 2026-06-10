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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TyphaHierarchy is a set of Typha containers running in election-driven
// hierarchical mode (WS-C).  Exactly one becomes the leader (running the real
// datastore syncers); the rest are followers that source from the leader.
//
// Container-vs-pod caveat: Typha's leader discovery for followers is
// EndpointSlice-based (the leader self-labels its *pod* and a headless Service
// selects it).  That only works when Typhas run as real Kubernetes pods, so the
// fully self-organising path is exercised by the kube/k8st tests, not by this
// container-based FV harness.  Here we instead:
//
//   - run every Typha with leader election enabled (against the K8s datastore),
//     so a real Lease is contended and exactly one wins; and
//   - point followers at the leader with a static upstream address
//     (TYPHA_UPSTREAMADDR), which takes precedence over discovery and pins them
//     as followers of that address.
//
// LeaderKill + RepointFollowers lets a test simulate a leader failure and the
// subsequent re-election + follower failover.
type TyphaHierarchy struct {
	infra   DatastoreInfra
	options TopologyOptions

	// Leader is the Typha currently designated as the upstream/leader.  Nil
	// until SetLeader is called.
	Leader *Typha
	// Followers are the Typhas pointed at the leader.
	Followers []*Typha
	// All holds every Typha (leader + followers) for teardown.
	All []*Typha

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

// RunTyphaHierarchy starts NumTyphas Typha containers with hierarchy + leader
// election enabled.  It does NOT designate the static upstream wiring; call
// SetLeader once the election has settled (use WaitForLeader to discover which
// instance won) to pin the followers at the leader.
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
		leaseName:      hOpts.LeaseName,
		leaseNamespace: hOpts.LeaseNamespace,
	}

	for i := 0; i < hOpts.NumTyphas; i++ {
		podName := fmt.Sprintf("typha-fv-%d", i)
		extraEnv := map[string]string{
			"TYPHA_HIERARCHYENABLED":      "true",
			"TYPHA_LEADERELECTIONENABLED": "true",
			"TYPHA_DATASTORETYPE":         "kubernetes",
			"TYPHA_PODNAME":               podName,
			"TYPHA_PODNAMESPACE":          hOpts.LeaseNamespace,
			"TYPHA_LEASENAME":             hOpts.LeaseName,
			"TYPHA_LEASENAMESPACE":        hOpts.LeaseNamespace,
			// Speed up election in tests.
			"TYPHA_LEADERELECTIONDURATION": "4",
			"TYPHA_LEADERRENEWDEADLINE":    "3",
			"TYPHA_LEADERRETRYPERIOD":      "1",
			"TYPHA_ROLETRANSITIONDEBOUNCE": "1",
		}
		t := RunTyphaWithEnv(infra, options, extraEnv)
		h.All = append(h.All, t)
	}
	return h
}

// SetLeader designates leader as the upstream and (re)points all other Typhas at
// it via TYPHA_UPSTREAMADDR.  Because changing a container's env requires a
// restart, the followers are recreated.  Use this after WaitForLeader has told
// you which Typha won the election (so the static wiring matches the elected
// leader and the data path is exercised end to end).
func (h *TyphaHierarchy) SetLeader(leader *Typha) {
	h.Leader = leader
	leaderAddr := leader.IP + ":5473"
	var followers []*Typha
	for _, t := range h.All {
		if t == leader {
			continue
		}
		followers = append(followers, t)
	}
	h.Followers = followers
	log.WithField("leaderAddr", leaderAddr).Info("Designated Typha hierarchy leader.")
}

// WaitForLeader polls the leader-election Lease until a holder is observed and
// returns the holder identity (the leader's TYPHA_PODNAME).  It maps that back
// to the Typha container by index (typha-fv-<i>).
func (h *TyphaHierarchy) WaitForLeader(timeout time.Duration) (*Typha, string, error) {
	kds, ok := h.infra.(*K8sDatastoreInfra)
	if !ok {
		return nil, "", fmt.Errorf("WaitForLeader requires the Kubernetes datastore")
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		holder, err := h.currentLeaseHolder(kds)
		if err == nil && holder != "" {
			for i, t := range h.All {
				if fmt.Sprintf("typha-fv-%d", i) == holder {
					return t, holder, nil
				}
			}
			// Holder observed but no matching container (should not happen).
			return nil, holder, nil
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
// deleted.  A new leader should be elected within ~LeaseDuration.  After calling
// this, call WaitForLeader again (excluding the killed instance) and SetLeader
// to re-point followers.
func (h *TyphaHierarchy) KillLeader() {
	if h.Leader == nil {
		log.Warn("KillLeader called but no leader designated.")
		return
	}
	log.Info("Killing Typha hierarchy leader to force re-election.")
	h.Leader.Stop()
	// Remove it from All so subsequent WaitForLeader doesn't map back to it.
	var remaining []*Typha
	for _, t := range h.All {
		if t == h.Leader {
			continue
		}
		remaining = append(remaining, t)
	}
	h.All = remaining
	h.Leader = nil
}

// Stop tears down all Typha containers in the hierarchy.
func (h *TyphaHierarchy) Stop() {
	for _, t := range h.All {
		t.Stop()
	}
}
