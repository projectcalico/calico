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

package fv_test

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

// describeTyphaHierarchyTests is the shared body for the Typha hierarchy FV
// tests.  Both sub-suites below call it; the chained-path suite uses 3 Typhas
// (leader + 2 followers) to exercise a deeper hierarchy, while the failover
// suite uses 2 Typhas so that the follower Felix is connected to wins
// re-election (in-process promotion) without requiring a container IP change.
//
// Discovery model: all Typhas run in roleManaged mode (HierarchyEnabled +
// LeaderElectionEnabled, no static UpstreamAddr).  The harness creates a
// headless K8s Service for leader discovery and updates its EndpointSlice
// after each election.  Followers query the EndpointSlice to find the leader.
//
// This FV validates:
//   - real Lease contention among N containers
//   - chained data path (Felix → follower Typha → leader Typha → datastore)
//   - in-process leader promotion: when a follower wins re-election it starts
//     real datastore syncers and keeps serving its Felix clients
//   - policy written during the outage appears on Felix after recovery
func describeTyphaHierarchyTests(getInfra infrastructure.InfraFactory, numTyphas int) {
	var (
		infra        infrastructure.DatastoreInfra
		hierarchy    *infrastructure.TyphaHierarchy
		tc           infrastructure.TopologyContainers
		calicoClient client.Interface
		w            [2]*workload.Workload
		cc           *connectivity.Checker
		// felixFollower is the Typha container the Felixes are pointed at.
		// With numTyphas == 2 this is the only follower; it will win re-election
		// (in-process promotion) after the leader is killed.
		felixFollower *infrastructure.Typha
	)

	BeforeEach(func() {
		infra = getInfra()

		opts := infrastructure.DefaultTopologyOptions()
		opts.IPIPMode = api.IPIPModeNever

		// Start numTyphas Typhas in roleManaged election mode.  The harness
		// creates a headless K8s Service so followers can discover the leader
		// once the EndpointSlice is populated by SetLeader.
		hierarchy = infrastructure.RunTyphaHierarchy(infra, opts,
			infrastructure.HierarchyOptions{NumTyphas: numTyphas})

		// Wait up to 30s for initial election (election duration 4s in test
		// config; allow extra time for container start).
		leader, leaderName, err := hierarchy.WaitForLeader(30 * time.Second)
		Expect(err).NotTo(HaveOccurred(), "timed out waiting for initial leader election")
		Expect(leader).NotTo(BeNil())
		By(fmt.Sprintf("Initial leader elected: %s", leaderName))

		// Update the leader EndpointSlice so followers can discover and connect
		// to the leader.  This also sets hierarchy.Followers.
		hierarchy.SetLeader(leader)
		Expect(hierarchy.Followers).To(HaveLen(numTyphas-1),
			"expected %d follower(s) after SetLeader", numTyphas-1)

		// Point all Felixes at the first follower so the chained data path is
		// exercised: Felix → Followers[0] → leader → datastore.
		// With numTyphas == 2, Followers[0] is the only follower and will
		// promote in-process when the leader is killed.
		felixFollower = hierarchy.Followers[0]
		opts.ExtraEnvVars["FELIX_TYPHAADDR"] = felixFollower.IP + ":5473"

		// Start 2-node topology (inits datastore + starts Felixes).
		tc, calicoClient = infrastructure.StartNNodeTopology(2, opts, infra)

		// Install a default allow-all profile so workloads communicate freely.
		infra.AddDefaultAllow()

		// Create one workload per Felix.
		for i := range w {
			wIP := fmt.Sprintf("10.65.%d.2", i)
			wName := fmt.Sprintf("w%d", i)
			infrastructure.AssignIP(wName, wIP, tc.Felixes[i].Hostname, calicoClient)
			w[i] = workload.Run(tc.Felixes[i], wName, "default", wIP, "8055", "tcp")
			w[i].ConfigureInInfra(infra)
		}

		cc = &connectivity.Checker{}
	})

	AfterEach(func() {
		for _, wl := range w {
			if wl != nil {
				wl.Stop()
			}
		}
		tc.Stop()
		// Hierarchy containers are registered via infra.AddCleanup; they are
		// torn down by the DatastoreDescribe AfterEach that calls infra.Stop.
	})

	It("should allow workload-to-workload connectivity via the hierarchy", func() {
		// Felixes reach the datastore through follower → leader → datastore.
		// Once both are Ready, the default-allow profile permits w[0]↔w[1].
		cc.ExpectSome(w[0], w[1])
		cc.ExpectSome(w[1], w[0])
		cc.CheckConnectivity()
	})

	It("should recover after the leader is killed and a new one is elected", func() {
		// Establish baseline connectivity via the hierarchy.
		cc.ExpectSome(w[0], w[1])
		cc.ExpectSome(w[1], w[0])
		cc.CheckConnectivity()
		cc.ResetExpectations()

		// Write a policy before killing the leader so we can verify the new
		// leader serves up-to-date data after failover.
		policy := api.NewNetworkPolicy()
		policy.Namespace = "default"
		policy.Name = "test-policy-during-outage"
		policy.Spec.Selector = w[0].NameSelector()
		// Deny all ingress to w[0]; unrestricted egress from w[0].
		policy.Spec.Ingress = []api.Rule{}
		policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
		policy.Spec.Types = []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress}
		_, err := calicoClient.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// Kill the leader.
		By("Killing the hierarchy leader to trigger re-election")
		hierarchy.KillLeader()

		// With numTyphas == 2 the single surviving Typha (felixFollower) is the
		// only candidate; it wins the election and transitions in-process from
		// follower to leader.  Felixes stay connected to the same container —
		// no IP change.
		//
		// With numTyphas == 3 one of the two remaining followers wins.  Felixes
		// were pointed at Followers[0]; if that container wins it promotes
		// in-process; if Followers[1] wins, Followers[0] discovers the new
		// leader via the updated EndpointSlice and reconnects.
		newLeader, newLeaderName, err := hierarchy.WaitForLeader(45 * time.Second)
		Expect(err).NotTo(HaveOccurred(), "timed out waiting for re-election after leader kill")
		Expect(newLeader).NotTo(BeNil())
		By(fmt.Sprintf("New leader elected after failover: %s", newLeaderName))

		// Update the EndpointSlice to the new leader so any remaining followers
		// can discover and connect to it.
		hierarchy.SetLeader(newLeader)

		// Wait for both Felixes to become Ready again (CalculationGraph catches up).
		for _, f := range tc.Felixes {
			f.WaitForReady()
		}

		// The policy written before the leader kill should now be enforced.
		// w[1] → w[0] is denied (ingress policy on w[0]); w[0] → w[1] is
		// allowed (egress unrestricted from w[0]).
		cc.ExpectNone(w[1], w[0])
		cc.ExpectSome(w[0], w[1])
		cc.CheckConnectivity()
	})
}

var _ = infrastructure.DatastoreDescribe(
	"_BPF-SAFE_ Typha hierarchy: chained data path (3 Typhas)",
	[]apiconfig.DatastoreType{apiconfig.Kubernetes},
	func(getInfra infrastructure.InfraFactory) {
		describeTyphaHierarchyTests(getInfra, 3)
	})

var _ = infrastructure.DatastoreDescribe(
	"_BPF-SAFE_ Typha hierarchy: leader failover (2 Typhas)",
	[]apiconfig.DatastoreType{apiconfig.Kubernetes},
	func(getInfra infrastructure.InfraFactory) {
		describeTyphaHierarchyTests(getInfra, 2)
	})
