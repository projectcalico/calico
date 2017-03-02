// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package main

import (
	log "github.com/Sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/apis/meta/v1"
)

// Our objective here is to test the scalability of the Felix calculation graph.
//
// The calculation graph is the dataplane-independent part of Felix whose input is the whole Calico
// data model, and whose output is everything that Felix needs to program on the local host,
// comprising:
//
// - the set of active local endpoints, both workload and host, including the ordered profile and
//   policy IDs that need to be applied for each of those endpoints (WorkloadEndpointUpdate,
//   WorkloadEndpointRemove, HostEndpointUpdate, HostEndpointRemove)
//
// - the definition of each locally needed profile and policy, using IP set IDs to represent
//   arbitrary sets of IP addresses, where a profile or policy (implicitly) uses those
//   (ActivePolicyUpdate, ActivePolicyRemove, ActiveProfileUpdate, ActiveProfileRemove)
//
// - the definition of the current set of IP addresses for each IP set ID (IPSetDeltaUpdate,
//   IPSetUpdate, IPSetRemove)
//
// - where IP-in-IP routes are needed to reach other compute hosts (HostMetadataUpdate,
//   HostMetadataRemove)
//
// - where IP masquerading is needed for outgoing endpoint data (IPAMPoolUpdate, IPAMPoolRemove).
//
// (The names in brackets here are those of the protobuf messages that carry the corresponding
// information from the calculation graph to the dataplane.)
//
// To narrow the focus further, we are only initially interested in the processing of
// endpoint-related state that can be fed into Felix by the Kubernetes datastore driver, through the
// Kubernetes API server.  This means that the interesting inputs become:
//
// - k8s namespaces (each of which gets mapped to a Calico profile and a policy)
//
// - k8s pods (which get mapped to Calico workload endpoints)
//
// - k8s network policies (which get mapped to Calico policies)
//
// The interesting outputs are now streamlined to:
//
// - the set of active local workload endpoints, including the policy and profile IDs for each
//   endpoint (WorkloadEndpointUpdate, WorkloadEndpointRemove)
//
// - active policy, i.e. the definition of each locally needed profile ID and policy ID
//   (ActivePolicyUpdate, ActivePolicyRemove, ActiveProfileUpdate, ActiveProfileRemove)
//
// - active IP sets, i.e. the definition of the IP addresses for each IP set ID that is referenced
//   by the active policy (IPSetDeltaUpdate, IPSetUpdate, IPSetRemove).
//
// Let's consider what inputs can cause each of those outputs to change, and the complexity of the
// calculation graph processing involved.
//
// The set of active local workload endpoints changes when a pod on the local host is created,
// updated or deleted, or when a pod is moved to or from the local host.  The processing complexity
// and effect on the set are 1:1 with the k8s pod input.
//
// The active policy set can change: if a pod is added to this host (if its labels match a policy
// that previously didn't match any other local endpoints); or if a pod is deleted from this host
// (if its labels were the only local match for a particular policy); or if a local pod's labels are
// changed such that it matches different policy; or if a local pod's namespace's labels are changed
// such that it matches different policy; or if the default deny/allow setting of a local pod's
// namespace changes; or if the content of an active network policy changes; or if the selector of a
// network policy changes so that it changes between active and inactive.
//
// The active IP sets can change: if an active network policy's rules are changed to use different
// selectors; or if a pod (on any host) is updated and has/had labels matching a source selector of
// an active network policy; or if a namespace is updated such that its pods has/had labels matching
// a source selector of an active network policy.
//
// Pod added to local host (inc move from remote to local)
// -> O(1) WorkloadEndpointUpdate New active local workload endpoint
// -> O(<num defined policies>) ActivePolicyUpdate If pod labels match policies not previously used on this host
//
// Pod deleted from local host (inc move from local to remote)
// -> O(1) WorkloadEndpointRemove Removed active local workload endpoint
// -> O(1 or <num defined policies>) ActivePolicyRemove If pod labels matched policies that are otherwise not needed
//
// Pod on local host updated (inc changing its namespace name)
// -> O(1) WorkloadEndpointUpdate Update content (addrs, policy/profile IDs) for local workload endpoint
// -> O(<num defined policies>) ActivePolicyUpdate If new pod labels match policies not previously used on this host
// -> O(1 or <num defined policies>) ActivePolicyRemove If old pod labels matched policies that are otherwise not needed
//
// Pod on any host is created or deleted, or has its labels updated
// -> O(<num active policies> * <num source selectors in each policy>) IPSetUpdate/DeltaUpdate/Remove to create/update/delete IP sets, if pod labels changing.
//
// Namespace labels updated
// -> O(<num local pods defined in that namespace>) <Pod on local host updated>
// -> O(<num pods in namespace> * <num active policies> * <num source selectors in each policy>) IPSetUpdate/DeltaUpdate/Remove to create/update/delete IP sets, if pod labels changing.
//
// Namespace default deny/allow changed
// -> O(<num local pods defined in that namespace>) ActivePolicyUpdate to change the default for the namespace-policy.
//
// Network policy selector changed
// -> O(<num active local endpoints>) WorkloadEndpointUpdate if policy now applies, and before didn't, or vice versa.
// -> O(<num active local endpoints>) <Active network policy rules changed> if policy didn't apply at all, but now does.
// -> O(<num active local endpoints>) ActivePolicyRemove if policy now doesn't apply at all, but previously did.
// -> O(<num active local endpoints> + <num source selectors in policy>) IPSetRemove if policy now doesn't apply at all, but previously did.
//
// Active network policy rules changed
// -> O(1) ActivePolicyUpdate with new rules
// -> O(<num changed source selectors in policy>) IPSetUpdate/DeltaUpdate/Remove to create/update/delete IP sets.
//
// So, some possible tests:
//
// 50 hosts (1 local + 49 remote)
// 20 namespaces
//  area=area1/2/3/4/5
//  maturity=production/test/staging/experimental/out-of-service
// 50 pods per namespace
//  role=role1/2/3/4/5
//  instance=instance1/2/3/4/5
//  ha=active/backup
//
// Rotate maturity labels on the namespace, e.g. change all 'production' to 'out-of-service', then all 'staging' to 'production'.
//
// Churn pods, i.e. delete and recreate (with same properties), in a ring.
//
// Create and delete network policies, each with:
//  selector = random set of labels to work on, random ops and values
//  between 1 and 10 rules, each with random source selector (as above) and ports
// Create say 10 of those, then churn by deleting the oldest, making a new one, etc.

func calcGraph1(clientset *kubernetes.Clientset) error {
	nsMaturity := map[string]string{}
	maturities := []string{"production", "test", "staging", "experimental"}

	// Create namespaces.
	for _, area := range []string{"1", "2", "3", "4", "5"} {
		for _, maturity := range maturities {
			name := "ns-" + area + "-" + maturity
			createNamespace(
				clientset,
				name,
				map[string]string{
					"area":     "area" + area,
					"maturity": maturity,
				},
			)
			nsMaturity[name] = maturity
		}
	}

	d := NewDeployment(49, true)

	// Create pods.
	waiter := make(chan int, len(nsMaturity))
	for nsName, _ := range nsMaturity {
		nsName := nsName
		go func() {
			for _, role := range []string{"1", "2", "3", "4", "5"} {
				for _, instance := range []string{"1", "2", "3", "4", "5"} {
					for _, ha := range []string{"active", "backup"} {
						createPod(
							clientset,
							d,
							nsName,
							podSpec{labels: map[string]string{
								"role":     "role" + role,
								"instance": "instance" + instance,
								"ha":       ha,
							}},
						)
					}
				}
			}
			waiter <- 1
		}()
	}
	for _ = range nsMaturity {
		<-waiter
	}
	// Churn the namespace labels.
	changeFrom := append(maturities, "out-of-service")
	changeTo := append([]string{"out-of-service"}, maturities...)
	for ii := range changeFrom {
		log.Infof("Change all '%s' namespaces to '%s'", changeFrom[ii], changeTo[ii])
		for nsName, maturity := range nsMaturity {
			if maturity == changeFrom[ii] {
				nsMaturity[nsName] = changeTo[ii]
				ns_in, err := clientset.Namespaces().Get(nsName, v1.GetOptions{})
				log.WithField("ns_in", ns_in).Debug("Namespace retrieved")
				if err != nil {
					panic(err)
				}
				ns_in.ObjectMeta.Labels["maturity"] = changeTo[ii]
				ns_out, err := clientset.Namespaces().Update(ns_in)
				log.WithField("ns_out", ns_out).Debug("Updated namespace")
			}
		}
	}
	return nil
}
