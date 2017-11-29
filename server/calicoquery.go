// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package server

import (
	"context"
	"net"
	"fmt"
	"sort"
	"strings"

	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/selector"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/names"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type (
	// Interface to Calico API objects.
	CalicoQuery interface {

		// Get a list of Policy objects for the given endpoint.
		GetPolicies(id names.WorkloadEndpointIdentifiers, namespace string) ([]api.GlobalNetworkPolicy, error)

		// Lookup an endpoint based on its IP address.
		GetEndpointFromIP(ip net.IP) (*model.KVPair)

		// Temporary, needed to find workload endpoint from container ID.
		// TODO (spikecurtis): remove this and replace with socket per pod.
		GetEndpointFromContainer(cid string, nodeName string) (id names.WorkloadEndpointIdentifiers, namespace string, err error)
	}

	calicoQuery struct {
		Client clientv3.Interface
		kubeClient *kubernetes.Clientset
	}

)

func NewCalicoQuery(client clientv3.Interface, kubeClient *kubernetes.Clientset) (CalicoQuery){
	q := calicoQuery{client, kubeClient}
	return &q
}

func (q *calicoQuery) GetPolicies(id names.WorkloadEndpointIdentifiers, namespace string) ([]api.GlobalNetworkPolicy, error) {
	weName, err := id.CalculateWorkloadEndpointName(false)
	if err != nil {
		log.Fatalf("Failed to compute workload endpoint name from ID: %v. %v", id, err)
	}
	we, err := q.Client.WorkloadEndpoints().Get(context.TODO(), namespace, weName, options.GetOptions{})
	if err != nil {
		return nil, err
	}
	return q.getPoliciesFromLabels(we.Labels)
}

// Methods to sort Polices by their ordering.
type orderedPolicies []api.GlobalNetworkPolicy

func (op orderedPolicies) Len() int      { return len(op) }
func (op orderedPolicies) Swap(i, j int) { op[i], op[j] = op[j], op[i] }
func (op orderedPolicies) Less(i, j int) bool {
	if op[i].Spec.Order != nil && op[j].Spec.Order == nil {
		return true
	} else if op[i].Spec.Order == nil && op[j].Spec.Order != nil {
		return false
	} else if op[i].Spec.Order != nil && op[j].Spec.Order != nil {
		return *op[i].Spec.Order < *op[j].Spec.Order
	} else {
		return strings.Compare(op[i].Name, op[j].Name) < 0
	}
}

// Return the list of active PolicySpecs for this endpoint.  This list should be sorted in the correct application
// order.
func (q *calicoQuery) getPoliciesFromLabels(labels map[string]string) ([]api.GlobalNetworkPolicy, error) {
	pActive := []api.GlobalNetworkPolicy{}
	pList, err := q.Client.GlobalNetworkPolicies().List(context.TODO(), options.ListOptions{})
	if err != nil {
		return nil, err
	}
	log.Debugf("Found %d total policies.", len(pList.Items))
	for _, p := range pList.Items {
		log.Debugf("Found policy %v", p)
		if policyActive(labels, &p) {
			log.Debugf("Active policy %v", p)
			pActive = append(pActive, p)
		}
	}
	sort.Sort(orderedPolicies(pActive))
	return pActive, nil
}

func policyActive(labels map[string]string, policy *api.GlobalNetworkPolicy) bool {
	sel, err := selector.Parse(policy.Spec.Selector)
	if err != nil {
		log.Warnf("Could not parse policy selector %v, %v", policy.Spec.Selector, err)
		return false
	}
	log.Debugf("Parsed selector %v", sel)
	return sel.Evaluate(labels)
}

func (q *calicoQuery) GetEndpointFromIP(ip net.IP) (*model.KVPair) {
	return nil
}

func (q *calicoQuery) GetEndpointFromContainer(cid string, nodeName string) (id names.WorkloadEndpointIdentifiers, namespace string, err error) {
	id.Node = nodeName
	id.Orchestrator = "k8s"
	id.Endpoint = "eth0"
	qStr := "spec.nodeName=" + nodeName
	opts := metav1.ListOptions{}
	opts.FieldSelector = qStr
	pods, err := q.kubeClient.CoreV1().Pods("").List(opts)
	if err != nil {
		return
	}
	log.Debugf("Number of pods on %v %v", qStr, len(pods.Items))

	matchCid := "docker://" + cid
	for _, pod := range pods.Items {
		for _, containerStatus := range pod.Status.ContainerStatuses {
			if containerStatus.ContainerID == matchCid {
				namespace = pod.ObjectMeta.Namespace
				id.Pod = pod.Name
				return
			}
		}
	}
	err = fmt.Errorf("unable to find pod with containerId %v", cid)
	return
}
