package server

import (
	"net"
	"fmt"
	"sort"
	"strings"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/selector"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type (
	// Interface to Calico API objects.
	CalicoQuery interface {

		// Get a list of Policy objects for the given endpoint.
		GetPolicies(metadata api.WorkloadEndpointMetadata) ([]api.Policy, error)

		// Lookup an endpoint based on its IP address.
		GetEndpointFromIP(ip net.IP) (*model.KVPair)

		// Temporary, needed to find workload endpoint from container ID.
		// TODO (spikecurtis): remove this and replace with socket per pod.
		GetEndpointFromContainer(cid string, nodeName string) (api.WorkloadEndpointMetadata, error)
	}

	calicoQuery struct {
		Client *client.Client
		kubeClient *kubernetes.Clientset
	}
)

func (q *calicoQuery) GetPolicies(metadata api.WorkloadEndpointMetadata) ([]api.Policy, error) {
	we, err := q.Client.WorkloadEndpoints().Get(metadata)
	if err != nil {
		return nil, err
	}
	return q.getPoliciesFromLabels(we.Metadata.Labels)
}

// Methods to sort Polices by their ordering.
type orderedPolicies []api.Policy

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
		return strings.Compare(op[i].Metadata.Name, op[j].Metadata.Name) < 0
	}
}

// Return the list of active PolicySpecs for this endpoint.  This list should be sorted in the correct application
// order.
func (q *calicoQuery) getPoliciesFromLabels(labels map[string]string) ([]api.Policy, error) {
	pi := q.Client.Policies()
	p_list, err := pi.List(api.PolicyMetadata{})
	if err != nil {
		log.Error("Failed to List.")
		return nil, err
	}

	p_active := []api.Policy{}
	log.Debugf("Found %d total policies.", len(p_list.Items))
	for _, p := range p_list.Items {
		log.Debugf("Found policy %v", p)
		if policyActive(labels, &p) {
			log.Debugf("Active policy %v", p)
			p_active = append(p_active, p)
		}
	}
	sort.Sort(orderedPolicies(p_active))
	return p_active, nil
}

func policyActive(labels map[string]string, policy *api.Policy) bool {
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

func (q *calicoQuery) GetEndpointFromContainer(cid string, nodeName string) (api.WorkloadEndpointMetadata, error) {
	wemeta := api.WorkloadEndpointMetadata{}
	qStr := "spec.nodeName=" + nodeName
	opts := metav1.ListOptions{}
	opts.FieldSelector = qStr
	pods, err := q.kubeClient.CoreV1().Pods("").List(opts)
	if err != nil {
		return wemeta, err
	}
	log.Debugf("Number of pods on %v %v", qStr, len(pods.Items))

	matchCid := "docker://" + cid
	for _, pod := range pods.Items {
		for _, containerStatus := range pod.Status.ContainerStatuses {
			if containerStatus.ContainerID == matchCid {
				wemeta.Workload = fmt.Sprintf("%s.%s", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)
				wemeta.Node = nodeName
				wemeta.Orchestrator = "k8s"
				return wemeta, nil
			}
		}
	}
	return wemeta, fmt.Errorf("unable to find pod with containerId %v", cid)
}


