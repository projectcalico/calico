package server

import (
	"net"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/selector"
	"github.com/projectcalico/libcalico-go/lib/converter"

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
		pLock sync.RWMutex
		pMap map[string]*api.Policy
		pConverter converter.PolicyConverter
		status bapi.SyncStatus
	}

)

func NewCalicoQuery(client *client.Client, kubeClient *kubernetes.Clientset) (CalicoQuery){
	q := calicoQuery{
		client, kubeClient, sync.RWMutex{}, make(map[string]*api.Policy),
		converter.PolicyConverter{}, bapi.WaitForDatastore}
	syncer := client.Backend.Syncer(&q)
	syncer.Start()
	return &q
}

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
	p_active := []api.Policy{}
	q.pLock.RLock()
	log.Debugf("Found %d total policies.", len(q.pMap))
	for _, p := range q.pMap {
		log.Debugf("Found policy %v", *p)
		if policyActive(labels, p) {
			log.Debugf("Active policy %v", *p)
			p_active = append(p_active, *p)
		}
	}
	q.pLock.RUnlock()
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


func (q *calicoQuery) OnUpdates(updates []bapi.Update) {
	for _, u := range updates {
		switch key := u.Key.(type) {
		case model.PolicyKey:
			if u.Value != nil {
				log.Debugf("Storing policy for key %v", key)
				policy, _ := q.pConverter.ConvertKVPairToAPI(&u.KVPair)
				q.pLock.Lock()
				q.pMap[key.Name] = policy.(*api.Policy)
				q.pLock.Unlock()
			} else {
				q.pLock.Lock()
				delete(q.pMap, key.Name)
				q.pLock.Unlock()
			}
		default:
			log.Debugf("Ignoring update for key %v", key)
		}
	}
}

func (q *calicoQuery) OnStatusUpdated(status bapi.SyncStatus) {
	q.status = status
}

