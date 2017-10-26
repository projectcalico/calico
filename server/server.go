package server

import (
	"sort"
	"strings"

	authz "tigera.io/dikastes/proto"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/selector"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type (
	auth_server struct {
		Client     *client.Client
		NodeName   string
		kubeClient *kubernetes.Clientset
	}
)

func NewServer(config api.CalicoAPIConfig, nodeName string) (*auth_server, error) {
	c, err := client.New(config)
	log.Debug("Created Calico Client.")
	if err != nil {
		return nil, err
	}

	// Temporary hack for direct access to K8s API.
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &auth_server{c, nodeName, clientset}, nil
}

func (as *auth_server) Check(ctx context.Context, req *authz.Request) (*authz.Response, error) {
	log.Debugf("Check(%v, %v)", ctx, req)
	resp := authz.Response{Status: &authz.Response_Status{Code: authz.INTERNAL}}
	labels, err := as.getLabelsFromContext(ctx)
	if err != nil {
		log.Errorf("Failed to get workload endpoint. %v", err)
		return &resp, nil
	}
	policies, err := as.getPolicies(labels)
	if err != nil {
		log.Errorf("Failed to get policies. %v", err)
		return &resp, nil
	}
	status := checkPolicies(policies, req)
	resp.Status.Code = status
	log.WithFields(log.Fields{
		"Request":  req,
		"Response": resp,
	}).Info("Check complete")
	return &resp, nil
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
func (as *auth_server) getPolicies(labels map[string]string) ([]api.Policy, error) {
	pi := as.Client.Policies()
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
