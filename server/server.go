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
)

type (
	auth_server struct {
		CalicoClient *client.Client
		Labels       map[string]string
	}
)

const (
	k8s_api     = "https://kubernetes"
	k8s_ca_file = "/var/run/"
)

func NewServer(labels map[string]string) (*auth_server, error) {
	c, err := client.NewFromEnv()
	log.Debug("Created Calico Client.")
	if err != nil {
		return nil, err
	}
	return &auth_server{c, labels}, nil
}

func (as *auth_server) Check(ctx context.Context, req *authz.Request) (*authz.Response, error) {
	log.Debugf("Check(%v)", req)
	resp := authz.Response{Status: &authz.Response_Status{Code: authz.Response_Status_INTERNAL}}
	policies, err := as.getPolicies()
	if err != nil {
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
func (as *auth_server) getPolicies() ([]api.Policy, error) {
	pi := as.CalicoClient.Policies()
	p_list, err := pi.List(api.PolicyMetadata{})
	if err != nil {
		return nil, err
	}

	p_active := []api.Policy{}
	log.Debugf("Found %d total policies.", len(p_list.Items))
	for _, p := range p_list.Items {
		log.Debugf("Found policy %v", p)
		if policyActive(as, &p) {
			log.Debugf("Active policy %v", p)
			p_active = append(p_active, p)
		}
	}
	sort.Sort(orderedPolicies(p_active))
	return p_active, nil
}

func policyActive(as *auth_server, policy *api.Policy) bool {
	sel, err := selector.Parse(policy.Spec.Selector)
	if err != nil {
		log.Warnf("Could not parse policy selector %v, %v", policy.Spec.Selector, err)
		return false
	}
	log.Debugf("Parsed selector %v", sel)
	return sel.Evaluate(as.Labels)
}
