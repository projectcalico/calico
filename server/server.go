package server

import (
	"sort"
	"strings"

	authz "tigera.io/dikastes/proto"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/selector"

	"github.com/projectcalico/libcalico-go/lib/backend/k8s/resources"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
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
	clientset, err := NewKubeClient(config)
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

// Modified from libcalico-go/lib/backend/k8s/k8s.go to return bare clientset.
func NewKubeClient(calCfg api.CalicoAPIConfig) (*kubernetes.Clientset, error) {
	kc := &calCfg.Spec.KubeConfig
	// Use the kubernetes client code to load the kubeconfig file and combine it with the overrides.
	log.Debugf("Building client for config: %+v", kc)
	configOverrides := &clientcmd.ConfigOverrides{}
	var overridesMap = []struct {
		variable *string
		value    string
	}{
		{&configOverrides.ClusterInfo.Server, kc.K8sAPIEndpoint},
		{&configOverrides.AuthInfo.ClientCertificate, kc.K8sCertFile},
		{&configOverrides.AuthInfo.ClientKey, kc.K8sKeyFile},
		{&configOverrides.ClusterInfo.CertificateAuthority, kc.K8sCAFile},
		{&configOverrides.AuthInfo.Token, kc.K8sAPIToken},
	}

	// Set an explicit path to the kubeconfig if one
	// was provided.
	loadingRules := clientcmd.ClientConfigLoadingRules{}
	if kc.Kubeconfig != "" {
		loadingRules.ExplicitPath = kc.Kubeconfig
	}

	// Using the override map above, populate any non-empty values.
	for _, override := range overridesMap {
		if override.value != "" {
			*override.variable = override.value
		}
	}
	if kc.K8sInsecureSkipTLSVerify {
		configOverrides.ClusterInfo.InsecureSkipTLSVerify = true
	}
	log.Debugf("Config overrides: %+v", configOverrides)

	// A kubeconfig file was provided.  Use it to load a config, passing through
	// any overrides.
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&loadingRules, configOverrides).ClientConfig()
	if err != nil {
		return nil, resources.K8sErrorToCalico(err, nil)
	}

	// Create the clientset
	cs, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, resources.K8sErrorToCalico(err, nil)
	}
	log.Debugf("Created k8s clientSet: %+v", cs)
	return cs, nil
}
