package server

import (
	authz "tigera.io/dikastes/proto"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/resources"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type (
	auth_server struct {
		NodeName   string
		Query CalicoQuery
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
	q := calicoQuery{c, clientset}
	return &auth_server{nodeName, &q}, nil
}

func (as *auth_server) Check(ctx context.Context, req *authz.Request) (*authz.Response, error) {
	log.Debugf("Check(%v, %v)", ctx, req)
	resp := authz.Response{Status: &authz.Response_Status{Code: authz.INTERNAL}}
	cid, err := getContainerFromContext(ctx)
	if err != nil {
		log.Errorf("Failed to get container ID. %v", err)
		return &resp, nil
	}
	wemeta, err := as.Query.GetEndpointFromContainer(cid, as.NodeName)
	if err != nil {
		log.Errorf("Failed to get endpoint for container %v. %v", cid, err)
	}
	policies, err := as.Query.GetPolicies(wemeta)
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
