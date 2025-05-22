package crdv3

import (
	"path/filepath"
	"strings"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/winutils"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func restConfig(ca *apiconfig.CalicoAPIConfigSpec) (*rest.Config, error) {
	// Use the kubernetes client code to load the kubeconfig file and combine it with the overrides.
	configOverrides := &clientcmd.ConfigOverrides{}
	overridesMap := []struct {
		variable *string
		value    string
	}{
		{&configOverrides.CurrentContext, ca.K8sCurrentContext},
		{&configOverrides.ClusterInfo.Server, ca.K8sAPIEndpoint},
		{&configOverrides.AuthInfo.ClientCertificate, ca.K8sCertFile},
		{&configOverrides.AuthInfo.ClientKey, ca.K8sKeyFile},
		{&configOverrides.ClusterInfo.CertificateAuthority, ca.K8sCAFile},
		{&configOverrides.AuthInfo.Token, ca.K8sAPIToken},
	}

	// Set an explicit path to the kubeconfig if one was provided.
	loadingRules := clientcmd.ClientConfigLoadingRules{}
	if ca.Kubeconfig != "" {
		fillLoadingRulesFromKubeConfigSpec(&loadingRules, ca.Kubeconfig)
	}

	// Using the override map above, populate any non-empty values.
	for _, override := range overridesMap {
		if override.value != "" {
			*override.variable = override.value
		}
	}
	if ca.K8sInsecureSkipTLSVerify {
		configOverrides.ClusterInfo.InsecureSkipTLSVerify = true
	}

	// A kubeconfig file was provided.  Use it to load a config, passing through any overrides.
	var config *rest.Config
	var err error
	if ca.KubeconfigInline != "" {
		var clientConfig clientcmd.ClientConfig
		clientConfig, err = clientcmd.NewClientConfigFromBytes([]byte(ca.KubeconfigInline))
		if err != nil {
			return nil, resources.K8sErrorToCalico(err, nil)
		}
		config, err = clientConfig.ClientConfig()
	} else {
		config, err = winutils.NewNonInteractiveDeferredLoadingClientConfig(
			&loadingRules, configOverrides)
	}
	if err != nil {
		return nil, resources.K8sErrorToCalico(err, nil)
	}

	config.AcceptContentTypes = strings.Join([]string{runtime.ContentTypeProtobuf, runtime.ContentTypeJSON}, ",")
	config.ContentType = runtime.ContentTypeProtobuf

	// Overwrite the QPS if provided. Default QPS is 5.
	if ca.K8sClientQPS != float32(0) {
		config.QPS = ca.K8sClientQPS
	}

	// Create the clientset. We increase the burst so that the IPAM code performs
	// efficiently. The IPAM code can create bursts of requests to the API, so
	// in order to keep pod creation times sensible we allow a higher request rate.
	config.Burst = 100
	return config, nil
}

// deduplicate removes any duplicated values and returns a new slice, keeping the order unchanged
//
//	based on deduplicate([]string) []string found in k8s.io/client-go/tools/clientcmd/loader.go#634
//	Copyright 2014 The Kubernetes Authors.
func deduplicate(s []string) []string {
	encountered := map[string]struct{}{}
	ret := make([]string, 0)
	for i := range s {
		if _, ok := encountered[s[i]]; ok {
			continue
		}
		encountered[s[i]] = struct{}{}
		ret = append(ret, s[i])
	}
	return ret
}

// fill out loading rules based on filename(s) encountered in specified kubeconfig
func fillLoadingRulesFromKubeConfigSpec(loadingRules *clientcmd.ClientConfigLoadingRules, kubeConfig string) {
	fileList := filepath.SplitList(kubeConfig)

	if len(fileList) > 1 {
		loadingRules.Precedence = deduplicate(fileList)
		loadingRules.WarnIfAllMissing = true
		return
	}

	loadingRules.ExplicitPath = kubeConfig
}
