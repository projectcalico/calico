/*
Copyright 2025 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package conformance_test

import (
	"io/fs"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance"
	"sigs.k8s.io/gateway-api/conformance/tests"
	"sigs.k8s.io/gateway-api/conformance/utils/flags"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
)

func TestConformance(t *testing.T) {
	cfg, err := config.GetConfig()
	if err != nil {
		t.Fatalf("Error loading Kubernetes config: %v", err)
	}

	// Register schemes
	s := scheme.Scheme
	if err := apiextensionsv1.AddToScheme(s); err != nil {
		t.Fatalf("error adding apiextensions to scheme: %v", err)
	}
	if err := gatewayv1.Install(s); err != nil {
		t.Fatalf("error installing Gateway API scheme: %v", err)
	}

	c, err := client.New(cfg, client.Options{Scheme: s})
	if err != nil {
		t.Fatalf("Error initializing Kubernetes client: %v", err)
	}

	kubeConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		t.Fatalf("error building Kube config for client-go: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		t.Fatalf("error when creating Kubernetes ClientSet: %v", err)
	}

	supportedFeatures := suite.ParseSupportedFeatures(*flags.SupportedFeatures)
	exemptFeatures := suite.ParseSupportedFeatures(*flags.ExemptFeatures)

	t.Logf("Running Gateway API conformance tests with:\n"+
		"  cleanup: %t\n"+
		"  debug: %t\n"+
		"  gateway-class: %s\n"+
		"  supported features: [%v]\n"+
		"  exempt features: [%v]",
		*flags.CleanupBaseResources,
		*flags.ShowDebug,
		*flags.GatewayClassName,
		*flags.SupportedFeatures,
		*flags.ExemptFeatures)

	// Use embedded Gateway API manifests for conformance testing
	// These include base manifests (namespaces, Gateways, backend services) and test-specific manifests
	opts := suite.ConformanceOptions{
		Client:                     c,
		Clientset:                  clientset,
		RestConfig:                 cfg,
		GatewayClassName:           *flags.GatewayClassName,
		Debug:                      *flags.ShowDebug,
		CleanupBaseResources:       *flags.CleanupBaseResources,
		SupportedFeatures:          supportedFeatures,
		ExemptFeatures:             exemptFeatures,
		EnableAllSupportedFeatures: *flags.EnableAllSupportedFeatures,
		SkipTests:                  []string{},
		BaseManifests:              "base/manifests.yaml",
		ManifestFS:                 []fs.FS{conformance.Manifests},
	}

	cSuite, err := suite.NewConformanceTestSuite(opts)
	if err != nil {
		t.Fatalf("error creating conformance test suite: %v", err)
	}

	cSuite.Setup(t, tests.ConformanceTests)
	err = cSuite.Run(t, tests.ConformanceTests)
	if err != nil {
		t.Fatalf("error running conformance tests: %v", err)
	}
}
