// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

// Gateway API conformance runner. Wraps the upstream
// sigs.k8s.io/gateway-api/conformance suite, runs it against the
// cluster at $KUBECONFIG, and writes the ConformanceReport YAML for
// upstream submission.
//
// All flags come from sigs.k8s.io/gateway-api/conformance/utils/flags;
// see that package for the full list.

package gateway_test

import (
	"io/fs"
	"os"
	"strings"
	"testing"

	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance"
	confv1 "sigs.k8s.io/gateway-api/conformance/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/tests"
	"sigs.k8s.io/gateway-api/conformance/utils/flags"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
	"sigs.k8s.io/yaml"
)

func TestGatewayAPIConformance(t *testing.T) {
	cfg, err := config.GetConfig()
	if err != nil {
		t.Fatalf("loading kube config: %v", err)
	}

	c, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatalf("controller-runtime client: %v", err)
	}

	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("clientset: %v", err)
	}

	if err := gwapiv1.Install(c.Scheme()); err != nil {
		t.Fatalf("install gateway-api scheme: %v", err)
	}
	if err := apiextv1.AddToScheme(c.Scheme()); err != nil {
		t.Fatalf("install apiextensions scheme: %v", err)
	}

	profileNames := sets.New[suite.ConformanceProfileName]()
	for _, p := range strings.Split(*flags.ConformanceProfiles, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		profileNames.Insert(suite.ConformanceProfileName(p))
	}
	if profileNames.Len() == 0 {
		// Default to GATEWAY-HTTP for Calico's Envoy-Gateway-based impl.
		profileNames.Insert(suite.GatewayHTTPConformanceProfileName)
	}

	var contacts []string
	if *flags.ImplementationContact != "" {
		contacts = strings.Split(*flags.ImplementationContact, ",")
		for i := range contacts {
			contacts[i] = strings.TrimSpace(contacts[i])
		}
	}

	supportedFeatures := parseFeatures(*flags.SupportedFeatures)
	exemptFeatures := parseFeatures(*flags.ExemptFeatures)
	skipTests := splitCSV(*flags.SkipTests)

	t.Logf("running gateway-api conformance: gatewayClass=%s mode=%s version=%q profiles=%v allFeatures=%t",
		*flags.GatewayClassName, *flags.Mode, *flags.ImplementationVersion, profileNames.UnsortedList(), *flags.EnableAllSupportedFeatures)

	cSuite, err := suite.NewConformanceTestSuite(suite.ConformanceOptions{
		Client:                     c,
		Clientset:                  cs,
		RestConfig:                 cfg,
		GatewayClassName:           *flags.GatewayClassName,
		MeshName:                   *flags.MeshName,
		Debug:                      *flags.ShowDebug,
		CleanupBaseResources:       *flags.CleanupBaseResources,
		Mode:                       *flags.Mode,
		AllowCRDsMismatch:          *flags.AllowCRDsMismatch,
		SupportedFeatures:          supportedFeatures,
		ExemptFeatures:             exemptFeatures,
		EnableAllSupportedFeatures: *flags.EnableAllSupportedFeatures,
		SkipTests:                  skipTests,
		SkipProvisionalTests:       *flags.SkipProvisionalTests,
		RunTest:                    *flags.RunTest,
		ManifestFS:                 []fs.FS{&conformance.Manifests},
		Implementation: confv1.Implementation{
			Organization: *flags.ImplementationOrganization,
			Project:      *flags.ImplementationProject,
			URL:          *flags.ImplementationURL,
			Version:      *flags.ImplementationVersion,
			Contact:      contacts,
		},
		ConformanceProfiles: profileNames,
	})
	if err != nil {
		t.Fatalf("constructing conformance suite: %v", err)
	}

	cSuite.Setup(t, tests.ConformanceTests)
	if err := cSuite.Run(t, tests.ConformanceTests); err != nil {
		t.Fatalf("running conformance: %v", err)
	}

	report, err := cSuite.Report()
	if err != nil {
		t.Fatalf("generating report: %v", err)
	}

	out, err := yaml.Marshal(report)
	if err != nil {
		t.Fatalf("marshalling report: %v", err)
	}

	if *flags.ReportOutput == "" {
		t.Logf("\n--- ConformanceReport ---\n%s\n", out)
		return
	}
	// Per upstream README: report MUST be uploaded exactly as produced.
	if err := os.WriteFile(*flags.ReportOutput, out, 0o600); err != nil {
		t.Fatalf("writing report: %v", err)
	}
	t.Logf("wrote ConformanceReport to %s", *flags.ReportOutput)
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseFeatures(s string) sets.Set[features.FeatureName] {
	out := sets.New[features.FeatureName]()
	for _, name := range splitCSV(s) {
		out.Insert(features.FeatureName(name))
	}
	return out
}
