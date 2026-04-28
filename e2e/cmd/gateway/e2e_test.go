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
// see that package for the full list. One additional flag is defined
// here, -curated, which selects a pre-baked feature/test/profile set
// that mirrors a known upstream implementation's curated configuration
// (currently: envoy-gateway).

package gateway_test

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"

	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwapiv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gwapiv1alpha3 "sigs.k8s.io/gateway-api/apis/v1alpha3"
	gwapiv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	"sigs.k8s.io/gateway-api/conformance"
	confv1 "sigs.k8s.io/gateway-api/conformance/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/tests"
	"sigs.k8s.io/gateway-api/conformance/utils/flags"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
	"sigs.k8s.io/yaml"
)

// curatedFlag selects a pre-baked feature/test/profile set. Empty means
// "honour the individual upstream flags". Currently supports:
//
//	envoy-gateway   - mirrors envoyproxy/gateway v1.7.0's
//	                  EnvoyGatewaySuite (default mode, no
//	                  gatewayNamespaceMode): full upstream features
//	                  minus mesh, plus UDP, with GatewayStaticAddresses
//	                  and GatewayInfrastructure tests skipped.
//	                  See internal/gatewayapi/conformance/suite.go in
//	                  the envoyproxy/gateway v1.7.0 tag.
var curatedFlag = flag.String("curated", "", "Pre-baked feature/test/profile set: \"envoy-gateway\" or empty.")

func TestGatewayAPIConformance(t *testing.T) {
	// controller-runtime emits a stack-trace warning the first time any of
	// its loggers is consulted without SetLogger having been called. Match
	// the upstream conformance.DefaultOptions and install a zap logger.
	ctrllog.SetLogger(zap.New(zap.WriteTo(os.Stderr), zap.UseDevMode(true)))

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

	// Install every gateway-api API version that conformance tests touch.
	// HTTPRoute reference-grant tests delete v1beta1.ReferenceGrant; the
	// TLSRoute / UDPRoute tests work in v1alpha2; BackendTLSPolicy is
	// v1alpha3. Mirrors sigs.k8s.io/gateway-api/conformance.DefaultOptions.
	for _, install := range []func(*runtime.Scheme) error{
		gwapiv1alpha3.Install,
		gwapiv1alpha2.Install,
		gwapiv1beta1.Install,
		gwapiv1.Install,
	} {
		if err := install(c.Scheme()); err != nil {
			t.Fatalf("install gateway-api scheme: %v", err)
		}
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
	enableAll := *flags.EnableAllSupportedFeatures

	if *curatedFlag != "" {
		curated, err := curatedConfig(*curatedFlag)
		if err != nil {
			t.Fatalf("curated config: %v", err)
		}
		// Curated overrides individual feature/test/profile flags so the
		// caller can't accidentally mix and match an inconsistent set.
		supportedFeatures = curated.SupportedFeatures
		exemptFeatures = curated.ExemptFeatures
		skipTests = curated.SkipTests
		profileNames = curated.Profiles
		enableAll = false
	}

	if profileNames.Len() == 0 {
		// Default to GATEWAY-HTTP for Calico's Envoy-Gateway-based impl.
		profileNames.Insert(suite.GatewayHTTPConformanceProfileName)
	}

	t.Logf("running gateway-api conformance: gatewayClass=%s mode=%s version=%q curated=%q profiles=%v allFeatures=%t",
		*flags.GatewayClassName, *flags.Mode, *flags.ImplementationVersion, *curatedFlag, profileNames.UnsortedList(), enableAll)

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
		EnableAllSupportedFeatures: enableAll,
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

// curatedSet bundles the four conformance suite levers a curated profile
// drives: which features are claimed, which are exempt, which tests are
// skipped, and which profiles are exercised.
type curatedSet struct {
	SupportedFeatures sets.Set[features.FeatureName]
	ExemptFeatures    sets.Set[features.FeatureName]
	SkipTests         []string
	Profiles          sets.Set[suite.ConformanceProfileName]
}

func curatedConfig(name string) (curatedSet, error) {
	switch name {
	case "envoy-gateway":
		return envoyGatewayCuratedSet(), nil
	default:
		return curatedSet{}, fmt.Errorf("unknown curated set %q (supported: envoy-gateway)", name)
	}
}

// envoyGatewayCuratedSet mirrors the curated configuration in
// envoyproxy/gateway v1.7.0's internal/gatewayapi/conformance/suite.go
// for the default (non-gatewayNamespaceMode) operating mode. Calico's
// Gateway API implementation is a Calico-deployed Envoy Gateway, so the
// supported feature surface is, by construction, the same.
//
// Source ref: https://github.com/envoyproxy/gateway/blob/v1.7.0/internal/gatewayapi/conformance/suite.go
func envoyGatewayCuratedSet() curatedSet {
	skipFeatures := sets.New(
		features.GatewayStaticAddressesFeature.Name,
		features.GatewayInfrastructurePropagationFeature.Name,
	)

	supported := sets.New[features.FeatureName]()
	for _, f := range features.AllFeatures.UnsortedList() {
		if !skipFeatures.Has(f.Name) {
			supported.Insert(f.Name)
		}
	}
	for _, f := range features.UDPRouteFeatures {
		supported.Insert(f.Name)
	}

	exempt := sets.New[features.FeatureName]()
	for _, f := range features.MeshCoreFeatures.UnsortedList() {
		exempt.Insert(f.Name)
	}
	for _, f := range features.MeshExtendedFeatures.UnsortedList() {
		exempt.Insert(f.Name)
	}

	return curatedSet{
		SupportedFeatures: supported,
		ExemptFeatures:    exempt,
		SkipTests: []string{
			tests.GatewayStaticAddresses.ShortName,
			tests.GatewayInfrastructure.ShortName,
		},
		Profiles: sets.New(
			suite.GatewayHTTPConformanceProfileName,
			suite.GatewayTLSConformanceProfileName,
			suite.GatewayGRPCConformanceProfileName,
		),
	}
}
