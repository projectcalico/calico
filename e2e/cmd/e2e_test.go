// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package main

import (
	"flag"
	"testing"

	"github.com/onsi/ginkgo/v2"
	"k8s.io/apimachinery/pkg/util/sets"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/test/e2e"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/framework/config"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/network-policy-api/apis/v1alpha1"
	"sigs.k8s.io/network-policy-api/conformance/tests"
	"sigs.k8s.io/network-policy-api/conformance/utils/suite"

	// Import test packages.
	_ "k8s.io/kubernetes/test/e2e/network"
)

func init() {
	klog.SetOutput(ginkgo.GinkgoWriter)

	// Register flags.
	config.CopyFlags(config.Flags, flag.CommandLine)
	framework.RegisterCommonFlags(flag.CommandLine)
	framework.RegisterClusterFlags(flag.CommandLine)

	// Parse all the flags
	flag.Parse()
	framework.AfterReadingAllFlags(&framework.TestContext)
}

func TestE2E(t *testing.T) {
	registerNetworkPolicyConformance(t)

	e2e.RunE2ETests(t)
}

// The sigs.k8s.io/network-policy-api/conformance/tests package contains the conformance tests for the NetworkPolicy API.
// They are written using testing.T and are not automatically run when imported, so we need this extra hook to register them
// as e2e tests.
func registerNetworkPolicyConformance(t *testing.T) {
	for _, test := range tests.ConformanceTests {
		framework.ConformanceIt(test.ShortName+" "+test.Description, func() {
			cfg, err := framework.LoadConfig()
			if err != nil {
				t.Fatalf("Error loading Kubernetes config: %v", err)
			}

			c, err := client.New(cfg, client.Options{})
			if err != nil {
				t.Fatalf("Error initializing Kubernetes client: %v", err)
			} else {
				v1alpha1.Install(c.Scheme())
			}

			cs, err := framework.LoadClientset()
			if err != nil {
				t.Fatalf("Error loading Kubernetes clientset: %v", err)
			}

			cSuite := suite.New(suite.Options{
				Client:                     c,
				ClientSet:                  cs,
				KubeConfig:                 *cfg,
				Debug:                      true,
				CleanupBaseResources:       true,
				SupportedFeatures:          sets.New(suite.SupportAdminNetworkPolicy, suite.SupportBaselineAdminNetworkPolicy),
				ExemptFeatures:             sets.New[suite.SupportedFeature](),
				EnableAllSupportedFeatures: true,
			})
			cSuite.Setup(t)

			test.Test(t, cSuite)
		})
	}
}
