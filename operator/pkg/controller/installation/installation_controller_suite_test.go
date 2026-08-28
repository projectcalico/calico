// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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

package installation

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	uzap "go.uber.org/zap"
	clientfeatures "k8s.io/client-go/features"
	clientfeaturestesting "k8s.io/client-go/features/testing"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/enterprise"
	eoptions "github.com/tigera/operator/pkg/enterprise/options"
	"github.com/tigera/operator/pkg/extensions"
)

// testExtensions is the enterprise extension Set the installation controller
// tests reconcile with, mirroring how main wires it in production. Reconcilers
// built in these tests put it on their options so the node image overrides and
// modifiers apply.
var testExtensions extensions.Extensions

// The installation extension owns background goroutines keyed to a spec's context, so
// each spec gets its own Set.
var _ = ginkgo.BeforeEach(func() {
	testExtensions = enterprise.New(operatorv1.CalicoEnterprise, eoptions.Options{})
})

func TestInstallation(t *testing.T) {
	// Disable WatchListClient for tests. In client-go v0.35+, this feature defaults to true and
	// causes informers to wait for bookmark events that fake clients never send, leading to timeouts.
	clientfeaturestesting.SetFeatureDuringTest(t, clientfeatures.WatchListClient, false)
	logf.SetLogger(zap.New(zap.WriteTo(ginkgo.GinkgoWriter), zap.UseDevMode(true), zap.Level(uzap.NewAtomicLevelAt(uzap.DebugLevel))))
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../report/ut/installation_controller_suite.xml"
	ginkgo.RunSpecs(t, "pkg/controller/installation Suite", suiteConfig, reporterConfig)
}
