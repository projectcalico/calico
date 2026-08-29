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

package test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/operator/pkg/components"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	uzap "go.uber.org/zap"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// A spec that builds the Enterprise extensions registers the Enterprise images for the
// whole process, so every spec starts from the images this build ships.
var _ = ginkgo.BeforeEach(func() {
	ginkgo.DeferCleanup(components.UseImages(nil))
})

func TestFeatureVerification(t *testing.T) {
	logf.SetLogger(zap.New(zap.WriteTo(ginkgo.GinkgoWriter), zap.UseDevMode(true), zap.Level(uzap.NewAtomicLevelAt(uzap.DebugLevel))))
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../report/fv/fv_suite.xml"
	ginkgo.RunSpecs(t, "FV test Suite", suiteConfig, reporterConfig)
}
