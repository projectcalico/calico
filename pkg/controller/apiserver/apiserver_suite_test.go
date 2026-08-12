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

package apiserver

import (
	"testing"

	uzap "go.uber.org/zap"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/enterprise"
	eoptions "github.com/tigera/operator/pkg/enterprise/options"
)

// testExtensions is the registry the API server controller tests reconcile with, so
// the componentHandler applies the API server modifier.
var testExtensions = enterprise.New(operatorv1.CalicoEnterprise, eoptions.Options{})

// multiTenantExtensions is the same registry in multi-tenant mode.
var multiTenantExtensions = enterprise.New(operatorv1.CalicoEnterprise, eoptions.Options{MultiTenant: true})

func TestStatus(t *testing.T) {
	logf.SetLogger(zap.New(zap.WriteTo(ginkgo.GinkgoWriter), zap.UseDevMode(true), zap.Level(uzap.NewAtomicLevelAt(uzap.DebugLevel))))
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../report/ut/apiserver_suite.xml"
	ginkgo.RunSpecs(t, "pkg/controller/apiserver Suite", suiteConfig, reporterConfig)
}
