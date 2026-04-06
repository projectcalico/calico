// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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
	"github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/test/e2e"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/framework/config"

	caliconfig "github.com/projectcalico/calico/e2e/pkg/config"
	"github.com/projectcalico/calico/e2e/pkg/testconfig"

	// Import tests.
	_ "k8s.io/kubernetes/test/e2e/network"

	_ "github.com/projectcalico/calico/e2e/pkg/tests/apis"
	_ "github.com/projectcalico/calico/e2e/pkg/tests/bgp"
	_ "github.com/projectcalico/calico/e2e/pkg/tests/hostendpoints"
	_ "github.com/projectcalico/calico/e2e/pkg/tests/ipam"
	_ "github.com/projectcalico/calico/e2e/pkg/tests/istio"
	_ "github.com/projectcalico/calico/e2e/pkg/tests/networking"
	_ "github.com/projectcalico/calico/e2e/pkg/tests/operator"
	_ "github.com/projectcalico/calico/e2e/pkg/tests/policy"
)

func init() {
	// Set up logging. We need to set the output for various logging systems used by the tests
	// and libraries imported by the tests.
	klog.SetOutput(ginkgo.GinkgoWriter)
	logrus.SetOutput(ginkgo.GinkgoWriter)

	// Register the standard -test.* flags so that the ginkgo CLI
	// can pass -test.timeout, -test.count, etc. to this binary.
	testing.Init()

	// Register flags.
	config.CopyFlags(config.Flags, flag.CommandLine)
	framework.RegisterCommonFlags(flag.CommandLine)
	framework.RegisterClusterFlags(flag.CommandLine)
	caliconfig.RegisterFlags(flag.CommandLine)

	// Parse all the flags
	flag.Parse()
	framework.AfterReadingAllFlags(&framework.TestContext)
	caliconfig.AfterReadingAllFlags()
}

func TestE2E(t *testing.T) {
	if path := caliconfig.TestConfigPath(); path != "" {
		runWithTestConfig(t, path)
		return
	}
	e2e.RunE2ETests(t)
}

// runWithTestConfig loads the test selection config file, applies the label
// filter and skip patterns to the ginkgo suite config, then runs the tests.
// This replaces e2e.RunE2ETests when a config file is provided.
func runWithTestConfig(t *testing.T, path string) {
	cfg, err := testconfig.Load(path)
	if err != nil {
		t.Fatalf("Failed to load test config %q: %v", path, err)
	}

	flags, err := testconfig.ToFlags(cfg)
	if err != nil {
		t.Fatalf("Failed to convert test config to flags: %v", err)
	}

	// Match the setup from e2e.RunE2ETests.
	logs.InitLogs()
	defer logs.FlushLogs()
	klog.EnableContextualLogging(true)

	gomega.RegisterFailHandler(framework.Fail)
	suiteConfig, reporterConfig := framework.CreateGinkgoConfig()

	if flags.LabelFilter != "" {
		logrus.Infof("Test config: label-filter = %s", flags.LabelFilter)
		suiteConfig.LabelFilter = flags.LabelFilter
	}
	if skip := flags.SkipString(); skip != "" {
		logrus.Infof("Test config: skip = %s", skip)
		suiteConfig.SkipStrings = append(suiteConfig.SkipStrings, skip)
	}

	klog.Infof("Starting e2e run %q on Ginkgo node %d", framework.RunID, suiteConfig.ParallelProcess)
	ginkgo.RunSpecs(t, "Kubernetes e2e suite", suiteConfig, reporterConfig)
}
