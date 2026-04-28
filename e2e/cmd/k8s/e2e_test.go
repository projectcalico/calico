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
	"fmt"
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/sirupsen/logrus"
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
	_ "github.com/projectcalico/calico/e2e/pkg/tests/kubevirt"
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
		if err := applyTestConfig(path); err != nil {
			t.Fatalf("Failed to apply test config %q: %v", path, err)
		}
	}
	e2e.RunE2ETests(t)
}

// applyTestConfig loads a YAML test selection config and injects its label
// filter and skip patterns into Ginkgo's suite config via the standard flag
// interface. Ginkgo binds --ginkgo.label-filter and --ginkgo.skip against its
// package-level suite config at init time, so setting them here before
// e2e.RunE2ETests reads the config is equivalent to passing them on the
// command line. This lets us reuse the upstream RunE2ETests unchanged rather
// than forking it.
func applyTestConfig(path string) error {
	cfg, err := testconfig.Load(path)
	if err != nil {
		return fmt.Errorf("load: %w", err)
	}

	flags, err := testconfig.ToFlags(cfg)
	if err != nil {
		return fmt.Errorf("convert to flags: %w", err)
	}

	if flags.LabelFilter != "" {
		logrus.Infof("Test config: ginkgo.label-filter = %s", flags.LabelFilter)
		if err := flag.Set("ginkgo.label-filter", flags.LabelFilter); err != nil {
			return fmt.Errorf("set ginkgo.label-filter: %w", err)
		}
	}
	if skip := flags.SkipString(); skip != "" {
		logrus.Infof("Test config: ginkgo.skip = %s", skip)
		if err := flag.Set("ginkgo.skip", skip); err != nil {
			return fmt.Errorf("set ginkgo.skip: %w", err)
		}
	}
	return nil
}
