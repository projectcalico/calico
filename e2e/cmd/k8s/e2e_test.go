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
	"context"
	"flag"
	"fmt"
	"testing"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/test/e2e"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/framework/config"

	"github.com/projectcalico/calico/e2e/pkg/capability"
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

// capabilityReport, when set, makes this run the capability check and write its
// JUnit report there instead of running specs.
var capabilityReport = flag.String(
	"calico.capability-check",
	"",
	"Check the cluster has every capability the test configs provide, write a JUnit report to this path, and run no specs.",
)

func TestE2E(t *testing.T) {
	if *capabilityReport != "" {
		if err := runCapabilityCheck(*capabilityReport, caliconfig.TestConfigPaths()); err != nil {
			t.Fatal(err)
		}
		return
	}

	if paths := caliconfig.TestConfigPaths(); len(paths) > 0 {
		if err := applyTestConfig(paths); err != nil {
			t.Fatalf("Failed to apply test config %q: %v", paths, err)
		}
	}
	e2e.RunE2ETests(t)
}

// runCapabilityCheck probes the cluster against what the configs declare and
// writes the report even when the check can't start, so the lane always
// uploads one visible result. It returns an error when the lane must stop.
func runCapabilityCheck(reportPath string, configPaths []string) error {
	start := time.Now()
	result := checkCapabilities(configPaths)
	fmt.Print(result.Summary())

	if err := capability.WriteJUnit(reportPath, result, time.Since(start)); err != nil {
		return err
	}
	if result.Failed() {
		return fmt.Errorf("capability check failed, so no specs ran:\n%s", result.Summary())
	}
	return nil
}

// checkCapabilities runs the check, folding a setup error into the result.
func checkCapabilities(configPaths []string) *capability.Result {
	decls, err := capability.DeclarationsFrom(configPaths)
	if err != nil {
		return capability.CouldNotRun(fmt.Errorf("load test configs: %w", err))
	}
	restConfig, err := clientcmd.BuildConfigFromFlags("", framework.TestContext.KubeConfig)
	if err != nil {
		return capability.CouldNotRun(fmt.Errorf("load kubeconfig: %w", err))
	}
	cluster, err := capability.NewCluster(restConfig, caliconfig.ExtNodeIP())
	if err != nil {
		return capability.CouldNotRun(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), capabilityCheckTimeout)
	defer cancel()
	return capability.Check(ctx, cluster, decls)
}

// capabilityCheckTimeout bounds every probe together. They only read API state,
// so a slower check means an unreachable API server.
const capabilityCheckTimeout = 2 * time.Minute

// applyTestConfig loads the YAML test selection configs, merged into one, and
// injects the label filter and skip patterns into Ginkgo's suite config via the
// standard flag interface. Ginkgo binds --ginkgo.label-filter and --ginkgo.skip
// against its package-level suite config at init time, so setting them here
// before e2e.RunE2ETests reads the config is equivalent to passing them on the
// command line, and the upstream RunE2ETests stays unforked.
func applyTestConfig(paths []string) error {
	cfg, err := testconfig.LoadAll(paths)
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
	if focus := flags.FocusString(); focus != "" {
		logrus.Infof("Test config: ginkgo.focus = %s", focus)
		if err := flag.Set("ginkgo.focus", focus); err != nil {
			return fmt.Errorf("set ginkgo.focus: %w", err)
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
