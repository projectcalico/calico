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
	"github.com/sirupsen/logrus"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/test/e2e"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/framework/config"

	caliconfig "github.com/projectcalico/calico/e2e/pkg/config"

	// Import tests.
	_ "k8s.io/kubernetes/test/e2e/network"

	_ "github.com/projectcalico/calico/e2e/pkg/tests/apis"
	_ "github.com/projectcalico/calico/e2e/pkg/tests/bgp"
	_ "github.com/projectcalico/calico/e2e/pkg/tests/hostendpoints"
	_ "github.com/projectcalico/calico/e2e/pkg/tests/ipam"
	_ "github.com/projectcalico/calico/e2e/pkg/tests/networking"
	_ "github.com/projectcalico/calico/e2e/pkg/tests/operator"
	_ "github.com/projectcalico/calico/e2e/pkg/tests/policy"
)

func init() {
	// Set up logging. We need to set the output for various logging systems used by the tests
	// and libraries imported by the tests.
	klog.SetOutput(ginkgo.GinkgoWriter)
	logrus.SetOutput(ginkgo.GinkgoWriter)

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
	e2e.RunE2ETests(t)
}
