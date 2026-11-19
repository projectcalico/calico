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

package config

import (
	"flag"
	"testing"

	. "github.com/onsi/gomega"
)

func TestRepeatedTestConfigFlagKeepsEveryPath(t *testing.T) {
	RegisterTestingT(t)
	resetTestConfig(t, "env.yaml")

	flags := flag.NewFlagSet("e2e", flag.ContinueOnError)
	RegisterFlags(flags)
	Expect(flags.Parse([]string{
		"--calico.test-config=suite/policy.yaml",
		"--calico.test-config=cluster/cni/calico.yaml",
	})).To(Succeed())
	AfterReadingAllFlags()

	// The flags replace TEST_CONFIG rather than adding to it.
	Expect(TestConfigPaths()).To(Equal([]string{"suite/policy.yaml", "cluster/cni/calico.yaml"}))
}

func TestTestConfigEnvironmentTakesAList(t *testing.T) {
	RegisterTestingT(t)
	resetTestConfig(t, "suite/policy.yaml  cluster/cni/calico.yaml")

	flags := flag.NewFlagSet("e2e", flag.ContinueOnError)
	RegisterFlags(flags)
	Expect(flags.Parse(nil)).To(Succeed())
	AfterReadingAllFlags()

	Expect(TestConfigPaths()).To(Equal([]string{"suite/policy.yaml", "cluster/cni/calico.yaml"}))
}

// resetTestConfig sets the test config as if TEST_CONFIG held env, and puts the
// package state back afterward, since the options live in package variables.
func resetTestConfig(t *testing.T, env string) {
	t.Helper()
	opt := allConfigOptions[testConfig]
	saved := *opt
	savedFlags := testConfigFlags
	t.Cleanup(func() {
		*opt = saved
		testConfigFlags = savedFlags
	})

	opt.actualValue = env
	opt.cmdLineValue = ""
	testConfigFlags = nil
}
