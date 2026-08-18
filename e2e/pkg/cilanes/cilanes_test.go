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

package cilanes

import (
	"testing"

	. "github.com/onsi/gomega"
)

const argoFixture = `
globalPrologue: |
  export K8S_E2E_FLAGS="${K8S_E2E_FLAGS:---ginkgo.focus=default}"
  export INSTALLER="${INSTALLER:-operator}"
  export FUNCTIONAL_AREA="${FUNCTIONAL_AREA:-iptables.yml}"
  export TEST_TYPE="${OTHER_TYPE:-nonsense}"
steps:
  - name: inherits-default
    commands: |
      .argoci/scripts/body_standard.sh
  - name: overrides-flags
    env:
      - name: K8S_E2E_FLAGS
        value: --ginkgo.focus=special
    commands: |
      .argoci/scripts/body_standard.sh
  - name: uses-config
    env:
      - name: E2E_TEST_CONFIG
        value: e2e/config/vpp/eks.yaml
      - name: K8S_E2E_FLAGS
        value: --ginkgo.focus=ignored
    commands: |
      .argoci/scripts/body_standard.sh
  - name: openstack
    env:
      - name: PROVISIONER
        value: gcp-openstack
    commands: |
      .argoci/scripts/body_standard.sh
  - name: migration
    commands: |
      .argoci/scripts/body_flannel-migration.sh
  - name: matrix-step
    matrix:
      - name: calico-cni
        env:
          - name: CNI
            value: calico
      - name: focused
        env:
          - name: K8S_E2E_FLAGS
            value: --ginkgo.focus=matrixed
    commands: |
      .argoci/scripts/body_standard.sh
`

func TestParseArgo(t *testing.T) {
	RegisterTestingT(t)

	lanes, err := parseArgo("cron.yaml", []byte(argoFixture))
	Expect(err).NotTo(HaveOccurred())

	byName := map[string]Lane{}
	for _, l := range lanes {
		byName[l.Name] = l
	}

	inherited := byName["inherits-default"]
	Expect(inherited.Flags).To(Equal("--ginkgo.focus=default"))
	Expect(inherited.PipelineDefault).To(BeTrue())
	Expect(inherited.TestType).To(Equal("k8s-e2e"))
	Expect(inherited.Area).To(Equal("iptables.yml"))
	Expect(inherited.RunsE2EBinary()).To(BeTrue())

	// The prologue's TEST_TYPE defaults off a different variable, so it does not
	// resolve to a value the parser can use.
	Expect(byName["overrides-flags"].PipelineDefault).To(BeFalse())
	Expect(byName["overrides-flags"].Selection()).To(Equal("flags:--ginkgo.focus=special"))

	// A config wins over flags, matching run_tests.sh.
	Expect(byName["uses-config"].Selection()).To(Equal("config:e2e/config/vpp/eks.yaml"))

	openstack := byName["openstack"]
	Expect(openstack.TestType).To(Equal("openstack-e2e"))
	Expect(openstack.RunsE2EBinary()).To(BeFalse())

	// The migration job runs the suite twice, so it resolves to two lanes.
	Expect(byName["migration"].Flags).To(Equal("--ginkgo.focus=default"))
	Expect(byName["migration"].PipelineDefault).To(BeTrue())
	Expect(byName["migration [pre-migration]"].Flags).To(Equal(flannelMigrationPreFlags))
	Expect(byName["migration [pre-migration]"].PipelineDefault).To(BeFalse())

	// The CNI axis leaves the selection alone, so its entries collapse into the
	// unsuffixed step.
	Expect(byName).To(HaveKey("matrix-step"))
	Expect(byName["matrix-step"].Flags).To(Equal("--ginkgo.focus=default"))
	Expect(byName["matrix-step [focused]"].Flags).To(Equal("--ginkgo.focus=matrixed"))
}

const semaphoreFixture = `
global_job_config:
  env_vars:
    - name: K8S_E2E_FLAGS
      value: --ginkgo.focus=default
    - name: FUNCTIONAL_AREA
      value: nftables.yml
blocks:
  - name: Block one
    task:
      env_vars:
        - name: INSTALLER
          value: operator
      jobs:
        - name: inherits
          commands:
            - body_standard.sh
        - name: configured
          env_vars:
            - name: E2E_TEST_CONFIG
              value: e2e/config/nftables/eks.yaml
          commands:
            - body_standard.sh
        - name: matrixed
          matrix:
            - env_var: NETWORK_PLUGIN
              values: ["calico", "aws"]
          commands:
            - body_standard.sh
`

const semaphoreSelectionMatrix = `
blocks:
  - name: Block one
    task:
      jobs:
        - name: matrixed
          matrix:
            - env_var: K8S_E2E_FLAGS
              values: ["--ginkgo.focus=one"]
          commands:
            - body_standard.sh
`

func TestParseSemaphore(t *testing.T) {
	RegisterTestingT(t)

	lanes, err := parseSemaphore("pipeline.yml", []byte(semaphoreFixture))
	Expect(err).NotTo(HaveOccurred())

	byName := map[string]Lane{}
	for _, l := range lanes {
		byName[l.Name] = l
	}

	Expect(byName["Block one / inherits"].PipelineDefault).To(BeTrue())
	Expect(byName["Block one / configured"].Selection()).To(Equal("config:e2e/config/nftables/eks.yaml"))
	Expect(byName["Block one / inherits"].Area).To(Equal("nftables.yml"))

	// A non-selection axis leaves the job as one lane.
	Expect(byName["Block one / matrixed"].Flags).To(Equal("--ginkgo.focus=default"))

	// No pipeline varies the selection by matrix, so the parser refuses to guess.
	_, err = parseSemaphore("pipeline.yml", []byte(semaphoreSelectionMatrix))
	Expect(err).To(MatchError(ContainSubstring("matrix on K8S_E2E_FLAGS")))
}

func TestSelectionArgs(t *testing.T) {
	RegisterTestingT(t)

	args, err := Lane{Config: "e2e/config/vpp/eks.yaml"}.SelectionArgs("/repo")
	Expect(err).NotTo(HaveOccurred())
	Expect(args).To(Equal([]string{"--calico.test-config=/repo/e2e/config/vpp/eks.yaml"}))

	args, err = Lane{Flags: "--ginkgo.focus=a --ginkgo.skip=b"}.SelectionArgs("/repo")
	Expect(err).NotTo(HaveOccurred())
	Expect(args).To(Equal([]string{"--ginkgo.focus=a", "--ginkgo.skip=b"}))

	_, err = Lane{Name: "empty"}.SelectionArgs("/repo")
	Expect(err).To(HaveOccurred())
}
