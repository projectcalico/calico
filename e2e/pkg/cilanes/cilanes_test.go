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
	"os"
	"testing"

	. "github.com/onsi/gomega"
)

const argoFixture = `
globalPrologue: |
  export E2E_TEST_CONFIG="${E2E_TEST_CONFIG:-e2e/config/iptables/xtables.yaml}"
  export INSTALLER="${INSTALLER:-operator}"
  export FUNCTIONAL_AREA="${FUNCTIONAL_AREA:-iptables.yml}"
  export TEST_TYPE="${OTHER_TYPE:-nonsense}"
steps:
  - name: inherits-default
    commands: |
      .argoci/scripts/body_standard.sh
  - name: overrides-config
    env:
      - name: E2E_TEST_CONFIG
        value: e2e/config/vpp/eks.yaml
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
      - name: encap
        env:
          - name: E2E_TEST_CONFIG
            value: e2e/config/iptables/xtables-encap-nobgp.yaml
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
	Expect(inherited.Config).To(Equal("e2e/config/iptables/xtables.yaml"))
	Expect(inherited.TestType).To(Equal("k8s-e2e"))
	Expect(inherited.Area).To(Equal("iptables.yml"))
	Expect(inherited.RunsE2EBinary()).To(BeTrue())

	// The prologue's TEST_TYPE defaults off a different variable, so it does not
	// resolve to a value the parser can use.
	Expect(byName["overrides-config"].Config).To(Equal("e2e/config/vpp/eks.yaml"))

	openstack := byName["openstack"]
	Expect(openstack.TestType).To(Equal("openstack-e2e"))
	Expect(openstack.RunsE2EBinary()).To(BeFalse())

	// The migration job runs the suite twice, so it resolves to two lanes.
	Expect(byName["migration"].Config).To(Equal("e2e/config/iptables/xtables.yaml"))
	Expect(byName["migration [pre-migration]"].Config).To(Equal(flannelMigrationPreConfig))

	// The CNI axis leaves the selection alone, so its entries collapse into the
	// unsuffixed step.
	Expect(byName).To(HaveKey("matrix-step"))
	Expect(byName["matrix-step"].Config).To(Equal("e2e/config/iptables/xtables.yaml"))
	Expect(byName["matrix-step [encap]"].Config).To(Equal("e2e/config/iptables/xtables-encap-nobgp.yaml"))
}

const semaphoreFixture = `
global_job_config:
  env_vars:
    - name: E2E_TEST_CONFIG
      value: e2e/config/nftables/xtables.yaml
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
            - env_var: E2E_TEST_CONFIG
              values: ["e2e/config/nftables/xtables.yaml"]
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

	Expect(byName["Block one / inherits"].Config).To(Equal("e2e/config/nftables/xtables.yaml"))
	Expect(byName["Block one / configured"].Config).To(Equal("e2e/config/nftables/eks.yaml"))
	Expect(byName["Block one / inherits"].Area).To(Equal("nftables.yml"))

	// A non-selection axis leaves the job as one lane.
	Expect(byName["Block one / matrixed"].Config).To(Equal("e2e/config/nftables/xtables.yaml"))

	// No pipeline varies the selection by matrix, so the parser refuses to guess.
	_, err = parseSemaphore("pipeline.yml", []byte(semaphoreSelectionMatrix))
	Expect(err).To(MatchError(ContainSubstring("matrix on E2E_TEST_CONFIG")))
}

func TestSelectionArgs(t *testing.T) {
	RegisterTestingT(t)

	args, err := Lane{Config: "e2e/config/vpp/eks.yaml"}.SelectionArgs("/repo")
	Expect(err).NotTo(HaveOccurred())
	Expect(args).To(Equal([]string{"--calico.test-config=/repo/e2e/config/vpp/eks.yaml"}))

	_, err = Lane{Name: "empty"}.SelectionArgs("/repo")
	Expect(err).To(HaveOccurred())
}

const blocksFixture = `
- name: E2E tests (KinD)
  task:
    jobs:
      - name: Conformance
        commands:
          - .semaphore/run-and-monitor e2e-test.log make e2e-test
      - name: Felix routing
        env_vars:
          - name: E2E_TEST_CONFIG
            value: e2e/config/kind/felix-routing.yaml
        commands:
          - .semaphore/run-and-monitor e2e-test-felix.log make e2e-test
      - name: ClusterNetworkPolicy
        env_vars:
          - name: E2E_TEST_CONFIG
            value: e2e/config/kind/felix-routing.yaml
        commands:
          - make e2e-test-clusternetworkpolicy
      - name: BPF
        env_vars:
          - name: E2E_TEST_CONFIG
            value: e2e/config/kind/felix-routing.yaml
        commands:
          - make e2e-test-bpf
- name: KubeVirt live migration (KIND)
  task:
    env_vars:
      - name: E2E_TEST_CONFIG
        value: e2e/config/kind/kubevirt.yaml
    jobs:
      - name: KubeVirt live migration (KIND)
        commands:
          - make kind-up
          - make e2e-run KUBECONFIG=kubeconfig
- name: Felix
  task:
    jobs:
      - name: Felix UT
        commands:
          - make -C felix ut
- name: E2E tests on GCP kubeadm
  task:
    env_vars:
      - name: E2E_TEST_CONFIG
        value: e2e/config/iptables/xtables.yaml
    jobs:
      - name: gcp-kubeadm
        commands:
          - ~/calico/.semaphore/end-to-end/scripts/body_standard.sh
`

func TestParseSemaphoreBlocks(t *testing.T) {
	RegisterTestingT(t)

	lanes, err := parseSemaphoreBlocks("blocks/20-e2e.yml", []byte(blocksFixture))
	Expect(err).NotTo(HaveOccurred())

	byName := map[string]Lane{}
	for _, l := range lanes {
		byName[l.Name] = l
	}

	// No config in the environment, so the target's Makefile default applies.
	Expect(byName["E2E tests (KinD) / Conformance"].Config).To(Equal("e2e/config/kind/conformance.yaml"))
	Expect(byName["E2E tests (KinD) / Conformance"].RunsE2EBinary()).To(BeTrue())

	// A config in the environment beats that default.
	Expect(byName["E2E tests (KinD) / Felix routing"].Config).To(Equal("e2e/config/kind/felix-routing.yaml"))

	// e2e-test-bpf hardcodes its config, so the environment's is ignored.
	Expect(byName["E2E tests (KinD) / BPF"].Config).To(Equal("e2e/config/kind/bpf.yaml"))

	// The ClusterNetworkPolicy job runs a different binary that takes no config,
	// so it is not a lane even though it sets one.
	Expect(byName).NotTo(HaveKey("E2E tests (KinD) / ClusterNetworkPolicy"))

	// A block whose job runs the suite through e2e-run keeps the environment's.
	kubevirt := byName["KubeVirt live migration (KIND) / KubeVirt live migration (KIND)"]
	Expect(kubevirt.Config).To(Equal("e2e/config/kind/kubevirt.yaml"))

	// Component blocks declare no e2e lane.
	Expect(byName).NotTo(HaveKey("Felix / Felix UT"))

	// A provisioned lane in the same directory still reads its config from the
	// environment.
	Expect(byName["E2E tests on GCP kubeadm / gcp-kubeadm"].Config).To(Equal("e2e/config/iptables/xtables.yaml"))
}

// kindTargets duplicates what the Makefile does with E2E_TEST_CONFIG, so a
// change to either has to be a change to both.
func TestKindTargetsMatchTheMakefile(t *testing.T) {
	RegisterTestingT(t)

	makefile, err := os.ReadFile("../../../Makefile")
	Expect(err).NotTo(HaveOccurred())
	text := string(makefile)

	for target, want := range kindTargets {
		Expect(text).To(ContainSubstring("\n"+target+":"), "target %s is gone from the Makefile", target)
		if want.fixed != "" {
			Expect(text).To(ContainSubstring("E2E_TEST_CONFIG=$(REPO_ROOT)/"+want.fixed),
				"target %s no longer hardcodes %s", target, want.fixed)
		}
		if want.fallback != "" {
			Expect(text).To(ContainSubstring("E2E_TEST_CONFIG ?= "+want.fallback),
				"the Makefile default is no longer %s", want.fallback)
		}
	}
}
