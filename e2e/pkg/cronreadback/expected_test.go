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

package cronreadback

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"
)

const cronFixture = `
generateName: e2e-demo-
globalPrologue: |
  export E2E_TEST_CONFIG="${E2E_TEST_CONFIG:-e2e/config/default.yaml}"
steps:
  - name: inherits
    commands: |
      .argoci/scripts/body_standard.sh
  - name: matrix-step
    matrix:
      - name: encap
        env:
          - name: E2E_TEST_CONFIG
            value: e2e/config/encap.yaml
      - name: plain
        env:
          - name: CNI
            value: calico
    commands: |
      .argoci/scripts/body_standard.sh
  - name: migration
    commands: |
      .argoci/scripts/body_flannel-migration.sh
  - name: no-suite
    commands: |
      echo hello
`

const noConfigCronFixture = `
generateName: renovate-
steps:
  - name: run
    commands: |
      echo hello
`

// writeRepo lays out a repo root with the directories cilanes.Load reads.
func writeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{".argoci/cron", ".argoci/modules", ".semaphore/semaphore.yml.d/blocks"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for rel, content := range files {
		if err := os.WriteFile(filepath.Join(root, rel), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestLoadExpected(t *testing.T) {
	RegisterTestingT(t)

	root := writeRepo(t, map[string]string{
		".argoci/cron/e2e-demo.yaml": cronFixture,
		".argoci/cron/renovate.yaml": noConfigCronFixture,
	})

	crons, err := LoadExpected(root, "release-v3.33")
	Expect(err).NotTo(HaveOccurred())
	Expect(crons).To(HaveLen(2))

	demo := crons[0]
	Expect(demo.Name).To(Equal("e2e-demo-release-v3-33"))
	Expect(demo.File).To(Equal(".argoci/cron/e2e-demo.yaml"))

	// Every step inherits the prologue default, as it does in the live object.
	Expect(demo.Cells).To(Equal(map[string]string{
		"inherits":          "e2e/config/default.yaml",
		"matrix-step-encap": "e2e/config/encap.yaml",
		"matrix-step-plain": "e2e/config/default.yaml",
		"migration":         "e2e/config/default.yaml",
		"no-suite":          "e2e/config/default.yaml",
	}))

	// A cron with no config cell still has to exist live.
	Expect(crons[1].Name).To(Equal("renovate-release-v3-33"))
	Expect(crons[1].Cells).To(BeEmpty())
}

func TestLoadExpectedExcludesPreMigrationRun(t *testing.T) {
	RegisterTestingT(t)

	root := writeRepo(t, map[string]string{".argoci/cron/e2e-demo.yaml": cronFixture})

	crons, err := LoadExpected(root, "master")
	Expect(err).NotTo(HaveOccurred())

	Expect(crons[0].Cells).NotTo(HaveKey("migration-pre-migration"))
}

const includingCronFixture = `
generateName: nightly-
includes:
  - path: .argoci/modules/20-kind.yaml
steps:
  - name: own
    env:
      - name: E2E_TEST_CONFIG
        value: e2e/config/own.yaml
    commands: |
      .argoci/scripts/body_standard.sh
`

const kindModuleFixture = `
steps:
  - name: e2e-kind
    matrix:
      - name: from-target
        env:
          - name: MAKE_TARGET
            value: e2e-test
      - name: explicit
        env:
          - name: E2E_TEST_CONFIG
            value: e2e/config/kind/explicit.yaml
    commands: |
      make -C e2e ${MAKE_TARGET:-e2e-test}
  - name: kubevirt
    env:
      - name: E2E_TEST_CONFIG
        value: e2e/config/kind/kubevirt.yaml
    commands: |
      make -C e2e e2e-test
  - name: build
    commands: |
      make build
`

const notIncludedModuleFixture = `
steps:
  - name: elsewhere
    env:
      - name: E2E_TEST_CONFIG
        value: e2e/config/kind/elsewhere.yaml
    commands: |
      make -C e2e e2e-test
`

// A cron expects the cells an included module sets E2E_TEST_CONFIG on, and
// nothing from a module it does not include.
func TestLoadExpectedAddsIncludedModuleCells(t *testing.T) {
	RegisterTestingT(t)

	root := writeRepo(t, map[string]string{
		".argoci/cron/nightly.yaml":         includingCronFixture,
		".argoci/modules/20-kind.yaml":      kindModuleFixture,
		".argoci/modules/20-elsewhere.yaml": notIncludedModuleFixture,
	})

	crons, err := LoadExpected(root, "master")
	Expect(err).NotTo(HaveOccurred())
	Expect(crons[0].Cells).To(Equal(map[string]string{
		"own":               "e2e/config/own.yaml",
		"e2e-kind-explicit": "e2e/config/kind/explicit.yaml",
		"kubevirt":          "e2e/config/kind/kubevirt.yaml",
	}))
}

func TestLoadExpectedFailsOnAMissingInclude(t *testing.T) {
	RegisterTestingT(t)

	root := writeRepo(t, map[string]string{".argoci/cron/nightly.yaml": includingCronFixture})

	_, err := LoadExpected(root, "master")
	Expect(err).To(MatchError(ContainSubstring("include .argoci/modules/20-kind.yaml")))
}

func TestLoadExpectedRequiresGenerateName(t *testing.T) {
	RegisterTestingT(t)

	root := writeRepo(t, map[string]string{".argoci/cron/anon.yaml": "steps:\n  - name: x\n    commands: echo\n"})

	_, err := LoadExpected(root, "master")
	Expect(err).To(MatchError(ContainSubstring("generateName")))
}

func TestLiveName(t *testing.T) {
	RegisterTestingT(t)

	Expect(liveName("e2e-bpf-", "master")).To(Equal("e2e-bpf-master"))
	Expect(liveName("e2e-bpf-", "release-v3.33")).To(Equal("e2e-bpf-release-v3-33"))
	Expect(liveName("e2e-bpf-", "Feature/Foo_bar")).To(Equal("e2e-bpf-feature-foo-bar"))
	Expect(liveName("e2e-bpf-", "-odd-")).To(Equal("e2e-bpf-odd"))
}

func TestLiveNameKeepsABaseThatEndsWithTheBranch(t *testing.T) {
	RegisterTestingT(t)

	Expect(liveName("e2e-bpf-master-", "master")).To(Equal("e2e-bpf-master"))

	// Only a whole trailing branch token counts.
	Expect(liveName("e2e-bpf-foo-master-", "release-v3.33")).To(Equal("e2e-bpf-foo-master-release-v3-33"))
	Expect(liveName("e2e-bpfmaster-", "master")).To(Equal("e2e-bpfmaster-master"))
}

func TestCellKey(t *testing.T) {
	RegisterTestingT(t)

	Expect(cellKey("bpf-run-matrix-aws-encap [true]")).To(Equal("bpf-run-matrix-aws-encap-true"))
	Expect(cellKey("arm64 [stable-1-azure-]")).To(Equal("arm64-stable-1-azure-"))
	Expect(cellKey("wireguard")).To(Equal("wireguard"))
	Expect(cellKey("Step [Rhel8.2]")).To(Equal("step-rhel8-2"))
}
