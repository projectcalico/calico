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
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"
)

const repoRoot = "../../.."

func TestSetName(t *testing.T) {
	RegisterTestingT(t)

	// The set is named after the lane, not the config it selects with.
	name, err := SetName(Lane{
		Source: ".argoci/cron/e2e-iptables.yaml",
		Name:   "datastore-k8s-e2e-kdd-old [stable-1-canal-yaml]",
		Config: "e2e/config/iptables/xtables-manifest-canal.yaml",
	})
	Expect(err).NotTo(HaveOccurred())
	Expect(name).To(Equal("cron/e2e-iptables/datastore-k8s-e2e-kdd-old-stable-1-canal-yaml"))

	name, err = SetName(Lane{Source: ".semaphore/semaphore.yml.d/blocks/20-e2e.yml", Name: "E2E tests (KinD) / Conformance"})
	Expect(err).NotTo(HaveOccurred())
	Expect(name).To(Equal("semaphore/20-e2e/e2e-tests-kind-conformance"))

	name, err = SetName(Lane{Source: ".argoci/modules/20-e2e.yaml", Name: "e2e-kind [defaulted]"})
	Expect(err).NotTo(HaveOccurred())
	Expect(name).To(Equal("modules/20-e2e/e2e-kind-defaulted"))

	// A set file must not land outside sets/.
	_, err = SetName(Lane{Source: "../shared/foo.yaml", Name: "one"})
	Expect(err).To(MatchError(ContainSubstring("not a known lane directory")))

	_, err = SetName(Lane{Source: ".argoci/cron/e2e-iptables.yaml", Name: "[]"})
	Expect(err).To(MatchError(ContainSubstring("leaves nothing")))
}

func TestResolveSets(t *testing.T) {
	RegisterTestingT(t)

	// Counterpart lanes in the two CI systems each get their own set, even when
	// they select with the same config.
	argo := Lane{Source: ".argoci/cron/a.yaml", Name: "one", Area: "bpf.yml", Config: "e2e/config/bpf/bpf.yaml", TestType: "k8s-e2e"}
	sem := argo
	sem.Source, sem.Name = ".semaphore/semaphore.yml.d/blocks/b.yml", "Block / job"
	sets, err := ResolveSets([]Lane{argo, sem})
	Expect(err).NotTo(HaveOccurred())
	Expect(sets).To(HaveLen(2))
	Expect(sets).To(HaveKeyWithValue("cron/a/one", argo))
	Expect(sets).To(HaveKeyWithValue("semaphore/b/block-job", sem))

	// Two lanes in one file whose names reduce to the same set would overwrite
	// each other's specs.
	clash := argo
	clash.Name = "ONE"
	_, err = ResolveSets([]Lane{argo, clash})
	Expect(err).To(MatchError(ContainSubstring("both resolve to set cron/a/one")))

	// Lanes that never run the binary have no set.
	sets, err = ResolveSets([]Lane{{Source: ".argoci/cron/a.yaml", Name: "os", Area: "openstack", TestType: "openstack-e2e", Config: "e2e/config/vpp/eks.yaml"}})
	Expect(err).NotTo(HaveOccurred())
	Expect(sets).To(BeEmpty())

	// A pipeline with no FUNCTIONAL_AREA runs no tests at all.
	_, err = ResolveSets([]Lane{{Source: ".argoci/cron/cleanup.yaml", Name: "gc", TestType: "k8s-e2e"}})
	Expect(err).NotTo(HaveOccurred())

	// An e2e lane that lost its selection is a lane that would exit 1.
	_, err = ResolveSets([]Lane{{Source: ".argoci/cron/a.yaml", Name: "broken", Area: "bpf.yml", TestType: "k8s-e2e"}})
	Expect(err).To(MatchError(ContainSubstring("selects nothing")))
}

// The pre-migration config is a copy of a literal in the script, so a change
// there has to fail here rather than silently freeze the recorded specs.
func TestFlannelMigrationPreConfig(t *testing.T) {
	RegisterTestingT(t)

	path := filepath.Join(repoRoot, ".argoci/scripts", flannelMigrationScript)
	script, err := os.ReadFile(path)
	Expect(err).NotTo(HaveOccurred())

	Expect(string(script)).To(ContainSubstring(flannelMigrationPreConfig))
}
