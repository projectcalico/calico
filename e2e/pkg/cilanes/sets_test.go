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

	name, err := SetName(Lane{Config: "e2e/config/vpp/eks.yaml", Area: "vpp.yml"})
	Expect(err).NotTo(HaveOccurred())
	Expect(name).To(Equal("vpp/eks"))

	// A set file must not land outside sets/.
	_, err = SetName(Lane{Config: "../shared/foo.yaml"})
	Expect(err).To(HaveOccurred())
}

func TestResolveSets(t *testing.T) {
	RegisterTestingT(t)

	// Counterpart lanes in the two CI systems share one set.
	argo := Lane{Source: "a.yaml", Name: "one", Area: "bpf.yml", Config: "e2e/config/bpf/bpf.yaml", TestType: "k8s-e2e"}
	sem := argo
	sem.Source, sem.Name = "b.yml", "Block / job"
	sets, err := ResolveSets([]Lane{argo, sem})
	Expect(err).NotTo(HaveOccurred())
	Expect(sets).To(HaveLen(1))
	Expect(sets).To(HaveKey("bpf/bpf"))

	// Lanes that never run the binary have no set.
	sets, err = ResolveSets([]Lane{{Source: "a.yaml", Name: "os", Area: "openstack", TestType: "openstack-e2e", Config: "e2e/config/vpp/eks.yaml"}})
	Expect(err).NotTo(HaveOccurred())
	Expect(sets).To(BeEmpty())

	// A pipeline with no FUNCTIONAL_AREA runs no tests at all.
	_, err = ResolveSets([]Lane{{Source: "cleanup.yml", Name: "gc", TestType: "k8s-e2e"}})
	Expect(err).NotTo(HaveOccurred())

	// An e2e lane that lost its selection is a lane that would exit 1.
	_, err = ResolveSets([]Lane{{Source: "a.yaml", Name: "broken", Area: "bpf.yml", TestType: "k8s-e2e"}})
	Expect(err).To(MatchError(ContainSubstring("selects nothing")))
}

// The pre-migration config is a copy of a literal in the script, so a change
// there has to fail here rather than silently freeze the recorded specs.
func TestFlannelMigrationPreConfig(t *testing.T) {
	RegisterTestingT(t)

	path := filepath.Join(repoRoot, ".semaphore/end-to-end/scripts", flannelMigrationScript)
	script, err := os.ReadFile(path)
	Expect(err).NotTo(HaveOccurred())

	Expect(string(script)).To(ContainSubstring(flannelMigrationPreConfig))
}
