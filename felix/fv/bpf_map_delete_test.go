// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

//go:build fvtests

package fv_test

import (
	"fmt"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/state"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
)

var (
	tc infrastructure.TopologyContainers
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ Felix bpf test delete previous map", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {

	if os.Getenv("FELIX_FV_ENABLE_BPF") != "true" {
		// Non-BPF run.
		return
	}

	var (
		infra infrastructure.DatastoreInfra
	)

	BeforeEach(func() {
		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()
		tc, _ = infrastructure.StartNNodeTopology(1, opts, infra)
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}

		tc.Stop()
		infra.Stop()
	})

	It("should delete previous maps after Felix restart", func() {

		stateMap := state.Map()
		stateCurrVersionedName := stateMap.(*maps.PinnedMap).VersionedName()
		statePrevVersionedName := fmt.Sprintf("%s%d", stateMap.(*maps.PinnedMap).Name, stateMap.(*maps.PinnedMap).Version-1)
		stateCmd := getMapCmd(statePrevVersionedName, "percpu_array", "4", "464", "2", "0")
		tc.Felixes[0].Exec(stateCmd...)

		// Before Felix restart: both curr and prev maps exists.
		eventuallyMapVersionShouldExist(stateCurrVersionedName)
		eventuallyMapVersionShouldExist(statePrevVersionedName)

		tc.Felixes[0].Restart()

		// After Felix restart: only the curr maps now exists.
		eventuallyMapVersionShouldExist(stateCurrVersionedName)
		eventuallyMapVersionShouldNotExist(statePrevVersionedName)

		//Expect(2).To(Equal(1))
	})

})

func eventuallyMapVersionShouldExist(version string) {
	Eventually(func() string {
		out, err := tc.Felixes[0].ExecOutput("bpftool", "map", "show")
		Expect(err).NotTo(HaveOccurred())
		return out
	}, "5s", "200ms").Should(ContainSubstring(version))
}

func eventuallyMapVersionShouldNotExist(version string) {
	Eventually(func() string {
		out, err := tc.Felixes[0].ExecOutput("bpftool", "map", "show")
		Expect(err).NotTo(HaveOccurred())
		return out
	}, "5s", "200ms").ShouldNot(ContainSubstring(version))
}

func getMapCmd(mapVersionedName, mapType, mapKey, mapValue, mapEntries, mapFlags string) []string {
	return []string{
		"bpftool",
		"map",
		"create",
		bpfdefs.GlobalPinDir + mapVersionedName,
		"type",
		mapType,
		"key",
		mapKey,
		"value",
		mapValue,
		"entries",
		mapEntries,
		"name",
		mapVersionedName,
		"flags",
		mapFlags,
	}
}
