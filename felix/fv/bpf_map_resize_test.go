// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/ipsets"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/felix/timeshim"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ Felix bpf test configurable map size", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {

	if !BPFMode() {
		// Non-BPF run.
		return
	}

	var (
		infra  infrastructure.DatastoreInfra
		tc     infrastructure.TopologyContainers
		client client.Interface

		w  [2]*workload.Workload
		cc *connectivity.Checker
	)

	BeforeEach(func() {
		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()
		tc, client = infrastructure.StartNNodeTopology(1, opts, infra)

		infra.AddDefaultAllow()
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}
		for _, wl := range w {
			wl.Stop()
		}
		tc.Stop()
		infra.Stop()
	})

	It("should copy data from old map to new map", func() {
		srcIP := net.IPv4(123, 123, 123, 123)
		dstIP := net.IPv4(121, 121, 121, 121)

		now := time.Duration(timeshim.RealTime().KTimeNanos())
		leg := conntrack.Leg{SynSeen: true, AckSeen: true, Opener: true}
		val := conntrack.NewValueNormal(now, now, 0, leg, leg)
		val64 := base64.StdEncoding.EncodeToString(val[:])

		key := conntrack.NewKey(6 /* TCP */, srcIP, 0, dstIP, 0)
		key64 := base64.StdEncoding.EncodeToString(key[:])

		tc.Felixes[0].Exec("calico-bpf", "conntrack", "write", key64, val64)
		out, err := tc.Felixes[0].ExecOutput("calico-bpf", "conntrack", "dump")
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.Count(out, srcIP.String())).To(Equal(1), "entry not found in conntrack map")
		newCtMapSize := 6000
		infrastructure.UpdateFelixConfiguration(client, func(cfg *api.FelixConfiguration) {
			cfg.Spec.BPFMapSizeConntrack = &newCtMapSize
		})

		ctMap := conntrack.Map()
		Eventually(getMapSizeFn(tc.Felixes[0], ctMap), "10s", "200ms").Should(Equal(newCtMapSize))
		out, err = tc.Felixes[0].ExecOutput("calico-bpf", "conntrack", "dump")
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.Count(out, srcIP.String())).To(Equal(1), "entry not found in conntrack map")
	})

	It("should program new map sizes", func() {
		affMap := nat.AffinityMap()
		feMap := nat.FrontendMap()
		beMap := nat.BackendMap()
		rtMap := routes.Map()
		ipsMap := ipsets.Map()
		ctMap := conntrack.Map()

		felix := tc.Felixes[0]
		Eventually(getMapSizeFn(felix, rtMap), "10s", "200ms").Should(Equal((rtMap.(*maps.PinnedMap)).MaxEntries))
		Eventually(getMapSizeFn(felix, feMap), "10s", "200ms").Should(Equal((feMap.(*maps.PinnedMap)).MaxEntries))
		Eventually(getMapSizeFn(felix, beMap), "10s", "200ms").Should(Equal((beMap.(*maps.PinnedMap)).MaxEntries))
		Eventually(getMapSizeFn(felix, affMap), "10s", "200ms").Should(Equal((affMap.(*maps.PinnedMap)).MaxEntries))
		Eventually(getMapSizeFn(felix, ipsMap), "10s", "200ms").Should(Equal((ipsMap.(*maps.PinnedMap)).MaxEntries))
		Eventually(getMapSizeFn(felix, ctMap), "10s", "200ms").Should(Equal((ctMap.(*maps.PinnedMap)).MaxEntries))

		By("configuring route map size = 1000, nat fe size = 2000, nat be size = 3000, nat affinity size = 4000")
		newRtSize := 1000
		newNATFeSize := 2000
		newNATBeSize := 3000
		newNATAffSize := 4000
		newIpSetMapSize := 5000
		newCtMapSize := 6000
		infrastructure.UpdateFelixConfiguration(client, func(cfg *api.FelixConfiguration) {
			cfg.Spec.BPFMapSizeRoute = &newRtSize
			cfg.Spec.BPFMapSizeNATFrontend = &newNATFeSize
			cfg.Spec.BPFMapSizeNATBackend = &newNATBeSize
			cfg.Spec.BPFMapSizeNATAffinity = &newNATAffSize
			cfg.Spec.BPFMapSizeIPSets = &newIpSetMapSize
			cfg.Spec.BPFMapSizeConntrack = &newCtMapSize
		})
		Eventually(getMapSizeFn(felix, rtMap), "10s", "200ms").Should(Equal(newRtSize))
		Eventually(getMapSizeFn(felix, feMap), "10s", "200ms").Should(Equal(newNATFeSize))
		Eventually(getMapSizeFn(felix, beMap), "10s", "200ms").Should(Equal(newNATBeSize))
		Eventually(getMapSizeFn(felix, affMap), "10s", "200ms").Should(Equal(newNATAffSize))
		Eventually(getMapSizeFn(felix, ipsMap), "10s", "200ms").Should(Equal(newIpSetMapSize))
		Eventually(getMapSizeFn(felix, ctMap), "10s", "200ms").Should(Equal(newCtMapSize))

		// Add some workloads after resize to verify that provisioning is working with the new map sizes.
		for i := range w {
			w[i] = workload.Run(
				tc.Felixes[0],
				fmt.Sprintf("w%d", i),
				"default",
				fmt.Sprintf("10.65.0.%d", i+2),
				"8080",
				"tcp",
			)
			w[i].ConfigureInInfra(infra)
		}
		cc = &connectivity.Checker{}

		cc.Expect(connectivity.Some, w[0], w[1])
		cc.Expect(connectivity.Some, w[1], w[0])
		cc.CheckConnectivity()
	})
})

func getMapSizeFn(felix *infrastructure.Felix, m maps.Map) func() (int, error) {
	return func() (int, error) {
		return getMapSize(felix, m)
	}
}

func getMapSize(felix *infrastructure.Felix, m maps.Map) (int, error) {
	output, err := showBpfMap(felix, m)
	if err != nil {
		return 0, err
	}
	return int(output["max_entries"].(float64)), nil
}

func showBpfMap(felix *infrastructure.Felix, m maps.Map) (map[string]interface{}, error) {
	var data map[string]interface{}
	cmd, err := maps.ShowMapCmd(m)
	if err != nil {
		return nil, err
	}
	out, err := felix.ExecOutput(cmd...)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal([]byte(out), &data)
	if err != nil {
		return nil, err
	}
	return data, nil
}
