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
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
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
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/timeshim"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ Felix bpf test configurable map size", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {

	if os.Getenv("FELIX_FV_ENABLE_BPF") != "true" {
		// Non-BPF run.
		return
	}

	var (
		infra  infrastructure.DatastoreInfra
		tc     infrastructure.TopologyContainers
		client client.Interface
	)

	BeforeEach(func() {
		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()
		tc, client = infrastructure.StartNNodeTopology(1, opts, infra)
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}

		tc.Stop()
		infra.Stop()
	})

	updateFelixConfig := func(deltaFn func(*api.FelixConfiguration)) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cfg, err := client.FelixConfigurations().Get(ctx, "default", options.GetOptions{})
		if _, doesNotExist := err.(errors.ErrorResourceDoesNotExist); doesNotExist {
			cfg = api.NewFelixConfiguration()
			cfg.Name = "default"
			deltaFn(cfg)
			_, err = client.FelixConfigurations().Create(ctx, cfg, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		} else {
			Expect(err).NotTo(HaveOccurred())
			deltaFn(cfg)
			_, err = client.FelixConfigurations().Update(ctx, cfg, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		}
	}

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
		updateFelixConfig(func(cfg *api.FelixConfiguration) {
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
		updateFelixConfig(func(cfg *api.FelixConfiguration) {
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
