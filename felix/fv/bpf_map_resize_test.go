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

package fv_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfmap"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/ipsets"
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
		infra   infrastructure.DatastoreInfra
		felixes []*infrastructure.Felix
		client  client.Interface
	)

	BeforeEach(func() {
		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()
		felixes, client = infrastructure.StartNNodeTopology(1, opts, infra)
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}

		felixes[0].Stop()
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

		felixes[0].Exec("calico-bpf", "conntrack", "write", key64, val64)
		out, err := felixes[0].ExecOutput("calico-bpf", "conntrack", "dump")
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.Count(out, srcIP.String())).To(Equal(1), "entry not found in conntrack map")
		newCtMapSize := 6000
		updateFelixConfig(func(cfg *api.FelixConfiguration) {
			cfg.Spec.BPFMapSizeConntrack = &newCtMapSize
		})

		ctMap := conntrack.Map(&bpf.MapContext{})
		Eventually(func() int { return getMapSize(felixes[0], ctMap) }, "10s", "200ms").Should(Equal(newCtMapSize))
		out, err = felixes[0].ExecOutput("calico-bpf", "conntrack", "dump")
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.Count(out, srcIP.String())).To(Equal(1), "entry not found in conntrack map")

	})

	It("should program new map sizes", func() {
		affMap := nat.AffinityMap(&bpf.MapContext{})
		feMap := nat.FrontendMap(&bpf.MapContext{})
		beMap := nat.BackendMap(&bpf.MapContext{})
		rtMap := routes.Map(&bpf.MapContext{})
		ipsMap := ipsets.Map(&bpf.MapContext{})
		ctMap := conntrack.Map(&bpf.MapContext{})

		felix := felixes[0]
		Expect(getMapSize(felix, rtMap)).To(Equal((rtMap.(*bpf.PinnedMap)).MaxEntries))
		Expect(getMapSize(felix, feMap)).To(Equal((feMap.(*bpf.PinnedMap)).MaxEntries))
		Expect(getMapSize(felix, beMap)).To(Equal((beMap.(*bpf.PinnedMap)).MaxEntries))
		Expect(getMapSize(felix, affMap)).To(Equal((affMap.(*bpf.PinnedMap)).MaxEntries))
		Expect(getMapSize(felix, ipsMap)).To(Equal((ipsMap.(*bpf.PinnedMap)).MaxEntries))
		Expect(getMapSize(felix, ctMap)).To(Equal((ctMap.(*conntrack.MultiVersionMap)).CtMap.(*bpf.PinnedMap).MaxEntries))

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
		Eventually(func() int { return getMapSize(felix, rtMap) }, "10s", "200ms").Should(Equal(newRtSize))
		Eventually(func() int { return getMapSize(felix, feMap) }, "10s", "200ms").Should(Equal(newNATFeSize))
		Eventually(func() int { return getMapSize(felix, beMap) }, "10s", "200ms").Should(Equal(newNATBeSize))
		Eventually(func() int { return getMapSize(felix, affMap) }, "10s", "200ms").Should(Equal(newNATAffSize))
		Eventually(func() int { return getMapSize(felix, ipsMap) }, "10s", "200ms").Should(Equal(newIpSetMapSize))
		Eventually(func() int { return getMapSize(felix, ctMap) }, "10s", "200ms").Should(Equal(newCtMapSize))
	})
})

func getMapSize(felix *infrastructure.Felix, m bpf.Map) int {
	output := showBpfMap(felix, m)
	return int(output["max_entries"].(float64))
}

func showBpfMap(felix *infrastructure.Felix, m bpf.Map) map[string]interface{} {
	fileExists := felix.FileExists(m.Path())
	Expect(fileExists).Should(BeTrue(), fmt.Sprintf("showBpfMap: map %s didn't show up inside container", m.Path()))
	cmd, err := bpfmap.ShowMapCmd(m)
	Expect(err).NotTo(HaveOccurred(), "Failed to get BPF map show command: "+m.Path())
	log.WithField("cmd", cmd).Debug("showBPFMap")
	out, err := felix.ExecOutput(cmd...)
	Expect(err).NotTo(HaveOccurred(), "Failed to get show BPF map: "+m.Path())
	var mapData map[string]interface{}
	err = json.Unmarshal([]byte(out), &mapData)
	Expect(err).NotTo(HaveOccurred(), "Failed to parse show map data: "+m.Path())
	return mapData
}
