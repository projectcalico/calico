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

package fv

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/ipsets"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
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

		for _, felix := range felixes {
			felix.Stop()
		}

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

	It("should program new map sizes", func() {
		newRtSize := 1000
		newNATFeSize := 2000
		newNATBeSize := 3000
		newNATAffSize := 4000
		newIpSetMapSize := 5000
		newCtMapSize := 6000

		affMap := nat.AffinityMap(&bpf.MapContext{})
		feMap := nat.FrontendMap(&bpf.MapContext{})
		beMap := nat.BackendMap(&bpf.MapContext{})
		rtMap := routes.Map(&bpf.MapContext{})
		ipsMap := ipsets.Map(&bpf.MapContext{})
		ctMap := conntrack.Map(&bpf.MapContext{})

		felix := felixes[0]
		Expect(getMapSize(felix, rtMap)).To(Equal(rtMap.GetMaxEntries()))
		Expect(getMapSize(felix, feMap)).To(Equal(feMap.GetMaxEntries()))
		Expect(getMapSize(felix, beMap)).To(Equal(beMap.GetMaxEntries()))
		Expect(getMapSize(felix, affMap)).To(Equal(affMap.GetMaxEntries()))
		Expect(getMapSize(felix, ipsMap)).To(Equal(ipsMap.GetMaxEntries()))
		Expect(getMapSize(felix, ctMap)).To(Equal(ctMap.GetMaxEntries()))

		By("configuring route map size = 1000, nat fe size = 2000, nat be size = 3000, nat affinity size = 4000")
		updateFelixConfig(func(cfg *api.FelixConfiguration) {
			cfg.Spec.BPFMapSizeRoute = &newRtSize
			cfg.Spec.BPFMapSizeNATFE = &newNATFeSize
			cfg.Spec.BPFMapSizeNATBE = &newNATBeSize
			cfg.Spec.BPFMapSizeNATAFF = &newNATAffSize
			cfg.Spec.BPFMapSizeIPSets = &newIpSetMapSize
			cfg.Spec.BPFMapSizeConntrack = &newCtMapSize
		})
		Eventually(func() int { return getMapSize(felix, rtMap) }, "5s", "200ms").Should(Equal(newRtSize))
		Eventually(func() int { return getMapSize(felix, feMap) }, "5s", "200ms").Should(Equal(newNATFeSize))
		Eventually(func() int { return getMapSize(felix, beMap) }, "5s", "200ms").Should(Equal(newNATBeSize))
		Eventually(func() int { return getMapSize(felix, affMap) }, "5s", "200ms").Should(Equal(newNATAffSize))
		Eventually(func() int { return getMapSize(felix, ipsMap) }, "5s", "200ms").Should(Equal(newIpSetMapSize))
		Eventually(func() int { return getMapSize(felix, ctMap) }, "5s", "200ms").Should(Equal(newCtMapSize))
	})
})

func getMapSize(felix *infrastructure.Felix, m bpf.Map) int {
	output := showBpfMap(felix, m)
	return int(output["max_entries"].(float64))
}

func showBpfMap(felix *infrastructure.Felix, m bpf.Map) map[string]interface{} {
	Eventually(func() bool {
		return felix.FileExists(m.Path())
	}).Should(BeTrue(), fmt.Sprintf("showBpfMap: map %s didn't show up inside container", m.Path()))
	cmd, err := bpf.ShowMapCmd(m)
	Expect(err).NotTo(HaveOccurred(), "Failed to get BPF map show command: "+m.Path())
	log.WithField("cmd", cmd).Debug("showBPFMap")
	out, err := felix.ExecOutput(cmd...)
	Expect(err).NotTo(HaveOccurred(), "Failed to get show BPF map: "+m.Path())
	var mapData map[string]interface{}
	err = json.Unmarshal([]byte(out), &mapData)
	Expect(err).NotTo(HaveOccurred(), "Failed to parse show map data: "+m.Path())
	return mapData
}
