// Copyright (c) 2021-2025 Tigera, Inc. All rights reserved.
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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
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
	"github.com/projectcalico/calico/felix/fv/utils"
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
		val := conntrack.NewValueNormal(now, 0, leg, leg)
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

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ Felix bpf conntrack table dynamic resize", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {

	if !BPFMode() {
		// Non-BPF run.
		return
	}

	var (
		infra infrastructure.DatastoreInfra
		tc    infrastructure.TopologyContainers

		w  [2]*workload.Workload
		pc *connectivity.PersistentConnection
	)

	BeforeEach(func() {
		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()
		opts.ExtraEnvVars["FELIX_BPFMapSizeConntrack"] = "10000"
		opts.ExtraEnvVars["FELIX_debugDisableLogDropping"] = "true"
		opts.FelixLogSeverity = "Debug"
		tc, _ = infrastructure.StartNNodeTopology(1, opts, infra)

		infra.AddDefaultAllow()

		for i := range w {
			w[i] = workload.Run(
				tc.Felixes[0],
				fmt.Sprintf("w%d", i),
				"default",
				fmt.Sprintf("10.65.0.%d", i+2),
				"8055",
				"tcp",
			)
			w[i].ConfigureInInfra(infra)
		}
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

	It("should resize ct map when it is full", func() {
		// make sure that connctivity is already established
		cc := &connectivity.Checker{}
		cc.Expect(connectivity.Some, w[0], w[1])
		cc.CheckConnectivity()

		By("Starting permanent connection")
		pc = w[0].StartPersistentConnection(w[1].IP, 8055, workload.PersistentConnectionOpts{
			MonitorConnectivity: true,
		})
		defer pc.Stop()

		expectPongs := func() {
			EventuallyWithOffset(1, pc.SinceLastPong, "5s").Should(
				BeNumerically("<", time.Second),
				"Expected to see pong responses on the connection but didn't receive any")
		}

		expectPongs()

		now := time.Duration(timeshim.RealTime().KTimeNanos())
		leg := conntrack.Leg{SynSeen: true, AckSeen: true, Opener: true}

		srcIP := net.IPv4(123, 123, 123, 123)
		dstIP := net.IPv4(121, 121, 121, 121)

		val := formatBytesWithPrefix(conntrack.NewValueNormal(now, 0, leg, leg).AsBytes())
		c := tc.Felixes[0].WatchStdoutFor(regexp.MustCompile(`.*Overriding bpfMapSizeConntrack \(10000\) with map size growth \(20000\)`))

		line := ""
		// Program 10k tcp ct entries into map. This is done in batches of 2k.
		for i := 1; i <= 20000; i++ {
			sport := uint16(i)
			dport := uint16(i & 0xffff)
			key := formatBytesWithPrefix(conntrack.NewKey(6 /* UDP */, srcIP, sport, dstIP, dport).AsBytes())
			args := []string{"map", "update", "pinned", conntrack.Map().Path()}
			args = append(args, "key")
			args = append(args, key...)
			args = append(args, []string{"value", "hex"}...)
			args = append(args, val...)
			output := strings.Join(args, " ")
			if line == "" {
				line = output
			} else {
				line = line + "\n" + output
			}
			if i%2000 == 0 {
				err := os.WriteFile("/tmp/data_in", []byte(line), 0644)
				Expect(err).NotTo(HaveOccurred())
				utils.Run("docker", "cp", "/tmp/data_in", fmt.Sprintf("%s:/tmp/data_in", tc.Felixes[0].Name))
				line = ""
				_, err = tc.Felixes[0].ExecOutput("bpftool", "batch", "file", "/tmp/data_in")
				Expect(err).NotTo(HaveOccurred())
			}
		}

		defer os.Remove("/tmp/data_in")
		Eventually(func() bool {
			select {
			case _, ok := <-c:
				if !ok {
					return true
				}
				return false
			default:
				return false
			}
		}, "60s", "1s").Should(BeTrue())

		expectPongs()

		err := tc.Felixes[0].ExecMayFail("calico-bpf", "conntrack", "dump", "--raw")
		Expect(err).NotTo(HaveOccurred())
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

func formatBytesWithPrefix(data []byte) []string {
	// Create a slice of strings to hold each formatted byte.
	// Pre-allocating the slice with the correct capacity is more efficient.
	parts := make([]string, len(data))

	// Loop over the input data slice.
	for i, b := range data {
		// For each byte, format it into the "0xHH" string format
		// and place it in our parts slice.
		parts[i] = fmt.Sprintf("0x%02x", b)
	}

	// Join all the parts together with a single space as the separator.
	return parts
}
