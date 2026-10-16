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

	. "github.com/onsi/ginkgo/v2"
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
		tc, client = infrastructure.StartSingleNodeTopology(opts, infra)

		infra.AddDefaultAllow()
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

		val := conntrack.NewValueNormal(now, 0, leg, leg).AsBytes()
		c := tc.Felixes[0].WatchStdoutFor(regexp.MustCompile(
			`.*Overriding bpfMapSizeConntrack \(10000\) with map size growth \(20000\) for IPv4`))

		fillCtMap(tc.Felixes[0], conntrack.Map(), 20000, func(i int) []byte {
			return conntrack.NewKey(6 /* TCP */, srcIP, uint16(i), dstIP, uint16(i)).AsBytes()
		}, val)

		Eventually(c, "60s", "1s").Should(BeClosed())
		Eventually(getMapSizeFn(tc.Felixes[0], conntrack.Map()), "30s", "1s").Should(Equal(20000))

		expectPongs()

		err := tc.Felixes[0].ExecMayFail("calico-bpf", "conntrack", "dump", "--raw")
		Expect(err).NotTo(HaveOccurred())
	})
})

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ Felix bpf IPv6 conntrack table dynamic resize",
	[]apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {

		if !BPFMode() {
			return
		}

		var tc infrastructure.TopologyContainers

		BeforeEach(func() {
			infra := getInfra(
				infrastructure.K8sWithDualStack(),
				infrastructure.K8sWithAPIServerBindAddress("::"),
				infrastructure.K8sWithServiceClusterIPRange("dead:beef::abcd:0:0:0/112,10.101.0.0/16"),
			)
			opts := infrastructure.DefaultTopologyOptions()
			opts.EnableIPv6 = true
			opts.IPIPMode = api.IPIPModeNever
			opts.ExtraEnvVars["FELIX_IPV6SUPPORT"] = "true"
			opts.ExtraEnvVars["FELIX_BPFMapSizeConntrack"] = "10000"
			tc, _ = infrastructure.StartNNodeTopology(1, opts, infra)
		})

		It("should resize only the IPv6 ct map when it is full", func() {
			felix := tc.Felixes[0]
			Eventually(getMapSizeFn(felix, conntrack.Map()), "30s", "1s").Should(Equal(10000))
			Eventually(getMapSizeFn(felix, conntrack.MapV6()), "30s", "1s").Should(Equal(10000))

			c := felix.WatchStdoutFor(regexp.MustCompile(
				`.*Overriding bpfMapSizeConntrack \(10000\) with map size growth \(20000\) for IPv6`))

			now := time.Duration(timeshim.RealTime().KTimeNanos())
			leg := conntrack.Leg{SynSeen: true, AckSeen: true, Opener: true}
			val := conntrack.NewValueV6Normal(now, 0, leg, leg).AsBytes()
			srcIP := net.ParseIP("dead:beef::123")
			dstIP := net.ParseIP("dead:beef::121")

			fillCtMap(felix, conntrack.MapV6(), 20000, func(i int) []byte {
				return conntrack.NewKeyV6(17 /* UDP */, srcIP, uint16(i), dstIP, 53).AsBytes()
			}, val)

			Eventually(c, "60s", "1s").Should(BeClosed())
			Eventually(getMapSizeFn(felix, conntrack.MapV6()), "30s", "1s").Should(Equal(20000))
			Expect(getMapSize(felix, conntrack.Map())).To(Equal(10000))
		})
	})

// fillCtMap writes n entries into the felix's ct map with bpftool, in batches of 2k.
func fillCtMap(felix *infrastructure.Felix, m maps.Map, n int, key func(i int) []byte, val []byte) {
	tmp, err := os.CreateTemp("", "ct-batch")
	Expect(err).NotTo(HaveOccurred())
	tmp.Close()
	defer os.Remove(tmp.Name())

	var lines []string
	for i := 1; i <= n; i++ {
		args := []string{"map", "update", "pinned", m.Path(), "key"}
		args = append(args, formatBytesWithPrefix(key(i))...)
		args = append(args, "value", "hex")
		args = append(args, formatBytesWithPrefix(val)...)
		lines = append(lines, strings.Join(args, " "))

		if i%2000 == 0 || i == n {
			Expect(os.WriteFile(tmp.Name(), []byte(strings.Join(lines, "\n")), 0o644)).To(Succeed())
			utils.Run("docker", "cp", tmp.Name(), felix.Name+":/tmp/data_in")
			_, err := felix.ExecOutput("bpftool", "batch", "file", "/tmp/data_in")
			Expect(err).NotTo(HaveOccurred())
			lines = nil
		}
	}
}

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

func showBpfMap(felix *infrastructure.Felix, m maps.Map) (map[string]any, error) {
	var data map[string]any
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
