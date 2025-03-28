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
	"encoding/base64"
	"net"
	"os"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	v2 "github.com/projectcalico/calico/felix/bpf/conntrack/v2"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/timeshim"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ Felix bpf test conntrack map upgrade", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {

	if os.Getenv("FELIX_FV_ENABLE_BPF") != "true" {
		// Non-BPF run.
		return
	}

	var (
		infra infrastructure.DatastoreInfra
		tc    infrastructure.TopologyContainers
		//client  client.Interface
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

	It("should upgrade conntrack entries from v2 to v3", func() {
		// create conntrack v2 map
		tc.Felixes[0].Exec("calico-bpf", "conntrack", "create", "--ver=2")
		srcIP := net.IPv4(123, 123, 123, 123)
		dstIP := net.IPv4(121, 121, 121, 121)

		now := time.Duration(timeshim.RealTime().KTimeNanos())
		leg := v2.Leg{SynSeen: true, AckSeen: true, Opener: true}
		val := v2.NewValueNormal(now, now, 0, leg, leg)
		val64 := base64.StdEncoding.EncodeToString(val[:])

		key := v2.NewKey(6 /* TCP */, srcIP, 0, dstIP, 0)
		key64 := base64.StdEncoding.EncodeToString(key[:])

		// write a normal key
		tc.Felixes[0].Exec("calico-bpf", "conntrack", "write", "--ver=2", key64, val64)

		k3Normal := conntrack.NewKey(6, srcIP, 0, dstIP, 0)
		leg3Normal := conntrack.Leg{SynSeen: true, AckSeen: true, Opener: true}
		val3Normal := conntrack.NewValueNormal(now, 0, leg3Normal, leg3Normal)

		srcIP = net.IPv4(121, 123, 125, 124)
		dstIP = net.IPv4(120, 121, 121, 119)
		key = v2.NewKey(11, srcIP, 0, dstIP, 0)
		key64 = base64.StdEncoding.EncodeToString(key[:])
		val = v2.NewValueNATForward(now, now, 0, key)
		val.SetNATSport(4321)
		val64 = base64.StdEncoding.EncodeToString(val[:])

		tc.Felixes[0].Exec("calico-bpf", "conntrack", "write", "--ver=2", key64, val64)
		k3NatFwd := conntrack.NewKey(11, srcIP, 0, dstIP, 0)
		val3NatFwd := conntrack.NewValueNATForward(now, 0, k3NatFwd)
		val3NatFwd.SetNATSport(4321)

		srcIP = net.IPv4(1, 2, 3, 4)
		dstIP = net.IPv4(5, 6, 7, 8)
		tunIP := net.IPv4(121, 123, 125, 127)
		origIP := net.IPv4(120, 121, 121, 115)
		key = v2.NewKey(11, srcIP, 0, dstIP, 0)
		key64 = base64.StdEncoding.EncodeToString(key[:])
		val = v2.NewValueNATReverse(now, now, 0, leg, leg, tunIP, origIP, 1234)
		val64 = base64.StdEncoding.EncodeToString(val[:])

		tc.Felixes[0].Exec("calico-bpf", "conntrack", "write", "--ver=2", key64, val64)
		k3NatRev := conntrack.NewKey(11, srcIP, 0, dstIP, 0)
		val3NatRev := conntrack.NewValueNATReverse(now, 0, leg3Normal, leg3Normal, tunIP, origIP, 1234)

		srcIP = net.IPv4(5, 6, 7, 8)
		dstIP = net.IPv4(55, 66, 77, 88)
		key = v2.NewKey(11, srcIP, 0, dstIP, 0)
		tunIP = net.IPv4(12, 13, 15, 17)
		origIP = net.IPv4(10, 11, 12, 15)
		origSIP := net.IPv4(16, 17, 18, 19)
		key = v2.NewKey(11, srcIP, 0, dstIP, 0)
		key64 = base64.StdEncoding.EncodeToString(key[:])
		val = v2.NewValueNATReverseSNAT(now, now, 0, leg, leg, tunIP, origIP, origSIP, 1234)
		val64 = base64.StdEncoding.EncodeToString(val[:])

		tc.Felixes[0].Exec("calico-bpf", "conntrack", "write", "--ver=2", key64, val64)
		k3NatRevSnat := conntrack.NewKey(11, srcIP, 0, dstIP, 0)
		val3NatRevSnat := conntrack.NewValueNATReverseSNAT(now, 0, leg3Normal, leg3Normal, tunIP, origIP, origSIP, 1234)

		tc.Felixes[0].Restart()
		Eventually(func() conntrack.MapMem { return dumpCTMap(tc.Felixes[0]) }, "10s", "100ms").Should(HaveKeyWithValue(k3Normal, val3Normal))
		Eventually(func() conntrack.MapMem { return dumpCTMap(tc.Felixes[0]) }, "10s", "100ms").Should(HaveKeyWithValue(k3NatFwd, val3NatFwd))
		Eventually(func() conntrack.MapMem { return dumpCTMap(tc.Felixes[0]) }, "10s", "100ms").Should(HaveKeyWithValue(k3NatRev, val3NatRev))
		Eventually(func() conntrack.MapMem { return dumpCTMap(tc.Felixes[0]) }, "10s", "100ms").Should(HaveKeyWithValue(k3NatRevSnat, val3NatRevSnat))
	})
})
