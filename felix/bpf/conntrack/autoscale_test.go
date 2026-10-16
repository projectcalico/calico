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

package conntrack_test

import (
	"net"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/mock"
)

const autoscaleMapSize = 100

var _ = Describe("BPF Conntrack map autoscaling", func() {
	var dir string

	BeforeEach(func() {
		orig := conntrack.MapSizeDir
		dir = GinkgoT().TempDir()
		conntrack.MapSizeDir = dir
		DeferCleanup(func() { conntrack.MapSizeDir = orig })
	})

	readFile := func(name string) string {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if os.IsNotExist(err) {
			return ""
		}
		Expect(err).NotTo(HaveOccurred())
		return string(data)
	}

	sizeFiles := map[int]string{4: "bpf_ct_map_size", 6: "bpf_ct6_map_size"}

	// sweep scans once per liveEntries element and returns the 1-based sweep
	// that requested a resize, or 0.
	sweep := func(ipVersion int, mode string, liveEntries []int) int {
		params := conntrack.MapParams
		kfb, vfb := conntrack.KeyFromBytes, conntrack.ValueFromBytes
		if ipVersion == 6 {
			params = conntrack.MapParamsV6
			kfb, vfb = conntrack.KeyV6FromBytes, conntrack.ValueV6FromBytes
		}
		params.MaxEntries = autoscaleMapSize
		ctMap := mock.NewMockMap(params)

		restarts := 0
		scanner := conntrack.NewScanner(ctMap, kfb, vfb, func() { restarts++ },
			mode, nil, ipVersion, nil)
		Expect(scanner).NotTo(BeNil())

		leg := conntrack.Leg{SynSeen: true, AckSeen: true, Opener: true}
		now := time.Duration(time.Now().UnixNano())
		for i, n := range liveEntries {
			ctMap.Contents = map[string]string{}
			for p := range n {
				var k, v []byte
				if ipVersion == 6 {
					key := conntrack.NewKeyV6(17, net.ParseIP("dead::1"), uint16(p), net.ParseIP("dead::2"), 53)
					val := conntrack.NewValueV6Normal(now, 0, leg, leg)
					k, v = key.AsBytes(), val.AsBytes()
				} else {
					key := conntrack.NewKey(17, net.IPv4(10, 0, 0, 1), uint16(p), net.IPv4(10, 0, 0, 2), 53)
					val := conntrack.NewValueNormal(now, 0, leg, leg)
					k, v = key.AsBytes(), val.AsBytes()
				}
				Expect(ctMap.Update(k, v)).To(Succeed())
			}
			scanner.Scan()
			if restarts > 0 {
				Expect(restarts).To(Equal(1))
				return i + 1
			}
		}
		return 0
	}

	for _, ipVersion := range []int{4, 6} {
		DescribeTable("resize decision",
			func(mode string, liveEntries []int, expectResizeAt int) {
				Expect(sweep(ipVersion, mode, liveEntries)).To(Equal(expectResizeAt))

				other := 10 - ipVersion
				Expect(readFile(sizeFiles[other])).To(BeEmpty(), "resize must not touch the other IP family")
				if expectResizeAt == 0 {
					Expect(readFile(sizeFiles[ipVersion])).To(BeEmpty())
				} else {
					Expect(readFile(sizeFiles[ipVersion])).To(Equal("200"))
				}
			},
			Entry("below 85%", "DoubleIfFull", []int{80, 84, 84, 84}, 0),
			Entry("above 90%", "DoubleIfFull", []int{91}, 1),
			Entry("growing above 85% for 3 sweeps", "DoubleIfFull", []int{86, 87, 88, 89}, 4),
			Entry("draining above 85%", "DoubleIfFull", []int{89, 88, 87, 86, 86}, 0),
			Entry("growth above 85% interrupted", "DoubleIfFull", []int{86, 87, 88, 87, 88}, 0),
			Entry("disabled", "Disabled", []int{95, 99}, 0),
		)
	}

	Describe("MapSizeFromFile", func() {
		writeFile := func(name, content string) {
			Expect(os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644)).To(Succeed())
		}

		expectSize := func(ipVersion, size int) {
			got, err := conntrack.MapSizeFromFile(ipVersion)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			ExpectWithOffset(1, got).To(Equal(size))
		}

		It("returns 0 for a map that never grew", func() {
			expectSize(4, 0)
			expectSize(6, 0)
		})

		It("keeps the families apart", func() {
			writeFile("bpf_ct6_map_size", "1024000")
			expectSize(4, 0)
			expectSize(6, 1024000)
		})

		It("adopts the shared size file for IPv6 once", func() {
			writeFile("bpf_ct_map_size", "1024000")
			expectSize(6, 1024000)
			Expect(readFile("bpf_ct6_map_size")).To(Equal("1024000"))

			writeFile("bpf_ct_map_size", "2048000")
			expectSize(4, 2048000)
			expectSize(6, 1024000)
		})

		It("fails on a corrupt file", func() {
			writeFile("bpf_ct_map_size", "garbage")
			_, err := conntrack.MapSizeFromFile(4)
			Expect(err).To(HaveOccurred())
		})
	})
})
