// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package labelindex_test

import (
	"fmt"
	"net"
	"runtime"
	"testing"

	"github.com/sirupsen/logrus"

	. "github.com/projectcalico/felix/labelindex"

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	calinet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/selector"
)

func BenchmarkWorkloadUpdate10Sels(b *testing.B) {
	benchmarkWorkloadUpdates(b, 10)
}
func BenchmarkWorkloadUpdate100Sels(b *testing.B) {
	benchmarkWorkloadUpdates(b, 100)
}
func BenchmarkWorkloadUpdate1000Sels(b *testing.B) {
	benchmarkWorkloadUpdates(b, 1000)
}
func BenchmarkWorkloadUpdate10000Sels(b *testing.B) {
	benchmarkWorkloadUpdates(b, 10000)
}

func benchmarkWorkloadUpdates(b *testing.B, numSels int) {
	var lastID string
	var lastMember IPSetMember

	logLevel := logrus.GetLevel()
	logrus.SetLevel(logrus.InfoLevel)
	defer logrus.SetLevel(logLevel)

	idx := NewSelectorAndNamedPortIndex()
	idx.OnMemberAdded = func(ipSetID string, member IPSetMember) {
		lastID = ipSetID
		lastMember = member
	}
	idx.OnMemberRemoved = func(ipSetID string, member IPSetMember) {
		lastID = ipSetID
		lastMember = member
	}
	for i := 0; i < numSels; i++ {
		sel, err := selector.Parse(fmt.Sprintf(`alpha == "beta" || has(ipset-%d)`, i))
		if err != nil {
			b.Fatal(err)
		}
		idx.UpdateIPSet(fmt.Sprintf("ipset-%d", i), sel, ProtocolNone, "")
	}

	updates := make([]api.Update, b.N)
	for n := 0; n < b.N; n++ {
		key := model.WorkloadEndpointKey{
			Hostname:       "host",
			OrchestratorID: "k8s",
			WorkloadID:     fmt.Sprintf("wep-%d", n),
			EndpointID:     "eth0",
		}
		ipNet := calinet.IPNet{IPNet: net.IPNet{
			IP:   net.IPv4(10, 0, byte(n>>8), byte(n&0xff)),
			Mask: net.CIDRMask(32, 32),
		}}
		updates[n] = api.Update{
			KVPair: model.KVPair{
				Key: key,
				Value: &model.WorkloadEndpoint{
					Labels:     map[string]string{"alpha": "beta"},
					IPv4Nets:   []calinet.IPNet{ipNet},
					ProfileIDs: []string{"default"},
				},
			},
		}
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		idx.OnUpdate(updates[n])
	}

	runtime.KeepAlive(lastID)
	runtime.KeepAlive(lastMember)
}
