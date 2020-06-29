// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.
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

// We keep the benchmarks in the proxy package to be able to bench unexported
// partial functionality.

// +build benchmark

package proxy

import (
	"fmt"
	"net"
	"testing"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sp "k8s.io/kubernetes/pkg/proxy"

	"github.com/projectcalico/felix/bpf/nat"
)

func makeState(svcCnt, epCnt int) DPSyncerState {
	state := DPSyncerState{
		SvcMap: make(k8sp.ServiceMap, svcCnt),
		EpsMap: make(k8sp.EndpointsMap, epCnt),
	}

	for i := 0; i < svcCnt; i++ {
		sk := k8sp.ServicePortName{
			NamespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      fmt.Sprintf("bench-svc-%d", i),
			},
		}
		state.SvcMap[sk] = NewK8sServicePort(
			net.IPv4(10, byte((i&0xff0000)>>16), byte((i&0xff00)>>8), byte(i&0xff)),
			1234,
			v1.ProtocolTCP,
		)

		eps := make([]k8sp.Endpoint, epCnt)
		for j := 0; j < epCnt; j++ {
			eps[j] = &k8sp.BaseEndpointInfo{Endpoint: fmt.Sprintf("11.1.1.1:%d", j+1)}
		}
		state.EpsMap[sk] = eps
	}

	return state
}

func stateToBPFMaps(state DPSyncerState) (nat.MapMem, nat.BackendMapMem) {
	fe := make(nat.MapMem, len(state.SvcMap))
	be := make(nat.BackendMapMem, len(state.SvcMap)*10)

	id := uint32(1)
	for sk, sv := range state.SvcMap {
		fk := nat.NewNATKey(sv.ClusterIP(), uint16(sv.Port()), ProtoV1ToIntPanic(sv.Protocol()))

		eps := state.EpsMap[sk]

		fe[fk] = nat.NewNATValue(id, uint32(len(eps)), 0, 0)

		for i, ep := range eps {
			port, _ := ep.Port()
			be[nat.NewNATBackendKey(id, uint32(i))] = nat.NewNATBackendValue(net.ParseIP(ep.IP()), uint16(port))
		}

		id++
	}

	return fe, be
}

func benchmarkStartupSync(b *testing.B, svcCnt, epCnt int) {
	state := makeState(svcCnt, epCnt)

	b.Run(fmt.Sprintf("Services %d Endpoints %d", svcCnt, epCnt), func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			b.StopTimer()
			origSvcs, origEps := stateToBPFMaps(state)
			s := &Syncer{
				prevSvcMap: make(map[svcKey]svcInfo),
				prevEpsMap: make(k8sp.EndpointsMap),
				origSvcs:   origSvcs,
				origEps:    origEps,
			}

			b.StartTimer()
			s.startupBuildPrev(state)
		}
	})
}

func BenchmarkStartupSync(b *testing.B) {
	logrus.SetLevel(logrus.InfoLevel)

	benchmarkStartupSync(b, 10, 1)
	benchmarkStartupSync(b, 10, 10)
	benchmarkStartupSync(b, 100, 1)
	benchmarkStartupSync(b, 100, 10)
	benchmarkStartupSync(b, 1000, 10)
	benchmarkStartupSync(b, 1000, 100)
	benchmarkStartupSync(b, 10000, 1)
	benchmarkStartupSync(b, 10000, 10)
	benchmarkStartupSync(b, 10000, 100)
}
