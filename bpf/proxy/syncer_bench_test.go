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

	. "github.com/onsi/gomega"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sp "k8s.io/kubernetes/pkg/proxy"

	"github.com/projectcalico/felix/bpf/mock"
	"github.com/projectcalico/felix/bpf/nat"
)

func makeSvcEpsPair(svcIdx, epCnt, port int) (k8sp.ServicePort, []k8sp.Endpoint) {
	svc := NewK8sServicePort(
		net.IPv4(10, byte((svcIdx&0xff0000)>>16), byte((svcIdx&0xff00)>>8), byte(svcIdx&0xff)),
		port,
		v1.ProtocolTCP,
	)

	eps := make([]k8sp.Endpoint, epCnt)
	for j := 0; j < epCnt; j++ {
		eps[j] = &k8sp.BaseEndpointInfo{Endpoint: fmt.Sprintf("11.1.1.1:%d", j+1)}
	}

	return svc, eps
}

func makeSvcKey(svcIdx int) k8sp.ServicePortName {
	return k8sp.ServicePortName{
		NamespacedName: types.NamespacedName{
			Namespace: "default",
			Name:      fmt.Sprintf("bench-svc-%d", svcIdx),
		},
	}
}

func makeState(svcCnt, epCnt int) DPSyncerState {
	state := DPSyncerState{
		SvcMap: make(k8sp.ServiceMap, svcCnt),
		EpsMap: make(k8sp.EndpointsMap, epCnt),
	}

	for i := 0; i < svcCnt; i++ {
		sk := makeSvcKey(i)
		state.SvcMap[sk], state.EpsMap[sk] = makeSvcEpsPair(i, epCnt, 1234)
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
	b.StopTimer()
	state := makeState(svcCnt, epCnt)

	b.Run(fmt.Sprintf("Services %d Endpoints %d", svcCnt, epCnt), func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			origSvcs, origEps := stateToBPFMaps(state)
			s := &Syncer{
				prevSvcMap: make(map[svcKey]svcInfo),
				prevEpsMap: make(k8sp.EndpointsMap),
				origSvcs:   origSvcs,
				origEps:    origEps,
			}

			b.StartTimer()
			s.startupBuildPrev(state)
			b.StopTimer()
		}
	})
}

func BenchmarkStartupSync(b *testing.B) {
	RegisterTestingT(b)
	loglevel := logrus.GetLevel()
	logrus.SetLevel(logrus.WarnLevel)
	defer logrus.SetLevel(loglevel)

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

func benchmarkServiceUpdate(b *testing.B, svcCnt, epCnt int) {
	b.StopTimer()
	state := makeState(svcCnt, epCnt)

	syncer, err := NewSyncer(
		[]net.IP{net.IPv4(1, 1, 1, 1)},
		&mock.DummyMap{},
		&mock.DummyMap{},
		&mock.DummyMap{},
		NewRTCache(),
	)
	Expect(err).ShouldNot(HaveOccurred())

	benchS := benchSyncer{
		DPSyncer: syncer,
		syncC:    make(chan struct{}, 1),
	}

	benchS.Apply(state)
	<-benchS.syncC

	b.Run(fmt.Sprintf("Services %d Endpoints %d", svcCnt, epCnt), func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			delKey := makeSvcKey(n)
			newIdx := svcCnt + n
			newKey := makeSvcKey(newIdx)

			delete(state.SvcMap, delKey)
			delete(state.EpsMap, delKey)

			state.SvcMap[newKey], state.EpsMap[newKey] = makeSvcEpsPair(newIdx, epCnt, 1234)

			b.StartTimer()

			benchS.Apply(state)
			<-benchS.syncC

			b.StopTimer()
		}
	})
}

func BenchmarkServiceUpdate(b *testing.B) {
	RegisterTestingT(b)
	loglevel := logrus.GetLevel()
	logrus.SetLevel(logrus.WarnLevel)
	defer logrus.SetLevel(loglevel)

	benchmarkServiceUpdate(b, 1, 1)
	benchmarkServiceUpdate(b, 1, 10)
	benchmarkServiceUpdate(b, 10, 1)
	benchmarkServiceUpdate(b, 100, 1)
	benchmarkServiceUpdate(b, 1000, 1)
	benchmarkServiceUpdate(b, 10000, 1)
}

type benchSyncer struct {
	DPSyncer
	syncC chan struct{}
}

func (s *benchSyncer) Apply(state DPSyncerState) error {
	err := s.DPSyncer.Apply(state)
	s.syncC <- struct{}{}
	return err
}
