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

package proxy

import (
	"fmt"
	"net"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/cachingmap"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sp "k8s.io/kubernetes/pkg/proxy"

	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/mock"
	"github.com/projectcalico/calico/felix/bpf/nat"
)

func makeSvcEpsPair(svcIdx, epCnt, port int, opts ...K8sServicePortOption) (k8sp.ServicePort, []k8sp.Endpoint) {
	svc := NewK8sServicePort(
		net.IPv4(10, byte((svcIdx&0xff0000)>>16), byte((svcIdx&0xff00)>>8), byte(svcIdx&0xff)),
		port,
		v1.ProtocolTCP,
		opts...,
	)

	eps := make([]k8sp.Endpoint, epCnt)
	for j := 0; j < epCnt; j++ {
		eps[j] = NewEndpointInfo("11.1.1.1", j+1)
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

func makeState(svcCnt, epCnt int, opts ...K8sServicePortOption) DPSyncerState {
	state := DPSyncerState{
		SvcMap: make(k8sp.ServicePortMap, svcCnt),
		EpsMap: make(k8sp.EndpointsMap, epCnt),
	}

	for i := 0; i < svcCnt; i++ {
		sk := makeSvcKey(i)
		state.SvcMap[sk], state.EpsMap[sk] = makeSvcEpsPair(i, epCnt, 1234, opts...)
	}

	return state
}

func stateToBPFMaps(state DPSyncerState) (
	*cachingmap.CachingMap[nat.FrontendKeyInterface, nat.FrontendValue],
	*cachingmap.CachingMap[nat.BackendKey, nat.BackendValueInterface],
) {
	fe := mock.NewMockMap(nat.FrontendMapParameters)
	be := mock.NewMockMap(nat.BackendMapParameters)

	id := uint32(1)
	for sk, sv := range state.SvcMap {
		fk := nat.NewNATKey(sv.ClusterIP(), uint16(sv.Port()), ProtoV1ToIntPanic(sv.Protocol()))

		eps := state.EpsMap[sk]

		fv := nat.NewNATValue(id, uint32(len(eps)), 0, 0)
		err := fe.Update(fk[:], fv[:])
		Expect(err).NotTo(HaveOccurred())

		for i, ep := range eps {
			port := ep.Port()
			bk := nat.NewNATBackendKey(id, uint32(i))
			bv := nat.NewNATBackendValue(net.ParseIP(ep.IP()), uint16(port))
			err := be.Update(bk[:], bv[:])
			Expect(err).NotTo(HaveOccurred())
		}

		id++
	}

	feCache := cachingmap.New[nat.FrontendKeyInterface, nat.FrontendValue](nat.FrontendMapParameters.Name,
		maps.NewTypedMap[nat.FrontendKeyInterface, nat.FrontendValue](fe, nat.FrontendKeyFromBytes, nat.FrontendValueFromBytes))
	beCache := cachingmap.New[nat.BackendKey, nat.BackendValueInterface](nat.BackendMapParameters.Name,
		maps.NewTypedMap[nat.BackendKey, nat.BackendValueInterface](be, nat.BackendKeyFromBytes, nat.BackendValueFromBytes))

	return feCache, beCache
}

func benchmarkStartupSync(b *testing.B, svcCnt, epCnt int) {
	b.StopTimer()
	state := makeState(svcCnt, epCnt)

	b.Run(fmt.Sprintf("Services %d Endpoints %d", svcCnt, epCnt), func(b *testing.B) {
		b.StopTimer()
		for n := 0; n < b.N; n++ {
			origSvcs, origEps := stateToBPFMaps(state)
			s := &Syncer{
				prevSvcMap: make(map[svcKey]svcInfo),
				prevEpsMap: make(k8sp.EndpointsMap),
				bpfSvcs:    origSvcs,
				bpfEps:     origEps,

				newFrontendKey:         nat.NewNATKeyIntf,
				newFrontendKeySrc:      nat.NewNATKeySrcIntf,
				affinityKeyFromBytes:   nat.AffinityKeyIntfFromBytes,
				affinityValueFromBytes: nat.AffinityValueIntfFromBytes,
			}
			Expect(origSvcs.LoadCacheFromDataplane()).NotTo(HaveOccurred())
			Expect(origEps.LoadCacheFromDataplane()).NotTo(HaveOccurred())

			b.StartTimer()
			err := s.startupBuildPrev(state)
			Expect(err).ShouldNot(HaveOccurred())
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

func runBenchmarkServiceUpdate(b *testing.B, svcCnt, epCnt int, mockMaps bool, opts ...K8sServicePortOption) {
	var (
		syncer DPSyncer
		err    error
	)

	b.StopTimer()
	state := makeState(svcCnt, epCnt, opts...)

	if mockMaps {
		syncer, err = NewSyncer(4,
			[]net.IP{net.IPv4(1, 1, 1, 1)},
			&mock.DummyMap{},
			&mock.DummyMap{},
			&mock.DummyMap{},
			NewRTCache(),
			nil,
		)
		Expect(err).ShouldNot(HaveOccurred())
	} else {
		feMap := nat.FrontendMap()
		err = feMap.EnsureExists()
		Expect(err).ShouldNot(HaveOccurred())
		beMap := nat.BackendMap()
		err = beMap.EnsureExists()
		Expect(err).ShouldNot(HaveOccurred())

		syncer, err = NewSyncer(4,
			[]net.IP{net.IPv4(1, 1, 1, 1)},
			&mock.DummyMap{},
			&mock.DummyMap{},
			&mock.DummyMap{},
			NewRTCache(),
			nil,
		)
		Expect(err).ShouldNot(HaveOccurred())
	}

	err = syncer.Apply(state)
	Expect(err).ShouldNot(HaveOccurred())

	title := fmt.Sprintf("Services %d Endpoints %d mockMaps %t", svcCnt, epCnt, mockMaps)
	if len(opts) > 0 {
		title += " + derived"
	}

	b.Run(title, func(b *testing.B) {
		b.StopTimer()
		for n := 0; n < b.N; n++ {
			delKey := makeSvcKey(n)
			newIdx := svcCnt + n
			newKey := makeSvcKey(newIdx)

			delete(state.SvcMap, delKey)
			delete(state.EpsMap, delKey)

			state.SvcMap[newKey], state.EpsMap[newKey] = makeSvcEpsPair(newIdx, epCnt, 1234, opts...)

			b.StartTimer()

			err := syncer.Apply(state)
			Expect(err).ShouldNot(HaveOccurred())

			b.StopTimer()
		}
	})
}

func BenchmarkServiceUpdate(b *testing.B) {
	RegisterTestingT(b)
	loglevel := logrus.GetLevel()
	logrus.SetLevel(logrus.WarnLevel)
	defer logrus.SetLevel(loglevel)

	dynaNodePort := func() K8sServicePortOption {
		np := 0
		return func(s interface{}) {
			np = (np + 1) % 30000
			K8sSvcWithNodePort(30000 + np)(s)
		}
	}

	for _, svcs := range []int{1, 10, 100, 1000, 10000} {
		for _, eps := range []int{1, 10} {
			for _, opts := range [][]K8sServicePortOption{nil, {dynaNodePort()}} {
				for _, mock := range []bool{true, false} {
					runBenchmarkServiceUpdate(b, svcs, eps, mock, opts...)
				}
			}
		}
	}
}
