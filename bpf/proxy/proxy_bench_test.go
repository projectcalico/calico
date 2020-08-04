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

package proxy_test

import (
	"fmt"
	"net"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/felix/bpf/conntrack"
	"github.com/projectcalico/felix/bpf/mock"
	"github.com/projectcalico/felix/bpf/proxy"
)

func benchmarkProxyUpdates(b *testing.B, svcN, epsN int) {
	b.StopTimer()

	for n := 0; n < b.N; n++ {
		svcs := makeSvcs(svcN)
		k8s := fake.NewSimpleClientset(svcs...)

		syncer, err := proxy.NewSyncer(
			[]net.IP{net.IPv4(1, 1, 1, 1)},
			&mock.DummyMap{},
			&mock.DummyMap{},
			&mock.DummyMap{},
			proxy.NewRTCache(),
		)
		Expect(err).ShouldNot(HaveOccurred())

		benchS := benchSyncer{
			DPSyncer: syncer,
			syncC:    make(chan struct{}, 1),
		}

		connScan := conntrack.NewScanner(&mock.DummyMap{})

		b.StartTimer()

		proxy, err := proxy.New(k8s, &benchS, connScan, "somename", proxy.WithImmediateSync())
		Expect(err).ShouldNot(HaveOccurred())
		// Wait for the initial sync to complete
		<-benchS.syncC

		b.StopTimer()

		proxy.Stop()
	}
}

func BenchmarkProxyUpdates(b *testing.B) {
	RegisterTestingT(b)
	loglevel := logrus.GetLevel()
	logrus.SetLevel(logrus.WarnLevel)
	defer logrus.SetLevel(loglevel)

	tests := []struct {
		svcCount int
		epsCount int
	}{
		{0, 0},
		{1, 0},
		{10, 0},
	}

	for _, tc := range tests {
		b.Run(fmt.Sprintf("Services %d x Endpoints %d", tc.svcCount, tc.epsCount), func(b *testing.B) {
			benchmarkProxyUpdates(b, tc.svcCount, tc.epsCount)
		})
	}
}

func makeSvcs(n int) []runtime.Object {
	svcs := make([]runtime.Object, n)

	for i := 0; i < n; i++ {
		ip := net.IPv4(10, byte((i&0xff0000)>>16), byte((i&0xff00)>>8), byte(i&0xff))
		svcs[i] = &v1.Service{
			TypeMeta:   typeMetaV1("Service"),
			ObjectMeta: objectMeataV1(fmt.Sprintf("service-%d", i)),
			Spec: v1.ServiceSpec{
				ClusterIP: ip.String(),
				Type:      v1.ServiceTypeClusterIP,
				Selector: map[string]string{
					"app": "test",
				},
				Ports: []v1.ServicePort{
					{
						Protocol: v1.ProtocolTCP,
						Port:     1234,
					},
				},
			},
		}
	}

	return svcs
}

func makeEps(sn, en int) []*v1.Endpoints {
	return nil
}

type benchSyncer struct {
	proxy.DPSyncer
	syncC chan struct{}
}

func (s *benchSyncer) Apply(state proxy.DPSyncerState) error {
	err := s.DPSyncer.Apply(state)
	s.syncC <- struct{}{}
	return err
}
