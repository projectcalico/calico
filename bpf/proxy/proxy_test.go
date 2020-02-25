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

package proxy_test

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8sp "k8s.io/kubernetes/pkg/proxy"

	proxy "github.com/projectcalico/felix/bpf/proxy"
)

func log(format string, a ...interface{}) {
	fmt.Fprintf(GinkgoWriter, format, a...)
}

var _ = Describe("BPF Proxy", func() {
	var syncStop chan struct{}

	It("should fail without k8s client", func() {
		_, err := proxy.New(nil, nil, "testnode")
		Expect(err).To(HaveOccurred())

		_, err = proxy.New(fake.NewSimpleClientset(), nil, "testnode")
		Expect(err).To(HaveOccurred())
	})

	It("should create proxy with fake client and mock syncer and sync with empty store", func() {
		k8s := fake.NewSimpleClientset()

		syncStop = make(chan struct{})
		dp := newMockSyncer(syncStop)

		p, err := proxy.New(k8s, dp, "testnode", proxy.WithImmediateSync())
		Expect(err).NotTo(HaveOccurred())

		defer func() {
			close(syncStop)
			p.Stop()
		}()

		dp.checkState(func(s proxy.DPSyncerState) {
			Expect(len(s.SvcMap)).To(Equal(0))
			Expect(len(s.EpsMap)).To(Equal(0))
			Expect(len(s.StaleUDPEps)).To(Equal(0))
			Expect(len(s.StaleUDPSvcs)).To(Equal(0))
		})
	})

	testSvc := &v1.Service{
		TypeMeta:   typeMetaV1("Service"),
		ObjectMeta: objectMeataV1("testService"),
		Spec: v1.ServiceSpec{
			ClusterIP: "10.1.0.1",
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

	testSvcEps := &v1.Endpoints{
		TypeMeta:   typeMetaV1("Endpoints"),
		ObjectMeta: objectMeataV1("testService"),
		Subsets: []v1.EndpointSubset{
			{
				Addresses: []v1.EndpointAddress{
					{
						IP: "10.1.2.1",
					},
					{
						IP: "10.1.2.2",
					},
				},
				Ports: []v1.EndpointPort{
					{
						Port: 1234,
					},
				},
			},
		},
	}

	secondSvc := &v1.Service{
		TypeMeta:   typeMetaV1("Service"),
		ObjectMeta: objectMeataV1("second-service"),
		Spec: v1.ServiceSpec{
			ClusterIP: "10.1.0.1",
			Type:      v1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"app": "test",
			},
			Ports: []v1.ServicePort{
				{
					Protocol: v1.ProtocolUDP,
					Port:     1221,
				},
			},
		},
	}

	secondSvcEps := &v1.Endpoints{
		TypeMeta:   typeMetaV1("Endpoints"),
		ObjectMeta: objectMeataV1("second-service"),
		Subsets: []v1.EndpointSubset{
			{
				Addresses: []v1.EndpointAddress{
					{
						IP: "10.1.2.11",
					},
					{
						IP: "10.1.2.22",
					},
				},
				Ports: []v1.EndpointPort{
					{
						Port: 1221,
					},
				},
			},
		},
	}

	Describe("with k8s client", func() {
		var p proxy.Proxy
		var dp *mockSyncer
		k8s := fake.NewSimpleClientset(testSvc, testSvcEps, secondSvc, secondSvcEps)

		BeforeEach(func() {
			By("creating proxy with fake client and mock syncer", func() {
				var err error

				syncStop = make(chan struct{})
				dp = newMockSyncer(syncStop)

				p, err = proxy.New(k8s, dp, "testnode", proxy.WithMinSyncPeriod(200*time.Millisecond))
				Expect(err).NotTo(HaveOccurred())
			})
		})

		AfterEach(func() {
			By("stopping the proxy", func() {
				close(syncStop)
				p.Stop()
			})
		})

		It("should make the right transitions", func() {

			By("getting the initial sync", func() {
				dp.checkState(func(s proxy.DPSyncerState) {
					Expect(len(s.SvcMap)).To(Equal(2))
					Expect(len(s.EpsMap)).To(Equal(2))
					Expect(len(s.StaleUDPEps)).To(Equal(0))
					Expect(len(s.StaleUDPSvcs)).To(Equal(0))
				})
			})

			By("adding a service", func() {
				err := k8s.Tracker().Add(
					&v1.Service{
						TypeMeta:   typeMetaV1("Service"),
						ObjectMeta: objectMeataV1("added"),
						Spec: v1.ServiceSpec{
							ClusterIP: "10.1.0.3",
							Type:      v1.ServiceTypeClusterIP,
							Selector: map[string]string{
								"app": "test",
							},
							Ports: []v1.ServicePort{
								{
									Protocol: v1.ProtocolTCP,
									Port:     1221,
								},
							},
						},
					},
				)
				Expect(err).NotTo(HaveOccurred())

				dp.checkState(func(s proxy.DPSyncerState) {
					Expect(len(s.SvcMap)).To(Equal(3))
					Expect(len(s.EpsMap)).To(Equal(2))
					Expect(len(s.StaleUDPEps)).To(Equal(0))
					Expect(len(s.StaleUDPSvcs)).To(Equal(0))
				})
			})

			By("deleting the last added service", func() {
				err := k8s.Tracker().Delete(v1.SchemeGroupVersion.WithResource("services"), "default", "added")
				Expect(err).NotTo(HaveOccurred())

				dp.checkState(func(s proxy.DPSyncerState) {
					Expect(len(s.SvcMap)).To(Equal(2))
					Expect(len(s.EpsMap)).To(Equal(2))
					Expect(len(s.StaleUDPEps)).To(Equal(0))
					Expect(len(s.StaleUDPSvcs)).To(Equal(0))
				})
			})

			By("deleting an endpoint of the second-service", func() {
				err := k8s.Tracker().Update(v1.SchemeGroupVersion.WithResource("endpoints"),
					&v1.Endpoints{
						TypeMeta:   typeMetaV1("Endpoints"),
						ObjectMeta: objectMeataV1("second-service"),
						Subsets: []v1.EndpointSubset{
							{
								Addresses: []v1.EndpointAddress{
									{
										IP: "10.1.2.11",
									},
								},
								Ports: []v1.EndpointPort{
									{
										Port: 1221,
									},
								},
							},
						},
					},
					"default")
				Expect(err).NotTo(HaveOccurred())

				secondSvcEpsKey := k8sp.ServicePortName{
					NamespacedName: types.NamespacedName{
						Namespace: secondSvcEps.ObjectMeta.Namespace,
						Name:      secondSvcEps.ObjectMeta.Name,
					},
				}

				dp.checkState(func(s proxy.DPSyncerState) {
					Expect(len(s.SvcMap)).To(Equal(2))
					Expect(len(s.EpsMap)).To(Equal(2))
					Expect(len(s.EpsMap[secondSvcEpsKey])).To(Equal(1))
					Expect(len(s.StaleUDPEps)).To(Equal(0))
					Expect(len(s.StaleUDPSvcs)).To(Equal(0))
				})
			})

			By("deleting the second-service", func() {
				err := k8s.Tracker().Delete(v1.SchemeGroupVersion.WithResource("services"),
					"default", "second-service")
				Expect(err).NotTo(HaveOccurred())

				dp.checkState(func(s proxy.DPSyncerState) {
					Expect(len(s.SvcMap)).To(Equal(1))
					Expect(len(s.EpsMap)).To(Equal(2))
					Expect(len(s.StaleUDPEps)).To(Equal(0))
					Expect(len(s.StaleUDPSvcs)).To(Equal(1))
				})
			})

			By("adding Endpoints with named ports", func() {
				httpSvcEps := &v1.Endpoints{
					TypeMeta:   typeMetaV1("Endpoints"),
					ObjectMeta: objectMeataV1("http-service"),
					Subsets: []v1.EndpointSubset{
						{
							Addresses: []v1.EndpointAddress{
								{
									IP:       "10.1.2.111",
									NodeName: strPtr("testnode"),
								},
								{
									IP:       "10.1.2.222",
									NodeName: strPtr("anothertestnode"),
								},
							},
							Ports: []v1.EndpointPort{
								{
									Name: "http",
									Port: 80,
								},
								{
									Name: "http-alt",
									Port: 8080,
								},
								{
									Name: "https",
									Port: 443,
								},
							},
						},
					},
				}

				err := k8s.Tracker().Add(httpSvcEps)
				Expect(err).NotTo(HaveOccurred())

				dp.checkState(func(s proxy.DPSyncerState) {
					for _, port := range httpSvcEps.Subsets[0].Ports {
						Expect(len(s.SvcMap)).To(Equal(1))
						Expect(len(s.EpsMap)).To(Equal(5))
						Expect(len(s.StaleUDPEps)).To(Equal(0))
						Expect(len(s.StaleUDPSvcs)).To(Equal(0))

						ep := s.EpsMap[k8sp.ServicePortName{
							NamespacedName: types.NamespacedName{
								Namespace: httpSvcEps.ObjectMeta.Namespace,
								Name:      httpSvcEps.ObjectMeta.Name,
							},
							Port: port.Name,
						}]

						Expect(len(ep)).To(Equal(2))
						Expect(ep[0].GetIsLocal).NotTo(Equal(ep[1].GetIsLocal))
					}
				})
			})

			By("including endpoints without service", func() {
				err := k8s.Tracker().Add(
					&v1.Endpoints{
						TypeMeta:   typeMetaV1("Endpoints"),
						ObjectMeta: objectMeataV1("noservice"),
						Subsets: []v1.EndpointSubset{
							{
								Addresses: []v1.EndpointAddress{
									{
										IP: "10.1.2.244",
									},
								},
								Ports: []v1.EndpointPort{
									{
										Port: 666,
									},
								},
							},
						},
					})
				Expect(err).NotTo(HaveOccurred())

				dp.checkState(func(s proxy.DPSyncerState) {
					Expect(len(s.SvcMap)).To(Equal(1))
					Expect(len(s.EpsMap)).To(Equal(6))
					Expect(len(s.StaleUDPEps)).To(Equal(0))
					Expect(len(s.StaleUDPSvcs)).To(Equal(0))
				})
			})

			By("adding a NodePort", func() {
				nodeport := &v1.Service{
					TypeMeta:   typeMetaV1("Service"),
					ObjectMeta: objectMeataV1("nodeport"),
					Spec: v1.ServiceSpec{
						ClusterIP: "10.1.0.1",
						Type:      v1.ServiceTypeNodePort,
						Selector: map[string]string{
							"app": "test",
						},
						Ports: []v1.ServicePort{
							{
								Protocol: v1.ProtocolTCP,
								Port:     1234,
								NodePort: 32678,
							},
						},
					},
				}

				nodeportEps := &v1.Endpoints{
					TypeMeta:   typeMetaV1("Endpoints"),
					ObjectMeta: objectMeataV1("nodeport"),
					Subsets: []v1.EndpointSubset{
						{
							Addresses: []v1.EndpointAddress{
								{
									IP: "10.1.2.1",
								},
							},
							Ports: []v1.EndpointPort{
								{
									Port: 1234,
								},
							},
						},
					},
				}

				err := k8s.Tracker().Add(nodeport)
				Expect(err).NotTo(HaveOccurred())
				dp.checkState(func(s proxy.DPSyncerState) { /* just consume the event */ })

				err = k8s.Tracker().Add(nodeportEps)
				Expect(err).NotTo(HaveOccurred())

				dp.checkState(func(s proxy.DPSyncerState) {
					Expect(len(s.SvcMap)).To(Equal(2))
					Expect(len(s.EpsMap)).To(Equal(7))
					Expect(len(s.StaleUDPEps)).To(Equal(0))
					Expect(len(s.StaleUDPSvcs)).To(Equal(0))

					npKey := k8sp.ServicePortName{
						NamespacedName: types.NamespacedName{
							Name:      "nodeport",
							Namespace: "default",
						},
					}

					Expect(s.SvcMap[npKey].Port()).
						To(Equal(int(nodeport.Spec.Ports[0].Port)))
					Expect(s.SvcMap[npKey].NodePort()).To(Equal(int(nodeport.Spec.Ports[0].NodePort)))
				})
			})
		})
	})

	Describe("ExternalPolicy=local", func() {
		var p proxy.Proxy
		var dp *mockSyncer

		testNodeName := "testnode"
		testNodeNameOther := "someothernode"

		nodeport := &v1.Service{
			TypeMeta:   typeMetaV1("Service"),
			ObjectMeta: objectMeataV1("nodeport"),
			Spec: v1.ServiceSpec{
				ClusterIP: "10.1.0.1",
				Type:      v1.ServiceTypeNodePort,
				Selector: map[string]string{
					"app": "test",
				},
				Ports: []v1.ServicePort{
					{
						Protocol: v1.ProtocolTCP,
						Port:     1234,
						NodePort: 32678,
					},
				},
				ExternalTrafficPolicy: "local",
			},
		}

		nodeportEps := &v1.Endpoints{
			TypeMeta:   typeMetaV1("Endpoints"),
			ObjectMeta: objectMeataV1("nodeport"),
			Subsets: []v1.EndpointSubset{
				{
					Addresses: []v1.EndpointAddress{
						{
							IP:       "10.1.2.1",
							NodeName: &testNodeName,
						},
						{
							IP:       "10.1.2.2",
							NodeName: &testNodeNameOther,
						},
						{
							IP:       "10.1.2.3",
							NodeName: nil,
						},
					},
					Ports: []v1.EndpointPort{
						{
							Port: 1234,
						},
					},
				},
			},
		}

		k8s := fake.NewSimpleClientset(nodeport, nodeportEps)

		BeforeEach(func() {
			By("creating proxy with fake client and mock syncer", func() {
				var err error

				syncStop = make(chan struct{})
				dp = newMockSyncer(syncStop)

				p, err = proxy.New(k8s, dp, testNodeName, proxy.WithMinSyncPeriod(200*time.Millisecond))
				Expect(err).NotTo(HaveOccurred())
			})
		})

		AfterEach(func() {
			By("stopping the proxy", func() {
				close(syncStop)
				p.Stop()
			})
		})

		It("should set local correctly", func() {
			dp.checkState(func(s proxy.DPSyncerState) {
				Expect(s.SvcMap).To(HaveLen(1))
				for k := range s.SvcMap {
					for _, ep := range s.EpsMap[k] {
						Expect(ep.GetIsLocal()).To(Equal(ep.String() == "10.1.2.1:1234"))
					}
				}
			})
		})
	})
})

type mockSyncer struct {
	out  chan proxy.DPSyncerState
	in   chan error
	stop chan struct{}
}

func newMockSyncer(stop chan struct{}) *mockSyncer {
	return &mockSyncer{
		out:  make(chan proxy.DPSyncerState),
		in:   make(chan error),
		stop: stop,
	}
}

func (s *mockSyncer) Stop() {}

func (s *mockSyncer) Apply(state proxy.DPSyncerState) error {
	log("SvcMap = %+v\n", state.SvcMap)
	log("EpsMap = %+v\n", state.EpsMap)
	select {
	case s.out <- state:
		return <-s.in
	case <-s.stop:
		return nil
	}
}

func (s *mockSyncer) checkState(f func(proxy.DPSyncerState)) {
	// defer to recover/unblock in case of expectations failing in f()
	defer func() { s.in <- nil }()
	f(<-s.out)
}

func typeMetaV1(kind string) metav1.TypeMeta {
	return metav1.TypeMeta{
		Kind:       kind,
		APIVersion: "v1",
	}
}

func objectMeataV1(name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:      name,
		Namespace: "default",
	}
}

func strPtr(s string) *string {
	return &s
}
