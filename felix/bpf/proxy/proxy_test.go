// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.
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
	"net"
	"runtime"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8sp "k8s.io/kubernetes/pkg/proxy"

	"github.com/projectcalico/calico/felix/bpf/proxy"
)

func log(format string, a ...interface{}) {
	fmt.Fprintf(GinkgoWriter, format, a...)
}

var _ = Describe("BPF Proxy", func() {
	var syncStop chan struct{}

	It("should fail without k8s client", func() {
		_, err := proxy.New(nil, nil, "testnode", nil)
		Expect(err).To(HaveOccurred())

		_, err = proxy.New(fake.NewSimpleClientset(), nil, "testnode", nil)
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
		})
	})

	testSvc := &v1.Service{
		TypeMeta:   typeMetaV1("Service"),
		ObjectMeta: objectMetaV1("testService"),
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

	testSvcEpsSlice := epsToSlice(&v1.Endpoints{
		TypeMeta:   typeMetaV1("Endpoints"),
		ObjectMeta: objectMetaV1("testService"),
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
						Name: "1234",
					},
				},
			},
		},
	})

	secondSvc := &v1.Service{
		TypeMeta:   typeMetaV1("Service"),
		ObjectMeta: objectMetaV1("second-service"),
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
					Name:     "1221",
				},
			},
		},
	}

	secondSvcEpsSlice := epsToSlice(&v1.Endpoints{
		TypeMeta:   typeMetaV1("Endpoints"),
		ObjectMeta: objectMetaV1("second-service"),
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
						Port:     1221,
						Name:     "1221",
						Protocol: v1.ProtocolTCP,
					},
				},
			},
		},
	})

	Describe("with k8s client", func() {
		var (
			p   proxy.Proxy
			dp  *mockSyncer
			k8s *fake.Clientset
		)

		JustBeforeEach(func() {
			By("creating proxy with fake client and mock syncer", func() {
				var err error

				syncStop = make(chan struct{})
				dp = newMockSyncer(syncStop)

				opts := []proxy.Option{proxy.WithImmediateSync()}

				p, err = proxy.New(k8s, dp, "testnode", opts...)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		AfterEach(func() {
			By("stopping the proxy", func() {
				close(syncStop)
				p.Stop()
			})
		})

		Context("with EndpointSlices", func() {

			BeforeEach(func() {
				k8s = fake.NewSimpleClientset(testSvc, testSvcEpsSlice, secondSvc, secondSvcEpsSlice)
			})

			It("should make the right transitions", func() {

				By("getting the initial sync", func() {
					dp.checkState(func(s proxy.DPSyncerState) {
						Expect(len(s.SvcMap)).To(Equal(2))
						Expect(len(s.EpsMap)).To(Equal(2))
					})
				})

				By("adding a service", func() {
					err := k8s.Tracker().Add(
						&v1.Service{
							TypeMeta:   typeMetaV1("Service"),
							ObjectMeta: objectMetaV1("added"),
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
					})
				})

				By("deleting the last added service", func() {
					err := k8s.Tracker().Delete(v1.SchemeGroupVersion.WithResource("services"), "default", "added")
					Expect(err).NotTo(HaveOccurred())

					dp.checkState(func(s proxy.DPSyncerState) {
						Expect(len(s.SvcMap)).To(Equal(2))
						Expect(len(s.EpsMap)).To(Equal(2))
					})
				})

				By("deleting an endpoint of the second-service", func() {
					eps := &v1.Endpoints{
						TypeMeta:   typeMetaV1("Endpoints"),
						ObjectMeta: objectMetaV1("second-service"),
						Subsets: []v1.EndpointSubset{
							{
								Addresses: []v1.EndpointAddress{
									{
										IP: "10.1.2.11",
									},
								},
								Ports: []v1.EndpointPort{
									{
										Port:     1221,
										Name:     "1221",
										Protocol: v1.ProtocolTCP,
									},
								},
							},
						},
					}

					slice := epsToSlice(eps)
					err := k8s.Tracker().Update(discovery.SchemeGroupVersion.WithResource("endpointslices"),
						slice, "default")
					Expect(err).NotTo(HaveOccurred())

					secondSvcEpsKey := k8sp.ServicePortName{
						NamespacedName: types.NamespacedName{
							Namespace: secondSvcEpsSlice.ObjectMeta.Namespace,
							Name:      secondSvcEpsSlice.ObjectMeta.Name,
						},
						Port:     eps.Subsets[0].Ports[0].Name,
						Protocol: v1.ProtocolTCP,
					}

					dp.checkState(func(s proxy.DPSyncerState) {
						Expect(len(s.SvcMap)).To(Equal(2))
						Expect(len(s.EpsMap)).To(Equal(2))
						Expect(len(s.EpsMap[secondSvcEpsKey])).To(Equal(1))
					})
				})

				By("deleting the second-service", func() {
					err := k8s.Tracker().Delete(v1.SchemeGroupVersion.WithResource("services"),
						"default", "second-service")
					Expect(err).NotTo(HaveOccurred())

					dp.checkState(func(s proxy.DPSyncerState) {
						Expect(len(s.SvcMap)).To(Equal(1))
						Expect(len(s.EpsMap)).To(Equal(2))
					})
				})

				By("adding Endpoints with named ports", func() {
					httpSvcEps := &v1.Endpoints{
						TypeMeta:   typeMetaV1("Endpoints"),
						ObjectMeta: objectMetaV1("http-service"),
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
										Name:     "http",
										Port:     80,
										Protocol: v1.ProtocolTCP,
									},
									{
										Name:     "http-alt",
										Port:     8080,
										Protocol: v1.ProtocolTCP,
									},
									{
										Name:     "https",
										Port:     443,
										Protocol: v1.ProtocolTCP,
									},
								},
							},
						},
					}

					err := k8s.Tracker().Add(epsToSlice(httpSvcEps))
					Expect(err).NotTo(HaveOccurred())

					dp.checkState(func(s proxy.DPSyncerState) {
						for _, port := range httpSvcEps.Subsets[0].Ports {
							Expect(len(s.SvcMap)).To(Equal(1))
							Expect(len(s.EpsMap)).To(Equal(5))

							ep := s.EpsMap[k8sp.ServicePortName{
								NamespacedName: types.NamespacedName{
									Namespace: httpSvcEps.ObjectMeta.Namespace,
									Name:      httpSvcEps.ObjectMeta.Name,
								},
								Port:     port.Name,
								Protocol: v1.ProtocolTCP,
							}]

							Expect(len(ep)).To(Equal(2))
							Expect(ep[0].IsLocal()).NotTo(Equal(ep[1].IsLocal()))
						}
					})
				})

				By("including endpoints without service", func() {
					eps := &v1.Endpoints{
						TypeMeta:   typeMetaV1("Endpoints"),
						ObjectMeta: objectMetaV1("noservice"),
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
					}

					err := k8s.Tracker().Add(epsToSlice(eps))
					Expect(err).NotTo(HaveOccurred())

					dp.checkState(func(s proxy.DPSyncerState) {
						Expect(len(s.SvcMap)).To(Equal(1))
						Expect(len(s.EpsMap)).To(Equal(6))
					})
				})

				By("adding a NodePort", func() {
					nodeport := &v1.Service{
						TypeMeta:   typeMetaV1("Service"),
						ObjectMeta: objectMetaV1("nodeport"),
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
						ObjectMeta: objectMetaV1("nodeport"),
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

					err = k8s.Tracker().Add(epsToSlice(nodeportEps))
					Expect(err).NotTo(HaveOccurred())

					dp.checkState(func(s proxy.DPSyncerState) {
						Expect(len(s.SvcMap)).To(Equal(2))
						Expect(len(s.EpsMap)).To(Equal(7))

						npKey := k8sp.ServicePortName{
							NamespacedName: types.NamespacedName{
								Name:      "nodeport",
								Namespace: "default",
							},
							Protocol: "TCP",
						}
						Expect(s.SvcMap).To(HaveKey(npKey))
						Expect(s.SvcMap[npKey].Port()).
							To(Equal(int(nodeport.Spec.Ports[0].Port)))
						Expect(s.SvcMap[npKey].NodePort()).To(Equal(int(nodeport.Spec.Ports[0].NodePort)))
					})
				})
			})
		},
		)

		Describe("ExternalPolicy=Local with k8s client", func() {
			Context("ExternalPolicy=Local with EndpointSlices", func() {

				testNodeName := "testnode"
				testNodeNameOther := "someothernode"

				nodeport := &v1.Service{
					TypeMeta:   typeMetaV1("Service"),
					ObjectMeta: objectMetaV1("nodeport"),
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
						ExternalTrafficPolicy: "Local",
					},
				}

				nodeportEps := &v1.Endpoints{
					TypeMeta:   typeMetaV1("Endpoints"),
					ObjectMeta: objectMetaV1("nodeport"),
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

				BeforeEach(func() {
					k8s = fake.NewSimpleClientset(nodeport, epsToSlice(nodeportEps))
				})

				It("should set local correctly", func() {
					dp.checkState(func(s proxy.DPSyncerState) {
						Expect(s.SvcMap).To(HaveLen(1))
						for k := range s.SvcMap {
							for _, ep := range s.EpsMap[k] {
								Expect(ep.IsLocal()).To(Equal(ep.String() == "10.1.2.1:1234"))
							}
						}
					})
				})
			},
			)
		})

		Context("with terminating workloads", func() {
			BeforeEach(func() {
				k8s = fake.NewSimpleClientset(testSvc, testSvcEpsSlice)
			})

			It("should see IsReady=false and IsTerminating=true", func() {
				By("getting the initial sync")

				dp.checkState(func(s proxy.DPSyncerState) {
					Expect(len(s.SvcMap)).To(Equal(1))
					Expect(len(s.EpsMap)).To(Equal(1))

				})

				By("placing one endpoint to terminating state")

				falsePtr := new(bool)
				*falsePtr = false

				truePtr := new(bool)
				*truePtr = true

				testSvcEpsSlice.Endpoints[0].Conditions.Ready = falsePtr
				testSvcEpsSlice.Endpoints[0].Conditions.Terminating = truePtr
				err := k8s.Tracker().Update(discovery.SchemeGroupVersion.WithResource("endpointslices"),
					testSvcEpsSlice, "default")
				Expect(err).NotTo(HaveOccurred())

				dp.checkState(func(s proxy.DPSyncerState) {
					Expect(len(s.SvcMap)).To(Equal(1))
					Expect(len(s.EpsMap)).To(Equal(1))

					var key k8sp.ServicePortName

					for key = range s.EpsMap {
					}

					isReady := 0
					isTerminating := 0
					for _, ep := range s.EpsMap[key] {
						if ep.IsReady() {
							isReady++
						}
						if ep.IsTerminating() {
							isTerminating++
						}
					}
					Expect(isReady).To(Equal(1))
					Expect(isTerminating).To(Equal(1))
				})
			})
		})

		Context("annotated service", func() {
			BeforeEach(func() {
				testSvc := &v1.Service{
					TypeMeta:   typeMetaV1("Service"),
					ObjectMeta: objectMetaV1("testService"),
					Spec: v1.ServiceSpec{
						ClusterIP: "10.1.0.1",
						Type:      v1.ServiceTypeClusterIP,
						Selector: map[string]string{
							"app": "test",
						},
						Ports: []v1.ServicePort{
							{
								Protocol: v1.ProtocolUDP,
								Port:     1234,
							},
						},
					},
				}

				testSvc.ObjectMeta.Annotations = map[string]string{
					proxy.ReapTerminatingUDPAnnotation: proxy.ReapTerminatingUDPImmediatelly,
				}

				k8s = fake.NewSimpleClientset(testSvc)
			})

			It("Should see the annotation", func() {
				dp.checkState(func(s proxy.DPSyncerState) {
					Expect(len(s.SvcMap)).To(Equal(1))
					Expect(len(s.EpsMap)).To(Equal(0))
					Expect(s.SvcMap[k8sp.ServicePortName{
						NamespacedName: types.NamespacedName{
							Namespace: "default",
							Name:      "testService",
						},
						Protocol: v1.ProtocolUDP,
					}].(proxy.Service).ReapTerminatingUDP()).To(BeTrue())
				})
			})
		})
	})
})

type mockSyncer struct {
	syncerConntrackAPIDummy
	out  chan proxy.DPSyncerState
	in   chan error
	stop chan struct{}
}

func (s *mockSyncer) SetTriggerFn(f func()) {
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

type syncerConntrackAPIDummy struct{}

func (*syncerConntrackAPIDummy) ConntrackScanStart() {}
func (*syncerConntrackAPIDummy) ConntrackScanEnd()   {}
func (*syncerConntrackAPIDummy) ConntrackFrontendHasBackend(ip net.IP, port uint16, backendIP net.IP,
	backendPort uint16, proto uint8) bool {
	return false
}

func (s *mockSyncer) checkState(f func(proxy.DPSyncerState)) {
	tickC := time.After(10 * time.Second)

	var fails []string

	// Since the k8s changes may not come atomically, we wait for the state to
	// be eventually what we expected
	for {
		select {
		case state, ok := <-s.out:
			if !ok {
				Fail("checkState : s.out closed")
			}
			fails = InterceptGomegaFailures(func() {
				// defer to recover/unblock in case of expectations failing in f()
				defer func() { s.in <- nil }()
				f(state)
			})

			if len(fails) == 0 {
				return
			}

		case <-tickC:
			_, file, line, _ := runtime.Caller(1)

			var msg string
			for _, f := range fails {
				msg += "\n" + f
			}

			Fail(fmt.Sprintf(
				"checkState timed out at File: %s Line: %d, last failed expectations: %s",
				file, line, msg,
			))
		}
	}
}

func typeMetaV1(kind string) metav1.TypeMeta {
	return metav1.TypeMeta{
		Kind:       kind,
		APIVersion: "v1",
	}
}

func objectMetaV1(name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:      name,
		Namespace: metav1.NamespaceDefault,
	}
}

func strPtr(s string) *string {
	return &s
}

func epsToSlice(eps *v1.Endpoints) *discovery.EndpointSlice {
	slice := &discovery.EndpointSlice{
		TypeMeta: metav1.TypeMeta{
			Kind:       "EndpointSlice",
			APIVersion: "discovery.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      eps.ObjectMeta.Name,
			Namespace: eps.ObjectMeta.Namespace,
			Labels: map[string]string{
				"kubernetes.io/service-name": eps.ObjectMeta.Name,
			},
		},
		AddressType: discovery.AddressTypeIPv4,
	}

	truePtr := new(bool)
	*truePtr = true

	for i, subset := range eps.Subsets {
		for _, addr := range subset.Addresses {
			slice.Endpoints = append(slice.Endpoints, discovery.Endpoint{
				Addresses: []string{addr.IP},
				Hostname:  &addr.Hostname,
				NodeName:  addr.NodeName,
				Conditions: discovery.EndpointConditions{
					Ready: truePtr,
				},
			})
		}

		for j, p := range subset.Ports {
			port := p
			ep := discovery.EndpointPort{
				Port: &port.Port,
			}

			if port.Name != "" {
				ep.Name = &port.Name
			} else {
				name := fmt.Sprintf("port-%d-%d-%d", i, j, port.Port)
				ep.Name = &name
			}

			if port.Protocol != "" {
				ep.Protocol = &port.Protocol
			} else {
				tcp := v1.ProtocolTCP
				ep.Protocol = &tcp
			}

			slice.Ports = append(slice.Ports, ep)
		}
	}

	return slice
}
