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
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"

	proxy "github.com/projectcalico/calico/felix/bpf/proxy"
)

var _ = Describe("BPF Proxy healthCheckNodeport", func() {
	var p proxy.Proxy
	k8s := fake.NewSimpleClientset()

	testNodeName := "testnode"
	testNodeNameOther := "anothertestnode"

	BeforeEach(func() {
		By("creating proxy with fake client and mock syncer", func() {
			var err error

			p, err = proxy.New(k8s, &mockDummySyncer{},
				testNodeName, proxy.WithMinSyncPeriod(200*time.Millisecond))
			Expect(err).NotTo(HaveOccurred())
		})
	})

	AfterEach(func() {
		By("stopping the proxy", func() {
			p.Stop()
		})
	})

	It("should expose health check enpoint", func() {
		healthCheckNodePort := 1212

		By("adding a LoadBalancer", func() {
			err := k8s.Tracker().Add(&v1.Service{
				TypeMeta:   typeMetaV1("Service"),
				ObjectMeta: objectMeataV1("LB"),
				Spec: v1.ServiceSpec{
					ClusterIP: "10.1.0.1",
					Type:      v1.ServiceTypeLoadBalancer,
					Selector: map[string]string{
						"app": "test",
					},
					ExternalTrafficPolicy: "Local",
					HealthCheckNodePort:   int32(healthCheckNodePort),
					Ports: []v1.ServicePort{
						{
							Protocol:   v1.ProtocolTCP,
							Port:       4321,
							TargetPort: intstr.FromInt(32678),
						},
					},
				},
			})
			Expect(err).NotTo(HaveOccurred())
		})

		By("adding its endpoints", func() {
			err := k8s.Tracker().Add(&v1.Endpoints{
				TypeMeta:   typeMetaV1("Endpoints"),
				ObjectMeta: objectMeataV1("LB"),
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
			})
			Expect(err).NotTo(HaveOccurred())
		})

		By("checking that the healthCheckNodePort is accessable", func() {
			Eventually(func() error {
				result, err := http.Get(fmt.Sprintf("http://localhost:%d", healthCheckNodePort))
				if err != nil {
					return err
				}
				if result.StatusCode != 503 {
					return fmt.Errorf("Unexpected status code %d; expected 503", result.StatusCode)
				}
				return nil
			}, "5s", "200ms").Should(Succeed())
		})

		By("checking that there is no local endpoint", func() {
			result, err := http.Get(fmt.Sprintf("http://localhost:%d", healthCheckNodePort))
			Expect(err).NotTo(HaveOccurred())
			Expect(result.StatusCode).Should(Equal(503))

			var status map[string]interface{}

			decoder := json.NewDecoder(result.Body)
			err = decoder.Decode(&status)
			Expect(err).NotTo(HaveOccurred())

			Expect(status).To(HaveKey("localEndpoints"))
			Expect(int(status["localEndpoints"].(float64))).To(Equal(0))
		})

		By("adding a local and a non-local endpoint", func() {
			err := k8s.Tracker().Update(v1.SchemeGroupVersion.WithResource("endpoints"),
				&v1.Endpoints{
					TypeMeta:   typeMetaV1("Endpoints"),
					ObjectMeta: objectMeataV1("LB"),
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
							},
							Ports: []v1.EndpointPort{
								{
									Port: 1234,
								},
							},
						},
					},
				},
				"default")
			Expect(err).NotTo(HaveOccurred())
		})

		By("checking that there is a local endpoint", func() {
			Eventually(func() error {
				result, err := http.Get(fmt.Sprintf("http://localhost:%d", healthCheckNodePort))
				if err != nil {
					return err
				}
				if result.StatusCode != 200 {
					return fmt.Errorf("Unexpected status code %d; expected 200", result.StatusCode)
				}

				var status map[string]interface{}

				decoder := json.NewDecoder(result.Body)
				err = decoder.Decode(&status)
				if err != nil {
					return err
				}

				if int(status["localEndpoints"].(float64)) != 1 {
					return fmt.Errorf("Expected 1 endpoint got %d", int(status["localEndpoints"].(float64)))
				}

				return nil
			}, "5s", "200ms").Should(Succeed())

			By("making non-local a local endpoint", func() {
				err := k8s.Tracker().Update(v1.SchemeGroupVersion.WithResource("endpoints"),
					&v1.Endpoints{
						TypeMeta:   typeMetaV1("Endpoints"),
						ObjectMeta: objectMeataV1("LB"),
						Subsets: []v1.EndpointSubset{
							{
								Addresses: []v1.EndpointAddress{
									{
										IP:       "10.1.2.1",
										NodeName: &testNodeName,
									},
									{
										IP:       "10.1.2.2",
										NodeName: &testNodeName,
									},
								},
								Ports: []v1.EndpointPort{
									{
										Port: 1234,
									},
								},
							},
						},
					},
					"default")
				Expect(err).NotTo(HaveOccurred())
			})

			By("checking that there is a local endpoint", func() {
				Eventually(func() error {
					result, err := http.Get(fmt.Sprintf("http://localhost:%d", healthCheckNodePort))
					if err != nil {
						return err
					}
					if result.StatusCode != 200 {
						return fmt.Errorf("Unexpected status code %d; expected 200", result.StatusCode)
					}

					var status map[string]interface{}

					decoder := json.NewDecoder(result.Body)
					err = decoder.Decode(&status)
					if err != nil {
						return err
					}

					if int(status["localEndpoints"].(float64)) != 2 {
						return fmt.Errorf("Expected 1 endpoint got %d", int(status["localEndpoints"].(float64)))
					}

					return nil
				}, "5s", "200ms").Should(Succeed())
			})
		})
	})
})

type mockDummySyncer struct {
	syncerConntrackAPIDummy
}

func (s *mockDummySyncer) SetTriggerFn(f func()) {
}

func (*mockDummySyncer) Stop() {}

func (*mockDummySyncer) Apply(state proxy.DPSyncerState) error {
	log("state = %+v\n", state)
	return nil
}
