// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.

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

package resources_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/types"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/names"

	k8sapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

var _ = Describe("WorkloadEndpointClient", func() {
	ctx := context.Background()

	Describe("Create", func() {
		Context("WorkloadEndpoint has no IPs set", func() {
			It("does not set the cni.projectcalico.org/podIP and cni.projectcalico.org/podIPs annotations", func() {
				k8sClient := fake.NewSimpleClientset(&k8sapi.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "simplePod",
						Namespace: "testNamespace",
					},
					Spec: k8sapi.PodSpec{
						NodeName: "test-node",
					},
				})

				wepClient := resources.NewWorkloadEndpointClient(k8sClient)

				wepIDs := names.WorkloadEndpointIdentifiers{
					Orchestrator: "k8s",
					Node:         "test-node",
					Pod:          "simplePod",
					Endpoint:     "eth0",
				}

				wepName, err := wepIDs.CalculateWorkloadEndpointName(false)
				Expect(err).ShouldNot(HaveOccurred())
				wep := &libapiv3.WorkloadEndpoint{
					ObjectMeta: metav1.ObjectMeta{
						Name:      wepName,
						Namespace: "testNamespace",
					},
					Spec: libapiv3.WorkloadEndpointSpec{
						IPNetworks: []string{},
					},
				}

				kvp := &model.KVPair{
					Key: model.ResourceKey{
						Name:      wep.Name,
						Namespace: wep.Namespace,
						Kind:      libapiv3.KindWorkloadEndpoint,
					},
					Value: wep,
				}

				ctxCNI := resources.ContextWithPatchMode(context.Background(), resources.PatchModeCNI)
				_, err = wepClient.Create(ctxCNI, kvp)
				Expect(err).ShouldNot(HaveOccurred())

				pod, err := k8sClient.CoreV1().Pods("testNamespace").Get(ctx, "simplePod", metav1.GetOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(pod.GetAnnotations()).Should(BeNil())
			})
		})
		Context("WorkloadEndpoint has IPs set", func() {
			It("sets the cni.projectcalico.org/podIP and cni.projectcalico.org/podIPs annotations to the WorkloadEndpoint IPs", func() {
				k8sClient := fake.NewSimpleClientset(&k8sapi.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "simplePod",
						Namespace: "testNamespace",
					},
					Spec: k8sapi.PodSpec{
						NodeName: "test-node",
					},
				})

				wepClient := resources.NewWorkloadEndpointClient(k8sClient)
				wepIDs := names.WorkloadEndpointIdentifiers{
					Orchestrator: "k8s",
					Node:         "test-node",
					Pod:          "simplePod",
					Endpoint:     "eth0",
				}

				wepName, err := wepIDs.CalculateWorkloadEndpointName(false)
				Expect(err).ShouldNot(HaveOccurred())
				wep := &libapiv3.WorkloadEndpoint{
					ObjectMeta: metav1.ObjectMeta{
						Name:      wepName,
						Namespace: "testNamespace",
					},
					Spec: libapiv3.WorkloadEndpointSpec{
						ContainerID: "abcde12345",
						IPNetworks:  []string{"192.168.91.117/32", "192.168.91.118/32"},
					},
				}

				kvp := &model.KVPair{
					Key: model.ResourceKey{
						Name:      wep.Name,
						Namespace: wep.Namespace,
						Kind:      libapiv3.KindWorkloadEndpoint,
					},
					Value: wep,
				}

				ctxCNI := resources.ContextWithPatchMode(context.Background(), resources.PatchModeCNI)
				_, err = wepClient.Create(ctxCNI, kvp)
				Expect(err).ShouldNot(HaveOccurred())

				pod, err := k8sClient.CoreV1().Pods("testNamespace").Get(ctx, "simplePod", metav1.GetOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(pod.GetAnnotations()).Should(Equal(map[string]string{
					conversion.AnnotationPodIP:       "192.168.91.117/32",
					conversion.AnnotationPodIPs:      "192.168.91.117/32,192.168.91.118/32",
					conversion.AnnotationContainerID: "abcde12345",
				}))
			})
		})
	})
	Describe("Update", func() {
		Context("WorkloadEndpoint has no IPs set", func() {
			It("does not set the cni.projectcalico.org/podIP and cni.projectcalico.org/podIPs annotations", func() {
				k8sClient := fake.NewSimpleClientset(&k8sapi.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "simplePod",
						Namespace: "testNamespace",
					},
					Spec: k8sapi.PodSpec{
						NodeName: "test-node",
					},
				})

				wepClient := resources.NewWorkloadEndpointClient(k8sClient)
				wepIDs := names.WorkloadEndpointIdentifiers{
					Orchestrator: "k8s",
					Node:         "test-node",
					Pod:          "simplePod",
					Endpoint:     "eth0",
				}

				wepName, err := wepIDs.CalculateWorkloadEndpointName(false)
				Expect(err).ShouldNot(HaveOccurred())
				wep := &libapiv3.WorkloadEndpoint{
					ObjectMeta: metav1.ObjectMeta{
						Name:      wepName,
						Namespace: "testNamespace",
					},
					Spec: libapiv3.WorkloadEndpointSpec{
						IPNetworks: []string{},
					},
				}

				kvp := &model.KVPair{
					Key: model.ResourceKey{
						Name:      wep.Name,
						Namespace: wep.Namespace,
						Kind:      libapiv3.KindWorkloadEndpoint,
					},
					Value: wep,
				}

				ctxCNI := resources.ContextWithPatchMode(context.Background(), resources.PatchModeCNI)
				_, err = wepClient.Update(ctxCNI, kvp)
				Expect(err).ShouldNot(HaveOccurred())

				pod, err := k8sClient.CoreV1().Pods("testNamespace").Get(ctx, "simplePod", metav1.GetOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(pod.GetAnnotations()).Should(BeNil())
			})
		})
		Context("WorkloadEndpoint has IPs set", func() {
			It("sets the cni.projectcalico.org/podIP and cni.projectcalico.org/podIPs annotations to the WorkloadEndpoint IPs", func() {
				k8sClient := fake.NewSimpleClientset(&k8sapi.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "simplePod",
						Namespace: "testNamespace",
					},
					Spec: k8sapi.PodSpec{
						NodeName: "test-node",
					},
				})

				wepClient := resources.NewWorkloadEndpointClient(k8sClient)
				wepIDs := names.WorkloadEndpointIdentifiers{
					Orchestrator: "k8s",
					Node:         "test-node",
					Pod:          "simplePod",
					Endpoint:     "eth0",
				}

				wepName, err := wepIDs.CalculateWorkloadEndpointName(false)
				Expect(err).ShouldNot(HaveOccurred())
				wep := &libapiv3.WorkloadEndpoint{
					ObjectMeta: metav1.ObjectMeta{
						Name:      wepName,
						Namespace: "testNamespace",
					},
					Spec: libapiv3.WorkloadEndpointSpec{
						IPNetworks:  []string{"192.168.91.117/32", "192.168.91.118/32"},
						ContainerID: "abcd1234",
					},
				}

				kvp := &model.KVPair{
					Key: model.ResourceKey{
						Name:      wep.Name,
						Namespace: wep.Namespace,
						Kind:      libapiv3.KindWorkloadEndpoint,
					},
					Value: wep,
				}

				ctxCNI := resources.ContextWithPatchMode(context.Background(), resources.PatchModeCNI)
				_, err = wepClient.Update(ctxCNI, kvp)
				Expect(err).ShouldNot(HaveOccurred())

				pod, err := k8sClient.CoreV1().Pods("testNamespace").Get(ctx, "simplePod", metav1.GetOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(pod.GetAnnotations()).Should(Equal(map[string]string{
					conversion.AnnotationPodIP:       "192.168.91.117/32",
					conversion.AnnotationPodIPs:      "192.168.91.117/32,192.168.91.118/32",
					conversion.AnnotationContainerID: "abcd1234",
				}))
			})
		})
	})

	Describe("Delete", func() {
		Context("WorkloadEndpoint has no IPs set", func() {
			It("zeros out the annotations", func() {
				podUID := types.UID(uuid.NewString())
				k8sClient := fake.NewSimpleClientset(&k8sapi.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "simplePod",
						Namespace: "testNamespace",
						Annotations: map[string]string{
							conversion.AnnotationPodIP:       "192.168.91.117/32",
							conversion.AnnotationPodIPs:      "192.168.91.117/32,192.168.91.118/32",
							conversion.AnnotationContainerID: "abcde12345",
						},
						UID: podUID,
					},
					Spec: k8sapi.PodSpec{
						NodeName: "test-node",
					},
				})

				wepIDs := names.WorkloadEndpointIdentifiers{
					Orchestrator: "k8s",
					Node:         "test-node",
					Pod:          "simplePod",
					Endpoint:     "eth0",
				}

				wepName, err := wepIDs.CalculateWorkloadEndpointName(false)
				Expect(err).ShouldNot(HaveOccurred())

				wepClient := resources.NewWorkloadEndpointClient(k8sClient)
				key := model.ResourceKey{
					Name:      wepName,
					Namespace: "testNamespace",
					Kind:      libapiv3.KindWorkloadEndpoint,
				}
				wep, err := wepClient.Get(context.Background(), key, "")
				Expect(err).NotTo(HaveOccurred())

				// Doesn't work because the fake k8s client allows the UID to be changed.
				//
				// By("Ignoring requests with the wrong UID.")
				// wrongUID := types.UID("19e9c0f4-501d-429f-b581-8954440883f4")
				// _, err = wepClient.Delete(context.Background(), key, wep.Revision, &wrongUID)
				// Expect(err).ShouldNot(HaveOccurred())
				// pod, err := k8sClient.CoreV1().Pods("testNamespace").Get("simplePod", metav1.GetOptions{})
				// Expect(err).ShouldNot(HaveOccurred())
				// Expect(pod.GetAnnotations()).Should(Equal(map[string]string{
				// 	conversion.AnnotationPodIP:  "192.168.91.117/32",
				// 	conversion.AnnotationPodIPs: "192.168.91.117/32,192.168.91.118/32",
				// }))

				By("Accepting requests with the right UID.")
				_, err = wepClient.Delete(context.Background(), key, wep.Revision, wep.UID)
				Expect(err).ShouldNot(HaveOccurred())
				pod, err := k8sClient.CoreV1().Pods("testNamespace").Get(ctx, "simplePod", metav1.GetOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(pod.GetAnnotations()).Should(Equal(map[string]string{
					conversion.AnnotationPodIP:       "",
					conversion.AnnotationPodIPs:      "",
					conversion.AnnotationContainerID: "abcde12345",
				}))
			})
		})
	})

	Describe("Get", func() {
		It("gets the WorkloadEndpoint using the given name", func() {
			k8sClient := fake.NewSimpleClientset(&k8sapi.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "simplePod",
					Namespace: "testNamespace",
					Annotations: map[string]string{
						conversion.AnnotationContainerID: "abcde12345",
					},
				},
				Spec: k8sapi.PodSpec{
					NodeName: "test-node",
				},
			})

			wepClient := resources.NewWorkloadEndpointClient(k8sClient).(*resources.WorkloadEndpointClient)
			wepIDs := names.WorkloadEndpointIdentifiers{
				Orchestrator: "k8s",
				Node:         "test-node",
				Pod:          "simplePod",
				Endpoint:     "eth0",
			}

			wepName, err := wepIDs.CalculateWorkloadEndpointName(false)
			Expect(err).ShouldNot(HaveOccurred())

			wep, err := wepClient.Get(context.Background(), model.ResourceKey{
				Name:      wepName,
				Namespace: "testNamespace",
				Kind:      libapiv3.KindWorkloadEndpoint,
			}, "")

			Expect(err).ShouldNot(HaveOccurred())
			Expect(wep.Value).Should(Equal(&libapiv3.WorkloadEndpoint{
				TypeMeta: metav1.TypeMeta{
					Kind:       libapiv3.KindWorkloadEndpoint,
					APIVersion: apiv3.GroupVersionCurrent,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      wepName,
					Namespace: "testNamespace",
					Labels: map[string]string{
						apiv3.LabelNamespace:    "testNamespace",
						apiv3.LabelOrchestrator: "k8s",
					},
				},
				Spec: libapiv3.WorkloadEndpointSpec{
					Orchestrator:  "k8s",
					Node:          "test-node",
					Pod:           "simplePod",
					Endpoint:      "eth0",
					Profiles:      []string{"kns.testNamespace"},
					IPNetworks:    []string{},
					InterfaceName: "caliedff4356bd6",
					ContainerID:   "abcde12345",
				},
			}))
		})
	})
	Describe("List", func() {
		Context("name is specified", func() {
			Context("the name contains an end suffix", func() {
				It("returns a list of WorkloadEndpoints with the single WorkloadEndpoint with the given name", func() {
					testListWorkloadEndpoints(
						[]runtime.Object{&k8sapi.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "simplePod",
								Namespace: "testNamespace",
							},
							Spec: k8sapi.PodSpec{
								NodeName: "test-node",
							},
							Status: k8sapi.PodStatus{
								PodIP: "192.168.91.113",
							},
						}},
						model.ResourceListOptions{
							Name:      "test--node-k8s-simplePod-eth0",
							Namespace: "testNamespace",
							Kind:      libapiv3.KindWorkloadEndpoint,
						},
						[]*libapiv3.WorkloadEndpoint{{
							TypeMeta: metav1.TypeMeta{
								Kind:       libapiv3.KindWorkloadEndpoint,
								APIVersion: apiv3.GroupVersionCurrent,
							},
							ObjectMeta: metav1.ObjectMeta{
								Name:      "test--node-k8s-simplePod-eth0",
								Namespace: "testNamespace",
								Labels: map[string]string{
									apiv3.LabelNamespace:    "testNamespace",
									apiv3.LabelOrchestrator: "k8s",
								},
							},
							Spec: libapiv3.WorkloadEndpointSpec{
								Orchestrator:  "k8s",
								Node:          "test-node",
								Pod:           "simplePod",
								Endpoint:      "eth0",
								Profiles:      []string{"kns.testNamespace"},
								IPNetworks:    []string{"192.168.91.113/32"},
								InterfaceName: "caliedff4356bd6",
							},
						}},
					)
				})
				It("returns an empty list if the endpoint is specified and does not match the pods wep endpoint", func() {
					testListWorkloadEndpoints(
						[]runtime.Object{&k8sapi.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "simplePod",
								Namespace: "testNamespace",
							},
							Spec: k8sapi.PodSpec{
								NodeName: "test-node",
							},
							Status: k8sapi.PodStatus{
								PodIP: "192.168.91.113",
							},
						}},
						model.ResourceListOptions{
							Name:      "test--node-k8s-simplePod-ens4",
							Namespace: "testNamespace",
							Kind:      libapiv3.KindWorkloadEndpoint,
						},
						[]*libapiv3.WorkloadEndpoint(nil),
					)
				})
			})
			Context("the name does not contain endpoint suffix, but contains the Pod name midfix", func() {
				It("returns a list of WorkloadEndpoints with the single WorkloadEndpoint for the matching pod", func() {
					testListWorkloadEndpoints(
						[]runtime.Object{&k8sapi.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "simplePod",
								Namespace: "testNamespace",
							},
							Spec: k8sapi.PodSpec{
								NodeName: "test-node",
							},
							Status: k8sapi.PodStatus{
								PodIP: "192.168.91.113",
							},
						}},
						model.ResourceListOptions{
							Name:      "test--node-k8s-simplePod",
							Namespace: "testNamespace",
							Kind:      libapiv3.KindWorkloadEndpoint,
						},
						[]*libapiv3.WorkloadEndpoint{{
							TypeMeta: metav1.TypeMeta{
								Kind:       libapiv3.KindWorkloadEndpoint,
								APIVersion: apiv3.GroupVersionCurrent,
							},
							ObjectMeta: metav1.ObjectMeta{
								Name:      "test--node-k8s-simplePod-eth0",
								Namespace: "testNamespace",
								Labels: map[string]string{
									apiv3.LabelNamespace:    "testNamespace",
									apiv3.LabelOrchestrator: "k8s",
								},
							},
							Spec: libapiv3.WorkloadEndpointSpec{
								Orchestrator:  "k8s",
								Node:          "test-node",
								Pod:           "simplePod",
								Endpoint:      "eth0",
								Profiles:      []string{"kns.testNamespace"},
								IPNetworks:    []string{"192.168.91.113/32"},
								InterfaceName: "caliedff4356bd6",
							},
						}},
					)
				})
			})
			Context("name contains neither the endpoint suffix or the pod name midfix", func() {
				It("returns an error", func() {
					k8sClient := fake.NewSimpleClientset(&k8sapi.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "simplePod",
							Namespace: "testNamespace",
						},
						Spec: k8sapi.PodSpec{
							NodeName: "test-node",
						},
						Status: k8sapi.PodStatus{
							PodIP: "192.168.91.113",
						},
					})
					wepClient := resources.NewWorkloadEndpointClient(k8sClient).(*resources.WorkloadEndpointClient)

					_, err := wepClient.List(context.Background(), model.ResourceListOptions{
						Name:      "test--node-k8s",
						Namespace: "testNamespace",
						Kind:      libapiv3.KindWorkloadEndpoint,
					}, "")

					Expect(err).Should(Equal(cerrors.ErrorResourceDoesNotExist{
						Identifier: model.ResourceListOptions{
							Name:      "test--node-k8s",
							Namespace: "testNamespace",
							Kind:      libapiv3.KindWorkloadEndpoint,
						},
						Err: errors.New("malformed WorkloadEndpoint name - unable to determine Pod name"),
					}))
				})
			})
		})
		Context("name is not specified", func() {
			It("returns WorkloadEndpoints for each pod in the namespace", func() {
				testListWorkloadEndpoints(
					[]runtime.Object{
						&k8sapi.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "simplePod",
								Namespace: "testNamespace",
							},
							Spec: k8sapi.PodSpec{
								NodeName: "test-node",
							},
							Status: k8sapi.PodStatus{
								PodIP: "192.168.91.113",
							},
						},
						&k8sapi.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "simplePod2",
								Namespace: "testNamespace",
							},
							Spec: k8sapi.PodSpec{
								NodeName: "test-node",
							},
							Status: k8sapi.PodStatus{
								PodIP: "192.168.91.120",
							},
						},
					},
					model.ResourceListOptions{
						Namespace: "testNamespace",
						Kind:      libapiv3.KindWorkloadEndpoint,
					},
					[]*libapiv3.WorkloadEndpoint{
						{
							TypeMeta: metav1.TypeMeta{
								Kind:       libapiv3.KindWorkloadEndpoint,
								APIVersion: apiv3.GroupVersionCurrent,
							},
							ObjectMeta: metav1.ObjectMeta{
								Name:      "test--node-k8s-simplePod-eth0",
								Namespace: "testNamespace",
								Labels: map[string]string{
									apiv3.LabelNamespace:    "testNamespace",
									apiv3.LabelOrchestrator: "k8s",
								},
							},
							Spec: libapiv3.WorkloadEndpointSpec{
								Orchestrator:  "k8s",
								Node:          "test-node",
								Pod:           "simplePod",
								Endpoint:      "eth0",
								Profiles:      []string{"kns.testNamespace"},
								IPNetworks:    []string{"192.168.91.113/32"},
								InterfaceName: "caliedff4356bd6",
							},
						},
						{
							TypeMeta: metav1.TypeMeta{
								Kind:       libapiv3.KindWorkloadEndpoint,
								APIVersion: apiv3.GroupVersionCurrent,
							},
							ObjectMeta: metav1.ObjectMeta{
								Name:      "test--node-k8s-simplePod2-eth0",
								Namespace: "testNamespace",
								Labels: map[string]string{
									apiv3.LabelNamespace:    "testNamespace",
									apiv3.LabelOrchestrator: "k8s",
								},
							},
							Spec: libapiv3.WorkloadEndpointSpec{
								Orchestrator:  "k8s",
								Node:          "test-node",
								Pod:           "simplePod2",
								Endpoint:      "eth0",
								Profiles:      []string{"kns.testNamespace"},
								IPNetworks:    []string{"192.168.91.120/32"},
								InterfaceName: "cali4274eb44391",
							},
						},
					},
				)
			})
		})
	})
	Describe("Watch", func() {
		Context("Pod added", func() {
			It("returns a single event containing the Pod's WorkloadEndpoint", func() {
				testWatchWorkloadEndpoints([]*k8sapi.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "simplePod",
							Namespace: "testNamespace",
						},
						Spec: k8sapi.PodSpec{
							NodeName: "test-node",
						},
						Status: k8sapi.PodStatus{
							PodIP: "192.168.91.113",
						},
					},
				}, []*libapiv3.WorkloadEndpoint{{
					TypeMeta: metav1.TypeMeta{
						Kind:       libapiv3.KindWorkloadEndpoint,
						APIVersion: apiv3.GroupVersionCurrent,
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test--node-k8s-simplePod-eth0",
						Namespace: "testNamespace",
						Labels: map[string]string{
							apiv3.LabelNamespace:    "testNamespace",
							apiv3.LabelOrchestrator: "k8s",
						},
					},
					Spec: libapiv3.WorkloadEndpointSpec{
						Orchestrator:  "k8s",
						Node:          "test-node",
						Pod:           "simplePod",
						Endpoint:      "eth0",
						Profiles:      []string{"kns.testNamespace"},
						IPNetworks:    []string{"192.168.91.113/32"},
						InterfaceName: "caliedff4356bd6",
					},
				}})
			})
		})
		Context("Terminating Pods and normal Pod added", func() {
			It("should ignore the IPs of a deleted pod with released IPs", func() {
				now := metav1.Now()
				testWatchWorkloadEndpoints([]*k8sapi.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:              "termPod",
							Namespace:         "testNamespace",
							DeletionTimestamp: &now,
							Annotations: map[string]string{
								conversion.AnnotationPodIP:  "192.168.91.114",
								conversion.AnnotationPodIPs: "192.168.91.114",
							},
						},
						Spec: k8sapi.PodSpec{
							NodeName: "test-node",
						},
						Status: k8sapi.PodStatus{
							PodIP: "192.168.91.114",
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:              "termPod2",
							Namespace:         "testNamespace",
							DeletionTimestamp: &now,
							Annotations: map[string]string{
								// Empty annotation signals that the CNI plugin has released the IP.
								conversion.AnnotationPodIP:  "",
								conversion.AnnotationPodIPs: "",
							},
						},
						Spec: k8sapi.PodSpec{
							NodeName: "test-node",
						},
						Status: k8sapi.PodStatus{
							PodIP: "192.168.91.115",
						},
					},
				}, []*libapiv3.WorkloadEndpoint{
					{
						TypeMeta: metav1.TypeMeta{
							Kind:       libapiv3.KindWorkloadEndpoint,
							APIVersion: apiv3.GroupVersionCurrent,
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test--node-k8s-termPod-eth0",
							Namespace: "testNamespace",
							Labels: map[string]string{
								apiv3.LabelNamespace:    "testNamespace",
								apiv3.LabelOrchestrator: "k8s",
							},
						},
						Spec: libapiv3.WorkloadEndpointSpec{
							Orchestrator:  "k8s",
							Node:          "test-node",
							Pod:           "termPod",
							Endpoint:      "eth0",
							Profiles:      []string{"kns.testNamespace"},
							IPNetworks:    []string{"192.168.91.114/32"},
							InterfaceName: "calidfce31fd9be",
						},
					},
					{
						TypeMeta: metav1.TypeMeta{
							Kind:       libapiv3.KindWorkloadEndpoint,
							APIVersion: apiv3.GroupVersionCurrent,
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test--node-k8s-termPod2-eth0",
							Namespace: "testNamespace",
							Labels: map[string]string{
								apiv3.LabelNamespace:    "testNamespace",
								apiv3.LabelOrchestrator: "k8s",
							},
						},
						Spec: libapiv3.WorkloadEndpointSpec{
							Orchestrator:  "k8s",
							Node:          "test-node",
							Pod:           "termPod2",
							Endpoint:      "eth0",
							Profiles:      []string{"kns.testNamespace"},
							IPNetworks:    []string{},
							InterfaceName: "cali9591578421e",
						},
					},
				})
			})
		})
	})
})

func testListWorkloadEndpoints(pods []runtime.Object, listOptions model.ResourceListOptions, expectedWEPs []*libapiv3.WorkloadEndpoint) {
	k8sClient := fake.NewSimpleClientset(pods...)
	wepClient := resources.NewWorkloadEndpointClient(k8sClient).(*resources.WorkloadEndpointClient)

	kvps, err := wepClient.List(context.Background(), listOptions, "")
	Expect(err).ShouldNot(HaveOccurred())

	var weps []*libapiv3.WorkloadEndpoint
	for _, kvp := range kvps.KVPairs {
		weps = append(weps, kvp.Value.(*libapiv3.WorkloadEndpoint))
	}

	Expect(weps).Should(Equal(expectedWEPs))
}

func testWatchWorkloadEndpoints(pods []*k8sapi.Pod, expectedWEPs []*libapiv3.WorkloadEndpoint) {
	k8sClient := fake.NewSimpleClientset()
	ctx := context.Background()

	wepClient := resources.NewWorkloadEndpointClient(k8sClient).(*resources.WorkloadEndpointClient)
	wepWatcher, err := wepClient.Watch(context.Background(), model.ResourceListOptions{}, "")

	Expect(err).ShouldNot(HaveOccurred())

	timer := time.NewTimer(1 * time.Second)
	defer timer.Stop()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer GinkgoRecover()
		i := 0

		for {
			select {
			case event := <-wepWatcher.ResultChan():
				Expect(event.Error).ShouldNot(HaveOccurred())
				Expect(event.New.Value).Should(Equal(expectedWEPs[i]))

				i++
				if i == len(expectedWEPs) {
					return
				}
			case <-timer.C:
				Fail(fmt.Sprintf("expected exactly %d events before timer expired, received %d", len(expectedWEPs), i))
			}
		}
	}()

	for _, pod := range pods {
		_, err = k8sClient.CoreV1().Pods(pod.Namespace).Create(ctx, pod, metav1.CreateOptions{})
		Expect(err).ShouldNot(HaveOccurred())
	}

	wg.Wait()
	wepWatcher.Stop()
}
