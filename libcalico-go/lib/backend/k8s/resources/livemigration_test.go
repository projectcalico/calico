// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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
	"fmt"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kubevirtv1 "kubevirt.io/api/core/v1"
	kubevirtfake "kubevirt.io/client-go/kubevirt/fake"

	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

func newVMIM(namespace, name, resourceVersion string, phase kubevirtv1.VirtualMachineInstanceMigrationPhase, vmiName, sourcePod, uid string) *kubevirtv1.VirtualMachineInstanceMigration {
	vmim := &kubevirtv1.VirtualMachineInstanceMigration{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       namespace,
			Name:            name,
			ResourceVersion: resourceVersion,
			UID:             types.UID(uid),
		},
		Spec: kubevirtv1.VirtualMachineInstanceMigrationSpec{
			VMIName: vmiName,
		},
		Status: kubevirtv1.VirtualMachineInstanceMigrationStatus{
			Phase: phase,
		},
	}
	if sourcePod != "" {
		vmim.Status.MigrationState = &kubevirtv1.VirtualMachineInstanceMigrationState{
			SourcePod: sourcePod,
		}
	}
	return vmim
}

func newLiveMigrationClient(kvFake *kubevirtfake.Clientset) resources.K8sResourceClient {
	return resources.NewLiveMigrationClient(func(ns string) resources.VMIMClient {
		return kvFake.KubevirtV1().VirtualMachineInstanceMigrations(ns)
	})
}

var _ = Describe("LiveMigrationClient", func() {
	ctx := context.Background()

	Describe("Get", func() {
		It("converts a matching VMIM to a LiveMigration with spec populated", func() {
			vmim := newVMIM("test-ns", "vmim-1", "100", kubevirtv1.MigrationRunning, "my-vmi", "source-pod-abc", "uid-123")
			kvFake := kubevirtfake.NewSimpleClientset(vmim)

			client := newLiveMigrationClient(kvFake)
			kvp, err := client.Get(ctx, model.ResourceKey{
				Kind:      internalapi.KindLiveMigration,
				Namespace: "test-ns",
				Name:      "vmim-1",
			}, "")

			Expect(err).NotTo(HaveOccurred())
			Expect(kvp).NotTo(BeNil())

			lm := kvp.Value.(*internalapi.LiveMigration)
			Expect(lm.Name).To(Equal("vmim-1"))
			Expect(lm.Namespace).To(Equal("test-ns"))
			Expect(lm.TypeMeta).To(Equal(metav1.TypeMeta{
				Kind:       internalapi.KindLiveMigration,
				APIVersion: apiv3.GroupVersionCurrent,
			}))
			Expect(*lm.Spec.Destination.Selector).To(Equal(
				"kubevirt.io/vmi-name == 'my-vmi' && kubevirt.io/migrationJobUID == 'uid-123'",
			))
			Expect(*lm.Spec.Source).To(Equal(types.NamespacedName{
				Name:      "source-pod-abc",
				Namespace: "test-ns",
			}))
			Expect(kvp.Key).To(Equal(model.ResourceKey{
				Kind:      internalapi.KindLiveMigration,
				Namespace: "test-ns",
				Name:      "vmim-1",
			}))
			Expect(kvp.Revision).To(Equal("100"))
		})

		It("returns an error when the VMIM does not exist", func() {
			kvFake := kubevirtfake.NewSimpleClientset()

			client := newLiveMigrationClient(kvFake)
			_, err := client.Get(ctx, model.ResourceKey{
				Kind:      internalapi.KindLiveMigration,
				Namespace: "test-ns",
				Name:      "nonexistent",
			}, "")

			Expect(err).To(HaveOccurred())
		})

		It("returns not-found when VMIM is in a non-matching phase", func() {
			vmim := newVMIM("test-ns", "vmim-done", "100", kubevirtv1.MigrationSucceeded, "my-vmi", "source-pod-abc", "uid-123")
			kvFake := kubevirtfake.NewSimpleClientset(vmim)

			client := newLiveMigrationClient(kvFake)
			_, err := client.Get(ctx, model.ResourceKey{
				Kind:      internalapi.KindLiveMigration,
				Namespace: "test-ns",
				Name:      "vmim-done",
			}, "")

			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(cerrors.ErrorResourceDoesNotExist{}))
		})

		It("returns not-found when VMIM is in matching phase but missing sourcePod", func() {
			vmim := newVMIM("test-ns", "vmim-no-source", "100", kubevirtv1.MigrationRunning, "my-vmi", "", "uid-123")
			kvFake := kubevirtfake.NewSimpleClientset(vmim)

			client := newLiveMigrationClient(kvFake)
			_, err := client.Get(ctx, model.ResourceKey{
				Kind:      internalapi.KindLiveMigration,
				Namespace: "test-ns",
				Name:      "vmim-no-source",
			}, "")

			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(cerrors.ErrorResourceDoesNotExist{}))
		})
	})

	Describe("List", func() {
		It("lists matching VMIMs and converts them to LiveMigrations with spec", func() {
			vmim1 := newVMIM("test-ns", "vmim-1", "100", kubevirtv1.MigrationRunning, "vmi-a", "src-pod-1", "uid-1")
			vmim2 := newVMIM("test-ns", "vmim-2", "101", kubevirtv1.MigrationTargetReady, "vmi-b", "src-pod-2", "uid-2")
			kvFake := kubevirtfake.NewSimpleClientset(vmim1, vmim2)

			client := newLiveMigrationClient(kvFake)
			kvps, err := client.List(ctx, model.ResourceListOptions{
				Namespace: "test-ns",
				Kind:      internalapi.KindLiveMigration,
			}, "")

			Expect(err).NotTo(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(2))

			lm1 := kvps.KVPairs[0].Value.(*internalapi.LiveMigration)
			Expect(lm1.Name).To(Equal("vmim-1"))
			Expect(lm1.Namespace).To(Equal("test-ns"))
			Expect(lm1.Spec.Source.Name).To(Equal("src-pod-1"))

			lm2 := kvps.KVPairs[1].Value.(*internalapi.LiveMigration)
			Expect(lm2.Name).To(Equal("vmim-2"))
			Expect(lm2.Namespace).To(Equal("test-ns"))
			Expect(lm2.Spec.Source.Name).To(Equal("src-pod-2"))
		})

		It("lists VMIMs across all namespaces", func() {
			vmim1 := newVMIM("ns-a", "vmim-1", "100", kubevirtv1.MigrationRunning, "vmi-a", "src-pod-1", "uid-1")
			vmim2 := newVMIM("ns-b", "vmim-2", "101", kubevirtv1.MigrationFailed, "vmi-b", "src-pod-2", "uid-2")
			kvFake := kubevirtfake.NewSimpleClientset(vmim1, vmim2)

			client := newLiveMigrationClient(kvFake)
			kvps, err := client.List(ctx, model.ResourceListOptions{
				Kind: internalapi.KindLiveMigration,
			}, "")

			Expect(err).NotTo(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(2))
		})

		It("returns empty list when no VMIMs exist", func() {
			kvFake := kubevirtfake.NewSimpleClientset()

			client := newLiveMigrationClient(kvFake)
			kvps, err := client.List(ctx, model.ResourceListOptions{
				Namespace: "test-ns",
				Kind:      internalapi.KindLiveMigration,
			}, "")

			Expect(err).NotTo(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(0))
		})

		It("filters out non-matching VMIMs", func() {
			matching := newVMIM("test-ns", "vmim-running", "100", kubevirtv1.MigrationRunning, "vmi-a", "src-pod-1", "uid-1")
			nonMatching := newVMIM("test-ns", "vmim-succeeded", "101", kubevirtv1.MigrationSucceeded, "vmi-b", "src-pod-2", "uid-2")
			noSourcePod := newVMIM("test-ns", "vmim-no-src", "102", kubevirtv1.MigrationRunning, "vmi-c", "", "uid-3")
			kvFake := kubevirtfake.NewSimpleClientset(matching, nonMatching, noSourcePod)

			client := newLiveMigrationClient(kvFake)
			kvps, err := client.List(ctx, model.ResourceListOptions{
				Namespace: "test-ns",
				Kind:      internalapi.KindLiveMigration,
			}, "")

			Expect(err).NotTo(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(1))
			lm := kvps.KVPairs[0].Value.(*internalapi.LiveMigration)
			Expect(lm.Name).To(Equal("vmim-running"))
		})
	})

	Describe("Watch", func() {
		It("receives watch events for matching VMIM resources as LiveMigrations", func() {
			kvFake := kubevirtfake.NewSimpleClientset()

			client := newLiveMigrationClient(kvFake)
			w, err := client.Watch(ctx, model.ResourceListOptions{
				Namespace: "test-ns",
				Kind:      internalapi.KindLiveMigration,
			}, api.WatchOptions{})
			Expect(err).NotTo(HaveOccurred())

			timer := time.NewTimer(2 * time.Second)
			defer timer.Stop()

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer GinkgoRecover()
				select {
				case event := <-w.ResultChan():
					Expect(event.Error).NotTo(HaveOccurred())
					lm := event.New.Value.(*internalapi.LiveMigration)
					Expect(lm.Name).To(Equal("vmim-watch-1"))
					Expect(lm.Namespace).To(Equal("test-ns"))
					Expect(lm.Spec.Source.Name).To(Equal("src-pod-w"))
				case <-timer.C:
					Fail(fmt.Sprintf("expected a watch event before timer expired"))
				}
			}()

			vmim := newVMIM("test-ns", "vmim-watch-1", "200", kubevirtv1.MigrationRunning, "vmi-w", "src-pod-w", "uid-w")
			_, err = kvFake.KubevirtV1().VirtualMachineInstanceMigrations("test-ns").Create(ctx, vmim, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			wg.Wait()
			w.Stop()
		})

		It("emits Deleted event when VMIM transitions to non-matching phase", func() {
			kvFake := kubevirtfake.NewSimpleClientset()

			client := newLiveMigrationClient(kvFake)
			w, err := client.Watch(ctx, model.ResourceListOptions{
				Namespace: "test-ns",
				Kind:      internalapi.KindLiveMigration,
			}, api.WatchOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Create a matching VMIM.
			vmim := newVMIM("test-ns", "vmim-trans", "300", kubevirtv1.MigrationRunning, "vmi-t", "src-pod-t", "uid-t")
			_, err = kvFake.KubevirtV1().VirtualMachineInstanceMigrations("test-ns").Create(ctx, vmim, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			timer := time.NewTimer(2 * time.Second)
			defer timer.Stop()

			// First event should be Added.
			select {
			case event := <-w.ResultChan():
				Expect(event.Error).NotTo(HaveOccurred())
				Expect(event.Type).To(Equal(api.WatchAdded))
				lm := event.New.Value.(*internalapi.LiveMigration)
				Expect(lm.Name).To(Equal("vmim-trans"))
			case <-timer.C:
				Fail("expected Added event before timer expired")
			}

			// Update to non-matching phase (Succeeded).
			vmimUpdated := newVMIM("test-ns", "vmim-trans", "301", kubevirtv1.MigrationSucceeded, "vmi-t", "src-pod-t", "uid-t")
			_, err = kvFake.KubevirtV1().VirtualMachineInstanceMigrations("test-ns").Update(ctx, vmimUpdated, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Second event should be Modified with nil value.
			select {
			case event := <-w.ResultChan():
				Expect(event.Error).NotTo(HaveOccurred())
				Expect(event.Type).To(Equal(api.WatchModified))
				Expect(event.New.Value).To(BeNil())
			case <-timer.C:
				Fail("expected Deleted event before timer expired")
			}

			w.Stop()
		})

		It("does not emit events for non-matching VMIMs", func() {
			kvFake := kubevirtfake.NewSimpleClientset()

			client := newLiveMigrationClient(kvFake)
			w, err := client.Watch(ctx, model.ResourceListOptions{
				Namespace: "test-ns",
				Kind:      internalapi.KindLiveMigration,
			}, api.WatchOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Create a non-matching VMIM (Scheduling phase).
			vmim := newVMIM("test-ns", "vmim-sched", "400", kubevirtv1.MigrationScheduling, "vmi-s", "src-pod-s", "uid-s")
			_, err = kvFake.KubevirtV1().VirtualMachineInstanceMigrations("test-ns").Create(ctx, vmim, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Expect an Added event but with nil value.
			timer := time.NewTimer(200 * time.Millisecond)
			defer timer.Stop()
			select {
			case event := <-w.ResultChan():
				Expect(event.Error).NotTo(HaveOccurred())
				Expect(event.Type).To(Equal(api.WatchAdded))
				Expect(event.New.Value).To(BeNil())
			case <-timer.C:
				// Expected: no event received.
			}

			w.Stop()
		})

		Context("typical VMIM progressions", func() {
			var (
				kvFake                  *kubevirtfake.Clientset
				vmim                    *kubevirtv1.VirtualMachineInstanceMigration
				w                       api.WatchInterface
				err                     error
				expectLiveMigration     func()
				expectEventWithNilValue func(api.WatchEventType)
			)

			BeforeEach(func() {
				kvFake = kubevirtfake.NewSimpleClientset()

				client := newLiveMigrationClient(kvFake)
				w, err = client.Watch(ctx, model.ResourceListOptions{
					Namespace: "test-ns",
					Kind:      internalapi.KindLiveMigration,
				}, api.WatchOptions{})
				Expect(err).NotTo(HaveOccurred())

				expectAndCheckEvent := func(check func(api.WatchEvent)) {
					timer := time.NewTimer(200 * time.Millisecond)
					defer timer.Stop()
					select {
					case event := <-w.ResultChan():
						if check != nil {
							check(event)
						} else {
							Expect(event).To(BeNil())
						}
					case <-timer.C:
						if check != nil {
							Fail("expected to get watch event")
						}
						// Else as expected: no event received.
					}
				}

				expectLiveMigration = func() {
					expectAndCheckEvent(func(e api.WatchEvent) {
						Expect(e.Type).To(Equal(api.WatchModified))
						Expect(e.New).NotTo(BeNil())
						Expect(e.New.Value).To(BeAssignableToTypeOf(&internalapi.LiveMigration{}))
						lm := e.New.Value.(*internalapi.LiveMigration)
						Expect(lm.Spec.Source.Namespace).To(Equal("test-ns"))
						Expect(lm.Spec.Source.Name).To(Equal("virt-launcher-vm12-snq7w"))
						Expect(lm.Spec.Destination.NamespacedName).To(BeNil())
						Expect(*lm.Spec.Destination.Selector).To(Equal("kubevirt.io/vmi-name == 'vm12' && kubevirt.io/migrationJobUID == 'c05275a7-f85b-42d5-a1d0-acdd49c26d57'"))
					})
				}

				expectEventWithNilValue = func(expectedEventType api.WatchEventType) {
					expectAndCheckEvent(func(e api.WatchEvent) {
						Expect(e.Type).To(Equal(expectedEventType))
						Expect(e.New).NotTo(BeNil())
						Expect(e.New.Value).To(BeNil())
					})
				}

				// Simulate the sequence of VMIM states that we have seen in actual
				// usage with KubeVirt, and check the resulting sequence of
				// LiveMigration events and contents.

				By("Pending")
				vmim = newVMIM("test-ns", "vmim-progression", "400", kubevirtv1.MigrationPending, "vm12", "virt-launcher-vm12-snq7w", "c05275a7-f85b-42d5-a1d0-acdd49c26d57")
				vmim, err = kvFake.KubevirtV1().VirtualMachineInstanceMigrations("test-ns").Create(ctx, vmim, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				expectEventWithNilValue(api.WatchAdded)

				By("Scheduling")
				vmim.Status.Phase = kubevirtv1.MigrationScheduled
				vmim, err = kvFake.KubevirtV1().VirtualMachineInstanceMigrations("test-ns").Update(ctx, vmim, metav1.UpdateOptions{})
				Expect(err).NotTo(HaveOccurred())
				expectEventWithNilValue(api.WatchModified)

				By("PreparingTarget")
				vmim.Status.Phase = kubevirtv1.MigrationPreparingTarget
				vmim, err = kvFake.KubevirtV1().VirtualMachineInstanceMigrations("test-ns").Update(ctx, vmim, metav1.UpdateOptions{})
				Expect(err).NotTo(HaveOccurred())
				expectEventWithNilValue(api.WatchModified)

				By("TargetReady")
				vmim.Status.Phase = kubevirtv1.MigrationTargetReady
				vmim, err = kvFake.KubevirtV1().VirtualMachineInstanceMigrations("test-ns").Update(ctx, vmim, metav1.UpdateOptions{})
				Expect(err).NotTo(HaveOccurred())
				expectLiveMigration()

				By("Running")
				vmim.Status.Phase = kubevirtv1.MigrationRunning
				vmim, err = kvFake.KubevirtV1().VirtualMachineInstanceMigrations("test-ns").Update(ctx, vmim, metav1.UpdateOptions{})
				Expect(err).NotTo(HaveOccurred())
				expectLiveMigration()
			})

			AfterEach(func() {
				w.Stop()
			})

			It("emits LiveMigrations as expected when migration succeeds ", func() {
				By("Succeeded")
				vmim.Status.Phase = kubevirtv1.MigrationSucceeded
				vmim, err = kvFake.KubevirtV1().VirtualMachineInstanceMigrations("test-ns").Update(ctx, vmim, metav1.UpdateOptions{})
				Expect(err).NotTo(HaveOccurred())
				expectEventWithNilValue(api.WatchModified)
			})

			It("emits LiveMigrations as expected when migration fails ", func() {
				By("Failed")
				vmim.Status.Phase = kubevirtv1.MigrationFailed
				vmim, err = kvFake.KubevirtV1().VirtualMachineInstanceMigrations("test-ns").Update(ctx, vmim, metav1.UpdateOptions{})
				Expect(err).NotTo(HaveOccurred())
				// Note, in this case the LiveMigration continues to exist so as to
				// maintain the existing routing for the target pod, until the
				// target pod is cleaned up.  In most failure cases this means
				// continuing the state of Felix not programming a route at all for
				// the target pod.  (On the other hand, if the LiveMigration was
				// deleted at this point, Felix _would_ program a route for the
				// target pod.)  If there are cases where live migration fails
				// _after_ the target pod has become live - which means that Felix
				// has programmed a higher priority route for the target pod - then
				// we will probably want to enhance LiveMigration to indicate a
				// failure at that point, and make Felix respond to that by removing
				// the target pod route.
				expectLiveMigration()
			})
		})
	})

	Describe("Read-only stubs", func() {
		It("Create returns ErrorOperationNotSupported", func() {
			kvFake := kubevirtfake.NewSimpleClientset()
			client := newLiveMigrationClient(kvFake)

			kvp := &model.KVPair{
				Key: model.ResourceKey{
					Kind:      internalapi.KindLiveMigration,
					Namespace: "test-ns",
					Name:      "test",
				},
				Value: internalapi.NewLiveMigration(),
			}

			_, err := client.Create(ctx, kvp)
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(cerrors.ErrorOperationNotSupported{}))
			Expect(err.Error()).To(ContainSubstring("read-only"))
		})

		It("Update returns ErrorOperationNotSupported", func() {
			kvFake := kubevirtfake.NewSimpleClientset()
			client := newLiveMigrationClient(kvFake)

			kvp := &model.KVPair{
				Key: model.ResourceKey{
					Kind:      internalapi.KindLiveMigration,
					Namespace: "test-ns",
					Name:      "test",
				},
				Value: internalapi.NewLiveMigration(),
			}

			_, err := client.Update(ctx, kvp)
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(cerrors.ErrorOperationNotSupported{}))
			Expect(err.Error()).To(ContainSubstring("read-only"))
		})

		It("Delete returns ErrorOperationNotSupported", func() {
			kvFake := kubevirtfake.NewSimpleClientset()
			client := newLiveMigrationClient(kvFake)

			_, err := client.Delete(ctx, model.ResourceKey{
				Kind:      internalapi.KindLiveMigration,
				Namespace: "test-ns",
				Name:      "test",
			}, "", nil)
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(cerrors.ErrorOperationNotSupported{}))
			Expect(err.Error()).To(ContainSubstring("read-only"))
		})

		It("DeleteKVP returns ErrorOperationNotSupported", func() {
			kvFake := kubevirtfake.NewSimpleClientset()
			client := newLiveMigrationClient(kvFake)

			kvp := &model.KVPair{
				Key: model.ResourceKey{
					Kind:      internalapi.KindLiveMigration,
					Namespace: "test-ns",
					Name:      "test",
				},
				Value: internalapi.NewLiveMigration(),
			}

			_, err := client.DeleteKVP(ctx, kvp)
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(cerrors.ErrorOperationNotSupported{}))
			Expect(err.Error()).To(ContainSubstring("read-only"))
		})
	})
})
