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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic/fake"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

// vmimGVR duplicated from the resources package (unexported).
var vmimGVR = schema.GroupVersionResource{
	Group:    "kubevirt.io",
	Version:  "v1",
	Resource: "virtualmachineinstancemigrations",
}

var gvrToListKind = map[schema.GroupVersionResource]string{
	vmimGVR: "VirtualMachineInstanceMigrationList",
}

func newVMIMUnstructured(namespace, name, resourceVersion, phase, vmiName, sourcePod, uid string) *unstructured.Unstructured {
	obj := map[string]interface{}{
		"apiVersion": "kubevirt.io/v1",
		"kind":       "VirtualMachineInstanceMigration",
		"metadata": map[string]interface{}{
			"namespace":       namespace,
			"name":            name,
			"resourceVersion": resourceVersion,
			"uid":             uid,
		},
	}
	if vmiName != "" {
		obj["spec"] = map[string]interface{}{
			"vmiName": vmiName,
		}
	}
	if phase != "" || sourcePod != "" {
		status := map[string]interface{}{}
		if phase != "" {
			status["phase"] = phase
		}
		if sourcePod != "" {
			status["migrationState"] = map[string]interface{}{
				"sourcePod": sourcePod,
			}
		}
		obj["status"] = status
	}
	return &unstructured.Unstructured{Object: obj}
}

var _ = Describe("LiveMigrationClient", func() {
	ctx := context.Background()

	Describe("Get", func() {
		It("converts a matching VMIM to a LiveMigration with spec populated", func() {
			vmim := newVMIMUnstructured("test-ns", "vmim-1", "100", "Running", "my-vmi", "source-pod-abc", "uid-123")
			dynClient := fake.NewSimpleDynamicClientWithCustomListKinds(
				runtime.NewScheme(), gvrToListKind, vmim,
			)

			client := resources.NewLiveMigrationClient(dynClient)
			kvp, err := client.Get(ctx, model.ResourceKey{
				Kind:      libapiv3.KindLiveMigration,
				Namespace: "test-ns",
				Name:      "vmim-1",
			}, "")

			Expect(err).NotTo(HaveOccurred())
			Expect(kvp).NotTo(BeNil())

			lm := kvp.Value.(*libapiv3.LiveMigration)
			Expect(lm.Name).To(Equal("vmim-1"))
			Expect(lm.Namespace).To(Equal("test-ns"))
			Expect(lm.TypeMeta).To(Equal(metav1.TypeMeta{
				Kind:       libapiv3.KindLiveMigration,
				APIVersion: apiv3.GroupVersionCurrent,
			}))
			Expect(lm.Spec.DestinationWorkloadEndpointSelector).To(Equal(
				"kubevirt.io/vmi-name == 'my-vmi' && kubevirt.io/migrationJobUID == 'uid-123'",
			))
			Expect(lm.Spec.SourceWorkloadEndpoint).To(Equal(types.NamespacedName{
				Name:      "source-pod-abc",
				Namespace: "test-ns",
			}))
			Expect(kvp.Key).To(Equal(model.ResourceKey{
				Kind:      libapiv3.KindLiveMigration,
				Namespace: "test-ns",
				Name:      "vmim-1",
			}))
			Expect(kvp.Revision).To(Equal("100"))
		})

		It("returns an error when the VMIM does not exist", func() {
			dynClient := fake.NewSimpleDynamicClientWithCustomListKinds(
				runtime.NewScheme(), gvrToListKind,
			)

			client := resources.NewLiveMigrationClient(dynClient)
			_, err := client.Get(ctx, model.ResourceKey{
				Kind:      libapiv3.KindLiveMigration,
				Namespace: "test-ns",
				Name:      "nonexistent",
			}, "")

			Expect(err).To(HaveOccurred())
		})

		It("returns not-found when VMIM is in a non-matching phase", func() {
			vmim := newVMIMUnstructured("test-ns", "vmim-done", "100", "Succeeded", "my-vmi", "source-pod-abc", "uid-123")
			dynClient := fake.NewSimpleDynamicClientWithCustomListKinds(
				runtime.NewScheme(), gvrToListKind, vmim,
			)

			client := resources.NewLiveMigrationClient(dynClient)
			_, err := client.Get(ctx, model.ResourceKey{
				Kind:      libapiv3.KindLiveMigration,
				Namespace: "test-ns",
				Name:      "vmim-done",
			}, "")

			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(cerrors.ErrorResourceDoesNotExist{}))
		})

		It("returns not-found when VMIM is in matching phase but missing sourcePod", func() {
			vmim := newVMIMUnstructured("test-ns", "vmim-no-source", "100", "Running", "my-vmi", "", "uid-123")
			dynClient := fake.NewSimpleDynamicClientWithCustomListKinds(
				runtime.NewScheme(), gvrToListKind, vmim,
			)

			client := resources.NewLiveMigrationClient(dynClient)
			_, err := client.Get(ctx, model.ResourceKey{
				Kind:      libapiv3.KindLiveMigration,
				Namespace: "test-ns",
				Name:      "vmim-no-source",
			}, "")

			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(cerrors.ErrorResourceDoesNotExist{}))
		})
	})

	Describe("List", func() {
		It("lists matching VMIMs and converts them to LiveMigrations with spec", func() {
			vmim1 := newVMIMUnstructured("test-ns", "vmim-1", "100", "Running", "vmi-a", "src-pod-1", "uid-1")
			vmim2 := newVMIMUnstructured("test-ns", "vmim-2", "101", "TargetReady", "vmi-b", "src-pod-2", "uid-2")
			dynClient := fake.NewSimpleDynamicClientWithCustomListKinds(
				runtime.NewScheme(), gvrToListKind, vmim1, vmim2,
			)

			client := resources.NewLiveMigrationClient(dynClient)
			kvps, err := client.List(ctx, model.ResourceListOptions{
				Namespace: "test-ns",
				Kind:      libapiv3.KindLiveMigration,
			}, "")

			Expect(err).NotTo(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(2))

			lm1 := kvps.KVPairs[0].Value.(*libapiv3.LiveMigration)
			Expect(lm1.Name).To(Equal("vmim-1"))
			Expect(lm1.Namespace).To(Equal("test-ns"))
			Expect(lm1.Spec.SourceWorkloadEndpoint.Name).To(Equal("src-pod-1"))

			lm2 := kvps.KVPairs[1].Value.(*libapiv3.LiveMigration)
			Expect(lm2.Name).To(Equal("vmim-2"))
			Expect(lm2.Namespace).To(Equal("test-ns"))
			Expect(lm2.Spec.SourceWorkloadEndpoint.Name).To(Equal("src-pod-2"))
		})

		It("lists VMIMs across all namespaces", func() {
			vmim1 := newVMIMUnstructured("ns-a", "vmim-1", "100", "Running", "vmi-a", "src-pod-1", "uid-1")
			vmim2 := newVMIMUnstructured("ns-b", "vmim-2", "101", "Failed", "vmi-b", "src-pod-2", "uid-2")
			dynClient := fake.NewSimpleDynamicClientWithCustomListKinds(
				runtime.NewScheme(), gvrToListKind, vmim1, vmim2,
			)

			client := resources.NewLiveMigrationClient(dynClient)
			kvps, err := client.List(ctx, model.ResourceListOptions{
				Kind: libapiv3.KindLiveMigration,
			}, "")

			Expect(err).NotTo(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(2))
		})

		It("returns empty list when no VMIMs exist", func() {
			dynClient := fake.NewSimpleDynamicClientWithCustomListKinds(
				runtime.NewScheme(), gvrToListKind,
			)

			client := resources.NewLiveMigrationClient(dynClient)
			kvps, err := client.List(ctx, model.ResourceListOptions{
				Namespace: "test-ns",
				Kind:      libapiv3.KindLiveMigration,
			}, "")

			Expect(err).NotTo(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(0))
		})

		It("filters out non-matching VMIMs", func() {
			matching := newVMIMUnstructured("test-ns", "vmim-running", "100", "Running", "vmi-a", "src-pod-1", "uid-1")
			nonMatching := newVMIMUnstructured("test-ns", "vmim-succeeded", "101", "Succeeded", "vmi-b", "src-pod-2", "uid-2")
			noSourcePod := newVMIMUnstructured("test-ns", "vmim-no-src", "102", "Running", "vmi-c", "", "uid-3")
			dynClient := fake.NewSimpleDynamicClientWithCustomListKinds(
				runtime.NewScheme(), gvrToListKind, matching, nonMatching, noSourcePod,
			)

			client := resources.NewLiveMigrationClient(dynClient)
			kvps, err := client.List(ctx, model.ResourceListOptions{
				Namespace: "test-ns",
				Kind:      libapiv3.KindLiveMigration,
			}, "")

			Expect(err).NotTo(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(1))
			lm := kvps.KVPairs[0].Value.(*libapiv3.LiveMigration)
			Expect(lm.Name).To(Equal("vmim-running"))
		})
	})

	Describe("Watch", func() {
		It("receives watch events for matching VMIM resources as LiveMigrations", func() {
			dynClient := fake.NewSimpleDynamicClientWithCustomListKinds(
				runtime.NewScheme(), gvrToListKind,
			)

			client := resources.NewLiveMigrationClient(dynClient)
			w, err := client.Watch(ctx, model.ResourceListOptions{
				Namespace: "test-ns",
				Kind:      libapiv3.KindLiveMigration,
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
					lm := event.New.Value.(*libapiv3.LiveMigration)
					Expect(lm.Name).To(Equal("vmim-watch-1"))
					Expect(lm.Namespace).To(Equal("test-ns"))
					Expect(lm.Spec.SourceWorkloadEndpoint.Name).To(Equal("src-pod-w"))
				case <-timer.C:
					Fail(fmt.Sprintf("expected a watch event before timer expired"))
				}
			}()

			vmim := newVMIMUnstructured("test-ns", "vmim-watch-1", "200", "Running", "vmi-w", "src-pod-w", "uid-w")
			_, err = dynClient.Resource(vmimGVR).Namespace("test-ns").Create(ctx, vmim, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			wg.Wait()
			w.Stop()
		})

		It("emits Deleted event when VMIM transitions to non-matching phase", func() {
			dynClient := fake.NewSimpleDynamicClientWithCustomListKinds(
				runtime.NewScheme(), gvrToListKind,
			)

			client := resources.NewLiveMigrationClient(dynClient)
			w, err := client.Watch(ctx, model.ResourceListOptions{
				Namespace: "test-ns",
				Kind:      libapiv3.KindLiveMigration,
			}, api.WatchOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Create a matching VMIM.
			vmim := newVMIMUnstructured("test-ns", "vmim-trans", "300", "Running", "vmi-t", "src-pod-t", "uid-t")
			_, err = dynClient.Resource(vmimGVR).Namespace("test-ns").Create(ctx, vmim, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			timer := time.NewTimer(2 * time.Second)
			defer timer.Stop()

			// First event should be Added.
			select {
			case event := <-w.ResultChan():
				Expect(event.Error).NotTo(HaveOccurred())
				Expect(event.Type).To(Equal(api.WatchAdded))
				lm := event.New.Value.(*libapiv3.LiveMigration)
				Expect(lm.Name).To(Equal("vmim-trans"))
			case <-timer.C:
				Fail("expected Added event before timer expired")
			}

			// Update to non-matching phase (Succeeded).
			vmimUpdated := newVMIMUnstructured("test-ns", "vmim-trans", "301", "Succeeded", "vmi-t", "src-pod-t", "uid-t")
			_, err = dynClient.Resource(vmimGVR).Namespace("test-ns").Update(ctx, vmimUpdated, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Second event should be Deleted.
			select {
			case event := <-w.ResultChan():
				Expect(event.Error).NotTo(HaveOccurred())
				Expect(event.Type).To(Equal(api.WatchDeleted))
			case <-timer.C:
				Fail("expected Deleted event before timer expired")
			}

			w.Stop()
		})

		It("does not emit events for non-matching VMIMs", func() {
			dynClient := fake.NewSimpleDynamicClientWithCustomListKinds(
				runtime.NewScheme(), gvrToListKind,
			)

			client := resources.NewLiveMigrationClient(dynClient)
			w, err := client.Watch(ctx, model.ResourceListOptions{
				Namespace: "test-ns",
				Kind:      libapiv3.KindLiveMigration,
			}, api.WatchOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Create a non-matching VMIM (Scheduling phase).
			vmim := newVMIMUnstructured("test-ns", "vmim-sched", "400", "Scheduling", "vmi-s", "src-pod-s", "uid-s")
			_, err = dynClient.Resource(vmimGVR).Namespace("test-ns").Create(ctx, vmim, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Should not receive any event.
			timer := time.NewTimer(200 * time.Millisecond)
			defer timer.Stop()
			select {
			case event := <-w.ResultChan():
				Fail(fmt.Sprintf("unexpected watch event: %v", event))
			case <-timer.C:
				// Expected: no event received.
			}

			w.Stop()
		})
	})

	Describe("Read-only stubs", func() {
		It("Create returns ErrorOperationNotSupported", func() {
			dynClient := fake.NewSimpleDynamicClientWithCustomListKinds(
				runtime.NewScheme(), gvrToListKind,
			)
			client := resources.NewLiveMigrationClient(dynClient)

			kvp := &model.KVPair{
				Key: model.ResourceKey{
					Kind:      libapiv3.KindLiveMigration,
					Namespace: "test-ns",
					Name:      "test",
				},
				Value: libapiv3.NewLiveMigration(),
			}

			_, err := client.Create(ctx, kvp)
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(cerrors.ErrorOperationNotSupported{}))
			Expect(err.Error()).To(ContainSubstring("read-only"))
		})

		It("Update returns ErrorOperationNotSupported", func() {
			dynClient := fake.NewSimpleDynamicClientWithCustomListKinds(
				runtime.NewScheme(), gvrToListKind,
			)
			client := resources.NewLiveMigrationClient(dynClient)

			kvp := &model.KVPair{
				Key: model.ResourceKey{
					Kind:      libapiv3.KindLiveMigration,
					Namespace: "test-ns",
					Name:      "test",
				},
				Value: libapiv3.NewLiveMigration(),
			}

			_, err := client.Update(ctx, kvp)
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(cerrors.ErrorOperationNotSupported{}))
			Expect(err.Error()).To(ContainSubstring("read-only"))
		})

		It("Delete returns ErrorOperationNotSupported", func() {
			dynClient := fake.NewSimpleDynamicClientWithCustomListKinds(
				runtime.NewScheme(), gvrToListKind,
			)
			client := resources.NewLiveMigrationClient(dynClient)

			_, err := client.Delete(ctx, model.ResourceKey{
				Kind:      libapiv3.KindLiveMigration,
				Namespace: "test-ns",
				Name:      "test",
			}, "", nil)
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(cerrors.ErrorOperationNotSupported{}))
			Expect(err.Error()).To(ContainSubstring("read-only"))
		})

		It("DeleteKVP returns ErrorOperationNotSupported", func() {
			dynClient := fake.NewSimpleDynamicClientWithCustomListKinds(
				runtime.NewScheme(), gvrToListKind,
			)
			client := resources.NewLiveMigrationClient(dynClient)

			kvp := &model.KVPair{
				Key: model.ResourceKey{
					Kind:      libapiv3.KindLiveMigration,
					Namespace: "test-ns",
					Name:      "test",
				},
				Value: libapiv3.NewLiveMigration(),
			}

			_, err := client.DeleteKVP(ctx, kvp)
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(cerrors.ErrorOperationNotSupported{}))
			Expect(err.Error()).To(ContainSubstring("read-only"))
		})
	})
})
