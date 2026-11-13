// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package kubevirt_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/libcalico-go/lib/kubevirt"
)

// newFakeInformers creates a pair of real SharedIndexInformers backed by a
// fake Kubernetes clientset. They sync immediately and can be used with Run().
func newFakeInformers(stop <-chan struct{}) (cache.SharedIndexInformer, cache.SharedIndexInformer) {
	cs := fake.NewClientset()
	factory := informers.NewSharedInformerFactory(cs, 0)
	vmInf := factory.Core().V1().ConfigMaps().Informer()
	vmiInf := factory.Core().V1().Secrets().Informer()
	return vmInf, vmiInf
}

// newFakeInformerFactory returns a GetIndexInformerFunc that returns nil for the
// first nilCount calls, then returns real (fake) informers.
func newFakeInformerFactory(nilCount int, stop <-chan struct{}) kubevirt.GetIndexInformerFunc {
	var calls atomic.Int32
	return func() (cache.SharedIndexInformer, cache.SharedIndexInformer, error) {
		n := int(calls.Add(1))
		if n <= nilCount {
			return nil, nil, nil
		}
		vm, vmi := newFakeInformers(stop)
		return vm, vmi, nil
	}
}

var _ = Describe("DeferredInformers", func() {
	It("should return nil before indexers are set", func() {
		di := &kubevirt.DeferredInformers{}
		Expect(di.VMIndexer()).To(BeNil())
		Expect(di.VMInstanceIndexer()).To(BeNil())
	})

	It("should return indexers after NewDeferredInformersWithIndexers", func() {
		vmIdx := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
		vmiIdx := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})

		di := kubevirt.NewDeferredInformersWithIndexers(vmIdx, vmiIdx)

		Expect(di.VMIndexer()).To(Equal(vmIdx))
		Expect(di.VMInstanceIndexer()).To(Equal(vmiIdx))
	})
})

var _ = Describe("NewDeferredInformers", func() {
	var stop chan struct{}

	BeforeEach(func() {
		stop = make(chan struct{})
	})

	AfterEach(func() {
		close(stop)
	})

	It("should publish indexers immediately when KubeVirt is present at startup", func() {
		factory := newFakeInformerFactory(0, stop)
		di := kubevirt.NewDeferredInformers(factory, 10*time.Millisecond, stop)

		Eventually(func() cache.Indexer { return di.VMIndexer() }, 5*time.Second).ShouldNot(BeNil())
		Expect(di.VMInstanceIndexer()).NotTo(BeNil())
	})

	It("should poll and publish indexers when KubeVirt appears after startup", func() {
		factory := newFakeInformerFactory(5, stop)
		di := kubevirt.NewDeferredInformers(factory, 10*time.Millisecond, stop)

		Eventually(func() cache.Indexer { return di.VMIndexer() }, 5*time.Second).ShouldNot(BeNil())
		Expect(di.VMInstanceIndexer()).NotTo(BeNil())
	})

	It("should not publish indexers when stop is closed before KubeVirt appears", func() {
		// Use a dedicated stop channel so we can close it independently of AfterEach.
		localStop := make(chan struct{})

		// Factory always returns nil — KubeVirt never appears.
		factory := func() (cache.SharedIndexInformer, cache.SharedIndexInformer, error) {
			return nil, nil, nil
		}

		di := kubevirt.NewDeferredInformers(factory, 10*time.Millisecond, localStop)

		// Assert indexers remain nil while polling.
		Consistently(func() cache.Indexer { return di.VMIndexer() }, 50*time.Millisecond).Should(BeNil())
		Consistently(func() cache.Indexer { return di.VMInstanceIndexer() }, 50*time.Millisecond).Should(BeNil())

		// Stop polling and verify indexers are still nil.
		close(localStop)
		Expect(di.VMIndexer()).To(BeNil())
		Expect(di.VMInstanceIndexer()).To(BeNil())
	})

	It("should recover from errors and eventually publish indexers", func() {
		var calls atomic.Int32
		factory := func() (cache.SharedIndexInformer, cache.SharedIndexInformer, error) {
			n := int(calls.Add(1))
			if n <= 2 {
				return nil, nil, fmt.Errorf("discovery error")
			}
			vm, vmi := newFakeInformers(stop)
			return vm, vmi, nil
		}

		di := kubevirt.NewDeferredInformers(factory, 10*time.Millisecond, stop)

		Eventually(func() cache.Indexer { return di.VMIndexer() }, 5*time.Second).ShouldNot(BeNil())
		Expect(di.VMInstanceIndexer()).NotTo(BeNil())
	})

	It("publishes the VMIM indexer once its informer syncs", func() {
		migrations := func() (cache.SharedIndexInformer, error) {
			return informers.NewSharedInformerFactory(fake.NewClientset(), 0).Core().V1().Services().Informer(), nil
		}
		di := kubevirt.NewDeferredInformersWithMigrations(newFakeInformerFactory(0, stop), migrations, 10*time.Millisecond, stop)

		Eventually(func() cache.Indexer { return di.MigrationIndexer() }, 5*time.Second).ShouldNot(BeNil())
		Expect(di.VMInstanceIndexer()).NotTo(BeNil())
	})

	It("does not create the VMIM informer before KubeVirt is found", func() {
		var created atomic.Int32
		migrations := func() (cache.SharedIndexInformer, error) {
			created.Add(1)
			return informers.NewSharedInformerFactory(fake.NewClientset(), 0).Core().V1().Services().Informer(), nil
		}
		di := kubevirt.NewDeferredInformersWithMigrations(newFakeInformerFactory(3, stop), migrations, 10*time.Millisecond, stop)

		Eventually(func() cache.Indexer { return di.MigrationIndexer() }, 5*time.Second).ShouldNot(BeNil())
		Expect(created.Load()).To(Equal(int32(1)))
	})

	It("publishes VM and VMI indexers when the VMIM informer never syncs", func() {
		migrations := func() (cache.SharedIndexInformer, error) {
			// A list that always fails, as when the caller may not list VMIMs.
			forbidden := &cache.ListWatch{
				ListWithContextFunc: func(context.Context, metav1.ListOptions) (runtime.Object, error) {
					return nil, fmt.Errorf("forbidden")
				},
				WatchFuncWithContext: func(context.Context, metav1.ListOptions) (watch.Interface, error) {
					return nil, fmt.Errorf("forbidden")
				},
			}
			return cache.NewSharedIndexInformer(forbidden, &corev1.Service{}, 0, cache.Indexers{}), nil
		}
		di := kubevirt.NewDeferredInformersWithMigrations(newFakeInformerFactory(0, stop), migrations, 10*time.Millisecond, stop)

		Eventually(func() cache.Indexer { return di.VMInstanceIndexer() }, 5*time.Second).ShouldNot(BeNil())
		Expect(di.VMIndexer()).NotTo(BeNil())
		Consistently(func() cache.Indexer { return di.MigrationIndexer() }, 200*time.Millisecond).Should(BeNil())
	})

	It("publishes VM and VMI indexers when the VMIM informer cannot be created", func() {
		migrations := func() (cache.SharedIndexInformer, error) { return nil, fmt.Errorf("bad config") }
		di := kubevirt.NewDeferredInformersWithMigrations(newFakeInformerFactory(0, stop), migrations, 10*time.Millisecond, stop)

		Eventually(func() cache.Indexer { return di.VMInstanceIndexer() }, 5*time.Second).ShouldNot(BeNil())
		Consistently(func() cache.Indexer { return di.MigrationIndexer() }, 200*time.Millisecond).Should(BeNil())
	})
})

var _ = Describe("DeferredInformers.AddEventHandlers", func() {
	var stop chan struct{}

	BeforeEach(func() {
		stop = make(chan struct{})
	})

	AfterEach(func() {
		close(stop)
	})

	// seededFactory returns informers over a clientset holding one ConfigMap
	// (VM) and two Secrets (VMI). It blocks until release is closed.
	seededFactory := func(release <-chan struct{}) kubevirt.GetIndexInformerFunc {
		cs := fake.NewClientset(
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "vm1", Namespace: "default"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "vmi1", Namespace: "default"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "vmi2", Namespace: "default"}},
		)
		factory := informers.NewSharedInformerFactory(cs, 0)
		return func() (cache.SharedIndexInformer, cache.SharedIndexInformer, error) {
			<-release
			return factory.Core().V1().ConfigMaps().Informer(), factory.Core().V1().Secrets().Informer(), nil
		}
	}

	type counts struct {
		mu     sync.Mutex
		vm     int
		vmi    int
		synced int
	}
	newHandlers := func(c *counts) kubevirt.EventHandlers {
		return kubevirt.EventHandlers{
			VM: cache.ResourceEventHandlerFuncs{AddFunc: func(any) {
				c.mu.Lock()
				defer c.mu.Unlock()
				c.vm++
			}},
			VMI: cache.ResourceEventHandlerFuncs{AddFunc: func(any) {
				c.mu.Lock()
				defer c.mu.Unlock()
				c.vmi++
			}},
			Synced: func() {
				c.mu.Lock()
				defer c.mu.Unlock()
				c.synced++
			}}
	}
	get := func(c *counts) (int, int, int) {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.vm, c.vmi, c.synced
	}

	It("attaches handlers registered before the informers start", func() {
		release := make(chan struct{})
		di := kubevirt.NewDeferredInformers(seededFactory(release), 10*time.Millisecond, stop)
		c := &counts{}
		di.AddEventHandlers(newHandlers(c))

		close(release)

		Eventually(func() []int {
			vm, vmi, synced := get(c)
			return []int{vm, vmi, synced}
		}, 5*time.Second).Should(Equal([]int{1, 2, 1}))
		Consistently(func() int { _, _, s := get(c); return s }, 100*time.Millisecond).Should(Equal(1))
	})

	It("attaches handlers registered after the informers start", func() {
		release := make(chan struct{})
		close(release)
		di := kubevirt.NewDeferredInformers(seededFactory(release), 10*time.Millisecond, stop)
		Eventually(di.VMIndexer, 5*time.Second).ShouldNot(BeNil())

		c := &counts{}
		di.AddEventHandlers(newHandlers(c))

		Eventually(func() []int {
			vm, vmi, synced := get(c)
			return []int{vm, vmi, synced}
		}, 5*time.Second).Should(Equal([]int{1, 2, 1}))
		Consistently(func() int { _, _, s := get(c); return s }, 100*time.Millisecond).Should(Equal(1))
	})

	It("calls MigrationsSynced once the VMIM indexer is published, before or after registering", func() {
		cs := fake.NewClientset(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "vmim1", Namespace: "default"}})
		migrations := func() (cache.SharedIndexInformer, error) {
			return informers.NewSharedInformerFactory(cs, 0).Core().V1().Services().Informer(), nil
		}
		var vmims, early, late atomic.Int32
		var sawIndexer atomic.Bool
		var di *kubevirt.DeferredInformers
		di = kubevirt.NewDeferredInformersWithMigrations(newFakeInformerFactory(0, stop), migrations, 10*time.Millisecond, stop)
		di.AddEventHandlers(kubevirt.EventHandlers{
			VMIM: cache.ResourceEventHandlerFuncs{AddFunc: func(any) { vmims.Add(1) }},
			MigrationsSynced: func() {
				sawIndexer.Store(di.MigrationIndexer() != nil)
				early.Add(1)
			},
		})
		Eventually(early.Load, 5*time.Second).Should(Equal(int32(1)))
		Expect(sawIndexer.Load()).To(BeTrue(), "the indexer is published before the callback")
		Eventually(vmims.Load, 5*time.Second).Should(Equal(int32(1)))

		di.AddEventHandlers(kubevirt.EventHandlers{MigrationsSynced: func() { late.Add(1) }})
		Expect(late.Load()).To(Equal(int32(1)), "a late registration is told at once")
		Consistently(early.Load, 100*time.Millisecond).Should(Equal(int32(1)))
	})

	It("never calls MigrationsSynced without a VMIM informer", func() {
		di := kubevirt.NewDeferredInformers(newFakeInformerFactory(0, stop), 10*time.Millisecond, stop)
		var called atomic.Int32
		synced := make(chan struct{})
		di.AddEventHandlers(kubevirt.EventHandlers{
			Synced:           func() { close(synced) },
			MigrationsSynced: func() { called.Add(1) },
		})
		Eventually(synced, 5*time.Second).Should(BeClosed())
		Consistently(called.Load, 200*time.Millisecond).Should(BeZero())
	})

	It("never calls Synced when KubeVirt is absent", func() {
		localStop := make(chan struct{})
		var polls atomic.Int32
		factory := func() (cache.SharedIndexInformer, cache.SharedIndexInformer, error) {
			polls.Add(1)
			return nil, nil, nil
		}
		di := kubevirt.NewDeferredInformers(factory, 10*time.Millisecond, localStop)
		c := &counts{}
		di.AddEventHandlers(newHandlers(c))

		Eventually(polls.Load, 5*time.Second).Should(BeNumerically(">=", 2))
		close(localStop)
		Consistently(func() int { _, _, s := get(c); return s }, 100*time.Millisecond).Should(Equal(0))
	})
})
