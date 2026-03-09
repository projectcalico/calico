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
	"fmt"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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

// newFakeInformerFactory returns a GetIndexerFunc that returns nil for the
// first nilCount calls, then returns real (fake) informers.
func newFakeInformerFactory(nilCount int, stop <-chan struct{}) kubevirt.GetIndexerFunc {
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
		// Factory always returns nil — KubeVirt never appears.
		factory := func() (cache.SharedIndexInformer, cache.SharedIndexInformer, error) {
			return nil, nil, nil
		}

		di := kubevirt.NewDeferredInformers(factory, 10*time.Millisecond, stop)

		// Let it poll a few times, then stop.
		time.Sleep(50 * time.Millisecond)
		close(stop)
		// Reopen stop so AfterEach doesn't double-close.
		stop = make(chan struct{})

		// Give the goroutine time to exit.
		time.Sleep(20 * time.Millisecond)

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
})
