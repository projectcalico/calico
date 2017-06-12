// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package k8s

import (
	"sync"

	log "github.com/Sirupsen/logrus"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/thirdparty"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/net"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	k8sapi "k8s.io/client-go/pkg/api/v1"
	extensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

type testWatch struct {
	name      string
	c         <-chan watch.Event
	stopped   bool
	stopMutex sync.Mutex
}

func (tw *testWatch) Stop() {
	tw.stopMutex.Lock()
	defer tw.stopMutex.Unlock()
	if tw.stopped {
		panic("testWatch already stopped")
	}
	tw.stopped = true
	return
}

func (tw *testWatch) ResultChan() <-chan watch.Event {
	return tw.c
}

type testClient struct {
	openWatchers []*testWatch
	podC         chan watch.Event
	poolC        chan watch.Event
	state        map[model.Key]interface{}
	stateMutex   sync.Mutex
	listCalls    int
	watchCalls   int
}

func (tc *testClient) OnStatusUpdated(status api.SyncStatus) {
	log.WithField("status", status).Info("OnStatusUpdated")
	return
}

func (tc *testClient) OnUpdates(updates []api.Update) {
	log.WithField("updates", updates).Info("OnUpdates")
	tc.stateMutex.Lock()
	defer tc.stateMutex.Unlock()
	for _, update := range updates {
		if update.UpdateType == api.UpdateTypeKVDeleted || update.Value == nil {
			delete(tc.state, update.Key)
		} else {
			tc.state[update.Key] = update.Value
		}
	}
	return
}

func (tc *testClient) newWatch(name string, c chan watch.Event) *testWatch {
	tc.stateMutex.Lock()
	defer tc.stateMutex.Unlock()
	w := &testWatch{
		name: name,
		c:    c,
	}
	tc.openWatchers = append(tc.openWatchers, w)
	tc.watchCalls++
	return w
}

func (tc *testClient) NamespaceWatch(opts metav1.ListOptions) (w watch.Interface, err error) {
	w = tc.newWatch("ns", make(chan watch.Event))
	err = nil
	return
}

func (tc *testClient) PodWatch(namespace string, opts metav1.ListOptions) (w watch.Interface, err error) {
	w = tc.newWatch("pod", tc.podC)
	err = nil
	return
}

func (tc *testClient) NetworkPolicyWatch(opts metav1.ListOptions) (w watch.Interface, err error) {
	w = tc.newWatch("pol", make(chan watch.Event))
	err = nil
	return
}

func (tc *testClient) GlobalConfigWatch(opts metav1.ListOptions) (w watch.Interface, err error) {
	w = tc.newWatch("global conf", make(chan watch.Event))
	err = nil
	return
}

func (tc *testClient) IPPoolWatch(opts metav1.ListOptions) (w watch.Interface, err error) {
	w = tc.newWatch("IP pool", tc.poolC)
	err = nil
	return
}

func (tc *testClient) NodeWatch(opts metav1.ListOptions) (w watch.Interface, err error) {
	w = tc.newWatch("node", make(chan watch.Event))
	err = nil
	return
}

func (tc *testClient) countList() {
	tc.stateMutex.Lock()
	defer tc.stateMutex.Unlock()
	tc.listCalls++
}

func (tc *testClient) NamespaceList(opts metav1.ListOptions) (list *k8sapi.NamespaceList, err error) {
	tc.countList()
	list = &k8sapi.NamespaceList{}
	err = nil
	return
}

func (tc *testClient) NetworkPolicyList() (list extensions.NetworkPolicyList, err error) {
	tc.countList()
	list = extensions.NetworkPolicyList{}
	err = nil
	return
}

func (tc *testClient) PodList(namespace string, opts metav1.ListOptions) (list *k8sapi.PodList, err error) {
	tc.countList()
	list = &k8sapi.PodList{}
	err = nil
	return
}

func (tc *testClient) GlobalConfigList(l model.GlobalConfigListOptions) ([]*model.KVPair, string, error) {
	tc.countList()
	return []*model.KVPair{}, "", nil
}

func (tc *testClient) HostConfigList(l model.HostConfigListOptions) ([]*model.KVPair, error) {
	tc.countList()
	return []*model.KVPair{}, nil
}

func (tc *testClient) IPPoolList(l model.IPPoolListOptions) ([]*model.KVPair, string, error) {
	tc.countList()
	return []*model.KVPair{}, "", nil
}

func (tc *testClient) NodeList(opts metav1.ListOptions) (list *k8sapi.NodeList, err error) {
	tc.countList()
	list = &k8sapi.NodeList{}
	err = nil
	return
}
func (tc *testClient) SystemNetworkPolicyWatch(opts metav1.ListOptions) (watch.Interface, error) {
	return tc.newWatch("system network policy", make(chan watch.Event)), nil
}

func (tc *testClient) SystemNetworkPolicyList() (*thirdparty.SystemNetworkPolicyList, error) {
	tc.countList()
	return &thirdparty.SystemNetworkPolicyList{}, nil
}

func (tc *testClient) getReadyStatus(key model.ReadyFlagKey) (*model.KVPair, error) {
	return &model.KVPair{Key: key, Value: true}, nil
}

// getNumListCalls returns the number of List() calls performed by the syncer
// against the Kubernetes API throuout the test.
func (tc *testClient) getNumListCalls() int {
	tc.stateMutex.Lock()
	defer tc.stateMutex.Unlock()
	log.WithField("listCalls", tc.listCalls).Info("")
	return tc.listCalls
}

// getNumWatchCalls returns the number of Watches performed by the syncer
// against the Kubernetes API through the test.
func (tc *testClient) getNumWatchCalls() int {
	tc.stateMutex.Lock()
	defer tc.stateMutex.Unlock()
	log.WithField("watchCalls", tc.watchCalls).Info("")
	return tc.watchCalls
}

var _ = Describe("Test Syncer", func() {
	var (
		tc  *testClient
		syn *kubeSyncer
	)

	BeforeEach(func() {
		tc = &testClient{
			podC:  make(chan watch.Event),
			poolC: make(chan watch.Event),
			state: map[model.Key]interface{}{},
		}
		syn = newSyncer(tc, converter{}, tc, false)
	})

	It("should create a syncer", func() {
		Expect(syn).NotTo(BeNil())
	})

	Describe("without starting the syncer", func() {
		// These tests reach in and test individual methods.
		It("should parse a node event with a nil IPs", func() {
			kv1, kv2 := syn.parseNodeEvent(watch.Event{
				Object: &k8sapi.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "some-host",
						ResourceVersion: "1234",
					},
				},
			})
			Expect(kv1).To(Equal(&model.KVPair{
				Key:      model.HostIPKey{Hostname: "some-host"},
				Revision: "1234",
			}))
			Expect(kv2).To(Equal(&model.KVPair{
				Key: model.HostConfigKey{
					Hostname: "some-host",
					Name:     "IpInIpTunnelAddr",
				},
				Revision: "1234",
			}))
		})
		It("should parse a node event with IPs set", func() {
			kv1, kv2 := syn.parseNodeEvent(watch.Event{
				Object: &k8sapi.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "some-host",
						ResourceVersion: "1234",
						Annotations: map[string]string{
							"projectcalico.org/IPv4Address": "11.0.0.1/24",
						},
					},
					Spec: k8sapi.NodeSpec{
						PodCIDR: "10.0.10.0/24",
					},
				},
			})
			// Using ParseCIDR here so that we get the same format of IP address as
			// K8sNodeToCalico.
			ip, _, err := net.ParseCIDR("11.0.0.1/24")
			Expect(err).NotTo(HaveOccurred())
			Expect(kv1).To(Equal(&model.KVPair{
				Key:      model.HostIPKey{Hostname: "some-host"},
				Value:    ip,
				Revision: "1234",
			}))
			Expect(kv2).To(Equal(&model.KVPair{
				Key: model.HostConfigKey{
					Hostname: "some-host",
					Name:     "IpInIpTunnelAddr",
				},
				Value:    "10.0.10.1",
				Revision: "1234",
			}))
		})
	})

	Context("with a running syncer", func() {

		BeforeEach(func() {
			syn.Start()
		})

		AfterEach(func() {
			syn.Stop()
		})

		It("should not resync when one watch times out", func() {
			// Initial resync makes 8 list calls and 7 watch calls.
			const (
				LIST_CALLS  = 8
				WATCH_CALLS = 7
			)
			Eventually(tc.getNumListCalls).Should(BeNumerically("==", LIST_CALLS))
			Eventually(tc.getNumWatchCalls).Should(BeNumerically("==", WATCH_CALLS))

			// Simulate timeout of the pod watch.
			tc.podC <- watch.Event{Object: nil}

			// Expect a new watch call.
			Eventually(tc.getNumWatchCalls).Should(BeNumerically("==", WATCH_CALLS+1))
			// But no new list calls.
			Expect(tc.getNumListCalls()).To(BeNumerically("==", LIST_CALLS))
		})

		It("should resync resources individually", func() {
			// Initial resync makes 8 list calls and 7 watch calls.
			const (
				LIST_CALLS  = 8
				WATCH_CALLS = 7
			)
			Eventually(tc.getNumListCalls).Should(BeNumerically("==", LIST_CALLS))
			Eventually(tc.getNumWatchCalls).Should(BeNumerically("==", WATCH_CALLS))

			// Simulate error on pod watch.
			tc.podC <- watch.Event{Type: watch.Error, Object: nil}
			// Expect a single new list call, but that each watcher is restarted.
			Eventually(tc.getNumWatchCalls).Should(BeNumerically("==", WATCH_CALLS+7))
			Expect(tc.getNumListCalls()).To(BeNumerically("==", LIST_CALLS+1))

			// Simulate error on IP Pool watch.
			tc.poolC <- watch.Event{Type: watch.Error, Object: nil}
			// Expect a single new list call, but that each watcher is restarted.
			Eventually(tc.getNumWatchCalls).Should(BeNumerically("==", WATCH_CALLS+14))
			Expect(tc.getNumListCalls()).To(BeNumerically("==", LIST_CALLS+2))

			// Simulate empty event on IP Pool watch (resourceVersion too old for TPRs)
			tc.poolC <- watch.Event{Object: nil}
			// Expect a single new list call, but that each watcher is restarted.
			Eventually(tc.getNumWatchCalls).Should(BeNumerically("==", WATCH_CALLS+21))
			Expect(tc.getNumListCalls()).To(BeNumerically("==", LIST_CALLS+3))
		})

		It("should correctly handle pod being deleted in resync", func() {
			// Define a Pod and corresponding Calico model key.
			pod := k8sapi.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-pod",
					Namespace: "my-namespace",
				},
				Spec: k8sapi.PodSpec{
					HostNetwork: false,
					NodeName:    "my-host-1",
				},
				Status: k8sapi.PodStatus{
					PodIP: "10.65.0.2",
				},
			}
			key := model.WorkloadEndpointKey{
				Hostname:       "my-host-1",
				OrchestratorID: "k8s",
				WorkloadID:     "my-namespace.my-pod",
				EndpointID:     "eth0",
			}
			getModelEndpoint := func() interface{} {
				tc.stateMutex.Lock()
				defer tc.stateMutex.Unlock()
				log.WithField("val", tc.state[key]).Info("state")
				return tc.state[key]
			}

			// Send in an update for that pod.
			tc.podC <- watch.Event{Type: watch.Added, Object: &pod}
			Eventually(getModelEndpoint).ShouldNot(BeNil())

			// Send in an update that causes the backend to resync.  The pod won't be in
			// the snapshot, so the pod is implicitly deleted.
			tc.podC <- watch.Event{Type: watch.Error, Object: nil}
			Eventually(getModelEndpoint).Should(BeNil())

			// Send in update for the pod again.
			tc.podC <- watch.Event{Type: watch.Added, Object: &pod}
			Eventually(getModelEndpoint).ShouldNot(BeNil())

			// Check that, after the resync, the old watchers are stopped.
			tc.stateMutex.Lock()
			defer tc.stateMutex.Unlock()
			// We expect 7 old watchers and 7 new. If that changes, we'll assert here
			// so the maintainer can re-check the test still matches the logic.
			Expect(tc.openWatchers).To(HaveLen(14))
			for _, w := range tc.openWatchers[:len(tc.openWatchers)/2] {
				w.stopMutex.Lock()
				stopped := w.stopped
				w.stopMutex.Unlock()
				Expect(stopped).To(BeTrue())
			}
		})
	})
})
