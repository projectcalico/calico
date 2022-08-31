// Copyright (c) 2016-2020 Tigera, Inc. All rights reserved.

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
	"context"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	k8sapi "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/felixsyncer"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

var (
	zeroOrder                  = float64(0.0)
	calicoAllowPolicyModelSpec = apiv3.GlobalNetworkPolicySpec{
		Order: &zeroOrder,
		Ingress: []apiv3.Rule{
			{
				Action: "Allow",
			},
		},
		Egress: []apiv3.Rule{
			{
				Action: "Allow",
			},
		},
	}
	calicoDisallowPolicyModelSpec = apiv3.GlobalNetworkPolicySpec{
		Order: &zeroOrder,
		Ingress: []apiv3.Rule{
			{
				Action: "Deny",
			},
		},
		Egress: []apiv3.Rule{
			{
				Action: "Deny",
			},
		},
	}

	// Used for testing Syncer conversion
	calicoAllowPolicyModelV1 = model.Policy{
		Order: &zeroOrder,
		InboundRules: []model.Rule{
			{
				Action: "allow",
			},
		},
		OutboundRules: []model.Rule{
			{
				Action: "allow",
			},
		},
	}
	calicoDisallowPolicyModelV1 = model.Policy{
		Order: &zeroOrder,
		InboundRules: []model.Rule{
			{
				Action: "deny",
			},
		},
		OutboundRules: []model.Rule{
			{
				Action: "deny",
			},
		},
	}
	calicoAllowProfileSpec = apiv3.ProfileSpec{
		Ingress: []apiv3.Rule{
			{
				Action: "Allow",
			},
		},
		Egress: []apiv3.Rule{
			{
				Action: "Allow",
			},
		},
	}

	defaultAllowProfileKey = model.ResourceKey{Name: "projectcalico-default-allow", Kind: apiv3.KindProfile}

	// Use a back-off set of intervals for testing deletion of a namespace
	// which can sometimes be slow.
	slowCheck = []interface{}{
		60 * time.Second,
		1 * time.Second,
	}
)

// cb implements the callback interface required for the
// backend Syncer API.
type cb struct {
	// Stores the current state for comparison by the tests.
	State map[string]api.Update
	Lock  *sync.Mutex

	status     api.SyncStatus
	updateChan chan api.Update
}

func (c cb) OnStatusUpdated(status api.SyncStatus) {
	defer GinkgoRecover()

	// Keep latest status up to date.
	log.Warnf("[TEST] Received status update: %+v", status)
	c.status = status

	// Once we get in sync, we don't ever expect to not
	// be in sync.
	if c.status == api.InSync {
		Expect(status).To(Equal(api.InSync))
	}
}

func (c cb) OnUpdates(updates []api.Update) {
	defer GinkgoRecover()

	// Ensure the given updates are valid.
	// We only perform mild validation here.
	for _, u := range updates {
		switch u.UpdateType {
		case api.UpdateTypeKVNew:
			// Sometimes the value is nil (e.g ProfileTags)
			log.Infof("[TEST] Syncer received new: %+v", u)
		case api.UpdateTypeKVUpdated:
			// Sometimes the value is nil (e.g ProfileTags)
			log.Infof("[TEST] Syncer received updated: %+v", u)
		case api.UpdateTypeKVDeleted:
			// Ensure the value is nil for deletes.
			log.Infof("[TEST] Syncer received deleted: %+v", u)
			Expect(u.Value).To(BeNil())
		case api.UpdateTypeKVUnknown:
			panic(fmt.Sprintf("[TEST] Syncer received unknown update: %+v", u))
		}

		// Send the update to a goroutine which will process it.
		c.updateChan <- u
	}
}

func (c cb) ProcessUpdates() {
	for u := range c.updateChan {
		// Store off the update so it can be checked by the test.
		// Use a mutex for safe cross-goroutine reads/writes.
		c.Lock.Lock()
		if u.UpdateType == api.UpdateTypeKVUnknown {
			// We should never get this!
			log.Panic("Received Unknown update type")
		} else if u.UpdateType == api.UpdateTypeKVDeleted {
			// Deleted.
			delete(c.State, u.Key.String())
			log.Infof("[TEST] Delete update %s", u.Key.String())
		} else {
			// Add or modified.
			c.State[u.Key.String()] = u
			log.Infof("[TEST] Stored update (type %d) %s", u.UpdateType, u.Key.String())
		}
		c.Lock.Unlock()
	}
}

func (c cb) ExpectExists(updates []api.Update) {
	// For each Key, wait for it to exist.
	for _, update := range updates {
		log.Infof("[TEST] Expecting key: %v", update.Key)
		matches := false

		_ = wait.PollImmediate(1*time.Second, 60*time.Second, func() (bool, error) {
			// Get the update.
			c.Lock.Lock()
			u, ok := c.State[update.Key.String()]
			c.Lock.Unlock()

			// See if we've got a matching update. For now, we just check
			// that the key exists and that it's the correct type.
			matches = ok && update.UpdateType == u.UpdateType

			log.Infof("[TEST] Key exists? %t matches? %t: expected %v; actual %v", ok, matches, update.UpdateType, u.UpdateType)
			if matches {
				// Expected the update to be present, and it is.
				return true, nil
			} else {
				// Update is not yet present.
				return false, nil
			}
		})

		// Expect the key to have existed.
		ExpectWithOffset(1, matches).To(Equal(true), fmt.Sprintf("Expected update not found: %v", update.Key))
	}
}

// ExpectDeleted asserts that the provided KVPairs have been deleted
// via an update over the Syncer.
func (c cb) ExpectDeleted(kvps []model.KVPair) {
	for _, kvp := range kvps {
		log.Infof("[TEST] Not expecting key: %v", kvp.Key)
		exists := true

		_ = wait.PollImmediate(1*time.Second, 60*time.Second, func() (bool, error) {
			// Get the update.
			c.Lock.Lock()
			update, ok := c.State[kvp.Key.String()]
			exists = ok
			c.Lock.Unlock()

			log.Infof("[TEST] Key exists? %t: %+v", ok, update)
			if ok {
				// Expected key to not exist, and it does.
				return false, nil
			} else {
				// Expected key to not exist, and it doesn't.
				return true, nil
			}
		})

		// Expect the key to not exist.
		ExpectWithOffset(1, exists).To(Equal(false), fmt.Sprintf("Expected key not to exist: %v", kvp.Key))
	}
}

// ExpectAddedEvent checks for an api.WatchAdded coming down a specific chan
// this is used in several tests below
func ExpectAddedEvent(events <-chan api.WatchEvent) *api.WatchEvent {
	return expectEventOfType(events, api.WatchAdded)
}

// ExpectModifiedEvent checks for an api.WatchModified coming down a specific chan
func ExpectModifiedEvent(events <-chan api.WatchEvent) *api.WatchEvent {
	return expectEventOfType(events, api.WatchModified)
}

func expectEventOfType(events <-chan api.WatchEvent, type_ api.WatchEventType) *api.WatchEvent {
	var receivedEvent *api.WatchEvent
poll:
	for i := 0; i < 10; i++ {
		select {
		case e := <-events:
			// Got an event. Check it's OK.
			ExpectWithOffset(2, e.Error).NotTo(HaveOccurred())
			ExpectWithOffset(2, e.Type).To(Equal(type_))
			receivedEvent = &e
			break poll
		default:
			time.Sleep(50 * time.Millisecond)
		}
	}
	ExpectWithOffset(2, receivedEvent).NotTo(BeNil(), "Did not receive watch event")
	return receivedEvent
}

// GetSyncerValueFunc returns a function that can be used to query the value of
// an entry in our syncer state store.  It's useful for performing "Eventually" testing.
//
// The returned function returns the cached entry or nil if the entry does not
// exist in the cache.
func (c cb) GetSyncerValueFunc(key model.Key) func() interface{} {
	return func() interface{} {
		log.Infof("Checking entry in cache: %v", key)
		c.Lock.Lock()
		defer func() {
			c.Lock.Unlock()
		}()
		if entry, ok := c.State[key.String()]; ok {
			return entry.Value
		}
		return nil
	}
}

// GetSyncerValuePresentFunc returns a function that can be used to query whether an entry
// is in our syncer state store.  It's useful for performing "Eventually" testing.
//
// When checking for presence use this function rather than GetSyncerValueFunc() because
// the Value may itself by nil.
//
// The returned function returns true if the entry is present.
func (c cb) GetSyncerValuePresentFunc(key model.Key) func() interface{} {
	return func() interface{} {
		log.Infof("Checking entry in cache: %v", key)
		c.Lock.Lock()
		defer func() { c.Lock.Unlock() }()
		_, ok := c.State[key.String()]
		return ok
	}
}

func CreateClientAndSyncer(cfg apiconfig.KubeConfig) (*KubeClient, *cb, api.Syncer) {
	// First create the client.
	caCfg := apiconfig.CalicoAPIConfigSpec{KubeConfig: cfg}
	c, err := NewKubeClient(&caCfg)
	if err != nil {
		panic(err)
	}

	// Ensure the backend is initialized.
	err = c.EnsureInitialized()
	Expect(err).NotTo(HaveOccurred(), "Failed to initialize the backend.")

	// Start the syncer.
	updateChan := make(chan api.Update)
	callback := cb{
		State:      map[string]api.Update{},
		status:     api.WaitForDatastore,
		Lock:       &sync.Mutex{},
		updateChan: updateChan,
	}
	syncer := felixsyncer.New(c, caCfg, callback, true)
	return c.(*KubeClient), &callback, syncer
}

var _ = testutils.E2eDatastoreDescribe("Test Syncer API for Kubernetes backend", testutils.DatastoreK8s, func(cfg apiconfig.CalicoAPIConfig) {
	var (
		c      *KubeClient
		cb     *cb
		syncer api.Syncer
	)

	ctx := context.Background()

	BeforeEach(func() {
		log.SetLevel(log.DebugLevel)

		// Create a Kubernetes client, callbacks, and a syncer.
		cfg := apiconfig.KubeConfig{Kubeconfig: "/kubeconfig.yaml"}
		c, cb, syncer = CreateClientAndSyncer(cfg)

		// Start the syncer.
		syncer.Start()

		// Node object is created by applying the mock-node.yaml manifest in advance.

		// Start processing updates.
		go cb.ProcessUpdates()
	})

	AfterEach(func() {
		// Clean up all Calico resources.
		err := c.Clean()
		Expect(err).NotTo(HaveOccurred())

		// Clean up any k8s network policy left over by the test.
		nps := networkingv1.NetworkPolicyList{}
		err = c.ClientSet.NetworkingV1().RESTClient().
			Get().
			Resource("networkpolicies").
			Timeout(10 * time.Second).
			Do(ctx).Into(&nps)
		Expect(err).NotTo(HaveOccurred())

		for _, np := range nps.Items {
			result := c.ClientSet.NetworkingV1().RESTClient().
				Delete().
				Resource("networkpolicies").
				Namespace(np.Namespace).
				Name(np.Name).
				Timeout(10 * time.Second).
				Do(ctx)
			Expect(result.Error()).NotTo(HaveOccurred())
		}

		// Clean up any pods left over by the test.
		pods, err := c.ClientSet.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())

		for _, p := range pods.Items {
			// Skip kube-system pods.
			if p.Namespace == "kube-system" {
				continue
			}
			err = c.ClientSet.CoreV1().Pods(p.Namespace).Delete(ctx, p.Name, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		}
		syncer.Stop()
	})

	It("should handle a Namespace with DefaultDeny (v1beta annotation for namespace isolation)", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-syncer-namespace-default-deny",
				Annotations: map[string]string{
					"net.beta.kubernetes.io/network-policy": "{\"ingress\": {\"isolation\": \"DefaultDeny\"}}",
				},
				Labels: map[string]string{"label": "value"},
			},
		}

		By("Creating a namespace", func() {
			_, err := c.ClientSet.CoreV1().Namespaces().Create(ctx, &ns, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		By("Performing a List of Profiles", func() {
			_, err := c.List(ctx, model.ResourceListOptions{Kind: apiv3.KindProfile}, "")
			Expect(err).NotTo(HaveOccurred())
		})

		By("Performing a List of Policies", func() {
			_, err := c.List(ctx, model.ResourceListOptions{Kind: apiv3.KindNetworkPolicy, Namespace: "test-syncer-namespace-default-deny"}, "")
			Expect(err).NotTo(HaveOccurred())
		})

		By("Performing a Get on the Profile and ensure no error in the Calico API", func() {
			_, err := c.Get(ctx, model.ResourceKey{Name: fmt.Sprintf("kns.%s", ns.ObjectMeta.Name), Kind: apiv3.KindProfile}, "")
			Expect(err).NotTo(HaveOccurred())
		})

		By("Checking the correct entries are in our cache", func() {
			expectedName := "kns.test-syncer-namespace-default-deny"
			Eventually(cb.GetSyncerValuePresentFunc(model.ProfileRulesKey{ProfileKey: model.ProfileKey{expectedName}})).Should(BeTrue())
			Eventually(cb.GetSyncerValuePresentFunc(model.ProfileLabelsKey{ProfileKey: model.ProfileKey{expectedName}})).Should(BeTrue())
		})

		By("Deleting the namespace", func() {
			testutils.DeleteNamespace(c.ClientSet, ns.ObjectMeta.Name)
		})

		By("Checking the correct entries are no longer in our cache", func() {
			expectedName := "kns.test-syncer-namespace-default-deny"
			Eventually(cb.GetSyncerValuePresentFunc(model.ProfileRulesKey{ProfileKey: model.ProfileKey{expectedName}}), slowCheck...).Should(BeFalse())
			Eventually(cb.GetSyncerValuePresentFunc(model.ProfileLabelsKey{ProfileKey: model.ProfileKey{expectedName}})).Should(BeFalse())
		})
	})

	It("should handle a Namespace without any annotations", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "test-syncer-namespace-no-default-deny",
				Annotations: map[string]string{},
				Labels:      map[string]string{"label": "value"},
			},
		}

		// Check to see if the create succeeded.
		By("Creating a namespace", func() {
			_, err := c.ClientSet.CoreV1().Namespaces().Create(ctx, &ns, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		// Perform a List and ensure it shows up in the Calico API.
		By("listing Profiles", func() {
			_, err := c.List(ctx, model.ResourceListOptions{Kind: apiv3.KindProfile}, "")
			Expect(err).NotTo(HaveOccurred())
		})

		By("listing Policies", func() {
			_, err := c.List(ctx, model.ResourceListOptions{Kind: apiv3.KindNetworkPolicy, Namespace: "test-syncer-namespace-no-default-deny"}, "")
			Expect(err).NotTo(HaveOccurred())
		})

		// Perform a Get and ensure no error in the Calico API.
		By("getting a Profile", func() {
			_, err := c.Get(ctx, model.ResourceKey{Name: fmt.Sprintf("kns.%s", ns.ObjectMeta.Name), Kind: apiv3.KindProfile}, "")
			Expect(err).NotTo(HaveOccurred())
		})

		// Expect corresponding Profile updates over the syncer for this Namespace.
		By("Checking the correct entries are in our cache", func() {
			expectedName := "kns.test-syncer-namespace-no-default-deny"
			Eventually(cb.GetSyncerValuePresentFunc(model.ProfileRulesKey{ProfileKey: model.ProfileKey{expectedName}})).Should(BeTrue())
			Eventually(cb.GetSyncerValuePresentFunc(model.ProfileLabelsKey{ProfileKey: model.ProfileKey{expectedName}})).Should(BeTrue())
		})

		By("deleting a namespace", func() {
			testutils.DeleteNamespace(c.ClientSet, ns.ObjectMeta.Name)
		})

		By("Checking the correct entries are in no longer in our cache", func() {
			expectedName := "kns.test-syncer-namespace-no-default-deny"
			Eventually(cb.GetSyncerValuePresentFunc(model.ProfileRulesKey{ProfileKey: model.ProfileKey{expectedName}}), slowCheck...).Should(BeFalse())
			Eventually(cb.GetSyncerValuePresentFunc(model.ProfileLabelsKey{ProfileKey: model.ProfileKey{expectedName}})).Should(BeFalse())
		})
	})

	It("should handle the static default-allow Profile", func() {
		findAllowAllProfileEvent := func(c <-chan api.WatchEvent) bool {
			found := false
			for i := 0; i < 10; i++ {
				select {
				case e := <-c:
					if e.Type == api.WatchAdded &&
						e.Old == nil &&
						e.New.Key == defaultAllowProfileKey {
						found = true
					}
				default:
					time.Sleep(50 * time.Millisecond)
				}
			}
			return found
		}

		expectNoAllowAllEvent := func(c <-chan api.WatchEvent) {
			found := findAllowAllProfileEvent(c)
			Expect(found).To(BeFalse())
		}

		By("existing in our cache", func() {
			expectedName := "projectcalico-default-allow"
			Eventually(cb.GetSyncerValuePresentFunc(model.ProfileRulesKey{ProfileKey: model.ProfileKey{expectedName}}), slowCheck...).Should(BeTrue())
		})

		By("watching all profiles with a valid rv does not return an event for the default-allow profile", func() {
			rvs := []string{"", "0", "1000000/", "1000/1000", "/100000000"}
			for _, rv := range rvs {
				watch, err := c.Watch(ctx, model.ResourceListOptions{Kind: apiv3.KindProfile}, rv)
				Expect(err).NotTo(HaveOccurred())
				defer watch.Stop()

				expectNoAllowAllEvent(watch.ResultChan())
			}
		})

		By("watching the default-allow profile with any rv does not return an event", func() {
			rvs := []string{"", "0"}
			for _, rv := range rvs {
				watch, err := c.Watch(ctx, model.ResourceListOptions{Name: "projectcalico-default-allow", Kind: apiv3.KindProfile}, rv)
				Expect(err).NotTo(HaveOccurred())
				defer watch.Stop()
				select {
				case e := <-watch.ResultChan():
					Fail(fmt.Sprintf("expected no events but got: %+v", e))
				case <-time.After(2 * time.Second):
				}
			}
		})

		By("getting the profile with any rv should return the profile", func() {
			rvs := []string{"", "0"}
			for _, rv := range rvs {
				kvp, err := c.Get(ctx, defaultAllowProfileKey, rv)
				Expect(err).NotTo(HaveOccurred())
				Expect(kvp).NotTo(BeNil())

				profile := kvp.Value.(*apiv3.Profile)
				Expect(profile.Spec).Should(Equal(calicoAllowProfileSpec))
			}
		})

		By("listing all profiles with any rv should include the profile", func() {
			rvs := []string{"", "0"}
			for _, rv := range rvs {
				kvps, err := c.List(ctx, model.ResourceListOptions{Kind: apiv3.KindProfile}, rv)
				Expect(err).NotTo(HaveOccurred())

				var found bool
				for _, kvp := range kvps.KVPairs {
					if kvp.Key == defaultAllowProfileKey {
						found = true
						Expect(kvp.Value.(*apiv3.Profile).Spec).Should(Equal(calicoAllowProfileSpec))
					}
				}
				Expect(found).To(BeTrue())
			}
		})

		By("creating the profile returns an error", func() {
			kvp, err := c.Get(ctx, defaultAllowProfileKey, "")
			Expect(err).NotTo(HaveOccurred())

			_, err = c.Create(ctx, kvp)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Create is not supported on Profile(projectcalico-default-allow)"))
		})

		By("updating the profile returns an error", func() {
			kvp, err := c.Get(ctx, defaultAllowProfileKey, "")
			Expect(err).NotTo(HaveOccurred())

			_, err = c.Update(ctx, kvp)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Update is not supported on Profile(projectcalico-default-allow)"))
		})

		By("deleting the profile returns an error", func() {
			_, err := c.Delete(ctx, defaultAllowProfileKey, "")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Delete is not supported on Profile(projectcalico-default-allow)"))
		})
	})

	It("should handle a basic NetworkPolicy", func() {
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-syncer-basic-net-policy",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{},
						},
						From: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k": "v",
									},
								},
							},
						},
					},
				},
			},
		}
		res := c.ClientSet.NetworkingV1().RESTClient().
			Post().
			Resource("networkpolicies").
			Namespace("default").
			Body(&np).
			Do(ctx)

		// Check to see if the create succeeded.
		Expect(res.Error()).NotTo(HaveOccurred())

		// Perform a List and ensure it shows up in the Calico API.
		l, err := c.List(ctx, model.ResourceListOptions{Kind: model.KindKubernetesNetworkPolicy}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(l.KVPairs)).To(Equal(1))

		// Perform a Get - it's not supported.
		_, err = c.Get(ctx, model.ResourceKey{
			Name:      np.ObjectMeta.Name,
			Namespace: "default",
		}, "")
		Expect(err).To(HaveOccurred())
	})

	It("should handle a CRUD of Global Network Policy", func() {
		var kvpRes *model.KVPair

		gnpClient := c.GetResourceClientFromResourceKind(apiv3.KindGlobalNetworkPolicy)
		kvp1Name := "my-test-gnp"
		kvp1KeyV1 := model.PolicyKey{Name: kvp1Name}
		kvp1a := &model.KVPair{
			Key: model.ResourceKey{Name: kvp1Name, Kind: apiv3.KindGlobalNetworkPolicy},
			Value: &apiv3.GlobalNetworkPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       apiv3.KindGlobalNetworkPolicy,
					APIVersion: apiv3.GroupVersionCurrent,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: kvp1Name,
				},
				Spec: calicoAllowPolicyModelSpec,
			},
		}

		kvp1b := &model.KVPair{
			Key: model.ResourceKey{Name: kvp1Name, Kind: apiv3.KindGlobalNetworkPolicy},
			Value: &apiv3.GlobalNetworkPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       apiv3.KindGlobalNetworkPolicy,
					APIVersion: apiv3.GroupVersionCurrent,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: kvp1Name,
				},
				Spec: calicoDisallowPolicyModelSpec,
			},
		}

		kvp2Name := "my-test-gnp2"
		kvp2KeyV1 := model.PolicyKey{Name: kvp2Name}
		kvp2a := &model.KVPair{
			Key: model.ResourceKey{Name: kvp2Name, Kind: apiv3.KindGlobalNetworkPolicy},
			Value: &apiv3.GlobalNetworkPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       apiv3.KindGlobalNetworkPolicy,
					APIVersion: apiv3.GroupVersionCurrent,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: kvp2Name,
				},
				Spec: calicoAllowPolicyModelSpec,
			},
		}

		kvp2b := &model.KVPair{
			Key: model.ResourceKey{Name: kvp2Name, Kind: apiv3.KindGlobalNetworkPolicy},
			Value: &apiv3.GlobalNetworkPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       apiv3.KindGlobalNetworkPolicy,
					APIVersion: apiv3.GroupVersionCurrent,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: kvp2Name,
				},
				Spec: calicoDisallowPolicyModelSpec,
			},
		}

		// Check our syncer has the correct GNP entries for the two
		// System Network Protocols that this test manipulates.  Neither
		// have been created yet.
		By("Checking cache does not have Global Network Policy entries", func() {
			Eventually(cb.GetSyncerValuePresentFunc(kvp1KeyV1)).Should(BeFalse())
			Eventually(cb.GetSyncerValuePresentFunc(kvp2KeyV1)).Should(BeFalse())
		})

		By("Creating a Global Network Policy", func() {
			var err error
			kvpRes, err = gnpClient.Create(ctx, kvp1a)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Checking cache has correct Global Network Policy entries", func() {
			Eventually(cb.GetSyncerValueFunc(kvp1KeyV1)).Should(Equal(&calicoAllowPolicyModelV1))
			Eventually(cb.GetSyncerValuePresentFunc(kvp2KeyV1)).Should(BeFalse())
		})

		By("Attempting to recreate an existing Global Network Policy", func() {
			_, err := gnpClient.Create(ctx, kvp1a)
			Expect(err).To(HaveOccurred())
		})

		By("Updating an existing Global Network Policy", func() {
			kvp1b.Revision = kvpRes.Revision
			_, err := gnpClient.Update(ctx, kvp1b)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Checking cache has correct Global Network Policy entries", func() {
			Eventually(cb.GetSyncerValueFunc(kvp1KeyV1)).Should(Equal(&calicoDisallowPolicyModelV1))
			Eventually(cb.GetSyncerValuePresentFunc(kvp2a.Key)).Should(BeFalse())
		})

		By("Create another Global Network Policy", func() {
			var err error
			kvpRes, err = gnpClient.Create(ctx, kvp2a)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Checking cache has correct Global Network Policy entries", func() {
			Eventually(cb.GetSyncerValueFunc(kvp1KeyV1)).Should(Equal(&calicoDisallowPolicyModelV1))
			Eventually(cb.GetSyncerValueFunc(kvp2KeyV1)).Should(Equal(&calicoAllowPolicyModelV1))
		})

		By("Updating the Global Network Policy created by Create", func() {
			kvp2b.Revision = kvpRes.Revision
			_, err := gnpClient.Update(ctx, kvp2b)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Checking cache has correct Global Network Policy entries", func() {
			Eventually(cb.GetSyncerValueFunc(kvp1KeyV1)).Should(Equal(&calicoDisallowPolicyModelV1))
			Eventually(cb.GetSyncerValueFunc(kvp2KeyV1)).Should(Equal(&calicoDisallowPolicyModelV1))
		})

		By("Deleted the Global Network Policy created by Apply", func() {
			_, err := gnpClient.Delete(ctx, kvp2a.Key, "", nil)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Checking cache has correct Global Network Policy entries", func() {
			Eventually(cb.GetSyncerValueFunc(kvp1KeyV1)).Should(Equal(&calicoDisallowPolicyModelV1))
			Eventually(cb.GetSyncerValuePresentFunc(kvp2KeyV1)).Should(BeFalse())
		})

		By("Getting a Global Network Policy that does not exist", func() {
			_, err := c.Get(ctx, model.ResourceKey{Name: "my-non-existent-test-gnp", Kind: apiv3.KindGlobalNetworkPolicy}, "")
			Expect(err).To(HaveOccurred())
		})

		By("Listing a missing Global Network Policy", func() {
			kvps, err := c.List(ctx, model.ResourceListOptions{Name: "my-non-existent-test-gnp", Kind: apiv3.KindGlobalNetworkPolicy}, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(0))
		})

		By("Getting an existing Global Network Policy", func() {
			kvp, err := c.Get(ctx, model.ResourceKey{Name: "my-test-gnp", Kind: apiv3.KindGlobalNetworkPolicy}, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(kvp.Key.(model.ResourceKey).Name).To(Equal("my-test-gnp"))
			Expect(kvp.Value.(*apiv3.GlobalNetworkPolicy).Spec).To(Equal(kvp1b.Value.(*apiv3.GlobalNetworkPolicy).Spec))
		})

		latestRevision := ""
		By("Listing all Global Network Policies", func() {
			kvps, err := c.List(ctx, model.ResourceListOptions{Kind: apiv3.KindGlobalNetworkPolicy}, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(1))
			Expect(kvps.KVPairs[len(kvps.KVPairs)-1].Key.(model.ResourceKey).Name).To(Equal("my-test-gnp"))
			Expect(kvps.KVPairs[len(kvps.KVPairs)-1].Value.(*apiv3.GlobalNetworkPolicy).Spec).To(Equal(kvp1b.Value.(*apiv3.GlobalNetworkPolicy).Spec))
			latestRevision = kvps.Revision
		})

		By("Listing all Global Network Policies, using an invalid revision", func() {
			_, err := c.List(ctx, model.ResourceListOptions{Kind: apiv3.KindGlobalNetworkPolicy}, fmt.Sprintf("1%s", kvp2b.Revision))
			Expect(err).To(HaveOccurred())
		})

		By("Listing all Global Network Policies with a valid revision", func() {
			Expect(latestRevision).NotTo(Equal(""))
			kvps, err := c.List(ctx, model.ResourceListOptions{Kind: apiv3.KindGlobalNetworkPolicy}, latestRevision)
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(1))
			Expect(kvps.KVPairs[len(kvps.KVPairs)-1].Key.(model.ResourceKey).Name).To(Equal("my-test-gnp"))
			Expect(kvps.KVPairs[len(kvps.KVPairs)-1].Value.(*apiv3.GlobalNetworkPolicy).Spec).To(Equal(kvp1b.Value.(*apiv3.GlobalNetworkPolicy).Spec))
		})

		By("Deleting an existing Global Network Policy", func() {
			_, err := gnpClient.Delete(ctx, kvp1a.Key, "", nil)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Checking cache has no Global Network Policy entries", func() {
			Eventually(cb.GetSyncerValuePresentFunc(kvp1KeyV1)).Should(BeFalse())
			Eventually(cb.GetSyncerValuePresentFunc(kvp2KeyV1)).Should(BeFalse())
		})
	})

	It("should handle a CRUD of Host Endpoint", func() {
		kvp1Name := "my-test-hep1"
		kvp1a := &model.KVPair{
			Key: model.ResourceKey{Name: kvp1Name, Kind: apiv3.KindHostEndpoint},
			Value: &apiv3.HostEndpoint{
				TypeMeta: metav1.TypeMeta{
					Kind:       apiv3.KindHostEndpoint,
					APIVersion: apiv3.GroupVersionCurrent,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: kvp1Name,
				},
				Spec: apiv3.HostEndpointSpec{
					Node:          "my-test-node1",
					InterfaceName: "eth0",
				},
			},
		}

		kvp1b := &model.KVPair{
			Key: model.ResourceKey{Name: kvp1Name, Kind: apiv3.KindHostEndpoint},
			Value: &apiv3.HostEndpoint{
				TypeMeta: metav1.TypeMeta{
					Kind:       apiv3.KindHostEndpoint,
					APIVersion: apiv3.GroupVersionCurrent,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: kvp1Name,
				},
				Spec: apiv3.HostEndpointSpec{
					Node:          "my-test-node1",
					InterfaceName: "eth1",
				},
			},
		}

		kvp2Name := "my-test-hep2"
		kvp2a := &model.KVPair{
			Key: model.ResourceKey{Name: kvp2Name, Kind: apiv3.KindHostEndpoint},
			Value: &apiv3.HostEndpoint{
				TypeMeta: metav1.TypeMeta{
					Kind:       apiv3.KindHostEndpoint,
					APIVersion: apiv3.GroupVersionCurrent,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: kvp2Name,
				},
				Spec: apiv3.HostEndpointSpec{
					Node:          "my-test-node2",
					InterfaceName: "eth0",
				},
			},
		}

		kvp2b := &model.KVPair{
			Key: model.ResourceKey{Name: kvp2Name, Kind: apiv3.KindHostEndpoint},
			Value: &apiv3.HostEndpoint{
				TypeMeta: metav1.TypeMeta{
					Kind:       apiv3.KindHostEndpoint,
					APIVersion: apiv3.GroupVersionCurrent,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: kvp2Name,
				},
				Spec: apiv3.HostEndpointSpec{
					Node:          "my-test-node2",
					InterfaceName: "eth1",
				},
			},
		}

		var kvpRes *model.KVPair
		var err error

		By("Creating a Host Endpoint", func() {
			kvpRes, err = c.Create(ctx, kvp1a)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Attempting to recreate an existing Host Endpoint", func() {
			_, err := c.Create(ctx, kvp1a)
			Expect(err).To(HaveOccurred())
		})

		By("Updating an existing Host Endpoint", func() {
			kvp1b.Revision = kvpRes.Revision
			_, err := c.Update(ctx, kvp1b)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Create a non-existent Host Endpoint", func() {
			kvpRes, err = c.Create(ctx, kvp2a)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Updating the Host Endpoint created by Create", func() {
			kvp2b.Revision = kvpRes.Revision
			_, err := c.Update(ctx, kvp2b)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Getting a missing Host Endpoint", func() {
			_, err := c.Get(ctx, model.ResourceKey{Name: "my-non-existent-test-hep", Kind: apiv3.KindHostEndpoint}, "")
			Expect(err).To(HaveOccurred())
		})

		By("Listing a missing Host Endpoint", func() {
			kvps, err := c.List(ctx, model.ResourceListOptions{Name: "my-non-existent-test-hep", Kind: apiv3.KindHostEndpoint}, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(0))
		})

		By("Listing an explicit Host Endpoint", func() {
			kvps, err := c.List(ctx, model.ResourceListOptions{Name: kvp1Name, Kind: apiv3.KindHostEndpoint}, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(1))
			Expect(kvps.KVPairs[0].Key).To(Equal(kvp1b.Key))
			Expect(kvps.KVPairs[0].Value.(*apiv3.HostEndpoint).ObjectMeta.Name).To(Equal(kvp1b.Value.(*apiv3.HostEndpoint).ObjectMeta.Name))
			Expect(kvps.KVPairs[0].Value.(*apiv3.HostEndpoint).Spec).To(Equal(kvp1b.Value.(*apiv3.HostEndpoint).Spec))
		})

		By("Listing all Host Endpoints", func() {
			kvps, err := c.List(ctx, model.ResourceListOptions{Kind: apiv3.KindHostEndpoint}, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(2))
			keys := []model.Key{}
			vals := []interface{}{}
			for _, k := range kvps.KVPairs {
				keys = append(keys, k.Key)
				vals = append(vals, k.Value.(*apiv3.HostEndpoint).Spec)
			}
			Expect(keys).To(ContainElement(kvp1b.Key))
			Expect(keys).To(ContainElement(kvp2b.Key))
			Expect(vals).To(ContainElement(kvp1b.Value.(*apiv3.HostEndpoint).Spec))
			Expect(vals).To(ContainElement(kvp2b.Value.(*apiv3.HostEndpoint).Spec))
		})

		By("Deleting an existing Host Endpoint", func() {
			_, err := c.Delete(ctx, kvp1a.Key, "")
			Expect(err).NotTo(HaveOccurred())
		})
	})

	It("should handle a CRUD of Network Sets", func() {
		kvp1 := &model.KVPair{
			Key: model.ResourceKey{
				Name:      "test-syncer-netset1",
				Kind:      apiv3.KindNetworkSet,
				Namespace: "test-syncer-ns1",
			},
			Value: &apiv3.NetworkSet{
				TypeMeta: metav1.TypeMeta{
					Kind:       apiv3.KindNetworkSet,
					APIVersion: apiv3.GroupVersionCurrent,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-syncer-netset1",
					Namespace: "test-syncer-ns1",
				},
				Spec: apiv3.NetworkSetSpec{
					Nets: []string{
						"10.11.12.13/32",
						"100.101.102.103/24",
					},
				},
			},
		}
		kvp2 := &model.KVPair{
			Key: model.ResourceKey{
				Name:      "test-syncer-netset1",
				Kind:      apiv3.KindNetworkSet,
				Namespace: "test-syncer-ns1",
			},
			Value: &apiv3.NetworkSet{
				TypeMeta: metav1.TypeMeta{
					Kind:       apiv3.KindNetworkSet,
					APIVersion: apiv3.GroupVersionCurrent,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-syncer-netset1",
					Namespace: "test-syncer-ns1",
				},
				Spec: apiv3.NetworkSetSpec{
					Nets: []string{
						"192.168.100.111/32",
					},
				},
			},
		}
		kvp3 := &model.KVPair{
			Key: model.ResourceKey{
				Name:      "test-syncer-netset3",
				Kind:      apiv3.KindNetworkSet,
				Namespace: "test-syncer-ns1",
			},
			Value: &apiv3.NetworkSet{
				TypeMeta: metav1.TypeMeta{
					Kind:       apiv3.KindNetworkSet,
					APIVersion: apiv3.GroupVersionCurrent,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-syncer-netset3",
					Namespace: "test-syncer-ns1",
				},
				Spec: apiv3.NetworkSetSpec{
					Nets: []string{
						"8.8.8.8/32",
						"aa:bb::cc",
					},
				},
			},
		}

		ns := k8sapi.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "test-syncer-ns1",
				Annotations: map[string]string{},
				Labels:      map[string]string{"label": "value"},
			},
		}

		var kvpRes *model.KVPair
		var err error

		// Check to see if the create succeeded.
		By("Creating a namespace", func() {
			_, err := c.ClientSet.CoreV1().Namespaces().Create(ctx, &ns, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		By("Creating a Network Set", func() {
			kvpRes, err = c.Create(ctx, kvp1)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Attempting to recreate an existing Network Set", func() {
			_, err := c.Create(ctx, kvp1)
			Expect(err).To(HaveOccurred())
		})

		By("Updating an existing Network Set", func() {
			kvp2.Revision = kvpRes.Revision
			_, err := c.Update(ctx, kvp2)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Listing a specific Network Set but in wrong namespace", func() {
			kvps, err := c.List(ctx, model.ResourceListOptions{Name: "test-syncer-netset1", Namespace: "default", Kind: apiv3.KindNetworkSet}, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(0))
		})

		By("Listing a specific Network Set", func() {
			kvps, err := c.List(ctx, model.ResourceListOptions{Name: "test-syncer-netset1", Namespace: ns.ObjectMeta.Name, Kind: apiv3.KindNetworkSet}, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(1))
			Expect(kvps.KVPairs[0].Key).To(Equal(kvp1.Key))
			Expect(kvps.KVPairs[0].Value.(*apiv3.NetworkSet).ObjectMeta.Name).To(Equal(kvp2.Value.(*apiv3.NetworkSet).ObjectMeta.Name))
			Expect(kvps.KVPairs[0].Value.(*apiv3.NetworkSet).Spec).To(Equal(kvp2.Value.(*apiv3.NetworkSet).Spec))
		})

		By("Creating another Network Set in the same namespace", func() {
			kvpRes, err = c.Create(ctx, kvp3)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Listing all Network Sets in default namespace", func() {
			kvps, err := c.List(ctx, model.ResourceListOptions{Namespace: "default", Kind: apiv3.KindNetworkSet}, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(0))
		})

		By("Listing all Network Sets in namespace", func() {
			kvps, err := c.List(ctx, model.ResourceListOptions{Namespace: ns.ObjectMeta.Name, Kind: apiv3.KindNetworkSet}, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(2))
			keys := []model.Key{}
			vals := []interface{}{}
			for _, k := range kvps.KVPairs {
				keys = append(keys, k.Key)
				vals = append(vals, k.Value.(*apiv3.NetworkSet).Spec)
			}
			Expect(keys).To(ContainElement(kvp2.Key))
			Expect(keys).To(ContainElement(kvp3.Key))
			Expect(vals).To(ContainElement(kvp2.Value.(*apiv3.NetworkSet).Spec))
			Expect(vals).To(ContainElement(kvp3.Value.(*apiv3.NetworkSet).Spec))
		})

		By("Deleting an existing Network Set", func() {
			_, err := c.Delete(ctx, kvp2.Key, "")
			Expect(err).NotTo(HaveOccurred())
		})

		By("Listing all Network Sets in namespace again", func() {
			kvps, err := c.List(ctx, model.ResourceListOptions{Namespace: ns.ObjectMeta.Name, Kind: apiv3.KindNetworkSet}, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(1))
			Expect(kvps.KVPairs[0].Key).To(Equal(kvp3.Key))
			Expect(kvps.KVPairs[0].Value.(*apiv3.NetworkSet).ObjectMeta.Name).To(Equal(kvp3.Value.(*apiv3.NetworkSet).ObjectMeta.Name))
			Expect(kvps.KVPairs[0].Value.(*apiv3.NetworkSet).Spec).To(Equal(kvp3.Value.(*apiv3.NetworkSet).Spec))
		})

		By("Deleting the namespace", func() {
			testutils.DeleteNamespace(c.ClientSet, ns.ObjectMeta.Name)
		})

		By("Listing all Network Sets in a non-existent namespace", func() {
			kvps, err := c.List(ctx, model.ResourceListOptions{Namespace: ns.ObjectMeta.Name, Kind: apiv3.KindNetworkSet}, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(0))
		})
	})

	It("should handle a CRUD of BGP Peer", func() {
		kvp1a := &model.KVPair{
			Key: model.ResourceKey{
				Name: "10-0-0-1",
				Kind: apiv3.KindBGPPeer,
			},
			Value: &apiv3.BGPPeer{
				TypeMeta: metav1.TypeMeta{
					Kind:       apiv3.KindBGPPeer,
					APIVersion: apiv3.GroupVersionCurrent,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "10-0-0-1",
				},
				Spec: apiv3.BGPPeerSpec{
					PeerIP:   "10.0.0.1",
					ASNumber: numorstring.ASNumber(6512),
				},
			},
		}

		kvp1b := &model.KVPair{
			Key: model.ResourceKey{
				Name: "10-0-0-1",
				Kind: apiv3.KindBGPPeer,
			},
			Value: &apiv3.BGPPeer{
				TypeMeta: metav1.TypeMeta{
					Kind:       apiv3.KindBGPPeer,
					APIVersion: apiv3.GroupVersionCurrent,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "10-0-0-1",
				},
				Spec: apiv3.BGPPeerSpec{
					PeerIP:   "10.0.0.1",
					ASNumber: numorstring.ASNumber(6513),
				},
			},
		}

		kvp2a := &model.KVPair{
			Key: model.ResourceKey{
				Name: "aa-bb-cc",
				Kind: apiv3.KindBGPPeer,
			},
			Value: &apiv3.BGPPeer{
				TypeMeta: metav1.TypeMeta{
					Kind:       apiv3.KindBGPPeer,
					APIVersion: apiv3.GroupVersionCurrent,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "aa-bb-cc",
				},
				Spec: apiv3.BGPPeerSpec{
					PeerIP:   "aa:bb::cc",
					ASNumber: numorstring.ASNumber(6514),
				},
			},
		}

		kvp2b := &model.KVPair{
			Key: model.ResourceKey{
				Name: "aa-bb-cc",
				Kind: apiv3.KindBGPPeer,
			},
			Value: &apiv3.BGPPeer{
				TypeMeta: metav1.TypeMeta{
					Kind:       apiv3.KindBGPPeer,
					APIVersion: apiv3.GroupVersionCurrent,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "aa-bb-cc",
				},
				Spec: apiv3.BGPPeerSpec{
					PeerIP: "aa:bb::cc",
				},
			},
		}

		var kvpRes *model.KVPair
		var err error

		By("Creating a BGP Peer", func() {
			kvpRes, err = c.Create(ctx, kvp1a)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Attempting to recreate an existing BGP Peer", func() {
			_, err := c.Create(ctx, kvp1a)
			Expect(err).To(HaveOccurred())
		})

		By("Updating an existing BGP Peer", func() {
			kvp1b.Revision = kvpRes.Revision
			_, err := c.Update(ctx, kvp1b)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Create a non-existent BGP Peer", func() {
			kvpRes, err = c.Create(ctx, kvp2a)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Updating the BGP Peer created by Create", func() {
			kvp2b.Revision = kvpRes.Revision
			_, err := c.Update(ctx, kvp2b)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Getting a missing BGP Peer", func() {
			_, err := c.Get(ctx, model.ResourceKey{Name: "1-1-1-1", Kind: apiv3.KindBGPPeer}, "")
			Expect(err).To(HaveOccurred())
		})

		By("Listing a missing BGP Peer", func() {
			kvps, err := c.List(ctx, model.ResourceListOptions{Name: "aa-bb-cc-dd-ee", Kind: apiv3.KindBGPPeer}, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(0))
		})

		By("Listing an explicit BGP Peer", func() {
			kvps, err := c.List(ctx, model.ResourceListOptions{Name: "10-0-0-1", Kind: apiv3.KindBGPPeer}, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(1))
			Expect(kvps.KVPairs[0].Key).To(Equal(kvp1b.Key))
			Expect(kvps.KVPairs[0].Value.(*apiv3.BGPPeer).ObjectMeta.Name).To(Equal(kvp1b.Value.(*apiv3.BGPPeer).ObjectMeta.Name))
			Expect(kvps.KVPairs[0].Value.(*apiv3.BGPPeer).Spec).To(Equal(kvp1b.Value.(*apiv3.BGPPeer).Spec))
		})

		By("Listing all BGP Peers (should be 2)", func() {
			kvps, err := c.List(ctx, model.ResourceListOptions{Kind: apiv3.KindBGPPeer}, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(2))
			keys := []model.Key{}
			vals := []interface{}{}
			for _, k := range kvps.KVPairs {
				keys = append(keys, k.Key)
				vals = append(vals, k.Value.(*apiv3.BGPPeer).Spec)
			}
			Expect(keys).To(ContainElement(kvp1b.Key))
			Expect(keys).To(ContainElement(kvp2b.Key))
			Expect(vals).To(ContainElement(kvp1b.Value.(*apiv3.BGPPeer).Spec))
			Expect(vals).To(ContainElement(kvp2b.Value.(*apiv3.BGPPeer).Spec))
		})

		By("Deleting the BGP Peer created by Create", func() {
			_, err := c.Delete(ctx, kvp2a.Key, "")
			Expect(err).NotTo(HaveOccurred())
		})

		By("Listing all BGP Peers (should now be 1)", func() {
			kvps, err := c.List(ctx, model.ResourceListOptions{Kind: apiv3.KindBGPPeer}, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(1))
			Expect(kvps.KVPairs[0].Key).To(Equal(kvp1b.Key))
			Expect(kvps.KVPairs[0].Value.(*apiv3.BGPPeer).ObjectMeta.Name).To(Equal(kvp1b.Value.(*apiv3.BGPPeer).ObjectMeta.Name))
			Expect(kvps.KVPairs[0].Value.(*apiv3.BGPPeer).Spec).To(Equal(kvp1b.Value.(*apiv3.BGPPeer).Spec))
		})

		By("Deleting an existing BGP Peer", func() {
			_, err := c.Delete(ctx, kvp1a.Key, "")
			Expect(err).NotTo(HaveOccurred())
		})
	})

	It("should handle a CRUD of Node BGP Peer", func() {
		var kvp1a, kvp1b, kvp2a, kvp2b, kvpRes *model.KVPair
		var nodename, peername1, peername2 string

		By("Listing all Nodes to find a suitable Node name", func() {
			nodes, err := c.List(ctx, model.ResourceListOptions{Kind: libapiv3.KindNode}, "")
			Expect(err).NotTo(HaveOccurred())
			// Get the hostname so we can make a Get call
			kvp := *nodes.KVPairs[0]
			nodename = kvp.Key.(model.ResourceKey).Name
			peername1 = "bgppeer1"
			peername2 = "bgppeer2"
			kvp1a = &model.KVPair{
				Key: model.ResourceKey{
					Name: peername1,
					Kind: apiv3.KindBGPPeer,
				},
				Value: &apiv3.BGPPeer{
					TypeMeta: metav1.TypeMeta{
						Kind:       apiv3.KindBGPPeer,
						APIVersion: apiv3.GroupVersionCurrent,
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: peername1,
					},
					Spec: apiv3.BGPPeerSpec{
						Node:     nodename,
						PeerIP:   "10.0.0.1",
						ASNumber: numorstring.ASNumber(6512),
					},
				},
			}
			kvp1b = &model.KVPair{
				Key: model.ResourceKey{
					Name: peername1,
					Kind: apiv3.KindBGPPeer,
				},
				Value: &apiv3.BGPPeer{
					TypeMeta: metav1.TypeMeta{
						Kind:       apiv3.KindBGPPeer,
						APIVersion: apiv3.GroupVersionCurrent,
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: peername1,
					},
					Spec: apiv3.BGPPeerSpec{
						Node:     nodename,
						PeerIP:   "10.0.0.1",
						ASNumber: numorstring.ASNumber(6513),
					},
				},
			}
			kvp2a = &model.KVPair{
				Key: model.ResourceKey{
					Name: peername2,
					Kind: apiv3.KindBGPPeer,
				},
				Value: &apiv3.BGPPeer{
					TypeMeta: metav1.TypeMeta{
						Kind:       apiv3.KindBGPPeer,
						APIVersion: apiv3.GroupVersionCurrent,
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: peername2,
					},
					Spec: apiv3.BGPPeerSpec{
						Node:     nodename,
						PeerIP:   "aa:bb::cc",
						ASNumber: numorstring.ASNumber(6514),
					},
				},
			}
			kvp2b = &model.KVPair{
				Key: model.ResourceKey{
					Name: peername2,
					Kind: apiv3.KindBGPPeer,
				},
				Value: &apiv3.BGPPeer{
					TypeMeta: metav1.TypeMeta{
						Kind:       apiv3.KindBGPPeer,
						APIVersion: apiv3.GroupVersionCurrent,
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: peername2,
					},
					Spec: apiv3.BGPPeerSpec{
						Node:   nodename,
						PeerIP: "aa:bb::cc",
					},
				},
			}
		})

		By("Creating a Node BGP Peer", func() {
			var err error
			kvpRes, err = c.Create(ctx, kvp1a)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Attempting to recreate an existing Node BGP Peer", func() {
			_, err := c.Create(ctx, kvp1a)
			Expect(err).To(HaveOccurred())
		})

		By("Updating an existing Node BGP Peer", func() {
			kvp1b.Revision = kvpRes.Revision
			_, err := c.Update(ctx, kvp1b)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Applying a non-existent Node BGP Peer", func() {
			var err error
			kvpRes, err = c.Apply(ctx, kvp2a)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Updating the Node BGP Peer created by Apply", func() {
			kvp2b.Revision = kvpRes.Revision
			_, err := c.Apply(ctx, kvp2b)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Getting a missing Node BGP Peer (wrong name)", func() {
			_, err := c.Get(ctx, model.ResourceKey{
				Name: "foobar",
				Kind: apiv3.KindBGPPeer,
			}, "")
			Expect(err).To(HaveOccurred())
		})

		By("Listing a missing Node BGP Peer (wrong name)", func() {
			kvps, err := c.List(ctx, model.ResourceListOptions{
				Name: "foobar",
				Kind: apiv3.KindBGPPeer,
			}, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(0))
		})

		By("Listing Node BGP Peers should contain Node name", func() {
			kvps, err := c.List(ctx, model.ResourceListOptions{Kind: apiv3.KindBGPPeer}, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(2))
			for _, kvp := range kvps.KVPairs {
				Expect(kvp.Value.(*apiv3.BGPPeer).Spec.Node).To(Equal(nodename))
			}
		})

		By("Listing an explicit Node BGP Peer", func() {
			kvps, err := c.List(ctx, model.ResourceListOptions{Name: peername1, Kind: apiv3.KindBGPPeer}, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(1))
			Expect(kvps.KVPairs[0].Key).To(Equal(kvp1b.Key))
			Expect(kvps.KVPairs[0].Value.(*apiv3.BGPPeer).ObjectMeta.Name).To(Equal(kvp1b.Value.(*apiv3.BGPPeer).ObjectMeta.Name))
			Expect(kvps.KVPairs[0].Value.(*apiv3.BGPPeer).Spec).To(Equal(kvp1b.Value.(*apiv3.BGPPeer).Spec))
		})

		By("Listing all Node BGP Peers (should be 2)", func() {
			kvps, err := c.List(ctx, model.ResourceListOptions{Kind: apiv3.KindBGPPeer}, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(2))
			keys := []model.Key{}
			vals := []interface{}{}
			for _, k := range kvps.KVPairs {
				keys = append(keys, k.Key)
				vals = append(vals, k.Value.(*apiv3.BGPPeer).Spec)
			}
			Expect(keys).To(ContainElement(kvp1b.Key))
			Expect(keys).To(ContainElement(kvp2b.Key))
			Expect(vals).To(ContainElement(kvp1b.Value.(*apiv3.BGPPeer).Spec))
			Expect(vals).To(ContainElement(kvp2b.Value.(*apiv3.BGPPeer).Spec))
		})

		By("Deleting the Node BGP Peer created by Apply", func() {
			_, err := c.Delete(ctx, kvp2a.Key, "")
			Expect(err).NotTo(HaveOccurred())
		})

		By("Listing all Node BGP Peers (should now be 1)", func() {
			kvps, err := c.List(ctx, model.ResourceListOptions{Kind: apiv3.KindBGPPeer}, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps.KVPairs).To(HaveLen(1))
			Expect(kvps.KVPairs[0].Key).To(Equal(kvp1b.Key))
			Expect(kvps.KVPairs[0].Value.(*apiv3.BGPPeer).ObjectMeta.Name).To(Equal(kvp1b.Value.(*apiv3.BGPPeer).ObjectMeta.Name))
			Expect(kvps.KVPairs[0].Value.(*apiv3.BGPPeer).Spec).To(Equal(kvp1b.Value.(*apiv3.BGPPeer).Spec))
		})

		By("Deleting an existing Node BGP Peer", func() {
			_, err := c.Delete(ctx, kvp1a.Key, "")
			Expect(err).NotTo(HaveOccurred())
		})

		By("Deleting a non-existent Node BGP Peer", func() {
			_, err := c.Delete(ctx, kvp1a.Key, "")
			Expect(err).To(HaveOccurred())
		})
	})

	createPodAndMarkAsRunning := func(name string) (*k8sapi.Pod, string) {
		pod := &k8sapi.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: "default",
			},
			Spec: k8sapi.PodSpec{
				NodeName: "127.0.0.1",
				Containers: []k8sapi.Container{
					{
						Name:    "container1",
						Image:   "busybox",
						Command: []string{"sleep", "3600"},
					},
				},
			},
		}
		pod, err := c.ClientSet.CoreV1().Pods("default").Create(ctx, pod, metav1.CreateOptions{})
		By("Creating a pod", func() {
			Expect(err).NotTo(HaveOccurred())
		})
		By("Assigning an IP", func() {
			// Update the Pod to have an IP and be running.
			pod.Annotations = map[string]string{
				conversion.AnnotationPodIP:  "192.168.1.1",
				conversion.AnnotationPodIPs: "192.168.1.1",
			}
			pod.Status.PodIP = "192.168.1.1"
			pod.Status.Phase = k8sapi.PodRunning
			pod, err = c.ClientSet.CoreV1().Pods("default").UpdateStatus(ctx, pod, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})
		By("Waiting for the pod to start", func() {
			// Wait up to 120s for pod to start running.
			log.Warnf("[TEST] Waiting for pod %s to start", pod.ObjectMeta.Name)
			for i := 0; i < 120; i++ {
				p, err := c.ClientSet.CoreV1().Pods("default").Get(ctx, pod.ObjectMeta.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				if p.Status.Phase == k8sapi.PodRunning {
					// Pod is running
					break
				}
				time.Sleep(1 * time.Second)
			}
			p, err := c.ClientSet.CoreV1().Pods("default").Get(ctx, pod.ObjectMeta.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(p.Status.Phase).To(Equal(k8sapi.PodRunning))
		})

		wepids := names.WorkloadEndpointIdentifiers{
			Node:         pod.Spec.NodeName,
			Orchestrator: apiv3.OrchestratorKubernetes,
			Endpoint:     "eth0",
			Pod:          pod.Name,
		}
		wepName, err := wepids.CalculateWorkloadEndpointName(false)
		Expect(err).NotTo(HaveOccurred())

		return pod, wepName
	}

	It("should handle a basic Pod", func() {
		pod, wepName := createPodAndMarkAsRunning("basic-pod")

		By("Performing a List() operation", func() {
			// Perform List and ensure it shows up in the Calico API.
			weps, err := c.List(ctx, model.ResourceListOptions{Kind: libapiv3.KindWorkloadEndpoint}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(weps.KVPairs)).To(BeNumerically(">", 0))
		})

		By("Performing a List(Name=wepName) operation", func() {
			// Perform List, including a workload Name
			weps, err := c.List(ctx, model.ResourceListOptions{Name: wepName, Namespace: "default", Kind: libapiv3.KindWorkloadEndpoint}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(weps.KVPairs)).To(Equal(1))
		})

		By("Performing a Get() operation then updating the wep", func() {
			// Perform a Get and ensure no error in the Calico API.
			wep, err := c.Get(ctx, model.ResourceKey{Name: wepName, Namespace: "default", Kind: libapiv3.KindWorkloadEndpoint}, "")
			Expect(err).NotTo(HaveOccurred())
			fmt.Printf("Updating Wep %+v\n", wep.Value.(*libapiv3.WorkloadEndpoint).Spec)
			ctxCNI := resources.ContextWithPatchMode(ctx, resources.PatchModeCNI)
			_, err = c.Update(ctxCNI, wep)
			Expect(err).NotTo(HaveOccurred())
		})

		expectedKVP := model.KVPair{
			Key: model.WorkloadEndpointKey{
				Hostname:       "127.0.0.1",
				OrchestratorID: "k8s",
				WorkloadID:     fmt.Sprintf("default/%s", pod.ObjectMeta.Name),
				EndpointID:     "eth0",
			},
		}

		By("Expecting an update with type 'KVUpdated' on the Syncer API", func() {
			cb.ExpectExists([]api.Update{
				{KVPair: expectedKVP, UpdateType: api.UpdateTypeKVUpdated},
			})
		})

		By("Expecting a Syncer snapshot to include the update with type 'KVNew'", func() {
			// Create a new syncer / callback pair so that it performs a snapshot.
			cfg := apiconfig.KubeConfig{Kubeconfig: "/kubeconfig.yaml"}
			_, snapshotCallbacks, snapshotSyncer := CreateClientAndSyncer(cfg)
			defer snapshotSyncer.Stop()
			go snapshotCallbacks.ProcessUpdates()
			snapshotSyncer.Start()

			// Expect the snapshot to include workload endpoint with type "KVNew".
			snapshotCallbacks.ExpectExists([]api.Update{
				{KVPair: expectedKVP, UpdateType: api.UpdateTypeKVNew},
			})
		})

		By("Deleting the Pod and expecting the wep to be deleted", func() {
			var zero int64
			policy := metav1.DeletePropagationBackground
			err := c.ClientSet.CoreV1().Pods("default").Delete(ctx, pod.ObjectMeta.Name, metav1.DeleteOptions{
				GracePeriodSeconds: &zero,
				PropagationPolicy:  &policy,
			})
			Expect(err).NotTo(HaveOccurred())
			cb.ExpectDeleted([]model.KVPair{expectedKVP})
		})
	})

	// There are several states that we consider "finished", run the test for each one.
	for _, finishPhase := range []k8sapi.PodPhase{k8sapi.PodSucceeded, k8sapi.PodFailed, "Terminating"} {
		finishPhase := finishPhase
		It(fmt.Sprintf("should treat a finished Pod (%v) as a deletion", finishPhase), func() {
			pod, wepName := createPodAndMarkAsRunning("finished-pod-" + strings.ToLower(string(finishPhase)))
			var err error

			expectedKVP := model.KVPair{
				Key: model.WorkloadEndpointKey{
					Hostname:       "127.0.0.1",
					OrchestratorID: "k8s",
					WorkloadID:     fmt.Sprintf("default/%s", pod.ObjectMeta.Name),
					EndpointID:     "eth0",
				},
			}

			By("Expecting an update with type 'UpdateTypeKVNew' on the Syncer API", func() {
				// The update processor filters out the initial update where the pod has no IP, then we get this
				// notification when the IP is added.
				cb.ExpectExists([]api.Update{
					{KVPair: expectedKVP, UpdateType: api.UpdateTypeKVNew},
				})
			})

			var wepKV *model.KVPair
			key := model.ResourceKey{Name: wepName, Namespace: "default", Kind: libapiv3.KindWorkloadEndpoint}
			By("Checking the pod is visible before we mark it as finished", func() {
				// Perform a Get and ensure no error in the Calico API.
				var err error
				wepKV, err = c.Get(ctx, key, "")
				Expect(err).NotTo(HaveOccurred())
				Expect(wepKV).NotTo(BeNil())

				// Perform List and ensure it shows up in the Calico API.
				weps, err := c.List(ctx, model.ResourceListOptions{Kind: libapiv3.KindWorkloadEndpoint}, "")
				Expect(err).NotTo(HaveOccurred())
				Expect(len(weps.KVPairs)).To(BeNumerically(">", 0))
			})

			By(fmt.Sprintf("Marking the Pod as finished (%v)", finishPhase), func() {
				if finishPhase == "Terminating" {
					// The Terminating state isn't a real state; it means the pod is being deleted but hasn't
					// finished yet. The CNI plugin calls through to DeleteKVP when it gets a DEL.
					var gracePeriod int64 = 60
					err = c.ClientSet.CoreV1().Pods("default").Delete(ctx, pod.Name,
						metav1.DeleteOptions{GracePeriodSeconds: &gracePeriod})

					// Terminating alone shouldn't remove the IP (so that pods that are gracefully shutting down
					// can finish).
					wepKV, err = c.Get(ctx, key, "")
					Expect(err).NotTo(HaveOccurred())
					Expect(wepKV.Value.(*libapiv3.WorkloadEndpoint).Spec.IPNetworks).NotTo(HaveLen(0))

					// Deleting in the Calico API with incorrect UID should fail.
					realUID := wepKV.UID
					badUID := types.UID("19e9c0f4-501d-429f-b581-8954440883f4")
					wepKV.UID = &badUID
					_, err = c.DeleteKVP(ctx, wepKV)
					Expect(err).To(BeAssignableToTypeOf(cerrors.ErrorResourceDoesNotExist{}))
					wepKV.UID = realUID
					wepKV2, err := c.Get(ctx, key, "")
					Expect(err).NotTo(HaveOccurred())
					Expect(wepKV2.Value.(*libapiv3.WorkloadEndpoint).Spec.IPNetworks).NotTo(HaveLen(0))

					// Successful deletion in the Calico API should make the IPs disappear.
					_, err = c.DeleteKVP(ctx, wepKV)
					Expect(err).NotTo(HaveOccurred())
					wepKV2, err = c.Get(ctx, key, "")
					Expect(err).NotTo(HaveOccurred())
					Expect(wepKV2.Value.(*libapiv3.WorkloadEndpoint).Spec.IPNetworks).To(HaveLen(0))

					return
				}
				pod.Status.Phase = finishPhase
				pod, err = c.ClientSet.CoreV1().Pods("default").UpdateStatus(ctx, pod, metav1.UpdateOptions{})
				Expect(err).NotTo(HaveOccurred())
			})

			By("Expecting an update with type 'KVDeleted' on the Syncer API", func() {
				cb.ExpectDeleted([]model.KVPair{expectedKVP})
			})

			// Now go back from finished to running again.  This is likely impossible on a real Kubernetes system
			// but it's helpful for testing out our UpdateType calculation logic.  I.e. since the last update was
			// a "delete", we should now see a "new", rather than an "update".

			By("Marking the Pod as running again", func() {
				if finishPhase == "Terminating" {
					// Recreate the WEP (this puts the annotations back again).
					wepKV.Revision = ""
					wepKV.UID = nil
					ctxCNI := resources.ContextWithPatchMode(ctx, resources.PatchModeCNI)
					_, err = c.Create(ctxCNI, wepKV)
					Expect(err).NotTo(HaveOccurred())
					return
				}
				pod.Status.Phase = k8sapi.PodRunning
				pod, err = c.ClientSet.CoreV1().Pods("default").UpdateStatus(ctx, pod, metav1.UpdateOptions{})
				Expect(err).NotTo(HaveOccurred())
			})

			By("Expecting an update that creates the wep again", func() {
				cb.ExpectExists([]api.Update{
					{KVPair: expectedKVP, UpdateType: api.UpdateTypeKVNew},
				})
			})

			By("Checking the pod is gettable", func() {
				// Perform a Get and ensure no error in the Calico API.
				_, err := c.Get(ctx, key, "")
				Expect(err).NotTo(HaveOccurred())
			})

			By("Deleting the Pod and expecting the wep to be deleted", func() {
				var zero int64
				policy := metav1.DeletePropagationBackground
				err := c.ClientSet.CoreV1().Pods("default").Delete(ctx, pod.ObjectMeta.Name, metav1.DeleteOptions{
					GracePeriodSeconds: &zero,
					PropagationPolicy:  &policy,
				})
				Expect(err).NotTo(HaveOccurred())
				cb.ExpectDeleted([]model.KVPair{expectedKVP})
			})
		})
	}

	It("should treat a pod that loses its IP as a deletion", func() {
		pod, wepName := createPodAndMarkAsRunning("pod-losing-ip")
		var err error

		expectedKVP := model.KVPair{
			Key: model.WorkloadEndpointKey{
				Hostname:       "127.0.0.1",
				OrchestratorID: "k8s",
				WorkloadID:     fmt.Sprintf("default/%s", pod.ObjectMeta.Name),
				EndpointID:     "eth0",
			},
		}

		By("Expecting an update with type 'UpdateTypeKVNew' on the Syncer API", func() {
			// The update processor filters out the initial update where the pod has no IP, then we get this
			// notification when the IP is added.
			cb.ExpectExists([]api.Update{
				{KVPair: expectedKVP, UpdateType: api.UpdateTypeKVNew},
			})
		})

		By("Checking the pod is visible before we remove its IP", func() {
			// Perform a Get and ensure no error in the Calico API.
			wep, err := c.Get(ctx, model.ResourceKey{Name: wepName, Namespace: "default", Kind: libapiv3.KindWorkloadEndpoint}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(wep).NotTo(BeNil())

			// Perform List and ensure it shows up in the Calico API.
			weps, err := c.List(ctx, model.ResourceListOptions{Kind: libapiv3.KindWorkloadEndpoint}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(weps.KVPairs)).To(BeNumerically(">", 0))
		})

		By("Removing its IP", func() {
			pod.Annotations = map[string]string{}
			pod.Status.PodIP = ""
			pod.Status.PodIPs = nil
			pod, err = c.ClientSet.CoreV1().Pods("default").UpdateStatus(ctx, pod, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		By("Expecting an update with type 'KVDeleted' on the Syncer API", func() {
			cb.ExpectDeleted([]model.KVPair{expectedKVP})
		})
	})

	defineAnnotationTest := func(preExistingAnnotations map[string]string) {
		pod := &k8sapi.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "test-syncer-basic-pod",
				Namespace:   "default",
				Annotations: preExistingAnnotations,
			},
			Spec: k8sapi.PodSpec{
				NodeName: "127.0.0.1",
				Containers: []k8sapi.Container{
					{
						Name:    "container1",
						Image:   "busybox",
						Command: []string{"sleep", "3600"},
					},
				},
			},
		}
		// Note: assigning back to pod variable in order to pick up revision information. If we don't do that then
		// the call to UpdateStatus() below would succeed, but it would overwrite our annotation patch.
		pod, err := c.ClientSet.CoreV1().Pods("default").Create(ctx, pod, metav1.CreateOptions{})
		wepName := "127.0.0.1-k8s-test--syncer--basic--pod-eth0"

		By("Creating a pod", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		By("Assigning an IP", func() {
			// Add the IP via our API.  This simulates what the CNI plugin does.
			wep, err := c.Get(
				ctx,
				model.ResourceKey{Name: wepName, Namespace: "default", Kind: libapiv3.KindWorkloadEndpoint},
				"",
			)
			Expect(err).NotTo(HaveOccurred())
			wep.Value.(*libapiv3.WorkloadEndpoint).Spec.IPNetworks = []string{"192.168.1.1"}
			fmt.Printf("Updating Wep %+v\n", wep.Value.(*libapiv3.WorkloadEndpoint).Spec)
			ctxCNI := resources.ContextWithPatchMode(ctx, resources.PatchModeCNI)
			_, err = c.Update(ctxCNI, wep)
			Expect(err).NotTo(HaveOccurred())

			// Get the pod through the k8s API to check the annotation has appeared.
			p, err := c.ClientSet.CoreV1().Pods("default").Get(ctx, pod.ObjectMeta.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(p.Annotations["cni.projectcalico.org/podIP"]).To(Equal("192.168.1.1"))

			// Get the wep through our API to check that the annotation round-trips.
			wep, err = c.Get(ctx, model.ResourceKey{Name: wepName, Namespace: "default", Kind: libapiv3.KindWorkloadEndpoint}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(wep.Value.(*libapiv3.WorkloadEndpoint).Spec.IPNetworks).To(ConsistOf("192.168.1.1/32"))
		})

		By("Setting the pod phase to Running", func() {
			// Try to update the pod using the old revision; this should fail because our patch made it
			// stale.
			pod.Status.Phase = k8sapi.PodRunning
			_, err = c.ClientSet.CoreV1().Pods("default").UpdateStatus(ctx, pod, metav1.UpdateOptions{})
			Expect(err).To(HaveOccurred())

			// Re-get the pod and try again...
			pod, err = c.ClientSet.CoreV1().Pods("default").Get(ctx, pod.ObjectMeta.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			pod.Status.Phase = k8sapi.PodRunning
			pod, err = c.ClientSet.CoreV1().Pods("default").UpdateStatus(ctx, pod, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		By("Waiting for the pod to start", func() {
			// Wait up to 120s for pod to start running.
			log.Warnf("[TEST] Waiting for pod %s to start", pod.ObjectMeta.Name)

			for i := 0; i < 120; i++ {
				p, err := c.ClientSet.CoreV1().Pods("default").Get(ctx, pod.ObjectMeta.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				if p.Status.Phase == k8sapi.PodRunning {
					// Pod is running
					break
				}
				time.Sleep(1 * time.Second)
			}

			pod, err = c.ClientSet.CoreV1().Pods("default").Get(ctx, pod.ObjectMeta.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(pod.Status.Phase).To(Equal(k8sapi.PodRunning))
			Expect(pod.Annotations["cni.projectcalico.org/podIP"]).To(Equal("192.168.1.1"))
			for k, v := range preExistingAnnotations {
				Expect(pod.Annotations[k]).To(Equal(v))
			}
		})

		expectedKVP := model.KVPair{
			Key: model.WorkloadEndpointKey{
				Hostname:       "127.0.0.1",
				OrchestratorID: "k8s",
				WorkloadID:     fmt.Sprintf("default/%s", pod.ObjectMeta.Name),
				EndpointID:     "eth0",
			},
		}

		// We only get this update if the Pod passes our check that it has an IP.
		By("Expecting an update with type 'KVUpdated' on the Syncer API", func() {
			cb.ExpectExists([]api.Update{
				{KVPair: expectedKVP, UpdateType: api.UpdateTypeKVUpdated},
			})
		})

		By("Deleting the Pod and expecting the wep to be deleted", func() {
			var zero int64
			policy := metav1.DeletePropagationBackground
			err = c.ClientSet.CoreV1().Pods("default").Delete(ctx, pod.ObjectMeta.Name, metav1.DeleteOptions{
				GracePeriodSeconds: &zero,
				PropagationPolicy:  &policy,
			})
			Expect(err).NotTo(HaveOccurred())
			cb.ExpectDeleted([]model.KVPair{expectedKVP})
		})
	}

	It("should patch Pod (with no existing annotations) with our PodIP annotation", func() {
		defineAnnotationTest(nil)
	})

	It("should patch Pod (with existing annotations) with our PodIP annotation", func() {
		defineAnnotationTest(map[string]string{
			"anotherAnnotation": "someValue",
		})
	})

	It("should support listing block affinities", func() {
		var nodename string
		By("Listing all Nodes to find a suitable Node name", func() {
			nodes, err := c.List(ctx, model.ResourceListOptions{Kind: libapiv3.KindNode}, "")
			Expect(err).NotTo(HaveOccurred())
			kvp := *nodes.KVPairs[0]
			nodename = kvp.Key.(model.ResourceKey).Name
		})
		By("Creating an affinity for that node", func() {
			cidr := net.MustParseCIDR("10.0.0.0/26")
			kvp := model.KVPair{
				Key: model.BlockAffinityKey{
					CIDR: cidr,
					Host: nodename,
				},
				Value: &model.BlockAffinity{},
			}
			_, err := c.Create(ctx, &kvp)
			Expect(err).NotTo(HaveOccurred())
		})
		By("Creating an affinity for a different node", func() {
			cidr := net.MustParseCIDR("10.0.1.0/26")
			kvp := model.KVPair{
				Key: model.BlockAffinityKey{
					CIDR: cidr,
					Host: "othernode",
				},
				Value: &model.BlockAffinity{},
			}
			_, err := c.Create(ctx, &kvp)
			Expect(err).NotTo(HaveOccurred())
		})
		By("Listing all BlockAffinity for all Nodes", func() {
			objs, err := c.List(ctx, model.BlockAffinityListOptions{}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(objs.KVPairs)).To(Equal(2))
		})
		By("Listing all BlockAffinity for a specific Node", func() {
			objs, err := c.List(ctx, model.BlockAffinityListOptions{Host: nodename}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(objs.KVPairs)).To(Equal(1))
		})
	})

	It("should support setting and getting FelixConfig", func() {
		enabled := apiv3.FloatingIPsEnabled
		fc := &model.KVPair{
			Key: model.ResourceKey{
				Name: "myfelixconfig",
				Kind: apiv3.KindFelixConfiguration,
			},
			Value: &apiv3.FelixConfiguration{
				TypeMeta: metav1.TypeMeta{
					Kind:       apiv3.KindFelixConfiguration,
					APIVersion: apiv3.GroupVersionCurrent,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "myfelixconfig",
				},
				Spec: apiv3.FelixConfigurationSpec{
					InterfacePrefix: "xali-",
					FloatingIPs:     &enabled,
				},
			},
		}
		var updFC *model.KVPair
		var err error

		By("creating a new object", func() {
			updFC, err = c.Create(ctx, fc)
			Expect(err).NotTo(HaveOccurred())
			Expect(updFC.Key.(model.ResourceKey).Name).To(Equal("myfelixconfig"))
			// Set the ResourceVersion (since it is auto populated by the Kubernetes datastore) to make it easier to compare objects.
			Expect(fc.Value.(*apiv3.FelixConfiguration).GetObjectMeta().GetResourceVersion()).To(Equal(""))
			fc.Value.(*apiv3.FelixConfiguration).GetObjectMeta().SetResourceVersion(updFC.Value.(*apiv3.FelixConfiguration).GetObjectMeta().GetResourceVersion())

			// UID and CreationTimestamp are auto-generated, make sure we don't fail the assertion based on it.
			fc.Value.(*apiv3.FelixConfiguration).ObjectMeta.UID = updFC.Value.(*apiv3.FelixConfiguration).ObjectMeta.UID
			fc.Value.(*apiv3.FelixConfiguration).ObjectMeta.CreationTimestamp = updFC.Value.(*apiv3.FelixConfiguration).ObjectMeta.CreationTimestamp

			// Assert the created object matches what we created.
			Expect(updFC.Value.(*apiv3.FelixConfiguration)).To(Equal(fc.Value.(*apiv3.FelixConfiguration)))
			Expect(updFC.Revision).NotTo(BeNil())

			// Unset the ResourceVersion for the original resource since we modified it just for the sake of comparing in the tests.
			fc.Value.(*apiv3.FelixConfiguration).GetObjectMeta().SetResourceVersion("")
		})

		By("getting an existing object", func() {
			updFC, err = c.Get(ctx, fc.Key, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(updFC.Value.(*apiv3.FelixConfiguration).Spec).To(Equal(fc.Value.(*apiv3.FelixConfiguration).Spec))
			Expect(updFC.Key.(model.ResourceKey).Name).To(Equal("myfelixconfig"))
			Expect(updFC.Revision).NotTo(BeNil())
		})

		By("updating an existing object", func() {
			updFC.Value.(*apiv3.FelixConfiguration).Spec.InterfacePrefix = "someotherprefix-"
			updFC, err = c.Update(ctx, updFC)
			Expect(err).NotTo(HaveOccurred())
			Expect(updFC.Value.(*apiv3.FelixConfiguration).Spec.InterfacePrefix).To(Equal("someotherprefix-"))
		})

		By("getting the updated object", func() {
			updFC, err = c.Get(ctx, fc.Key, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(updFC.Value.(*apiv3.FelixConfiguration).Spec.InterfacePrefix).To(Equal("someotherprefix-"))
			Expect(updFC.Key.(model.ResourceKey).Name).To(Equal("myfelixconfig"))
			Expect(updFC.Revision).NotTo(BeNil())
		})

		By("applying an existing object", func() {
			val := &apiv3.FelixConfiguration{
				TypeMeta: metav1.TypeMeta{
					Kind:       apiv3.KindFelixConfiguration,
					APIVersion: apiv3.GroupVersionCurrent,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "myfelixconfig",
				},
				Spec: apiv3.FelixConfigurationSpec{
					InterfacePrefix: "somenewprefix-",
				},
			}
			updFC.Value = val
			updFC, err = c.Apply(ctx, updFC)
			Expect(err).NotTo(HaveOccurred())
			Expect(updFC.Value.(*apiv3.FelixConfiguration).Spec.InterfacePrefix).To(Equal("somenewprefix-"))
		})

		By("getting the applied object", func() {
			updFC, err = c.Get(ctx, fc.Key, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(updFC.Value.(*apiv3.FelixConfiguration).Spec.InterfacePrefix).To(Equal("somenewprefix-"))
			Expect(updFC.Key.(model.ResourceKey).Name).To(Equal("myfelixconfig"))
			Expect(updFC.Revision).NotTo(BeNil())
		})

		By("deleting an existing object", func() {
			_, err = c.Delete(ctx, fc.Key, "")
			Expect(err).NotTo(HaveOccurred())
		})

		By("deleting a non-existing object", func() {
			_, err = c.Delete(ctx, fc.Key, "")
			Expect(err).To(HaveOccurred())
		})

		By("getting a non-existing object", func() {
			updFC, err = c.Get(ctx, fc.Key, "")
			Expect(err).To(HaveOccurred())
			Expect(updFC).To(BeNil())
		})

		By("applying a new object", func() {
			// Revision should not be specified when creating.
			fc.Revision = ""
			updFC, err = c.Apply(ctx, fc)
			Expect(err).NotTo(HaveOccurred())
			Expect(updFC.Value.(*apiv3.FelixConfiguration).Spec).To(Equal(fc.Value.(*apiv3.FelixConfiguration).Spec))
		})

		By("getting the applied object", func() {
			updFC, err = c.Get(ctx, fc.Key, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(updFC.Value.(*apiv3.FelixConfiguration).Spec).To(Equal(fc.Value.(*apiv3.FelixConfiguration).Spec))
			Expect(updFC.Key.(model.ResourceKey).Name).To(Equal("myfelixconfig"))
			Expect(updFC.Revision).NotTo(BeNil())
		})

		By("deleting the existing object", func() {
			_, err = c.Delete(ctx, updFC.Key, "")
			Expect(err).NotTo(HaveOccurred())
		})
	})

	It("should support setting and getting IP Pools", func() {
		By("listing IP pools when none have been created", func() {
			_, err := c.List(ctx, model.ResourceListOptions{Kind: apiv3.KindIPPool}, "")
			Expect(err).NotTo(HaveOccurred())
		})

		By("creating an IP Pool and getting it back", func() {
			cidr := "192.168.0.0/16"
			pool := &model.KVPair{
				Key: model.ResourceKey{
					Name: "192-16-0-0-16",
					Kind: apiv3.KindIPPool,
				},
				Value: &apiv3.IPPool{
					TypeMeta: metav1.TypeMeta{
						Kind:       apiv3.KindIPPool,
						APIVersion: apiv3.GroupVersionCurrent,
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "192-16-0-0-16",
					},
					Spec: apiv3.IPPoolSpec{
						CIDR:     cidr,
						IPIPMode: apiv3.IPIPModeCrossSubnet,
						Disabled: true,
					},
				},
			}
			_, err := c.Create(ctx, pool)
			Expect(err).NotTo(HaveOccurred())

			receivedPool, err := c.Get(ctx, pool.Key, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(receivedPool.Value.(*apiv3.IPPool).Spec.CIDR).To(Equal(cidr))
			Expect(receivedPool.Value.(*apiv3.IPPool).Spec.IPIPMode).To(BeEquivalentTo(apiv3.IPIPModeCrossSubnet))
			Expect(receivedPool.Value.(*apiv3.IPPool).Spec.Disabled).To(Equal(true))
		})

		By("deleting the IP Pool", func() {
			_, err := c.Delete(ctx, model.ResourceKey{
				Name: "192-16-0-0-16",
				Kind: apiv3.KindIPPool,
			}, "")
			Expect(err).NotTo(HaveOccurred())
		})
	})

	It("Should support getting, deleting, and listing Nodes", func() {
		nodeHostname := ""
		var kvp model.KVPair
		ip := "192.168.0.101"

		By("Listing all Nodes", func() {
			nodes, err := c.List(ctx, model.ResourceListOptions{Kind: libapiv3.KindNode}, "")
			Expect(err).NotTo(HaveOccurred())
			// Get the hostname so we can make a Get call
			kvp = *nodes.KVPairs[0]
			nodeHostname = kvp.Key.(model.ResourceKey).Name
		})

		By("Listing a specific Node", func() {
			nodes, err := c.List(ctx, model.ResourceListOptions{Name: nodeHostname, Kind: libapiv3.KindNode}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(nodes.KVPairs).To(HaveLen(1))
			Expect(nodes.KVPairs[0].Key).To(Equal(kvp.Key))
			Expect(nodes.KVPairs[0].Value).To(Equal(kvp.Value))
		})

		By("Listing a specific invalid Node", func() {
			nodes, err := c.List(ctx, model.ResourceListOptions{Name: "foobarbaz-node", Kind: libapiv3.KindNode}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(nodes.KVPairs).To(HaveLen(0))
		})

		By("Getting a specific nodeHostname", func() {
			n, err := c.Get(ctx, model.ResourceKey{Name: nodeHostname, Kind: libapiv3.KindNode}, "")
			Expect(err).NotTo(HaveOccurred())

			// Check to see we have the right Node
			Expect(nodeHostname).To(Equal(n.Key.(model.ResourceKey).Name))
		})

		By("Creating a new Node", func() {
			_, err := c.Create(ctx, &kvp)
			Expect(err).To(HaveOccurred())
		})

		By("Getting non-existent Node", func() {
			_, err := c.Get(ctx, model.ResourceKey{Name: "Fake", Kind: libapiv3.KindNode}, "")
			Expect(err).To(HaveOccurred())
		})

		By("Deleting a Node", func() {
			_, err := c.Delete(ctx, kvp.Key, "")
			Expect(err).To(HaveOccurred())
		})

		By("Updating changes to a node", func() {
			newAsn := numorstring.ASNumber(23455)

			testKvp := model.KVPair{
				Key: model.ResourceKey{
					Name: kvp.Key.(model.ResourceKey).Name,
					Kind: libapiv3.KindNode,
				},
				Value: &libapiv3.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: kvp.Key.(model.ResourceKey).Name,
					},
					Spec: libapiv3.NodeSpec{
						BGP: &libapiv3.NodeBGPSpec{
							ASNumber:    &newAsn,
							IPv4Address: ip,
						},
					},
				},
			}
			node, err := c.Update(ctx, &testKvp)
			Expect(err).NotTo(HaveOccurred())
			Expect(*node.Value.(*libapiv3.Node).Spec.BGP.ASNumber).To(Equal(newAsn))

			// Also check that Get() returns the changes
			getNode, err := c.Get(ctx, kvp.Key.(model.ResourceKey), "")
			Expect(err).NotTo(HaveOccurred())
			Expect(*getNode.Value.(*libapiv3.Node).Spec.BGP.ASNumber).To(Equal(newAsn))
			Expect(getNode.Value.(*libapiv3.Node).Spec.BGP.IPv4IPIPTunnelAddr).To(Equal(""))

			// We do not support creating Nodes, we should see an error
			// if the Node does not exist.
			missingKvp := model.KVPair{
				Key: model.ResourceKey{
					Name: "IDontExist",
					Kind: libapiv3.KindNode,
				},
			}
			_, err = c.Create(ctx, &missingKvp)

			Expect(err).To(HaveOccurred())
		})

		By("Updating a Node", func() {
			testKvp := model.KVPair{
				Key: model.ResourceKey{
					Name: kvp.Key.(model.ResourceKey).Name,
					Kind: libapiv3.KindNode,
				},
				Value: &libapiv3.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: kvp.Key.(model.ResourceKey).Name,
					},
					Spec: libapiv3.NodeSpec{
						BGP: &libapiv3.NodeBGPSpec{
							IPv4Address:        ip,
							IPv4IPIPTunnelAddr: "10.0.0.1",
						},
					},
				},
			}
			node, err := c.Update(ctx, &testKvp)

			Expect(err).NotTo(HaveOccurred())
			Expect(node.Value.(*libapiv3.Node).Spec.BGP.ASNumber).To(BeNil())
			Expect(node.Value.(*libapiv3.Node).Spec.BGP.IPv4IPIPTunnelAddr).To(Equal("10.0.0.1"))

			// Also check that Get() returns the changes
			getNode, err := c.Get(ctx, kvp.Key.(model.ResourceKey), "")
			Expect(err).NotTo(HaveOccurred())
			Expect(getNode.Value.(*libapiv3.Node).Spec.BGP.ASNumber).To(BeNil())
			Expect(getNode.Value.(*libapiv3.Node).Spec.BGP.IPv4IPIPTunnelAddr).To(Equal("10.0.0.1"))
		})

		By("Syncing HostIPs over the Syncer", func() {
			expectExist := []api.Update{
				{model.KVPair{Key: model.HostIPKey{Hostname: nodeHostname}}, api.UpdateTypeKVUpdated},
			}

			// Expect the snapshot to include the right keys.
			cb.ExpectExists(expectExist)
		})

		By("Not syncing Nodes when K8sDisableNodePoll is enabled", func() {
			cfg := apiconfig.KubeConfig{Kubeconfig: "/kubeconfig.yaml", K8sDisableNodePoll: true}
			_, snapshotCallbacks, snapshotSyncer := CreateClientAndSyncer(cfg)
			defer snapshotSyncer.Stop()
			go snapshotCallbacks.ProcessUpdates()
			snapshotSyncer.Start()

			expectNotExist := []model.KVPair{
				{Key: model.HostIPKey{Hostname: nodeHostname}},
			}

			// Expect the snapshot to have not received the update.
			snapshotCallbacks.ExpectDeleted(expectNotExist)
		})

		By("Syncing HostConfig for a Node on Syncer start", func() {
			cfg := apiconfig.KubeConfig{Kubeconfig: "/kubeconfig.yaml", K8sDisableNodePoll: true}
			_, snapshotCallbacks, snapshotSyncer := CreateClientAndSyncer(cfg)
			defer snapshotSyncer.Stop()
			go snapshotCallbacks.ProcessUpdates()
			snapshotSyncer.Start()

			hostConfigKey := model.KVPair{
				Key: model.HostConfigKey{
					Hostname: "127.0.0.1",
					Name:     "IpInIpTunnelAddr",
				},
			}

			expectedKeys := []api.Update{
				{hostConfigKey, api.UpdateTypeKVNew},
			}

			snapshotCallbacks.ExpectExists(expectedKeys)
		})
	})
})

var _ = testutils.E2eDatastoreDescribe("Test Watch support", testutils.DatastoreK8s, func(cfg apiconfig.CalicoAPIConfig) {
	var (
		c   *KubeClient
		ctx context.Context
	)

	BeforeEach(func() {
		// Create a client
		client, err := NewKubeClient(&cfg.Spec)
		Expect(err).NotTo(HaveOccurred())
		c = client.(*KubeClient)

		ctx = context.Background()
	})

	Describe("watching Profiles", func() {
		createTestServiceAccount := func(name string) {
			sa := k8sapi.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name: name,
				},
			}
			_, err := c.ClientSet.CoreV1().ServiceAccounts("default").Create(ctx, &sa, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		}
		deleteAllServiceAccounts := func() {
			var zero int64
			err := c.ClientSet.CoreV1().ServiceAccounts("default").DeleteCollection(ctx, metav1.DeleteOptions{GracePeriodSeconds: &zero}, metav1.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
		}
		BeforeEach(func() {
			createTestServiceAccount("test-sa-1")
			createTestServiceAccount("test-sa-2")
		})
		AfterEach(func() {
			deleteAllServiceAccounts()
		})
		It("supports watching a specific profile (from namespace)", func() {
			watch, err := c.Watch(ctx, model.ResourceListOptions{Name: "kns.default", Kind: apiv3.KindProfile}, "")
			Expect(err).NotTo(HaveOccurred())
			defer watch.Stop()
			event := ExpectAddedEvent(watch.ResultChan())
			Expect(event.New.Key.String()).To(Equal("Profile(kns.default)"))
		})
		It("supports watching a specific profile (from serviceAccount)", func() {
			watch, err := c.Watch(ctx, model.ResourceListOptions{Name: "ksa.default.test-sa-1", Kind: apiv3.KindProfile}, "")
			Expect(err).NotTo(HaveOccurred())
			defer watch.Stop()
			event := ExpectAddedEvent(watch.ResultChan())
			Expect(event.New.Key.String()).To(Equal("Profile(ksa.default.test-sa-1)"))
		})
		It("supports watching all profiles", func() {
			watch, err := c.Watch(ctx, model.ResourceListOptions{Kind: apiv3.KindProfile}, "")
			Expect(err).NotTo(HaveOccurred())
			defer watch.Stop()
			ExpectAddedEvent(watch.ResultChan())
		})
		It("rejects names without prefixes", func() {
			_, err := c.Watch(ctx, model.ResourceListOptions{Name: "default", Kind: apiv3.KindProfile}, "")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("Unsupported prefix for resource name: default"))
		})
	})

	Describe("watching NetworkPolicies (native)", func() {
		createTestNetworkPolicy := func(name string) {
			np := networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: name,
				},
			}
			_, err := c.ClientSet.NetworkingV1().NetworkPolicies("default").Create(ctx, &np, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		}
		deleteAllNetworkPolicies := func() {
			var zero int64
			err := c.ClientSet.NetworkingV1().NetworkPolicies("default").DeleteCollection(ctx, metav1.DeleteOptions{GracePeriodSeconds: &zero}, metav1.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
		}
		BeforeEach(func() {
			createTestNetworkPolicy("test-net-policy-1")
			createTestNetworkPolicy("test-net-policy-2")
		})
		AfterEach(func() {
			deleteAllNetworkPolicies()
		})
		It("supports watching all networkpolicies", func() {
			watch, err := c.Watch(ctx, model.ResourceListOptions{Kind: model.KindKubernetesNetworkPolicy}, "")
			Expect(err).NotTo(HaveOccurred())
			defer watch.Stop()
			ExpectAddedEvent(watch.ResultChan())
		})
		It("supports resuming watch from previous revision", func() {
			watch, err := c.Watch(ctx, model.ResourceListOptions{Kind: model.KindKubernetesNetworkPolicy}, "")
			Expect(err).NotTo(HaveOccurred())
			event := ExpectAddedEvent(watch.ResultChan())
			watch.Stop()

			watch, err = c.Watch(ctx, model.ResourceListOptions{Kind: model.KindKubernetesNetworkPolicy}, event.New.Revision)
			Expect(err).NotTo(HaveOccurred())
			watch.Stop()
		})
		It("should handle a list for many network policies with a revision", func() {
			for i := 3; i < 1000; i++ {
				createTestNetworkPolicy(fmt.Sprintf("test-net-policy-%d", i))
			}
			kvs, err := c.List(ctx, model.ResourceListOptions{Kind: model.KindKubernetesNetworkPolicy}, "")
			Expect(err).NotTo(HaveOccurred())
			_, err = c.List(ctx, model.ResourceListOptions{Kind: model.KindKubernetesNetworkPolicy}, kvs.Revision)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("watching NetworkPolicies (calico)", func() {
		createTestNetworkPolicy := func(name string) {
			np := &model.KVPair{
				Key: model.ResourceKey{
					Name:      name,
					Namespace: "default",
					Kind:      apiv3.KindNetworkPolicy,
				},
				Value: &apiv3.NetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						Kind:       apiv3.KindNetworkPolicy,
						APIVersion: apiv3.GroupVersionCurrent,
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      name,
						Namespace: "default",
					},
				},
			}
			_, err := c.Create(ctx, np)
			Expect(err).NotTo(HaveOccurred())
		}
		deleteAllNetworkPolicies := func() {
			err := c.Clean()
			Expect(err).NotTo(HaveOccurred())
		}
		BeforeEach(func() {
			createTestNetworkPolicy("test-net-policy-3")
			createTestNetworkPolicy("test-net-policy-4")
		})
		AfterEach(func() {
			deleteAllNetworkPolicies()
		})
		It("supports watching a specific networkpolicy", func() {
			watch, err := c.Watch(ctx, model.ResourceListOptions{Name: "test-net-policy-3", Namespace: "default", Kind: apiv3.KindNetworkPolicy}, "")
			Expect(err).NotTo(HaveOccurred())
			defer watch.Stop()
			event := ExpectAddedEvent(watch.ResultChan())
			Expect(event.New.Key.String()).To(Equal("NetworkPolicy(default/test-net-policy-3)"))
		})
		It("rejects watching a specific networkpolicy without a namespace", func() {
			_, err := c.Watch(ctx, model.ResourceListOptions{Name: "test-net-policy-3", Kind: apiv3.KindNetworkPolicy}, "")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("name present, but missing namespace on watch request"))
		})
		It("supports watching all networkpolicies", func() {
			watch, err := c.Watch(ctx, model.ResourceListOptions{Kind: apiv3.KindNetworkPolicy}, "")
			Expect(err).NotTo(HaveOccurred())
			defer watch.Stop()
			ExpectAddedEvent(watch.ResultChan())
		})
	})

	Describe("watching / listing network polices (k8s and Calico)", func() {
		createCalicoNetworkPolicy := func(name string) {
			np := &model.KVPair{
				Key: model.ResourceKey{
					Name:      name,
					Namespace: "default",
					Kind:      apiv3.KindNetworkPolicy,
				},
				Value: &apiv3.NetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						Kind:       apiv3.KindNetworkPolicy,
						APIVersion: apiv3.GroupVersionCurrent,
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      name,
						Namespace: "default",
					},
				},
			}
			_, err := c.Create(ctx, np)
			Expect(err).NotTo(HaveOccurred())
		}
		createK8sNetworkPolicy := func(name string) {
			np := networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: name,
				},
			}
			_, err := c.ClientSet.NetworkingV1().NetworkPolicies("default").Create(ctx, &np, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		}
		deleteAllNetworkPolicies := func() {
			var zero int64
			err := c.ClientSet.NetworkingV1().NetworkPolicies("default").DeleteCollection(ctx, metav1.DeleteOptions{GracePeriodSeconds: &zero}, metav1.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			err = c.Clean()
			Expect(err).NotTo(HaveOccurred())
		}
		BeforeEach(func() {
			// Create 2x Calico NP and 2x k8s NP
			createCalicoNetworkPolicy("test-net-policy-1")
			createCalicoNetworkPolicy("test-net-policy-2")
			createK8sNetworkPolicy("test-net-policy-3")
			createK8sNetworkPolicy("test-net-policy-4")
			log.Info("[Test] Done Setup ---")
		})
		AfterEach(func() {
			log.Info("[Test] Beginning Cleanup ----")
			deleteAllNetworkPolicies()
		})

		It("supports resuming watch from previous revision (calico)", func() {
			// Should only return Calico NPs
			l, err := c.List(ctx, model.ResourceListOptions{Kind: apiv3.KindNetworkPolicy}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(l.KVPairs).To(HaveLen(2))

			// Now, modify all the policies.  It's important to do this with
			// multiple policies of each type, because we want to test that revision
			// numbers come out in a sensible order. We're going to resume the watch
			// from the "last" event to come out of the watch, and if it doesn't
			// really represent the latest update, when we resume watching, we
			// will get duplicate events. Worse, if the "last" event from a watch
			// doesn't represent the latest state, this implies some earlier
			// event from the watch did, and if we happened to have stopped the
			// watch at that point we would have missed some data!

			// Modify the policies.
			found := 0
			var kvp1or2 *model.KVPair
			for _, kvp := range l.KVPairs {
				policy := kvp.Value.(*apiv3.NetworkPolicy)
				policy.SetLabels(map[string]string{"test": "00"})
				kvp1or2, err = c.Update(ctx, kvp)
				Expect(err).ToNot(HaveOccurred())
				found++
			}
			Expect(found).To(Equal(2))

			log.WithField("revision", l.Revision).Info("[TEST] first watch")
			watch, err := c.Watch(ctx, model.ResourceListOptions{Kind: apiv3.KindNetworkPolicy}, l.Revision)
			Expect(err).NotTo(HaveOccurred())

			// We should see 2 events for Calico NPs.
			event := ExpectModifiedEvent(watch.ResultChan())
			log.WithField("revision", event.New.Revision).Info("[TEST] first event")
			event = ExpectModifiedEvent(watch.ResultChan())
			log.WithField("revision", event.New.Revision).Info("[TEST] second event")

			// There should be no more events
			Expect(watch.ResultChan()).ToNot(Receive())
			watch.Stop()

			// Make a second change to the Calico NP
			kvp1or2.Value.(*apiv3.NetworkPolicy).SetLabels(map[string]string{"test": "01"})
			_, err = c.Update(ctx, kvp1or2)
			Expect(err).ToNot(HaveOccurred())

			// Resume watching at the revision of the event we got
			log.WithField("revision", event.New.Revision).Info("second watch")
			watch, err = c.Watch(ctx, model.ResourceListOptions{Kind: apiv3.KindNetworkPolicy}, event.New.Revision)
			Expect(err).NotTo(HaveOccurred())

			// We should only get 1 update, because the event from the previous watch should have been "latest"
			ExpectModifiedEvent(watch.ResultChan())

			// There should be no more events
			Expect(watch.ResultChan()).ToNot(Receive())
			watch.Stop()
		})

		It("supports resuming watch from previous revision (k8s)", func() {
			// Should only return k8s NPs
			l, err := c.List(ctx, model.ResourceListOptions{Kind: model.KindKubernetesNetworkPolicy}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(l.KVPairs).To(HaveLen(2))

			// Now, modify all the policies.  It's important to do this with
			// multiple policies of each type, because we want to test that revision
			// numbers come out in a sensible order. We're going to resume the watch
			// from the "last" event to come out of the watch, and if it doesn't
			// really represent the latest update, when we resume watching, we
			// will get duplicate events. Worse, if the "last" event from a watch
			// doesn't represent the latest state, this implies some earlier
			// event from the watch did, and if we happened to have stopped the
			// watch at that point we would have missed some data!

			// Modify the kubernetes policies
			found := 0
			for _, kvp := range l.KVPairs {
				name := strings.TrimPrefix(kvp.Value.(*apiv3.NetworkPolicy).Name, "knp.default.")
				p, err := c.ClientSet.NetworkingV1().NetworkPolicies("default").Get(ctx, name, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				p.SetLabels(map[string]string{"test": "00"})
				_, err = c.ClientSet.NetworkingV1().NetworkPolicies("default").Update(ctx, p, metav1.UpdateOptions{})
				Expect(err).ToNot(HaveOccurred())
				found++
			}
			Expect(found).To(Equal(2))

			log.WithField("revision", l.Revision).Info("[TEST] first watch")
			watch, err := c.Watch(ctx, model.ResourceListOptions{Kind: model.KindKubernetesNetworkPolicy}, l.Revision)
			Expect(err).NotTo(HaveOccurred())

			event := ExpectModifiedEvent(watch.ResultChan())
			log.WithField("revision", event.New.Revision).Info("[TEST] first k8s event")
			event = ExpectModifiedEvent(watch.ResultChan())
			log.WithField("revision", event.New.Revision).Info("[TEST] second k8s event")

			// There should be no more events
			Expect(watch.ResultChan()).ToNot(Receive())
			watch.Stop()

			// Make a second change to one of the NPs
			for _, kvp := range l.KVPairs {
				name := strings.TrimPrefix(kvp.Value.(*apiv3.NetworkPolicy).Name, "knp.default.")
				p, err := c.ClientSet.NetworkingV1().NetworkPolicies("default").Get(ctx, name, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				p.SetLabels(map[string]string{"test": "01"})
				_, err = c.ClientSet.NetworkingV1().NetworkPolicies("default").Update(ctx, p, metav1.UpdateOptions{})
				Expect(err).ToNot(HaveOccurred())
				break
			}

			// Resume watching at the revision of the event we got
			log.WithField("revision", event.New.Revision).Info("second watch")
			watch, err = c.Watch(ctx, model.ResourceListOptions{Kind: model.KindKubernetesNetworkPolicy}, event.New.Revision)
			Expect(err).NotTo(HaveOccurred())

			// We should only get 1 update, because the event from the previous watch should have been "latest"
			ExpectModifiedEvent(watch.ResultChan())

			// There should be no more events
			Expect(watch.ResultChan()).ToNot(Receive())
			watch.Stop()
		})

		It("supports watching from part way through a list (calico)", func() {
			// Only 2 Calico NPs
			l, err := c.List(ctx, model.ResourceListOptions{Kind: apiv3.KindNetworkPolicy}, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(l.KVPairs).To(HaveLen(2))

			// Watch from part way
			for i := 0; i < 2; i++ {
				revision := l.KVPairs[i].Revision
				log.WithFields(log.Fields{
					"revision": revision,
					"key":      l.KVPairs[i].Key.String(),
				}).Info("[Test] starting watch")
				watch, err := c.Watch(ctx, model.ResourceListOptions{Kind: apiv3.KindNetworkPolicy}, revision)
				Expect(err).ToNot(HaveOccurred())
				// Since the items in the list aren't guaranteed to be in any specific order, we
				// can't assert anything useful about what you should get out of this watch, so we
				// just confirm that there is no error.
				watch.Stop()
			}
		})

		It("supports watching from part way through a list (k8s)", func() {
			// Only 2 Calico NPs
			l, err := c.List(ctx, model.ResourceListOptions{Kind: model.KindKubernetesNetworkPolicy}, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(l.KVPairs).To(HaveLen(2))

			// Watch from part way
			for i := 0; i < 2; i++ {
				revision := l.KVPairs[i].Revision
				log.WithFields(log.Fields{
					"revision": revision,
					"key":      l.KVPairs[i].Key.String(),
				}).Info("[Test] starting watch")
				watch, err := c.Watch(ctx, model.ResourceListOptions{Kind: apiv3.KindNetworkPolicy}, revision)
				Expect(err).ToNot(HaveOccurred())
				// Since the items in the list aren't guaranteed to be in any specific order, we
				// can't assert anything useful about what you should get out of this watch, so we
				// just confirm that there is no error.
				watch.Stop()
			}
		})
	})

	Describe("watching Custom Resources", func() {
		createTestIPPool := func(name string) {
			cidr := "192.168.0.0/16"
			pool := &model.KVPair{
				Key: model.ResourceKey{
					Name: name,
					Kind: apiv3.KindIPPool,
				},
				Value: &apiv3.IPPool{
					TypeMeta: metav1.TypeMeta{
						Kind:       apiv3.KindIPPool,
						APIVersion: apiv3.GroupVersionCurrent,
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: name,
					},
					Spec: apiv3.IPPoolSpec{
						CIDR: cidr,
					},
				},
			}
			_, err := c.Create(ctx, pool)
			Expect(err).NotTo(HaveOccurred())
		}
		deleteAllIPPools := func() {
			err := c.Clean()
			Expect(err).NotTo(HaveOccurred())
		}
		BeforeEach(func() {
			createTestIPPool("test-ippool-1")
			createTestIPPool("test-ippool-2")
		})
		AfterEach(func() {
			deleteAllIPPools()
		})
		It("supports watching a specific custom resource (IPPool)", func() {
			watch, err := c.Watch(ctx, model.ResourceListOptions{Name: "test-ippool-1", Kind: apiv3.KindIPPool}, "")
			Expect(err).NotTo(HaveOccurred())
			defer watch.Stop()
			event := ExpectAddedEvent(watch.ResultChan())
			Expect(event.New.Key.String()).To(Equal("IPPool(test-ippool-1)"))
		})
		It("supports watching all custom resources (IPPool)", func() {
			watch, err := c.Watch(ctx, model.ResourceListOptions{Kind: apiv3.KindIPPool}, "")
			Expect(err).NotTo(HaveOccurred())
			defer watch.Stop()
			ExpectAddedEvent(watch.ResultChan())
		})
	})

	Describe("watching WorkloadEndpoints", func() {
		createTestPod := func(name string) {
			pod := &k8sapi.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: "default",
				},
				Spec: k8sapi.PodSpec{
					NodeName: "127.0.0.1",
					Containers: []k8sapi.Container{
						{
							Name:    "container1",
							Image:   "busybox",
							Command: []string{"sleep", "3600"},
						},
					},
				},
			}
			_, err := c.ClientSet.CoreV1().Pods("default").Create(ctx, pod, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		}
		deleteAllPods := func() {
			var zero int64
			err := c.ClientSet.CoreV1().Pods("default").DeleteCollection(ctx, metav1.DeleteOptions{GracePeriodSeconds: &zero}, metav1.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
		}
		BeforeEach(func() {
			createTestPod("test-pod-1")
			createTestPod("test-pod-2")
		})
		AfterEach(func() {
			deleteAllPods()
		})
		It("supports watching a specific workloadEndpoint", func() {
			watch, err := c.Watch(ctx, model.ResourceListOptions{Name: "127.0.0.1-k8s-test--pod--1-eth0", Namespace: "default", Kind: libapiv3.KindWorkloadEndpoint}, "")
			Expect(err).NotTo(HaveOccurred())
			defer watch.Stop()
			event := ExpectAddedEvent(watch.ResultChan())
			Expect(event.New.Key.String()).To(Equal("WorkloadEndpoint(default/127.0.0.1-k8s-test--pod--1-eth0)"))
		})
		It("rejects watching a specific workloadEndpoint without a namespace", func() {
			_, err := c.Watch(ctx, model.ResourceListOptions{Name: "127.0.0.1-k8s-test--pod--1-eth0", Kind: libapiv3.KindWorkloadEndpoint}, "")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("cannot watch a specific WorkloadEndpoint without a namespace"))
		})
		It("supports watching all workloadEndpoints", func() {
			watch, err := c.Watch(ctx, model.ResourceListOptions{Kind: libapiv3.KindWorkloadEndpoint}, "")
			Expect(err).NotTo(HaveOccurred())
			defer watch.Stop()
			ExpectAddedEvent(watch.ResultChan())
		})
	})

	It("Should support watching Nodes", func() {
		By("Watching a single node", func() {
			name := "127.0.0.1" // Node created by test/mock-node.yaml
			watch, err := c.Watch(ctx, model.ResourceListOptions{Name: name, Kind: libapiv3.KindNode}, "")
			Expect(err).NotTo(HaveOccurred())
			defer watch.Stop()

			// We should get at least one event from the watch.
			var receivedEvent bool
			for i := 0; i < 10; i++ {
				select {
				case e := <-watch.ResultChan():
					// Got an event. Check it's OK.
					Expect(e.Error).NotTo(HaveOccurred())
					Expect(e.Type).To(Equal(api.WatchAdded))
					receivedEvent = true
					break
				default:
					time.Sleep(50 * time.Millisecond)
				}
			}
			Expect(receivedEvent).To(BeTrue(), "Did not receive watch event")
		})

		By("Watching all nodes", func() {
			watch, err := c.Watch(ctx, model.ResourceListOptions{Kind: libapiv3.KindNode}, "")
			Expect(err).NotTo(HaveOccurred())
			defer watch.Stop()

			// We should get at least one event from the watch.
			var receivedEvent bool
			for i := 0; i < 10; i++ {
				select {
				case e := <-watch.ResultChan():
					// Got an event. Check it's OK.
					Expect(e.Error).NotTo(HaveOccurred())
					Expect(e.Type).To(Equal(api.WatchAdded))
					receivedEvent = true
					break
				default:
					time.Sleep(50 * time.Millisecond)
				}
			}
			Expect(receivedEvent).To(BeTrue(), "Did not receive watch event")
		})
	})

	It("should support watching BlockAffinities", func() {
		By("watching all affinities", func() {
			watch, err := c.Watch(ctx, model.BlockAffinityListOptions{}, "")
			Expect(err).NotTo(HaveOccurred())
			defer watch.Stop()

			// Create a block affinity.
			_, err = c.Create(ctx, &model.KVPair{
				Key: model.BlockAffinityKey{
					CIDR: net.MustParseCIDR("10.0.0.0/26"),
					Host: "test-hostname",
				},
				Value: &model.BlockAffinity{State: model.StatePending},
			})
			Expect(err).NotTo(HaveOccurred())

			// We should get at least one event from the watch.
			var receivedEvent bool
			for i := 0; i < 10; i++ {
				select {
				case e := <-watch.ResultChan():
					// Got an event. Check it's OK.
					Expect(e.Error).NotTo(HaveOccurred())
					Expect(e.Type).To(Equal(api.WatchAdded))
					receivedEvent = true
					break
				default:
					time.Sleep(50 * time.Millisecond)
				}
			}
			Expect(receivedEvent).To(BeTrue(), "Did not receive watch event")
		})
	})

	It("should support watching IPAM blocks", func() {
		By("watching all blocks", func() {
			watch, err := c.Watch(ctx, model.BlockListOptions{}, "")
			Expect(err).NotTo(HaveOccurred())
			defer watch.Stop()

			// Create a block.
			_, err = c.Create(ctx, &model.KVPair{
				Key: model.BlockKey{
					CIDR: net.MustParseCIDR("10.0.0.0/26"),
				},
				Value: &model.AllocationBlock{
					Affinity:    nil,
					Allocations: []*int{},
					Unallocated: []int{},
					Attributes:  nil,
					Deleted:     false,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			// We should get at least one event from the watch.
			var receivedEvent bool
			for i := 0; i < 10; i++ {
				select {
				case e := <-watch.ResultChan():
					// Got an event. Check it's OK.
					Expect(e.Error).NotTo(HaveOccurred())
					Expect(e.Type).To(Equal(api.WatchAdded))
					receivedEvent = true
					break
				default:
					time.Sleep(50 * time.Millisecond)
				}
			}
			Expect(receivedEvent).To(BeTrue(), "Did not receive watch event")
		})
	})

	It("should handle a CRUD of IPAM Config (v1 format)", func() {
		ipamKVP := &model.KVPair{
			Key: model.IPAMConfigKey{},
			Value: &model.IPAMConfig{
				StrictAffinity:     false,
				AutoAllocateBlocks: true,
			},
		}
		v3Key := model.ResourceKey{
			Name: "default",
			Kind: "IPAMConfig",
		}

		By("Creating an IPAM Config", func() {
			kvpRes, err := c.Create(ctx, ipamKVP)
			Expect(err).NotTo(HaveOccurred())
			Expect(kvpRes.Value).To(Equal(ipamKVP.Value))
		})

		var createdAt metav1.Time
		var uid types.UID
		By("Reading it with the v3 client and checking metadata", func() {
			v3Res, err := c.Get(ctx, v3Key, "")
			Expect(err).NotTo(HaveOccurred())
			createdAt = v3Res.Value.(*libapiv3.IPAMConfig).CreationTimestamp
			uid = v3Res.Value.(*libapiv3.IPAMConfig).UID
			Expect(createdAt).NotTo(Equal(metav1.Time{}))
			Expect(uid).NotTo(Equal(""))
		})

		By("Reading and updating an IPAM Config", func() {
			kvpRes, err := c.Get(ctx, ipamKVP.Key, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(kvpRes.Value).To(Equal(ipamKVP.Value))

			kvpRes.Value.(*model.IPAMConfig).StrictAffinity = true
			kvpRes.Value.(*model.IPAMConfig).AutoAllocateBlocks = false
			kvpRes2, err := c.Update(ctx, kvpRes)
			Expect(err).NotTo(HaveOccurred())

			Expect(kvpRes2.Value).NotTo(Equal(ipamKVP.Value))
			Expect(kvpRes2.Value).To(Equal(kvpRes.Value))
		})

		By("Reading it with the v3 client and checking metadata hasn't changed", func() {
			v3Res, err := c.Get(ctx, v3Key, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(v3Res.Value.(*libapiv3.IPAMConfig).CreationTimestamp).To(Equal(createdAt))
			Expect(v3Res.Value.(*libapiv3.IPAMConfig).UID).To(Equal(uid))
		})

		By("Deleting an IPAM Config", func() {
			_, err := c.Delete(ctx, ipamKVP.Key, "")
			Expect(err).NotTo(HaveOccurred())
		})
	})

	It("should handle a CRUD of IPAM config (v3 format)", func() {
		ipamKVP := &model.KVPair{
			Key: model.ResourceKey{
				Name: "default",
				Kind: "IPAMConfig",
			},
			Value: &libapiv3.IPAMConfig{
				TypeMeta: metav1.TypeMeta{
					Kind:       "IPAMConfig",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: libapiv3.IPAMConfigSpec{
					StrictAffinity:     false,
					AutoAllocateBlocks: true,
				},
			},
		}

		kvpRes, err := c.Create(ctx, ipamKVP)
		By("Creating an IPAM Config", func() {
			Expect(err).NotTo(HaveOccurred())
			Expect(kvpRes.Value.(*libapiv3.IPAMConfig).Spec).To(Equal(ipamKVP.Value.(*libapiv3.IPAMConfig).Spec))
		})

		By("Expecting the creation timestamp to be set")
		createdAt := kvpRes.Value.(*libapiv3.IPAMConfig).CreationTimestamp
		Expect(createdAt).NotTo(Equal(metav1.Time{}))

		By("Reading and updating an IPAM Config", func() {
			kvpRes, err := c.Get(ctx, ipamKVP.Key, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(kvpRes.Value.(*libapiv3.IPAMConfig).Spec).To(Equal(ipamKVP.Value.(*libapiv3.IPAMConfig).Spec))

			kvpRes.Value.(*libapiv3.IPAMConfig).Spec.StrictAffinity = true
			kvpRes.Value.(*libapiv3.IPAMConfig).Spec.AutoAllocateBlocks = false
			kvpRes2, err := c.Update(ctx, kvpRes)
			Expect(err).NotTo(HaveOccurred())

			Expect(kvpRes2.Value.(*libapiv3.IPAMConfig).Spec).NotTo(Equal(ipamKVP.Value.(*libapiv3.IPAMConfig).Spec))
			Expect(kvpRes.Value.(*libapiv3.IPAMConfig).Spec).To(Equal(kvpRes.Value.(*libapiv3.IPAMConfig).Spec))

			// Expect the creation time stamp to be the same.
			Expect(kvpRes2.Value.(*libapiv3.IPAMConfig).CreationTimestamp).To(Equal(createdAt))
		})

		By("Updating the IPAMConfig using the v1 client", func() {
			kvpRes, err := c.Get(ctx, model.IPAMConfigKey{}, "")
			Expect(err).NotTo(HaveOccurred())

			kvpRes.Value.(*model.IPAMConfig).MaxBlocksPerHost = 1000

			kvpRes, err = c.Update(ctx, kvpRes)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Checking the update using the v3 client", func() {
			kvpRes, err := c.Get(ctx, ipamKVP.Key, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(kvpRes.Value.(*libapiv3.IPAMConfig).Spec.MaxBlocksPerHost).To(Equal(1000))

			// Expect the creation time stamp to be the same.
			Expect(kvpRes.Value.(*libapiv3.IPAMConfig).CreationTimestamp).To(Equal(createdAt))
		})

		By("Deleting an IPAM Config", func() {
			_, err := c.Delete(ctx, ipamKVP.Key, "")
			Expect(err).NotTo(HaveOccurred())
		})
	})
})

var _ = testutils.E2eDatastoreDescribe("Test Inline kubeconfig support", testutils.DatastoreK8s, func(cfg apiconfig.CalicoAPIConfig) {
	var c *KubeClient

	ctx := context.Background()

	BeforeEach(func() {
		// Load kubeconfig file that was mounted in to the test.
		conf, err := ioutil.ReadFile("/kubeconfig.yaml")
		Expect(err).NotTo(HaveOccurred())

		// Override the provided config to use inline configuration.
		cfg.Spec = apiconfig.CalicoAPIConfigSpec{
			KubeConfig: apiconfig.KubeConfig{
				KubeconfigInline: string(conf),
			},
		}

		// Create a client using the config.
		client, err := NewKubeClient(&cfg.Spec)
		Expect(err).NotTo(HaveOccurred())
		c = client.(*KubeClient)
	})

	AfterEach(func() {
		// Clean up all Calico resources.
		err := c.Clean()
		Expect(err).NotTo(HaveOccurred())
	})

	It("should handle creating and deleting a namespace", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-inline-ns",
			},
		}

		By("Creating a namespace", func() {
			_, err := c.ClientSet.CoreV1().Namespaces().Create(ctx, &ns, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})
		By("Deleting the namespace", func() {
			testutils.DeleteNamespace(c.ClientSet, ns.ObjectMeta.Name)
		})
	})
})
