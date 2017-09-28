// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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
	"fmt"
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	log "github.com/sirupsen/logrus"

	capi "github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"

	extensions "github.com/projectcalico/libcalico-go/lib/backend/extensions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	k8sapi "k8s.io/client-go/pkg/api/v1"
)

var (
	zeroOrder              = float64(0.0)
	calicoAllowPolicyModel = model.Policy{
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
	calicoDisallowPolicyModel = model.Policy{
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
			panic(fmt.Sprintf("[TEST] Syncer received unkown update: %+v", u))
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

var updateTypeStr = map[api.UpdateType]string{
	api.UpdateTypeKVDeleted: "Deleted",
	api.UpdateTypeKVNew:     "New",
	api.UpdateTypeKVUnknown: "Unknown",
	api.UpdateTypeKVUpdated: "Updated",
}

func (c cb) ExpectExists(updates []api.Update) {
	// For each Key, wait for it to exist.
	for _, update := range updates {
		log.Infof("[TEST] Expecting key: %s, %s", update.Key, updateTypeStr[update.UpdateType])
		matches := false

		wait.PollImmediate(1*time.Second, 60*time.Second, func() (bool, error) {
			// Get the update.
			c.Lock.Lock()
			u, ok := c.State[update.Key.String()]
			c.Lock.Unlock()

			// See if we've got a matching update. For now, we just check
			// that the key exists and that it's the correct type.
			matches = ok && update.UpdateType == u.UpdateType

			log.Infof("[TEST] Key exists? %t matches? %t: %+v %s", ok, matches, u, updateTypeStr[u.UpdateType])
			if matches {
				// Expected the update to be present, and it is.
				return true, nil
			} else {
				// Update is not yet present.
				return false, nil
			}
		})

		// Expect the key to have existed.
		Expect(matches).To(Equal(true), fmt.Sprintf("Expected update not found: %s", update.Key))
	}
}

// ExpectDeleted asserts that the provided KVPairs have been deleted
// via an update over the Syncer.
func (c cb) ExpectDeleted(kvps []model.KVPair) {
	for _, kvp := range kvps {
		log.Infof("[TEST] Not expecting key: %s", kvp.Key)
		exists := true

		wait.PollImmediate(1*time.Second, 60*time.Second, func() (bool, error) {
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
		Expect(exists).To(Equal(false), fmt.Sprintf("Expected key not to exist: %s", kvp.Key))
	}
}

// GetSyncerValueFunc returns a function that can be used to query the value of
// an entry in our syncer state store.  It's useful for performing "Eventually" testing.
//
// The returned function returns the cached entry or nil if the entry does not
// exist in the cache.
func (c cb) GetSyncerValueFunc(key model.Key) func() interface{} {
	return func() interface{} {
		log.Infof("Checking entry in cache: %s", key)
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
		log.Infof("Checking entry in cache: %s", key)
		c.Lock.Lock()
		defer func() { c.Lock.Unlock() }()
		_, ok := c.State[key.String()]
		return ok
	}
}

func CreateClientAndSyncer(cfg capi.KubeConfig) (*KubeClient, *cb, api.Syncer) {
	// First create the client.
	c, err := NewKubeClient(&cfg)
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
	syncer := c.Syncer(callback)
	return c, &callback, syncer
}

var _ = Describe("Test Syncer API for Kubernetes backend", func() {
	var (
		c      *KubeClient
		cb     *cb
		syncer api.Syncer
	)

	BeforeEach(func() {
		log.SetLevel(log.DebugLevel)

		// Create a Kubernetes client, callbacks, and a syncer.
		cfg := capi.KubeConfig{K8sAPIEndpoint: "http://localhost:8080"}
		c, cb, syncer = CreateClientAndSyncer(cfg)

		// Start the syncer.
		syncer.Start()

		// Node object is created by applying the mock-node.yaml manifest in advance.

		// Start processing updates.
		go cb.ProcessUpdates()
	})

	It("should handle a Namespace with DefaultDeny (v1beta annotation for namespace isolation)", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-syncer-namespace-default-deny",
				Annotations: map[string]string{
					"net.beta.kubernetes.io/network-policy": "{\"ingress\": {\"isolation\": \"DefaultDeny\"}}",
				},
			},
		}

		// Make sure we clean up.  Don't check for errors since we attempt
		// to delete as part of the test below.
		defer func() {
			c.clientSet.Namespaces().Delete(ns.ObjectMeta.Name, &metav1.DeleteOptions{})
		}()

		By("Creating a namespace", func() {
			_, err := c.clientSet.Namespaces().Create(&ns)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Performing a List of Profiles", func() {
			_, err := c.List(model.ProfileListOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		By("Performing a List of Policies", func() {
			_, err := c.List(model.PolicyListOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		By("Performing a Get on the Profile and ensure no error in the Calico API", func() {
			_, err := c.Get(model.ProfileKey{Name: fmt.Sprintf("k8s_ns.%s", ns.ObjectMeta.Name)})
			Expect(err).NotTo(HaveOccurred())
		})

		By("Checking the correct entries are in our cache", func() {
			expectedName := "k8s_ns.test-syncer-namespace-default-deny"
			Eventually(cb.GetSyncerValuePresentFunc(model.ProfileRulesKey{ProfileKey: model.ProfileKey{expectedName}})).Should(BeTrue())
			Eventually(cb.GetSyncerValuePresentFunc(model.ProfileTagsKey{ProfileKey: model.ProfileKey{expectedName}})).Should(BeTrue())
			Eventually(cb.GetSyncerValuePresentFunc(model.ProfileLabelsKey{ProfileKey: model.ProfileKey{expectedName}})).Should(BeTrue())
		})

		By("Deleting the namespace", func() {
			err := c.clientSet.Namespaces().Delete(ns.ObjectMeta.Name, &metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		By("Checking the correct entries are no longer in our cache", func() {
			expectedName := "k8s_ns.test-syncer-namespace-default-deny"
			Eventually(cb.GetSyncerValuePresentFunc(model.ProfileRulesKey{ProfileKey: model.ProfileKey{expectedName}}), slowCheck...).Should(BeFalse())
			Eventually(cb.GetSyncerValuePresentFunc(model.ProfileTagsKey{ProfileKey: model.ProfileKey{expectedName}})).Should(BeFalse())
			Eventually(cb.GetSyncerValuePresentFunc(model.ProfileLabelsKey{ProfileKey: model.ProfileKey{expectedName}})).Should(BeFalse())
		})
	})

	It("should handle a Namespace without any annotations", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "test-syncer-namespace-no-default-deny",
				Annotations: map[string]string{},
			},
		}

		// Make sure we clean up after ourselves.  Don't check for errors since we attempt
		// to delete as part of the test below.
		defer func() {
			c.clientSet.Namespaces().Delete(ns.ObjectMeta.Name, &metav1.DeleteOptions{})
		}()

		// Check to see if the create succeeded.
		By("Creating a namespace", func() {
			_, err := c.clientSet.Namespaces().Create(&ns)
			Expect(err).NotTo(HaveOccurred())
		})

		// Perform a List and ensure it shows up in the Calico API.
		By("listing Profiles", func() {
			_, err := c.List(model.ProfileListOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		By("listing Policies", func() {
			_, err := c.List(model.PolicyListOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		// Perform a Get and ensure no error in the Calico API.
		By("getting a Profile", func() {
			_, err := c.Get(model.ProfileKey{Name: fmt.Sprintf("k8s_ns.%s", ns.ObjectMeta.Name)})
			Expect(err).NotTo(HaveOccurred())
		})

		// Expect corresponding Profile updates over the syncer for this Namespace.
		By("Checking the correct entries are in our cache", func() {
			expectedName := "k8s_ns.test-syncer-namespace-no-default-deny"
			Eventually(cb.GetSyncerValuePresentFunc(model.ProfileRulesKey{ProfileKey: model.ProfileKey{expectedName}})).Should(BeTrue())
			Eventually(cb.GetSyncerValuePresentFunc(model.ProfileTagsKey{ProfileKey: model.ProfileKey{expectedName}})).Should(BeTrue())
			Eventually(cb.GetSyncerValuePresentFunc(model.ProfileLabelsKey{ProfileKey: model.ProfileKey{expectedName}})).Should(BeTrue())
		})

		By("deleting a namespace", func() {
			err := c.clientSet.Namespaces().Delete(ns.ObjectMeta.Name, &metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		By("Checking the correct entries are in no longer in our cache", func() {
			expectedName := "k8s_ns.test-syncer-namespace-no-default-deny"
			Eventually(cb.GetSyncerValuePresentFunc(model.ProfileRulesKey{ProfileKey: model.ProfileKey{expectedName}}), slowCheck...).Should(BeFalse())
			Eventually(cb.GetSyncerValuePresentFunc(model.ProfileTagsKey{ProfileKey: model.ProfileKey{expectedName}})).Should(BeFalse())
			Eventually(cb.GetSyncerValuePresentFunc(model.ProfileLabelsKey{ProfileKey: model.ProfileKey{expectedName}})).Should(BeFalse())
		})
	})

	It("should handle a basic NetworkPolicy", func() {
		np := extensions.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-syncer-basic-net-policy",
			},
			Spec: extensions.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
				Ingress: []extensions.NetworkPolicyIngressRule{
					extensions.NetworkPolicyIngressRule{
						Ports: []extensions.NetworkPolicyPort{
							extensions.NetworkPolicyPort{},
						},
						From: []extensions.NetworkPolicyPeer{
							extensions.NetworkPolicyPeer{
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
		res := c.extensionsClientV1Beta1.
			Post().
			Resource("networkpolicies").
			Namespace("default").
			Body(&np).
			Do()

		// Make sure we clean up after ourselves.
		defer func() {
			res := c.extensionsClientV1Beta1.
				Delete().
				Resource("networkpolicies").
				Namespace("default").
				Name(np.ObjectMeta.Name).
				Do()
			Expect(res.Error()).NotTo(HaveOccurred())
		}()

		// Check to see if the create succeeded.
		Expect(res.Error()).NotTo(HaveOccurred())

		// Perform a List and ensure it shows up in the Calico API.
		_, err := c.List(model.PolicyListOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Perform a Get and ensure no error in the Calico API.
		_, err = c.Get(model.PolicyKey{Name: fmt.Sprintf("knp.default.default.%s", np.ObjectMeta.Name)})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should handle a basic NetworkPolicy with egress rules", func() {
		np := extensions.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-syncer-basic-net-with-egress-policy",
			},
			Spec: extensions.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
				Egress: []extensions.NetworkPolicyEgressRule{
					{
						To: []extensions.NetworkPolicyPeer{
							{
								IPBlock: &extensions.IPBlock{
									CIDR:   "192.168.0.0/16",
									Except: []string{"192.168.3.0/24", "192.168.4.0/24"},
								},
							},
						},
					},
				},
				PolicyTypes: []extensions.PolicyType{extensions.PolicyTypeIngress, extensions.PolicyTypeEgress},
			},
		}
		res := c.extensionsClientV1Beta1.
			Post().
			Resource("networkpolicies").
			Namespace("default").
			Body(&np).
			Do()

		// Make sure we clean up after ourselves.
		defer func() {
			res := c.extensionsClientV1Beta1.
				Delete().
				Resource("networkpolicies").
				Namespace("default").
				Name(np.ObjectMeta.Name).
				Do()
			Expect(res.Error()).NotTo(HaveOccurred())
		}()

		// Check to see if the create succeeded.
		Expect(res.Error()).NotTo(HaveOccurred())

		By("Getting the NetworkPolicy", func() {
			newNP := extensions.NetworkPolicy{}
			c.extensionsClientV1Beta1.Get().
				Resource("networkpolicies").
				Namespace("default").
				Name(np.ObjectMeta.Name).Do().
				Into(&newNP)
			Expect(len(newNP.Spec.Egress)).To(Equal(1))
		})

		By("Listing the Calico API policy", func() {
			// Perform a List and ensure it shows up in the Calico API.
			_, err := c.List(model.PolicyListOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Perform a Get and ensure no error in the Calico API.
			p, err := c.Get(model.PolicyKey{Name: fmt.Sprintf("knp.default.default.%s", np.ObjectMeta.Name)})
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
			policy := p.Value.(*model.Policy)
			Expect(len(policy.OutboundRules)).To(Equal(1))
		})
	})

	// Add a defer to wait for policies to clean up.
	defer func() {
		log.Warnf("[TEST] Waiting for policies to tear down")
		It("should clean up all policies", func() {
			nps := extensions.NetworkPolicyList{}
			err := c.extensionsClientV1Beta1.
				Get().
				Resource("networkpolicies").
				Namespace("default").
				Timeout(10 * time.Second).
				Do().Into(&nps)
			Expect(err).NotTo(HaveOccurred())

			// Loop until no network policies exist.
			for i := 0; i < 10; i++ {
				if len(nps.Items) == 0 {
					return
				}
				nps := extensions.NetworkPolicyList{}
				err := c.extensionsClientV1Beta1.
					Get().
					Resource("networkpolicies").
					Namespace("default").
					Timeout(10 * time.Second).
					Do().Into(&nps)
				Expect(err).NotTo(HaveOccurred())
				time.Sleep(1 * time.Second)
			}
			panic(fmt.Sprintf("Failed to clean up policies: %+v", nps))
		})
	}()

	It("should handle a CRUD of Global Network Policy", func() {

		kvp1Name := "my-test-gnp"
		kvp1a := &model.KVPair{
			Key:   model.PolicyKey{Name: kvp1Name},
			Value: &calicoAllowPolicyModel,
		}

		kvp1b := &model.KVPair{
			Key:   model.PolicyKey{Name: kvp1Name},
			Value: &calicoDisallowPolicyModel,
		}

		kvp2Name := "my-test-gnp2"
		kvp2a := &model.KVPair{
			Key:   model.PolicyKey{Name: kvp2Name},
			Value: &calicoAllowPolicyModel,
		}

		kvp2b := &model.KVPair{
			Key:   model.PolicyKey{Name: kvp2Name},
			Value: &calicoDisallowPolicyModel,
		}

		// Make sure we clean up after ourselves.  We allow this to fail because
		// part of our explicit testing below is to delete the resource.
		defer func() {
			c.gnpClient.Delete(kvp1a)
			c.gnpClient.Delete(kvp2a)
		}()

		// Check our syncer has the correct GNP entries for the two
		// System Network Protocols that this test manipulates.  Neither
		// have been created yet.
		By("Checking cache does not have Global Network Policy entries", func() {
			Eventually(cb.GetSyncerValuePresentFunc(kvp1a.Key)).Should(BeFalse())
			Eventually(cb.GetSyncerValuePresentFunc(kvp2a.Key)).Should(BeFalse())
		})

		By("Creating a Global Network Policy", func() {
			_, err := c.gnpClient.Create(kvp1a)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Checking cache has correct Global Network Policy entries", func() {
			// The GNP has been roundtripped through conversion to and from an API
			// Policy object, and in that process the Types field has been defaulted.
			kvp1a.Value.(*model.Policy).Types = []string{
				string(capi.PolicyTypeIngress),
				string(capi.PolicyTypeEgress),
			}
			Eventually(cb.GetSyncerValueFunc(kvp1a.Key)).Should(Equal(kvp1a.Value))
			Eventually(cb.GetSyncerValuePresentFunc(kvp2a.Key)).Should(BeFalse())
		})

		By("Attempting to recreate an existing Global Network Policy", func() {
			_, err := c.gnpClient.Create(kvp1a)
			Expect(err).To(HaveOccurred())
		})

		By("Updating an existing Global Network Policy", func() {
			_, err := c.gnpClient.Update(kvp1b)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Checking cache has correct Global Network Policy entries", func() {
			// The GNP has been roundtripped through conversion to and from an API
			// Policy object, and in that process the Types field has been defaulted.
			kvp1b.Value.(*model.Policy).Types = []string{
				string(capi.PolicyTypeIngress),
				string(capi.PolicyTypeEgress),
			}
			Eventually(cb.GetSyncerValueFunc(kvp1a.Key)).Should(Equal(kvp1b.Value))
			Eventually(cb.GetSyncerValuePresentFunc(kvp2a.Key)).Should(BeFalse())
		})

		By("Applying a non-existent Global Network Policy", func() {
			_, err := c.gnpClient.Apply(kvp2a)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Checking cache has correct Global Network Policy entries", func() {
			Eventually(cb.GetSyncerValueFunc(kvp1a.Key)).Should(Equal(kvp1b.Value))
			Eventually(cb.GetSyncerValueFunc(kvp2a.Key)).Should(Equal(kvp2a.Value))
		})

		By("Updating the Global Network Policy created by Apply", func() {
			_, err := c.gnpClient.Apply(kvp2b)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Checking cache has correct Global Network Policy entries", func() {
			Eventually(cb.GetSyncerValueFunc(kvp1a.Key)).Should(Equal(kvp1b.Value))
			Eventually(cb.GetSyncerValueFunc(kvp2a.Key)).Should(Equal(kvp2b.Value))
		})

		By("Deleted the Global Network Policy created by Apply", func() {
			err := c.gnpClient.Delete(kvp2a)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Checking cache has correct Global Network Policy entries", func() {
			Eventually(cb.GetSyncerValueFunc(kvp1a.Key)).Should(Equal(kvp1b.Value))
			Eventually(cb.GetSyncerValuePresentFunc(kvp2a.Key)).Should(BeFalse())
		})

		// Perform Get operations directly on the main client - this
		// will fan out requests to the appropriate Policy client
		// (including the Global Network Policy client).
		By("Getting a Global Network Policy that does noe exist", func() {
			_, err := c.Get(model.PolicyKey{Name: "my-non-existent-test-gnp"})
			Expect(err).To(HaveOccurred())
		})

		By("Listing a missing Global Network Policy", func() {
			kvps, err := c.List(model.PolicyListOptions{Name: "my-non-existent-test-gnp"})
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps).To(HaveLen(0))
		})

		By("Getting an existing Global Network Policy", func() {
			kvp, err := c.Get(model.PolicyKey{Name: "my-test-gnp"})
			Expect(err).ToNot(HaveOccurred())
			Expect(kvp.Key.(model.PolicyKey).Name).To(Equal("my-test-gnp"))
			Expect(kvp.Value.(*model.Policy)).To(Equal(kvp1b.Value))
		})

		By("Listing all policies (including a Global Network Policy)", func() {
			// We expect namespace entries for kube-system, kube-public
			// and default.
			kvps, err := c.List(model.PolicyListOptions{})
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps).To(HaveLen(1))
			Expect(kvps[len(kvps)-1].Key.(model.PolicyKey).Name).To(Equal("my-test-gnp"))
			Expect(kvps[len(kvps)-1].Value.(*model.Policy)).To(Equal(kvp1b.Value))
		})

		By("Deleting an existing Global Network Policy", func() {
			err := c.gnpClient.Delete(kvp1a)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Checking cache has no Global Network Policy entries", func() {
			Eventually(cb.GetSyncerValuePresentFunc(kvp1a.Key)).Should(BeFalse())
			Eventually(cb.GetSyncerValuePresentFunc(kvp2a.Key)).Should(BeFalse())
		})
	})

	It("should handle a CRUD of Global BGP Peer", func() {
		kvp1a := &model.KVPair{
			Key: model.GlobalBGPPeerKey{
				PeerIP: cnet.MustParseIP("10.0.0.1"),
			},
			Value: &model.BGPPeer{
				PeerIP: cnet.MustParseIP("10.0.0.1"),
				ASNum:  numorstring.ASNumber(6512),
			},
		}

		kvp1b := &model.KVPair{
			Key: model.GlobalBGPPeerKey{
				PeerIP: cnet.MustParseIP("10.0.0.1"),
			},
			Value: &model.BGPPeer{
				PeerIP: cnet.MustParseIP("10.0.0.1"),
				ASNum:  numorstring.ASNumber(6513),
			},
		}

		kvp2a := &model.KVPair{
			Key: model.GlobalBGPPeerKey{
				PeerIP: cnet.MustParseIP("aa:bb::cc"),
			},
			Value: &model.BGPPeer{
				PeerIP: cnet.MustParseIP("aa:bb::cc"),
				ASNum:  numorstring.ASNumber(6514),
			},
		}

		kvp2b := &model.KVPair{
			Key: model.GlobalBGPPeerKey{
				PeerIP: cnet.MustParseIP("aa:bb::cc"),
			},
			Value: &model.BGPPeer{
				PeerIP: cnet.MustParseIP("aa:bb::cc"),
			},
		}

		// Make sure we clean up after ourselves.  We allow this to fail because
		// part of our explicit testing below is to delete the resource.
		defer func() {
			c.Delete(kvp1a)
			c.Delete(kvp2a)
		}()

		By("Creating a Global BGP Peer", func() {
			_, err := c.Create(kvp1a)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Attempting to recreate an existing Global BGP Peer", func() {
			_, err := c.Create(kvp1a)
			Expect(err).To(HaveOccurred())
		})

		By("Updating an existing Global BGP Peer", func() {
			_, err := c.Update(kvp1b)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Applying a non-existent Global BGP Peer", func() {
			_, err := c.Apply(kvp2a)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Updating the Global BGP Peer created by Apply", func() {
			_, err := c.Apply(kvp2b)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Getting a missing Global BGP Peer", func() {
			_, err := c.Get(model.GlobalBGPPeerKey{PeerIP: cnet.MustParseIP("1.1.1.1")})
			Expect(err).To(HaveOccurred())
		})

		By("Listing a missing Global BGP Peer", func() {
			kvps, err := c.List(model.GlobalBGPPeerListOptions{PeerIP: cnet.MustParseIP("aa:bb:cc:dd::ee")})
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps).To(HaveLen(0))
		})

		By("Listing an explicit Global BGP Peer", func() {
			kvps, err := c.List(model.GlobalBGPPeerListOptions{PeerIP: cnet.MustParseIP("10.0.0.1")})
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps).To(HaveLen(1))
			Expect(kvps[0].Key).To(Equal(kvp1b.Key))
			Expect(kvps[0].Value).To(Equal(kvp1b.Value))
		})

		By("Listing all Global BGP Peers (should be 2)", func() {
			kvps, err := c.List(model.GlobalBGPPeerListOptions{})
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps).To(HaveLen(2))
			keys := []model.Key{}
			vals := []interface{}{}
			for _, k := range kvps {
				keys = append(keys, k.Key)
				vals = append(vals, k.Value)
			}
			Expect(keys).To(ContainElement(kvp1b.Key))
			Expect(keys).To(ContainElement(kvp2b.Key))
			Expect(vals).To(ContainElement(kvp1b.Value))
			Expect(vals).To(ContainElement(kvp2b.Value))

		})

		By("Deleting the Global BGP Peer created by Apply", func() {
			err := c.Delete(kvp2a)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Listing all Global BGP Peers (should now be 1)", func() {
			kvps, err := c.List(model.GlobalBGPPeerListOptions{})
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps).To(HaveLen(1))
			Expect(kvps[0].Key).To(Equal(kvp1b.Key))
			Expect(kvps[0].Value).To(Equal(kvp1b.Value))
		})

		By("Deleting an existing Global BGP Peer", func() {
			err := c.Delete(kvp1a)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	It("should handle a CRUD of Node BGP Peer", func() {
		var kvp1a, kvp1b, kvp2a, kvp2b *model.KVPair
		var nodename string

		// Make sure we clean up after ourselves.  We allow this to fail because
		// part of our explicit testing below is to delete the resource.
		defer func() {
			log.Debug("Deleting Node BGP Peers")
			if peers, err := c.List(model.NodeBGPPeerListOptions{}); err == nil {
				log.WithField("Peers", peers).Debug("Deleting resources")
				for _, peer := range peers {
					log.WithField("Key", peer.Key).Debug("Deleting resource")
					peer.Revision = nil
					_ = c.Delete(peer)
				}
			}
		}()

		By("Listing all Nodes to find a suitable Node name", func() {
			nodes, err := c.List(model.NodeListOptions{})
			Expect(err).NotTo(HaveOccurred())
			// Get the hostname so we can make a Get call
			kvp := *nodes[0]
			nodename = kvp.Key.(model.NodeKey).Hostname
			kvp1a = &model.KVPair{
				Key: model.NodeBGPPeerKey{
					PeerIP:   cnet.MustParseIP("10.0.0.1"),
					Nodename: nodename,
				},
				Value: &model.BGPPeer{
					PeerIP: cnet.MustParseIP("10.0.0.1"),
					ASNum:  numorstring.ASNumber(6512),
				},
			}
			kvp1b = &model.KVPair{
				Key: model.NodeBGPPeerKey{
					PeerIP:   cnet.MustParseIP("10.0.0.1"),
					Nodename: nodename,
				},
				Value: &model.BGPPeer{
					PeerIP: cnet.MustParseIP("10.0.0.1"),
					ASNum:  numorstring.ASNumber(6513),
				},
			}
			kvp2a = &model.KVPair{
				Key: model.NodeBGPPeerKey{
					PeerIP:   cnet.MustParseIP("aa:bb::cc"),
					Nodename: nodename,
				},
				Value: &model.BGPPeer{
					PeerIP: cnet.MustParseIP("aa:bb::cc"),
					ASNum:  numorstring.ASNumber(6514),
				},
			}
			kvp2b = &model.KVPair{
				Key: model.NodeBGPPeerKey{
					PeerIP:   cnet.MustParseIP("aa:bb::cc"),
					Nodename: nodename,
				},
				Value: &model.BGPPeer{
					PeerIP: cnet.MustParseIP("aa:bb::cc"),
				},
			}
		})

		By("Creating a Node BGP Peer", func() {
			_, err := c.Create(kvp1a)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Attempting to recreate an existing Node BGP Peer", func() {
			_, err := c.Create(kvp1a)
			Expect(err).To(HaveOccurred())
		})

		By("Updating an existing Node BGP Peer", func() {
			_, err := c.Update(kvp1b)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Applying a non-existent Node BGP Peer", func() {
			_, err := c.Apply(kvp2a)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Updating the Node BGP Peer created by Apply", func() {
			_, err := c.Apply(kvp2b)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Getting a missing Node BGP Peer (wrong IP)", func() {
			_, err := c.Get(model.NodeBGPPeerKey{Nodename: nodename, PeerIP: cnet.MustParseIP("1.1.1.1")})
			Expect(err).To(HaveOccurred())
		})

		By("Getting a missing Node BGP Peer (wrong nodename)", func() {
			_, err := c.Get(model.NodeBGPPeerKey{Nodename: "foobarbaz", PeerIP: cnet.MustParseIP("10.0.0.1")})
			Expect(err).To(HaveOccurred())
		})

		By("Listing a missing Node BGP Peer (wrong IP)", func() {
			kvps, err := c.List(model.NodeBGPPeerListOptions{PeerIP: cnet.MustParseIP("aa:bb:cc:dd::ee")})
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps).To(HaveLen(0))
		})

		By("Listing a missing Node BGP Peer (wrong nodename)", func() {
			kvps, err := c.List(model.NodeBGPPeerListOptions{Nodename: "foobarbaz"})
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps).To(HaveLen(0))
		})

		By("Listing an explicit Node BGP Peer (IP specific, Node is missing)", func() {
			kvps, err := c.List(model.NodeBGPPeerListOptions{PeerIP: cnet.MustParseIP("10.0.0.1")})
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps).To(HaveLen(1))
			Expect(kvps[0].Key).To(Equal(kvp1b.Key))
			Expect(kvps[0].Value).To(Equal(kvp1b.Value))
		})

		By("Listing an explicit Node BGP Peer (IP and Node are specified)", func() {
			kvps, err := c.List(model.NodeBGPPeerListOptions{Nodename: nodename, PeerIP: cnet.MustParseIP("10.0.0.1")})
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps).To(HaveLen(1))
			Expect(kvps[0].Key).To(Equal(kvp1b.Key))
			Expect(kvps[0].Value).To(Equal(kvp1b.Value))
		})

		By("Listing all Node BGP Peers (should be 2)", func() {
			kvps, err := c.List(model.NodeBGPPeerListOptions{})
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps).To(HaveLen(2))
			keys := []model.Key{}
			vals := []interface{}{}
			for _, k := range kvps {
				keys = append(keys, k.Key)
				vals = append(vals, k.Value)
			}
			Expect(keys).To(ContainElement(kvp1b.Key))
			Expect(keys).To(ContainElement(kvp2b.Key))
			Expect(vals).To(ContainElement(kvp1b.Value))
			Expect(vals).To(ContainElement(kvp2b.Value))
		})

		By("Deleting the Node BGP Peer created by Apply", func() {
			err := c.Delete(kvp2a)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Listing all Node BGP Peers (should now be 1)", func() {
			kvps, err := c.List(model.NodeBGPPeerListOptions{})
			Expect(err).ToNot(HaveOccurred())
			Expect(kvps).To(HaveLen(1))
			Expect(kvps[0].Key).To(Equal(kvp1b.Key))
			Expect(kvps[0].Value).To(Equal(kvp1b.Value))
		})

		By("Deleting an existing Node BGP Peer", func() {
			err := c.Delete(kvp1a)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Deleting a non-existent Node BGP Peer", func() {
			err := c.Delete(kvp1a)
			Expect(err).To(HaveOccurred())
		})
	})

	It("should handle a basic Pod", func() {
		pod := k8sapi.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-syncer-basic-pod",
				Namespace: "default",
			},
			Spec: k8sapi.PodSpec{
				NodeName: "127.0.0.1",
				Containers: []k8sapi.Container{
					k8sapi.Container{
						Name:    "container1",
						Image:   "busybox",
						Command: []string{"sleep", "3600"},
					},
				},
			},
		}
		_, err := c.clientSet.Pods("default").Create(&pod)

		// Make sure we clean up after ourselves.  This might fail if we reach the
		// test below which deletes this pod, but that's OK.
		defer func() {
			log.Warnf("[TEST] Cleaning up test pod: %s", pod.ObjectMeta.Name)
			_ = c.clientSet.Pods("default").Delete(pod.ObjectMeta.Name, &metav1.DeleteOptions{})
		}()
		By("Creating a pod", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		By("Assigning an IP", func() {
			// Update the Pod to have an IP and be running.
			pod.Status.PodIP = "192.168.1.1"
			pod.Status.Phase = k8sapi.PodRunning
			_, err = c.clientSet.Pods("default").UpdateStatus(&pod)
			Expect(err).NotTo(HaveOccurred())
		})

		By("Waiting for the pod to start", func() {
			// Wait up to 120s for pod to start running.
			log.Warnf("[TEST] Waiting for pod %s to start", pod.ObjectMeta.Name)
			for i := 0; i < 120; i++ {
				p, err := c.clientSet.Pods("default").Get(pod.ObjectMeta.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				if p.Status.Phase == k8sapi.PodRunning {
					// Pod is running
					break
				}
				time.Sleep(1 * time.Second)
			}
			p, err := c.clientSet.Pods("default").Get(pod.ObjectMeta.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(p.Status.Phase).To(Equal(k8sapi.PodRunning))
		})

		By("Performing a List() operation", func() {
			// Perform List and ensure it shows up in the Calico API.
			weps, err := c.List(model.WorkloadEndpointListOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(len(weps)).To(BeNumerically(">", 0))
		})

		By("Performing a List(workloadID=pod) operation", func() {
			// Perform List, including a workloadID
			weps, err := c.List(model.WorkloadEndpointListOptions{
				WorkloadID: fmt.Sprintf("default.%s", pod.ObjectMeta.Name),
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(len(weps)).To(Equal(1))
		})

		By("Performing a Get() operation", func() {
			// Perform a Get and ensure no error in the Calico API.
			wep, err := c.Get(model.WorkloadEndpointKey{WorkloadID: fmt.Sprintf("default.%s", pod.ObjectMeta.Name)})
			Expect(err).NotTo(HaveOccurred())
			_, err = c.Apply(wep)
			Expect(err).NotTo(HaveOccurred())
		})

		expectedKVP := model.KVPair{
			Key: model.WorkloadEndpointKey{
				Hostname:       "127.0.0.1",
				OrchestratorID: "k8s",
				WorkloadID:     fmt.Sprintf("default.%s", pod.ObjectMeta.Name),
				EndpointID:     "eth0",
			},
		}

		By("Expecting an update with type 'KVNew' on the Syncer API", func() {
			cb.ExpectExists([]api.Update{
				{KVPair: expectedKVP, UpdateType: api.UpdateTypeKVNew},
			})
		})

		By("Expecting a Syncer snapshot to include the update with type 'KVNew'", func() {
			// Create a new syncer / callback pair so that it performs a snapshot.
			cfg := capi.KubeConfig{K8sAPIEndpoint: "http://localhost:8080"}
			_, snapshotCallbacks, snapshotSyncer := CreateClientAndSyncer(cfg)
			go snapshotCallbacks.ProcessUpdates()
			snapshotSyncer.Start()

			// Expect the snapshot to include workload endpoint with type "KVNew".
			snapshotCallbacks.ExpectExists([]api.Update{
				{KVPair: expectedKVP, UpdateType: api.UpdateTypeKVNew},
			})

		})

		By("Deleting the Pod and expecting the wep to be deleted", func() {
			err = c.clientSet.Pods("default").Delete(pod.ObjectMeta.Name, &metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
			cb.ExpectDeleted([]model.KVPair{expectedKVP})
		})
	})

	// Add a defer to wait for all pods to clean up.
	defer func() {
		It("should clean up all pods", func() {
			log.Warnf("[TEST] Waiting for pods to tear down")
			pods, err := c.clientSet.Pods("default").List(metav1.ListOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Wait up to 60s for pod cleanup to occur.
			for i := 0; i < 60; i++ {
				if len(pods.Items) == 0 {
					return
				}
				pods, err = c.clientSet.Pods("default").List(metav1.ListOptions{})
				Expect(err).NotTo(HaveOccurred())
				time.Sleep(1 * time.Second)
			}
			panic(fmt.Sprintf("Failed to clean up pods: %+v", pods))
		})
	}()

	It("should not error on unsupported List() calls", func() {
		objs, err := c.List(model.BlockAffinityListOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(len(objs)).To(Equal(0))
	})

	It("should report ErrorResourceDoesNotExist for HostConfig", func() {
		kv, err := c.Get(model.HostConfigKey{Hostname: "host", Name: "foo"})
		Expect(kv).To(BeNil())
		Expect(err).To(BeAssignableToTypeOf(errors.ErrorResourceDoesNotExist{}))
	})

	It("should support setting and getting GlobalFelixConfig", func() {
		gc := &model.KVPair{
			Key: model.GlobalConfigKey{
				Name: "ClusterGUID",
			},
			Value: "someguid",
		}
		var updGC *model.KVPair
		var err error

		defer func() {
			// Always make sure we tidy up after ourselves.  Ignore
			// errors since the test itself should delete what it created.
			_ = c.Delete(gc)
		}()

		By("creating a new object", func() {
			updGC, err = c.Create(gc)
			Expect(err).NotTo(HaveOccurred())
			Expect(updGC.Value.(string)).To(Equal(gc.Value.(string)))
			Expect(updGC.Key.(model.GlobalConfigKey).Name).To(Equal("ClusterGUID"))
			Expect(updGC.Revision).NotTo(BeNil())
		})

		By("getting an existing object", func() {
			updGC, err = c.Get(gc.Key)
			Expect(err).NotTo(HaveOccurred())
			Expect(updGC.Value.(string)).To(Equal(gc.Value.(string)))
			Expect(updGC.Key.(model.GlobalConfigKey).Name).To(Equal("ClusterGUID"))
			Expect(updGC.Revision).NotTo(BeNil())
		})

		By("updating an existing object", func() {
			updGC.Value = "someotherguid"
			updGC, err = c.Update(updGC)
			Expect(err).NotTo(HaveOccurred())
			Expect(updGC.Value.(string)).To(Equal("someotherguid"))
		})

		By("getting the updated object", func() {
			updGC, err = c.Get(gc.Key)
			Expect(err).NotTo(HaveOccurred())
			Expect(updGC.Value.(string)).To(Equal("someotherguid"))
			Expect(updGC.Key.(model.GlobalConfigKey).Name).To(Equal("ClusterGUID"))
			Expect(updGC.Revision).NotTo(BeNil())
		})

		By("applying an existing object", func() {
			updGC.Value = "somenewguid"
			updGC, err = c.Apply(updGC)
			Expect(err).NotTo(HaveOccurred())
			Expect(updGC.Value.(string)).To(Equal("somenewguid"))
		})

		By("getting the applied object", func() {
			updGC, err = c.Get(gc.Key)
			Expect(err).NotTo(HaveOccurred())
			Expect(updGC.Value.(string)).To(Equal("somenewguid"))
			Expect(updGC.Key.(model.GlobalConfigKey).Name).To(Equal("ClusterGUID"))
			Expect(updGC.Revision).NotTo(BeNil())
		})

		By("deleting an existing object", func() {
			err = c.Delete(gc)
			Expect(err).NotTo(HaveOccurred())
		})

		By("deleting a non-existing object", func() {
			err = c.Delete(gc)
			Expect(err).To(HaveOccurred())
		})

		By("getting a non-existing object", func() {
			updGC, err = c.Get(gc.Key)
			Expect(err).To(HaveOccurred())
			Expect(updGC).To(BeNil())
		})

		By("applying a new object", func() {
			// Revision should not be specified when creating.
			gc.Revision = nil
			updGC, err = c.Apply(gc)
			Expect(err).NotTo(HaveOccurred())
			Expect(updGC.Value.(string)).To(Equal(gc.Value.(string)))
		})

		By("getting the applied object", func() {
			updGC, err = c.Get(gc.Key)
			Expect(err).NotTo(HaveOccurred())
			Expect(updGC.Value.(string)).To(Equal(gc.Value.(string)))
			Expect(updGC.Key.(model.GlobalConfigKey).Name).To(Equal("ClusterGUID"))
			Expect(updGC.Revision).NotTo(BeNil())
		})

		By("deleting the existing object", func() {
			err = c.Delete(updGC)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	It("should support setting and getting IP Pools", func() {
		By("listing IP pools when none have been created", func() {
			_, err := c.List(model.IPPoolListOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		By("creating an IP Pool and getting it back", func() {
			_, cidr, _ := cnet.ParseCIDR("192.168.0.0/16")
			pool := &model.KVPair{
				Key: model.IPPoolKey{
					CIDR: *cidr,
				},
				Value: &model.IPPool{
					CIDR:          *cidr,
					IPIPInterface: "tunl0",
					Masquerade:    true,
					IPAM:          false,
					Disabled:      true,
				},
			}
			_, err := c.Create(pool)
			Expect(err).NotTo(HaveOccurred())

			receivedPool, err := c.Get(pool.Key)
			Expect(err).NotTo(HaveOccurred())
			Expect(receivedPool.Value.(*model.IPPool).CIDR).To(Equal(*cidr))
			Expect(receivedPool.Value.(*model.IPPool).IPIPInterface).To(Equal("tunl0"))
			Expect(receivedPool.Value.(*model.IPPool).Masquerade).To(Equal(true))
			Expect(receivedPool.Value.(*model.IPPool).IPAM).To(Equal(false))
			Expect(receivedPool.Value.(*model.IPPool).Disabled).To(Equal(true))
		})

		By("deleting the IP Pool", func() {
			_, cidr, _ := cnet.ParseCIDR("192.168.0.0/16")
			err := c.Delete(&model.KVPair{
				Key: model.IPPoolKey{
					CIDR: *cidr,
				},
				Value: &model.IPPool{
					CIDR:          *cidr,
					IPIPInterface: "tunl0",
					Masquerade:    true,
					IPAM:          true,
					Disabled:      true,
				},
			})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	It("Should support getting, deleting, and listing Nodes", func() {
		nodeHostname := ""
		var kvp model.KVPair
		ip, cidr, _ := cnet.ParseCIDR("192.168.0.101/24")

		By("Listing all Nodes", func() {
			nodes, err := c.List(model.NodeListOptions{})
			Expect(err).NotTo(HaveOccurred())
			// Get the hostname so we can make a Get call
			kvp = *nodes[0]
			nodeHostname = kvp.Key.(model.NodeKey).Hostname
		})

		By("Listing a specific Node", func() {
			nodes, err := c.List(model.NodeListOptions{Hostname: nodeHostname})
			Expect(err).NotTo(HaveOccurred())
			Expect(nodes).To(HaveLen(1))
			Expect(nodes[0].Key).To(Equal(kvp.Key))
			Expect(nodes[0].Value).To(Equal(kvp.Value))
		})

		By("Listing a specific invalid Node", func() {
			nodes, err := c.List(model.NodeListOptions{Hostname: "foobarbaz-node"})
			Expect(err).NotTo(HaveOccurred())
			Expect(nodes).To(HaveLen(0))
		})

		By("Getting a specific nodeHostname", func() {
			n, err := c.Get(model.NodeKey{Hostname: nodeHostname})
			Expect(err).NotTo(HaveOccurred())

			// Check to see we have the right Node
			Expect(nodeHostname).To(Equal(n.Key.(model.NodeKey).Hostname))
		})

		By("Creating a new Node", func() {
			_, err := c.Create(&kvp)
			Expect(err).To(HaveOccurred())
		})

		By("Getting non-existent Node", func() {
			_, err := c.Get(model.NodeKey{Hostname: "Fake"})
			Expect(err).To(HaveOccurred())
		})

		By("Deleting a Node", func() {
			err := c.Delete(&kvp)
			Expect(err).To(HaveOccurred())
		})

		By("Applying changes to a node", func() {
			newAsn := numorstring.ASNumber(23455)

			testKvp := model.KVPair{
				Key: model.NodeKey{
					Hostname: kvp.Key.(model.NodeKey).Hostname,
				},
				Value: &model.Node{
					BGPASNumber: &newAsn,
					BGPIPv4Net:  cidr,
					BGPIPv4Addr: ip,
				},
			}
			node, err := c.Apply(&testKvp)
			Expect(err).NotTo(HaveOccurred())
			Expect(*node.Value.(*model.Node).BGPASNumber).To(Equal(newAsn))

			// Also check that Get() returns the changes
			getNode, err := c.Get(kvp.Key.(model.NodeKey))
			Expect(err).NotTo(HaveOccurred())
			Expect(*getNode.Value.(*model.Node).BGPASNumber).To(Equal(newAsn))

			// We do not support creating Nodes, we should see an error
			// if the Node does not exist.
			missingKvp := model.KVPair{
				Key: model.NodeKey{
					Hostname: "IDontExist",
				},
			}
			_, err = c.Apply(&missingKvp)

			Expect(err).To(HaveOccurred())
		})

		By("Updating a Node", func() {
			testKvp := model.KVPair{
				Key: model.NodeKey{
					Hostname: kvp.Key.(model.NodeKey).Hostname,
				},
				Value: &model.Node{
					BGPIPv4Net:  cidr,
					BGPIPv4Addr: ip,
				},
			}
			node, err := c.Update(&testKvp)

			Expect(err).NotTo(HaveOccurred())
			Expect(node.Value.(*model.Node).BGPASNumber).To(BeNil())

			// Also check that Get() returns the changes
			getNode, err := c.Get(kvp.Key.(model.NodeKey))
			Expect(err).NotTo(HaveOccurred())
			Expect(getNode.Value.(*model.Node).BGPASNumber).To(BeNil())
		})

		By("Syncing HostIPs over the Syncer", func() {
			expectExist := []api.Update{
				{model.KVPair{Key: model.HostIPKey{Hostname: nodeHostname}}, api.UpdateTypeKVUpdated},
			}

			// Expect the snapshot to include the right keys.
			cb.ExpectExists(expectExist)
		})

		By("Not syncing Nodes when K8sDisableNodePoll is enabled", func() {
			cfg := capi.KubeConfig{K8sAPIEndpoint: "http://localhost:8080", K8sDisableNodePoll: true}
			_, snapshotCallbacks, snapshotSyncer := CreateClientAndSyncer(cfg)

			go snapshotCallbacks.ProcessUpdates()
			snapshotSyncer.Start()

			expectNotExist := []model.KVPair{
				{Key: model.HostIPKey{Hostname: nodeHostname}},
			}

			// Expect the snapshot to have not received the update.
			snapshotCallbacks.ExpectDeleted(expectNotExist)
		})

		By("Syncing HostConfig for a Node on Syncer start", func() {
			cfg := capi.KubeConfig{K8sAPIEndpoint: "http://localhost:8080", K8sDisableNodePoll: true}
			_, snapshotCallbacks, snapshotSyncer := CreateClientAndSyncer(cfg)

			go snapshotCallbacks.ProcessUpdates()
			snapshotSyncer.Start()

			hostConfigKey := model.KVPair{
				Key: model.HostConfigKey{
					Hostname: "127.0.0.1",
					Name:     "IpInIpTunnelAddr",
				}}

			expectedKeys := []api.Update{
				api.Update{hostConfigKey, api.UpdateTypeKVNew},
			}

			snapshotCallbacks.ExpectExists(expectedKeys)
		})
	})

	It("Should support Getting and Listing HostConfig", func() {
		By("Listing all Nodes HostConfig", func() {
			l, err := c.List(model.HostConfigListOptions{Hostname: ""})
			Expect(err).NotTo(HaveOccurred())
			Expect(l[0].Value).NotTo(BeZero())
		})

		By("Getting a specific Nodes HostConfig", func() {
			h, err := c.Get(model.HostConfigKey{Hostname: "127.0.0.1", Name: "IpInIpTunnelAddr"})
			Expect(err).NotTo(HaveOccurred())
			Expect(h.Value).NotTo(BeZero())
		})
	})
})
