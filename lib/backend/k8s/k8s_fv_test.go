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

	log "github.com/Sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"

	k8sapi "k8s.io/client-go/pkg/api/v1"
	extensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	metav1 "k8s.io/client-go/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/util/wait"
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
			log.Infof("[TEST] Stored update %s", u.Key.String())
		}
		c.Lock.Unlock()
	}
}

func (c cb) ExpectExists(kvps []model.KVPair) {
	// For each Key, wait for it to exist.
	for _, kvp := range kvps {
		log.Infof("[TEST] Expecting key: %s", kvp.Key)
		exists := false

		wait.PollImmediate(1*time.Second, 60*time.Second, func() (bool, error) {
			// Get the update.
			c.Lock.Lock()
			update, ok := c.State[kvp.Key.String()]
			exists = ok
			c.Lock.Unlock()

			log.Infof("[TEST] Key exists? %t: %+v", ok, update)
			if ok {
				// Expected key to exist, and it does.
				return true, nil
			} else {
				// Key does not yet exist.
				return false, nil
			}
		})

		// Expect the key to have existed.
		Expect(exists).To(Equal(true), fmt.Sprintf("Expected key to exist: %s", kvp.Key))
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

func CreateClientAndSyncer() (*KubeClient, *cb, api.Syncer) {
	// First create the client.
	cfg := KubeConfig{
		K8sAPIEndpoint: "http://localhost:8080",
	}
	c, err := NewKubeClient(&cfg)
	if err != nil {
		panic(err)
	}

	// Ensure the backend is initialized.
	err = c.EnsureInitialized()
	if err != nil {
		panic(err)
	}

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
	log.SetLevel(log.DebugLevel)

	// Start the syncer.
	c, cb, syncer := CreateClientAndSyncer()
	syncer.Start()

	// Start processing updates.
	go cb.ProcessUpdates()

	It("should handle a Namespace with DefaultDeny", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: k8sapi.ObjectMeta{
				Name: "test-syncer-namespace-default-deny",
				Annotations: map[string]string{
					"net.beta.kubernetes.io/network-policy": "{\"ingress\": {\"isolation\": \"DefaultDeny\"}}",
				},
			},
		}
		_, err := c.clientSet.Namespaces().Create(&ns)

		// Make sure we clean up.
		defer func() {
			err = c.clientSet.Namespaces().Delete(ns.ObjectMeta.Name, &k8sapi.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		}()

		// Check to see if the create succeeded.
		Expect(err).NotTo(HaveOccurred())

		// Perform a List and ensure it shows up in the Calico API.
		_, err = c.List(model.ProfileListOptions{})
		Expect(err).NotTo(HaveOccurred())

		_, err = c.List(model.PolicyListOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Perform a Get and ensure no error in the Calico API.
		_, err = c.Get(model.ProfileKey{Name: fmt.Sprintf("default.%s", ns.ObjectMeta.Name)})
		Expect(err).NotTo(HaveOccurred())

		_, err = c.Get(model.PolicyKey{Name: fmt.Sprintf("ns.projectcalico.org/%s", ns.ObjectMeta.Name)})
		Expect(err).NotTo(HaveOccurred())

		// Expect corresponding Profile updates over the syncer for this Namespace.
		expectedName := "ns.projectcalico.org/test-syncer-namespace-default-deny"
		expectedKeys := []model.KVPair{
			{Key: model.ProfileRulesKey{model.ProfileKey{Name: expectedName}}},
			{Key: model.ProfileTagsKey{model.ProfileKey{Name: expectedName}}},
			{Key: model.ProfileLabelsKey{model.ProfileKey{Name: expectedName}}},
		}
		time.Sleep(1 * time.Second)
		cb.ExpectExists(expectedKeys)
	})

	It("should handle a Namespace without DefaultDeny", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: k8sapi.ObjectMeta{
				Name: "test-syncer-namespace-no-default-deny",
				Annotations: map[string]string{
					"net.beta.kubernetes.io/network-policy": "{\"ingress\": {\"isolation\": \"\"}}",
				},
			},
		}
		_, err := c.clientSet.Namespaces().Create(&ns)

		// Make sure we clean up after ourselves.
		defer func() {
			err = c.clientSet.Namespaces().Delete(ns.ObjectMeta.Name, &k8sapi.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		}()

		// Check to see if the create succeeded.
		Expect(err).NotTo(HaveOccurred())

		// Perform a List and ensure it shows up in the Calico API.
		By("listing Profiles", func() {
			_, err = c.List(model.ProfileListOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		By("listing Policies", func() {
			_, err = c.List(model.PolicyListOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		// Perform a Get and ensure no error in the Calico API.
		By("getting a Profile", func() {
			_, err = c.Get(model.ProfileKey{Name: fmt.Sprintf("default.%s", ns.ObjectMeta.Name)})
			Expect(err).NotTo(HaveOccurred())
		})

		By("getting a Policy", func() {
			_, err = c.Get(model.PolicyKey{Name: fmt.Sprintf("ns.projectcalico.org/%s", ns.ObjectMeta.Name)})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	It("should handle a basic NetworkPolicy", func() {
		np := extensions.NetworkPolicy{
			ObjectMeta: k8sapi.ObjectMeta{
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
		res := c.clientSet.Extensions().RESTClient().
			Post().
			Resource("networkpolicies").
			Namespace("default").
			Body(&np).
			Do()

		// Make sure we clean up after ourselves.
		defer func() {
			res := c.clientSet.Extensions().RESTClient().
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
		_, err = c.Get(model.PolicyKey{Name: fmt.Sprintf("np.projectcalico.org/default.%s", np.ObjectMeta.Name)})
		Expect(err).NotTo(HaveOccurred())
	})

	// Add a defer to wait for policies to clean up.
	defer func() {
		log.Warnf("[TEST] Waiting for policies to tear down")
		It("should clean up all policies", func() {
			nps := extensions.NetworkPolicyList{}
			err := c.clientSet.Extensions().RESTClient().
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
				err := c.clientSet.Extensions().RESTClient().
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

	It("should handle a basic Pod", func() {
		pod := k8sapi.Pod{
			ObjectMeta: k8sapi.ObjectMeta{
				Name:      "test-syncer-basic-pod",
				Namespace: "default",
			},
			Spec: k8sapi.PodSpec{
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
			_ = c.clientSet.Pods("default").Delete(pod.ObjectMeta.Name, &k8sapi.DeleteOptions{})
		}()
		By("Creating a pod", func() {
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

		// The expected KVPair keys that should exist as a result of creating this Pod.
		expectedKeys := []model.KVPair{
			{Key: model.WorkloadEndpointKey{
				Hostname:       "127.0.0.1",
				OrchestratorID: "k8s",
				WorkloadID:     fmt.Sprintf("default.%s", pod.ObjectMeta.Name),
				EndpointID:     "eth0",
			}},
		}

		By("Expecting an update on the Syncer API", func() {
			// Expect corresponding updates over the syncer for this Pod.
			cb.ExpectExists(expectedKeys)
		})

		By("Expecting a Syncer snapshot to include the update", func() {
			// Create a new syncer / callback pair so that it performs a snapshot.
			_, snapshotCallbacks, snapshotSyncer := CreateClientAndSyncer()
			go snapshotCallbacks.ProcessUpdates()
			snapshotSyncer.Start()

			// Expect the snapshot to include the right keys.
			snapshotCallbacks.ExpectExists(expectedKeys)
		})

		By("Deleting the Pod and expecting the wep to be deleted", func() {
			err = c.clientSet.Pods("default").Delete(pod.ObjectMeta.Name, &k8sapi.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
			cb.ExpectDeleted(expectedKeys)
		})
	})

	// Add a defer to wait for all pods to clean up.
	defer func() {
		It("should clean up all pods", func() {
			log.Warnf("[TEST] Waiting for pods to tear down")
			pods, err := c.clientSet.Pods("default").List(k8sapi.ListOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Wait up to 60s for pod cleanup to occur.
			for i := 0; i < 60; i++ {
				if len(pods.Items) == 0 {
					return
				}
				pods, err = c.clientSet.Pods("default").List(k8sapi.ListOptions{})
				Expect(err).NotTo(HaveOccurred())
				time.Sleep(1 * time.Second)
			}
			panic(fmt.Sprintf("Failed to clean up pods: %+v", pods))
		})
	}()

	It("should not error on unsupported List() calls", func() {
		objs, err := c.List(model.BGPPeerListOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(len(objs)).To(Equal(0))
	})

	It("should report ErrorResourceDoesNotExist for HostConfig", func() {
		kv, err := c.Get(model.HostConfigKey{Hostname: "host", Name: "foo"})
		Expect(kv).To(BeNil())
		Expect(err).To(BeAssignableToTypeOf(errors.ErrorResourceDoesNotExist{}))
	})

	It("should support setting and getting GlobalConfig", func() {
		gc := &model.KVPair{
			Key: model.GlobalConfigKey{
				Name: "ClusterGUID",
			},
			Value: "someguid",
		}
		var updGC *model.KVPair
		var err error

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

		By("getting a non-existing object", func() {
			updGC, err = c.Get(gc.Key)
			Expect(err).To(HaveOccurred())
			Expect(updGC).To(BeNil())
		})

		By("applying a new object", func() {
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
					IPAM:          true,
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
			Expect(receivedPool.Value.(*model.IPPool).IPAM).To(Equal(true))
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
