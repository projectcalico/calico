package k8s

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	k8sapi "k8s.io/client-go/pkg/api/v1"
	extensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	metav1 "k8s.io/client-go/pkg/apis/meta/v1"
)

// cb implements the callback interface required for the
// backend Syncer API.
type cb struct {
	status api.SyncStatus
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
	}
}

func CreateClientAndStartSyncer() *KubeClient {
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
	callback := cb{
		status: api.WaitForDatastore,
	}
	syncer := c.Syncer(callback)
	syncer.Start()
	return c
}

var _ = Describe("Test Syncer API for Kubernetes backend", func() {
	log.SetLevel(log.DebugLevel)

	// Start the syncer.
	c := CreateClientAndStartSyncer()

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

		// Make sure we clean up after ourselves.
		defer func() {
			log.Warnf("[TEST] Cleaning up test pod: %s", pod.ObjectMeta.Name)
			err = c.clientSet.Pods("default").Delete(pod.ObjectMeta.Name, &k8sapi.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		}()
		Expect(err).NotTo(HaveOccurred())

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

		// Perform List and ensure it shows up in the Calico API.
		weps, err := c.List(model.WorkloadEndpointListOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(len(weps)).To(BeNumerically(">", 0))

		// Perform List, including a workloadID
		weps, err = c.List(model.WorkloadEndpointListOptions{
			WorkloadID: fmt.Sprintf("default.%s", pod.ObjectMeta.Name),
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(len(weps)).To(Equal(1))

		// Perform a Get and ensure no error in the Calico API.
		wep, err := c.Get(model.WorkloadEndpointKey{WorkloadID: fmt.Sprintf("default.%s", pod.ObjectMeta.Name)})
		Expect(err).NotTo(HaveOccurred())
		_, err = c.Apply(wep)
		Expect(err).NotTo(HaveOccurred())
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
})
