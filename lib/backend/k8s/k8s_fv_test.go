package k8s

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	k8sapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/apis/extensions"
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
			// Value should not be nil.
			Expect(u.Value).NotTo(BeNil())
		case api.UpdateTypeKVUpdated:
			// Value should not be nil.
			Expect(u.Value).NotTo(BeNil())
		case api.UpdateTypeKVDeleted:
			// Ensure the value is nil.
			Expect(u.Value).To(BeNil())
		case api.UpdateTypeKVUnknown:
			panic(fmt.Sprintf("Received unkown update: %+v", u))
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

		// Perform a Get and ensure no error in the Calico API.
		_, err = c.Get(model.ProfileKey{Name: fmt.Sprintf("default.%s", ns.ObjectMeta.Name)})
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
		_, err = c.List(model.ProfileListOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Perform a Get and ensure no error in the Calico API.
		_, err = c.Get(model.ProfileKey{Name: fmt.Sprintf("default.%s", ns.ObjectMeta.Name)})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should handle a basic NetworkPolicy", func() {
		np := extensions.NetworkPolicy{
			ObjectMeta: k8sapi.ObjectMeta{
				Name: "test-syncer-basic-net-policy",
			},
			Spec: extensions.NetworkPolicySpec{
				PodSelector: unversioned.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
				Ingress: []extensions.NetworkPolicyIngressRule{
					extensions.NetworkPolicyIngressRule{
						Ports: []extensions.NetworkPolicyPort{
							extensions.NetworkPolicyPort{},
						},
						From: []extensions.NetworkPolicyPeer{
							extensions.NetworkPolicyPeer{
								PodSelector: &unversioned.LabelSelector{
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
		_, err := c.clientSet.NetworkPolicies("default").Create(&np)

		// Make sure we clean up after ourselves.
		defer func() {
			err = c.clientSet.NetworkPolicies("default").Delete(np.ObjectMeta.Name, &k8sapi.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		}()

		// Check to see if the create succeeded.
		Expect(err).NotTo(HaveOccurred())

		// Perform a List and ensure it shows up in the Calico API.
		_, err = c.List(model.PolicyListOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Perform a Get and ensure no error in the Calico API.
		_, err = c.Get(model.PolicyKey{Name: fmt.Sprintf("default.%s", np.ObjectMeta.Name)})
		Expect(err).NotTo(HaveOccurred())
	})

	// Add a defer to wait for policies to clean up.
	defer func() {
		log.Warnf("[TEST] Waiting for policies to tear down")
		It("should clean up all policies", func() {
			nps, err := c.clientSet.NetworkPolicies("default").List(k8sapi.ListOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Loop until no network policies exist.
			for i := 0; i < 10; i++ {
				if len(nps.Items) == 0 {
					return
				}
				nps, err = c.clientSet.NetworkPolicies("default").List(k8sapi.ListOptions{})
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
			p, err := c.clientSet.Pods("default").Get(pod.ObjectMeta.Name)
			Expect(err).NotTo(HaveOccurred())
			if p.Status.Phase == k8sapi.PodRunning {
				// Pod is running
				break
			}
			time.Sleep(1 * time.Second)
		}
		p, err := c.clientSet.Pods("default").Get(pod.ObjectMeta.Name)
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
		_, err = c.Get(model.WorkloadEndpointKey{WorkloadID: fmt.Sprintf("default.%s", pod.ObjectMeta.Name)})
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
})
