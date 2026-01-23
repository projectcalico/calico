// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package ippool_test

import (
	"context"
	"fmt"
	"slices"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/ippool"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
)

var _ = Describe("IP pool lifecycle FV", func() {
	var (
		etcd              *containers.Container
		kubectrl          *containers.Container
		apiserver         *containers.Container
		k8sClient         *kubernetes.Clientset
		cli               ctrlclient.Client
		controllerManager *containers.Container
		err               error
		pool              *v3.IPPool
		ipamcli           ipam.Interface
	)

	BeforeEach(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()

		// Determine if we should use v3 CRDs based on the test config.
		var cfg *apiconfig.CalicoAPIConfig
		cfg, err = apiconfig.LoadClientConfigFromEnvironment()
		Expect(err).NotTo(HaveOccurred())
		useV3CRDs := k8s.UsingV3CRDs(&cfg.Spec)
		if !useV3CRDs {
			Skip("IP pool controller only runs against v3 CRDs")
		}

		// Run apiserver.
		apiserver = testutils.RunK8sApiserver(etcd.IP)
		kubeconfig, cleanup := testutils.BuildKubeconfig(apiserver.IP)
		defer cleanup()

		// Create clients for the test.
		ipamcli = testutils.GetCalicoClient(apiconfig.Kubernetes, "", kubeconfig).IPAM()
		k8sClient, err = testutils.GetK8sClient(kubeconfig)
		Expect(err).NotTo(HaveOccurred())

		// Register Calico CRD types with the scheme.
		Expect(v3.AddToGlobalScheme()).NotTo(HaveOccurred())

		// Create a client for interacting with CRDs directly.
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		Expect(err).NotTo(HaveOccurred())
		cli, err = ctrlclient.New(config, ctrlclient.Options{})
		Expect(err).NotTo(HaveOccurred())

		// Wait for the apiserver to be available.
		Eventually(func() error {
			_, err := k8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
			return err
		}, 30*time.Second, 1*time.Second).Should(BeNil())

		// Apply the necessary CRDs if we're running in k8s mode.
		testutils.ApplyCRDs(apiserver)

		// Run kube-controllers.
		mode := apiconfig.Kubernetes
		kubectrl = testutils.RunKubeControllers(mode, etcd.IP, kubeconfig, "")

		// Create default pool for tests.
		pool = &v3.IPPool{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-pool",
			},
			Spec: v3.IPPoolSpec{
				CIDR: "192.168.0.0/24",
			},
		}

		By("creating a node for the test", func() {
			_, err = k8sClient.CoreV1().Nodes().Create(context.Background(),
				&v1.Node{
					TypeMeta:   metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "test-node"},
					Spec:       v1.NodeSpec{},
				},
				metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	AfterEach(func() {
		controllerManager.Stop()
		kubectrl.Stop()
		apiserver.Stop()
		etcd.Stop()
	})

	It("should create and delete an IP pool", func() {
		// Create an IP pool.
		err = cli.Create(context.Background(), pool)
		Expect(err).NotTo(HaveOccurred())

		waitForFinalizerAddition(cli, pool.Name)

		// Delete the IP pool.
		err = cli.Delete(context.Background(), pool)
		Expect(err).NotTo(HaveOccurred())

		// Expect the IP pool to be removed from the API server.
		waitForPoolDeleted(cli, pool.Name)
	})

	It("should not remove a pool that is in use", func() {
		// Create an IP pool.
		err = cli.Create(context.Background(), pool)
		Expect(err).NotTo(HaveOccurred())
		waitForFinalizerAddition(cli, pool.Name)

		// Assign an IP address from the pool, putting it "in use".
		_, _, err = ipamcli.AutoAssign(context.Background(), ipam.AutoAssignArgs{
			Num4:        1,
			HandleID:    ptr.To("test-handle"),
			IntendedUse: v3.IPPoolAllowedUseWorkload,
			Hostname:    "test-node",
		})
		Expect(err).NotTo(HaveOccurred())

		// Delete the IP pool.
		err = cli.Delete(context.Background(), pool)
		Expect(err).NotTo(HaveOccurred())

		// Expect the IP pool to still exist in the API server.
		p := &v3.IPPool{}
		EventuallyWithOffset(1, func() error {
			return cli.Get(context.Background(), ctrlclient.ObjectKey{Name: pool.Name}, p)
		}, 10*time.Second, 1*time.Second).ShouldNot(HaveOccurred(), "IP pool should still exist")

		// Release the assigned IP address.
		Expect(ipamcli.ReleaseByHandle(context.Background(), "test-handle")).NotTo(HaveOccurred())

		// Expect the IP pool to be removed from the API server.
		waitForPoolDeleted(cli, pool.Name)
	})
})

func waitForPoolDeleted(cli ctrlclient.Client, poolName string) {
	pool := &v3.IPPool{}
	EventuallyWithOffset(1, func() error {
		err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: poolName}, pool)
		if errors.IsNotFound(err) {
			// Pool has been deleted.
			return nil
		} else if err != nil {
			// Some other error occurred.
			return err
		}
		return fmt.Errorf("pool still exists")
	}, 10*time.Second, 1*time.Second).ShouldNot(HaveOccurred(), "IP pool should be deleted")
}

func waitForFinalizerAddition(cli ctrlclient.Client, poolName string) {
	pool := &v3.IPPool{}
	EventuallyWithOffset(1, func() error {
		err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: poolName}, pool)
		if err != nil {
			return err
		}
		if slices.Contains(pool.Finalizers, ippool.IPPoolFinalizer) {
			return nil
		}
		return fmt.Errorf("finalizer not found")
	}, 10*time.Second, 1*time.Second).ShouldNot(HaveOccurred(), "finalizer should be added to IP pool")
}
