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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/ippool"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = Describe("IP pool controller on crd.projectcalico.org/v1 FV", func() {
	var (
		etcd      *containers.Container
		apiserver *containers.Container
		kubectrl  *containers.Container
		calicoCli client.Interface
	)

	BeforeEach(func() {
		cfg, err := apiconfig.LoadClientConfigFromEnvironment()
		Expect(err).NotTo(HaveOccurred())
		if k8s.UsingV3CRDs(&cfg.Spec) {
			Skip("covers the crd.projectcalico.org/v1 datastore")
		}

		etcd = testutils.RunEtcd()
		apiserver = testutils.RunK8sApiserver(etcd.IP)
		kubeconfig, cleanup := testutils.BuildKubeconfig(apiserver.IP)
		DeferCleanup(cleanup)

		k8sClient, err := testutils.GetK8sClient(kubeconfig)
		Expect(err).NotTo(HaveOccurred())
		Eventually(func() error {
			_, err := k8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
			return err
		}, 30*time.Second, 1*time.Second).Should(Succeed())

		testutils.ApplyCRDs(apiserver)
		calicoCli = testutils.GetCalicoClient(apiconfig.Kubernetes, "", kubeconfig)
		kubectrl = testutils.RunKubeControllers(apiconfig.Kubernetes, etcd.IP, kubeconfig, "")
	})

	AfterEach(func() {
		kubectrl.Stop()
		apiserver.Stop()
		etcd.Stop()
	})

	It("should write pool conditions without adding a finalizer", func() {
		ctx := context.Background()
		pool := &v3.IPPool{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pool"},
			Spec:       v3.IPPoolSpec{CIDR: "192.168.1.0/24"},
		}
		_, err := calicoCli.IPPools().Create(ctx, pool, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Only the controller writes PoolDisabled, so this proves it runs in v1 mode.
		updatePool(calicoCli, pool.Name, func(p *v3.IPPool) { p.Spec.Disabled = true })
		expectV1Condition(calicoCli, pool.Name, metav1.ConditionFalse, v3.IPPoolReasonDisabled)

		updatePool(calicoCli, pool.Name, func(p *v3.IPPool) { p.Spec.Disabled = false })
		expectV1Condition(calicoCli, pool.Name, metav1.ConditionTrue, v3.IPPoolReasonOK)

		Consistently(func() []string {
			p, err := calicoCli.IPPools().Get(ctx, pool.Name, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return p.Finalizers
		}, 5*time.Second, 1*time.Second).ShouldNot(ContainElement(ippool.IPPoolFinalizer))

		_, err = calicoCli.IPPools().Delete(ctx, pool.Name, options.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
		_, err = calicoCli.IPPools().Get(ctx, pool.Name, options.GetOptions{})
		Expect(err).To(BeAssignableToTypeOf(cerrors.ErrorResourceDoesNotExist{}))
	})
})

func updatePool(cli client.Interface, name string, mutate func(*v3.IPPool)) {
	EventuallyWithOffset(1, func() error {
		p, err := cli.IPPools().Get(context.Background(), name, options.GetOptions{})
		if err != nil {
			return err
		}
		mutate(p)
		_, err = cli.IPPools().Update(context.Background(), p, options.SetOptions{})
		return err
	}, 10*time.Second, 1*time.Second).Should(Succeed())
}

func expectV1Condition(cli client.Interface, name string, status metav1.ConditionStatus, reason string) {
	EventuallyWithOffset(1, func() error {
		p, err := cli.IPPools().Get(context.Background(), name, options.GetOptions{})
		if err != nil {
			return err
		}
		if p.Status == nil {
			return fmt.Errorf("pool %s has no status", name)
		}
		for _, c := range p.Status.Conditions {
			if c.Type == v3.IPPoolConditionAllocatable && c.Status == status && c.Reason == reason {
				return nil
			}
		}
		return fmt.Errorf("pool %s conditions %+v do not include Allocatable=%s/%s", name, p.Status.Conditions, status, reason)
	}, 15*time.Second, 1*time.Second).Should(Succeed())
}
