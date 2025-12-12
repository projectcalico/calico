// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
package networkpolicy_test

import (
	"context"
	"fmt"
	"os"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = Describe("policy name migration tests (etcd mode)", func() {
	var (
		etcd              *containers.Container
		policyController  *containers.Container
		apiserver         *containers.Container
		cli               client.Interface
		bcli              bapi.Client
		k8sClient         *kubernetes.Clientset
		controllerManager *containers.Container
	)

	BeforeEach(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()
		cli = testutils.GetCalicoClient(apiconfig.EtcdV3, etcd.IP, "")

		type accessor interface {
			Backend() bapi.Client
		}
		bcli = cli.(accessor).Backend()

		// Run apiserver.
		apiserver = testutils.RunK8sApiserver(etcd.IP)

		// Write out a kubeconfig file
		kconfigfile, err := os.CreateTemp("", "policy-migrator-test")
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = os.Remove(kconfigfile.Name()) }()

		data := testutils.BuildKubeconfig(apiserver.IP)
		_, err = kconfigfile.Write([]byte(data))
		Expect(err).NotTo(HaveOccurred())

		// Make the kubeconfig readable by the container.
		Expect(kconfigfile.Chmod(os.ModePerm)).NotTo(HaveOccurred())

		// Run the controller.
		policyController = testutils.RunKubeControllers(apiconfig.EtcdV3, etcd.IP, kconfigfile.Name(), "")

		k8sClient, err = testutils.GetK8sClient(kconfigfile.Name())
		Expect(err).NotTo(HaveOccurred())

		// Wait for the apiserver to be available.
		Eventually(func() error {
			_, err := k8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
			return err
		}, 30*time.Second, 1*time.Second).Should(BeNil())

		// Run controller manager.  Empirically it can take around 10s until the
		// controller manager is ready to create default service accounts, even
		// when the k8s image has already been downloaded to run the API
		// server.  We use Eventually to allow for possible delay when doing
		// initial pod creation below.
		controllerManager = testutils.RunK8sControllerManager(apiserver.IP)
	})

	AfterEach(func() {
		_ = cli.Close()
		controllerManager.Stop()
		policyController.Stop()
		apiserver.Stop()
		etcd.Stop()
	})

	It("should update NetworkPolicy names correctly", func() {
		var err error

		// Create a policy that was created without a tier prefix in the v3 API, but
		// whose backend representation includes the tier prefix.
		mismatchedNames := v3.NewNetworkPolicy()
		mismatchedNames.Name = "mismatched" // Name was created without tier.
		mismatchedNames.Namespace = "default"
		mismatchedNames.Spec = v3.NetworkPolicySpec{
			Tier:     "default",
			Selector: "all()",
			Ingress:  []v3.Rule{{}},
		}
		_, err = bcli.Create(context.Background(), &model.KVPair{
			Key: model.ResourceKey{
				Kind:      v3.KindNetworkPolicy,
				Name:      "default.mismatched", // Old generated name format including tier.
				Namespace: mismatchedNames.Namespace,
			},
			Value: mismatchedNames,
		})
		Expect(err).NotTo(HaveOccurred())

		// Create a policy that was created in a non-default tier, and that
		// has a name that matches between the v3 API and backend.
		matchingWithPrefix := v3.NewNetworkPolicy()
		matchingWithPrefix.Name = "custom-tier.policy-in-non-default-tier"
		matchingWithPrefix.Namespace = "default"
		matchingWithPrefix.Spec = v3.NetworkPolicySpec{
			Tier:     "custom-tier",
			Selector: "all()",
			Ingress:  []v3.Rule{{}},
		}
		_, err = bcli.Create(context.Background(), &model.KVPair{
			Key: model.ResourceKey{
				Kind:      v3.KindNetworkPolicy,
				Name:      matchingWithPrefix.Name, // Name matches between v3 and backend.
				Namespace: matchingWithPrefix.Namespace,
			},
			Value: matchingWithPrefix,
		})
		Expect(err).NotTo(HaveOccurred())

		// Create a policy that was created without a tier prefix in the v3 API, and
		// whose backend representation also does not include the tier prefix.
		matchingNoPrefix := v3.NewNetworkPolicy()
		matchingNoPrefix.Name = "matching-name"
		matchingNoPrefix.Namespace = "default"
		matchingNoPrefix.Spec = v3.NetworkPolicySpec{
			Tier:     "default",
			Selector: "all()",
			Ingress:  []v3.Rule{{}},
		}
		_, err = bcli.Create(context.Background(), &model.KVPair{
			Key: model.ResourceKey{
				Kind:      v3.KindNetworkPolicy,
				Name:      matchingNoPrefix.Name, // Name matches between v3 and backend.
				Namespace: matchingNoPrefix.Namespace,
			},
			Value: matchingNoPrefix,
		})
		Expect(err).NotTo(HaveOccurred())

		// Check that all policies are accessible via the v3 API with the correct v3 API names.
		for _, np := range []*v3.NetworkPolicy{mismatchedNames, matchingWithPrefix, matchingNoPrefix} {
			Eventually(func() error {
				_, err = cli.NetworkPolicies().Get(context.Background(), np.Namespace, np.Name, options.GetOptions{})
				return err
			}, 5*time.Second, 1*time.Second).Should(BeNil(), "NetworkPolicy was not accessible via v3 API: %s", np.Name)
		}

		// Check that the v1 backend representation for the mismatched policy has been updated to match
		// the v3 API name.
		kvp := expectFound(bcli, "mismatched", mismatchedNames.Namespace, v3.KindNetworkPolicy)
		Expect(kvp.Value.(*v3.NetworkPolicy).Name).To(Equal("mismatched"))

		// Check that the old mismatched key is no longer present in the backend.
		expectNotFound(bcli, "default.mismatched", mismatchedNames.Namespace, v3.KindNetworkPolicy)

		// Check that the other two policies are still present under their original names.
		kvp = expectFound(bcli, matchingWithPrefix.Name, matchingWithPrefix.Namespace, v3.KindNetworkPolicy)
		Expect(kvp.Value.(*v3.NetworkPolicy).Name).To(Equal(matchingWithPrefix.Name))

		kvp = expectFound(bcli, matchingNoPrefix.Name, matchingNoPrefix.Namespace, v3.KindNetworkPolicy)
		Expect(kvp.Value.(*v3.NetworkPolicy).Name).To(Equal(matchingNoPrefix.Name))
	})

	It("sholuld update a GlobalNetworkPolicy name correctly", func() {
		var err error

		// Create a GlobalNetworkPolicy that was created without a tier prefix in the v3 API, but
		// whose backend representation includes the tier prefix.
		mismatchedNames := v3.NewGlobalNetworkPolicy()
		mismatchedNames.Name = "mismatched"
		mismatchedNames.Spec = v3.GlobalNetworkPolicySpec{
			Tier:     "default",
			Selector: "all()",
			Ingress:  []v3.Rule{{}},
		}
		_, err = bcli.Create(context.Background(), &model.KVPair{
			Key: model.ResourceKey{
				Kind: v3.KindGlobalNetworkPolicy,
				Name: "default.mismatched", // Old generated name format including tier.
			},
			Value: mismatchedNames,
		})
		Expect(err).NotTo(HaveOccurred())

		// Check that the policy is accessible via the v3 API with the correct v3 API name.
		Eventually(func() error {
			_, err = cli.GlobalNetworkPolicies().Get(context.Background(), mismatchedNames.Name, options.GetOptions{})
			return err
		}, 5*time.Second, 1*time.Second).Should(BeNil(), "GlobalNetworkPolicy was not accessible via v3 API: %s", mismatchedNames.Name)

		// Check that the v1 backend representation for the mismatched policy has been updated to match
		// the v3 API name.
		kvp := expectFound(bcli, "mismatched", "", v3.KindGlobalNetworkPolicy)
		Expect(kvp.Value.(*v3.GlobalNetworkPolicy).Name).To(Equal("mismatched"))

		// Check that the old mismatched key is no longer present in the backend.
		expectNotFound(bcli, "default.mismatched", "", v3.KindGlobalNetworkPolicy)
	})

	It("should update a StagedNetworkPolicy name correctly", func() {
		var err error

		// Create a StagedNetworkPolicy that was created without a tier prefix in the v3 API, but
		// whose backend representation includes the tier prefix.
		mismatchedNames := v3.NewStagedNetworkPolicy()
		mismatchedNames.Name = "mismatched"
		mismatchedNames.Namespace = "default"
		mismatchedNames.Spec = v3.StagedNetworkPolicySpec{
			Tier:     "default",
			Selector: "all()",
			Ingress:  []v3.Rule{{}},
		}
		_, err = bcli.Create(context.Background(), &model.KVPair{
			Key: model.ResourceKey{
				Kind:      v3.KindStagedNetworkPolicy,
				Name:      "default.mismatched", // Old generated name format including tier.
				Namespace: mismatchedNames.Namespace,
			},
			Value: mismatchedNames,
		})
		Expect(err).NotTo(HaveOccurred())

		// Check that the policy is accessible via the v3 API with the correct v3 API name.
		Eventually(func() error {
			_, err = cli.StagedNetworkPolicies().Get(context.Background(), mismatchedNames.Namespace, mismatchedNames.Name, options.GetOptions{})
			return err
		}, 5*time.Second, 1*time.Second).Should(BeNil(), "StagedNetworkPolicy was not accessible via v3 API: %s", mismatchedNames.Name)

		// Check that the v1 backend representation for the mismatched policy has been updated to match
		// the v3 API name.
		kvp := expectFound(bcli, "mismatched", mismatchedNames.Namespace, v3.KindStagedNetworkPolicy)
		Expect(kvp.Value.(*v3.StagedNetworkPolicy).Name).To(Equal("mismatched"))

		// Check that the old mismatched key is no longer present in the backend.
		expectNotFound(bcli, "default.mismatched", mismatchedNames.Namespace, v3.KindStagedNetworkPolicy)
	})

	It("should fix if both mismatched and correct keys exist", func() {
		var err error

		// Create a policy that was created without a tier prefix in the v3 API, but
		// whose backend representation includes the tier prefix.
		mismatchedNames := v3.NewNetworkPolicy()
		mismatchedNames.Name = "mismatched"
		mismatchedNames.Namespace = "default"
		mismatchedNames.Spec = v3.NetworkPolicySpec{
			Tier:     "default",
			Selector: "all()",
			Ingress:  []v3.Rule{{}},
		}

		// Create the correct key.
		_, err = bcli.Create(context.Background(), &model.KVPair{
			Key: model.ResourceKey{
				Kind:      v3.KindNetworkPolicy,
				Name:      "mismatched", // Correct name.
				Namespace: mismatchedNames.Namespace,
			},
			Value: mismatchedNames,
		})
		Expect(err).NotTo(HaveOccurred())

		// Create the old mismatched key.
		_, err = bcli.Create(context.Background(), &model.KVPair{
			Key: model.ResourceKey{
				Kind:      v3.KindNetworkPolicy,
				Name:      "default.mismatched", // Old generated name format including tier.
				Namespace: mismatchedNames.Namespace,
			},
			Value: mismatchedNames,
		})
		Expect(err).NotTo(HaveOccurred())

		// Check that the policy is accessible via the v3 API with the correct v3 API name.
		Eventually(func() error {
			_, err = cli.NetworkPolicies().Get(context.Background(), mismatchedNames.Namespace, mismatchedNames.Name, options.GetOptions{})
			return err
		}, 5*time.Second, 1*time.Second).Should(BeNil(), "NetworkPolicy was not accessible via v3 API: %s", mismatchedNames.Name)

		// Check that the old mismatched key is no longer present in the backend.
		expectNotFound(bcli, "default.mismatched", mismatchedNames.Namespace, v3.KindNetworkPolicy)

		// Check that the correct key is still present.
		kvp := expectFound(bcli, "mismatched", mismatchedNames.Namespace, v3.KindNetworkPolicy)
		Expect(kvp.Value.(*v3.NetworkPolicy).Name).To(Equal("mismatched"))
	})
})

func expectFound(bcli bapi.Client, name, ns, kind string) *model.KVPair {
	var kvp *model.KVPair
	var err error
	EventuallyWithOffset(1, func() error {
		kvp, err = bcli.Get(context.Background(), model.ResourceKey{
			Kind:      kind,
			Name:      name,
			Namespace: ns,
		}, "")
		return err
	}, 5*time.Second, 1*time.Second).Should(BeNil(), "expected to find key %s/%s for kind %s", ns, name, kind)
	return kvp
}

func expectNotFound(bcli bapi.Client, name, ns, kind string) {
	EventuallyWithOffset(1, func() error {
		_, err := bcli.Get(context.Background(), model.ResourceKey{
			Kind:      kind,
			Name:      name,
			Namespace: ns,
		}, "")
		if _, ok := err.(errors.ErrorResourceDoesNotExist); ok {
			return nil
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("expected not to find old key for mismatched policy")
	}, 5*time.Second, 1*time.Second).Should(BeNil())
}
