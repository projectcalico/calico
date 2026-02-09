// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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
	"encoding/json"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	v1scheme "github.com/projectcalico/calico/libcalico-go/lib/apis/crd.projectcalico.org/v1/scheme"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = Describe("policy name migration tests (etcd mode)", func() {
	var (
		etcd              *containers.Container
		kubectrl          *containers.Container
		apiserver         *containers.Container
		cli               client.Interface
		bcli              bapi.Client
		k8sClient         *kubernetes.Clientset
		controllerManager *containers.Container
		err               error
	)

	// Define an interface to access the backend client from the Calico client.
	type accessor interface {
		Backend() bapi.Client
	}

	BeforeEach(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()

		// Run apiserver.
		apiserver = testutils.RunK8sApiserver(etcd.IP)
		kubeconfig, cleanup := testutils.BuildKubeconfig(apiserver.IP)
		defer cleanup()

		// Run the controller.
		mode := apiconfig.EtcdV3
		kubectrl = testutils.RunKubeControllers(mode, etcd.IP, kubeconfig, "")

		// Create clients for the test.
		cli = testutils.GetCalicoClient(mode, etcd.IP, kubeconfig)
		k8sClient, err = testutils.GetK8sClient(kubeconfig)
		Expect(err).NotTo(HaveOccurred())
		bcli = cli.(accessor).Backend()

		// Wait for the apiserver to be available.
		Eventually(func() error {
			_, err := k8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
			return err
		}, 30*time.Second, 1*time.Second).Should(BeNil())
	})

	AfterEach(func() {
		_ = cli.Close()
		controllerManager.Stop()
		kubectrl.Stop()
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
			Ingress: []v3.Rule{{
				Action: "Allow",
			}},
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
			Ingress: []v3.Rule{{
				Action: "Allow",
			}},
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
			Ingress: []v3.Rule{{
				Action: "Allow",
			}},
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

	It("should update a GlobalNetworkPolicy name correctly", func() {
		var err error

		// Create a GlobalNetworkPolicy that was created without a tier prefix in the v3 API, but
		// whose backend representation includes the tier prefix.
		mismatchedNames := v3.NewGlobalNetworkPolicy()
		mismatchedNames.Name = "mismatched"
		mismatchedNames.Spec = v3.GlobalNetworkPolicySpec{
			Tier:     "default",
			Selector: "all()",
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

	It("should update a StagedGlobalNetworkPolicy name correctly", func() {
		var err error

		// Create a StagedGlobalNetworkPolicy that was created without a tier prefix in the v3 API, but
		// whose backend representation includes the tier prefix.
		mismatchedNames := v3.NewStagedGlobalNetworkPolicy()
		mismatchedNames.Name = "mismatched"
		mismatchedNames.Spec = v3.StagedGlobalNetworkPolicySpec{
			Tier:     "default",
			Selector: "all()",
		}
		_, err = bcli.Create(context.Background(), &model.KVPair{
			Key: model.ResourceKey{
				Kind: v3.KindStagedGlobalNetworkPolicy,
				Name: "default.mismatched", // Old generated name format including tier.
			},
			Value: mismatchedNames,
		})
		Expect(err).NotTo(HaveOccurred())

		// Check that the policy is accessible via the v3 API with the correct v3 API name.
		Eventually(func() error {
			_, err = cli.StagedGlobalNetworkPolicies().Get(context.Background(), mismatchedNames.Name, options.GetOptions{})
			return err
		}, 5*time.Second, 1*time.Second).Should(BeNil(), "StagedGlobalNetworkPolicy was not accessible via v3 API: %s", mismatchedNames.Name)

		// Check that the v1 backend representation for the mismatched policy has been updated to match
		// the v3 API name.
		kvp := expectFound(bcli, "mismatched", "", v3.KindStagedGlobalNetworkPolicy)
		Expect(kvp.Value.(*v3.StagedGlobalNetworkPolicy).Name).To(Equal("mismatched"))

		// Check that the old mismatched key is no longer present in the backend.
		expectNotFound(bcli, "default.mismatched", "", v3.KindStagedGlobalNetworkPolicy)
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

// Kubernetes CRD backend needs separate tests since the v1 API behavior is different such that it does not allow us
// to write objects with mismatched v3 and v1 names. Instead, we'll access the CRD API directly to create the mismatched
// objects.
var _ = Describe("policy name migration tests (kdd mode)", func() {
	var (
		etcd              *containers.Container
		kubectrl          *containers.Container
		apiserver         *containers.Container
		k8sClient         *kubernetes.Clientset
		crdClient         ctrlclient.Client
		controllerManager *containers.Container
		err               error
	)

	BeforeEach(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()

		// Determine if we should use v3 CRDs based on the test config.
		var cfg *apiconfig.CalicoAPIConfig
		cfg, err = apiconfig.LoadClientConfigFromEnvironment()
		Expect(err).NotTo(HaveOccurred())
		useV3CRDs := k8s.UsingV3CRDs(&cfg.Spec)
		if useV3CRDs {
			Skip("policy name migration does not apply to projectcalico.org/v3 CRDs")
		}

		// Run apiserver.
		apiserver = testutils.RunK8sApiserver(etcd.IP)
		kubeconfig, cleanup := testutils.BuildKubeconfig(apiserver.IP)
		defer cleanup()

		// Run the controller.
		mode := apiconfig.Kubernetes
		kubectrl = testutils.RunKubeControllers(mode, etcd.IP, kubeconfig, "")

		// Create clients for the test.
		k8sClient, err = testutils.GetK8sClient(kubeconfig)
		Expect(err).NotTo(HaveOccurred())

		// Register Calico CRD types with the scheme.
		v1scheme.AddCalicoResourcesToGlobalScheme()

		// Create a client for interacting with CRDs directly.
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		Expect(err).NotTo(HaveOccurred())
		crdClient, err = ctrlclient.New(config, ctrlclient.Options{})
		Expect(err).NotTo(HaveOccurred())

		// Wait for the apiserver to be available.
		Eventually(func() error {
			_, err := k8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
			return err
		}, 30*time.Second, 1*time.Second).Should(BeNil())

		// Apply the necessary CRDs if we're running in k8s mode.
		testutils.ApplyCRDs(apiserver)
	})

	AfterEach(func() {
		controllerManager.Stop()
		kubectrl.Stop()
		apiserver.Stop()
		etcd.Stop()
	})

	It("should update NetworkPolicy names correctly", func() {
		// Create a CRD NetworkPolicy that was created without a tier prefix in the v3 API, but
		// whose backend representation includes the tier prefix.
		mismatchedNames := &v3.NetworkPolicy{}
		mismatchedNames.Name = "default.mismatched"
		mismatchedNames.Namespace = "default"
		mismatchedNames.Spec = v3.NetworkPolicySpec{
			Tier:     "default",
			Selector: "all()",
		}

		// Set the annotation to indicate the v3 API name.
		v3meta := &metav1.ObjectMeta{}
		v3meta.Name = "mismatched" // Name was created without tier.
		v3metaBytes, err := json.Marshal(v3meta)
		Expect(err).NotTo(HaveOccurred())
		mismatchedNames.Annotations = map[string]string{"projectcalico.org/metadata": string(v3metaBytes)}

		err = crdClient.Create(context.Background(), mismatchedNames)
		Expect(err).NotTo(HaveOccurred())

		// We should see the CRD re-written with the correct name.
		Eventually(func() error {
			np := &v3.NetworkPolicy{}
			err := crdClient.Get(context.Background(), ctrlclient.ObjectKey{
				Namespace: "default",
				Name:      "mismatched",
			}, np)
			return err
		}, 5*time.Second, 1*time.Second).Should(BeNil(), "NetworkPolicy was not accessible via CRD API with correct name")

		// Check that the old mismatched key is no longer present in the backend.
		Eventually(func() error {
			np := &v3.NetworkPolicy{}
			err := crdClient.Get(context.Background(), ctrlclient.ObjectKey{
				Namespace: "default",
				Name:      "default.mismatched",
			}, np)
			if err != nil {
				if kerrors.IsNotFound(err) {
					return nil
				}
				return err
			}
			return fmt.Errorf("expected not to find old key for mismatched policy")
		}, 5*time.Second, 1*time.Second).Should(BeNil(), "expected not to find old key for mismatched policy")
	})

	It("should update a GlobalNetworkPolicy name correctly", func() {
		// Same test, but for GNP.
		mismatchedNames := &v3.GlobalNetworkPolicy{}
		mismatchedNames.Name = "default.mismatched"
		mismatchedNames.Spec = v3.GlobalNetworkPolicySpec{
			Tier:     "default",
			Selector: "all()",
		}

		// Set the annotation to indicate the v3 API name.
		v3meta := &metav1.ObjectMeta{}
		v3meta.Name = "mismatched" // Name was created without tier.
		v3metaBytes, err := json.Marshal(v3meta)
		Expect(err).NotTo(HaveOccurred())
		mismatchedNames.Annotations = map[string]string{"projectcalico.org/metadata": string(v3metaBytes)}

		err = crdClient.Create(context.Background(), mismatchedNames)
		Expect(err).NotTo(HaveOccurred())

		// We should see the CRD re-written with the correct name.
		Eventually(func() error {
			gnp := &v3.GlobalNetworkPolicy{}
			err := crdClient.Get(context.Background(), ctrlclient.ObjectKey{
				Name: "mismatched",
			}, gnp)
			return err
		}, 5*time.Second, 1*time.Second).Should(BeNil(), "GlobalNetworkPolicy was not accessible via CRD API with correct name")
	})

	It("should update a StagedNetworkPolicy name correctly", func() {
		// Same test, but for SNP.
		mismatchedNames := &v3.StagedNetworkPolicy{}
		mismatchedNames.Name = "default.mismatched"
		mismatchedNames.Namespace = "default"
		mismatchedNames.Spec = v3.StagedNetworkPolicySpec{
			Tier:     "default",
			Selector: "all()",
		}

		// Set the annotation to indicate the v3 API name.
		v3meta := &metav1.ObjectMeta{}
		v3meta.Name = "mismatched" // Name was created without tier.
		v3metaBytes, err := json.Marshal(v3meta)
		Expect(err).NotTo(HaveOccurred())
		mismatchedNames.Annotations = map[string]string{"projectcalico.org/metadata": string(v3metaBytes)}

		err = crdClient.Create(context.Background(), mismatchedNames)
		Expect(err).NotTo(HaveOccurred())

		// We should see the CRD re-written with the correct name.
		Eventually(func() error {
			snp := &v3.StagedNetworkPolicy{}
			err := crdClient.Get(context.Background(), ctrlclient.ObjectKey{
				Namespace: "default",
				Name:      "mismatched",
			}, snp)
			return err
		}, 5*time.Second, 1*time.Second).Should(BeNil(), "StagedNetworkPolicy was not accessible via CRD API with correct name")
	})

	It("should update a StagedGlobalNetworkPolicy name correctly", func() {
		// Same test, but for SGNP.
		mismatchedNames := &v3.StagedGlobalNetworkPolicy{}
		mismatchedNames.Name = "default.mismatched"
		mismatchedNames.Spec = v3.StagedGlobalNetworkPolicySpec{
			Tier:     "default",
			Selector: "all()",
		}

		// Set the annotation to indicate the v3 API name.
		v3meta := &metav1.ObjectMeta{}
		v3meta.Name = "mismatched" // Name was created without tier.
		v3metaBytes, err := json.Marshal(v3meta)
		Expect(err).NotTo(HaveOccurred())
		mismatchedNames.Annotations = map[string]string{"projectcalico.org/metadata": string(v3metaBytes)}

		err = crdClient.Create(context.Background(), mismatchedNames)
		Expect(err).NotTo(HaveOccurred())

		// We should see the CRD re-written with the correct name.
		Eventually(func() error {
			sgnp := &v3.StagedGlobalNetworkPolicy{}
			err := crdClient.Get(context.Background(), ctrlclient.ObjectKey{
				Name: "mismatched",
			}, sgnp)
			return err
		}, 5*time.Second, 1*time.Second).Should(BeNil(), "StagedGlobalNetworkPolicy was not accessible via CRD API with correct name")
	})

	It("should fix if both mismatched and correct keys exist", func() {
		// Create two CRDs - one with the correct name and one with the old mismatched name.
		matchingNames := &v3.NetworkPolicy{}
		matchingNames.Name = "policy-name" // Correct name, i.e., "already migrated".
		matchingNames.Namespace = "default"
		matchingNames.Spec = v3.NetworkPolicySpec{
			Tier:     "default",
			Selector: "all()",
		}
		v3meta := &metav1.ObjectMeta{}
		v3meta.Name = "policy-name" // Name matches underlying CRD.
		v3metaBytes, err := json.Marshal(v3meta)
		Expect(err).NotTo(HaveOccurred())
		matchingNames.Annotations = map[string]string{"projectcalico.org/metadata": string(v3metaBytes)}

		err = crdClient.Create(context.Background(), matchingNames)
		Expect(err).NotTo(HaveOccurred())

		// Create the same object, but this time with the old mismatched name in the CRD name.
		mismatchedNames := &v3.NetworkPolicy{}
		mismatchedNames.Name = "default.mismatched"
		mismatchedNames.Namespace = "default"
		mismatchedNames.Spec = matchingNames.Spec
		mismatchedNames.Annotations = matchingNames.Annotations

		err = crdClient.Create(context.Background(), mismatchedNames)
		Expect(err).NotTo(HaveOccurred())

		// We should see the incorrect CRD removed, leaving only the correctly named one.
		Eventually(func() error {
			np := &v3.NetworkPolicy{}
			err := crdClient.Get(context.Background(), ctrlclient.ObjectKey{
				Namespace: "default",
				Name:      "default.mismatched",
			}, np)
			if err != nil {
				if kerrors.IsNotFound(err) {
					return nil
				}
				return err
			}
			return fmt.Errorf("expected not to find old key for mismatched policy")
		}, 5*time.Second, 1*time.Second).Should(BeNil(), "expected not to find old key for mismatched policy")

		// Check that the correct key is still present.
		Eventually(func() error {
			np := &v3.NetworkPolicy{}
			err := crdClient.Get(context.Background(), ctrlclient.ObjectKey{
				Namespace: "default",
				Name:      "policy-name",
			}, np)
			return err
		}, 5*time.Second, 1*time.Second).Should(BeNil(), "NetworkPolicy was not accessible via CRD API with correct name")
	})
})
