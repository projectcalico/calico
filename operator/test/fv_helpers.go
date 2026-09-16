// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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

package test

import (
	"context"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	kerror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	operator "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/crds"
)

func VerifyCRDsExist(c client.Client, variant operator.ProductVariant) {
	crdNames := []string{}
	for _, x := range crds.GetCRDs(variant, false) {
		crdNames = append(crdNames, fmt.Sprintf("%s.%s", x.Spec.Names.Plural, x.Spec.Group))
	}

	// Eventually all the CRDs should be available
	EventuallyWithOffset(1, func() error {
		for _, n := range crdNames {
			crd := &apiextensionsv1.CustomResourceDefinition{
				TypeMeta:   metav1.TypeMeta{Kind: "CustomResourceDefinition", APIVersion: "apiextensions.k8s.io/v1"},
				ObjectMeta: metav1.ObjectMeta{Name: n},
			}
			if err := GetResource(c, crd); err != nil {
				// If getting any of the CRDs is an error then the CRDs do not exist
				return err
			}
		}
		return nil
	}, 10*time.Second).Should(BeNil())
}

func CleanupResources(c client.Client) {
	removeAPIServer(context.Background(), c)
	removeInstallation(context.Background(), c, "default")
	cleanupIPPools(c)
	waitForProductTeardown(c)
}

func CreateInstallation(c client.Client, mgr manager.Manager, ctx context.Context, spec *operator.InstallationSpec) (doneChan chan struct{}) {
	s := operator.InstallationSpec{}
	if spec != nil {
		s = *spec
	}
	By("Creating an Installation CRD")
	instance := &operator.Installation{
		TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       s,
	}
	err := c.Create(context.Background(), instance)
	Expect(err).NotTo(HaveOccurred())

	By("Running the operator")
	return RunOperator(mgr, ctx)
}

func removeAPIServer(ctx context.Context, c client.Client) {
	instance := &operator.APIServer{
		TypeMeta:   metav1.TypeMeta{Kind: "APIServer", APIVersion: "operator.tigera.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}

	// Use Eventually to handle transient errors.
	exists := true
	Eventually(func() error {
		err := c.Get(ctx, client.ObjectKey{Name: "default"}, instance)
		if err != nil && kerror.IsNotFound(err) {
			exists = false
			return nil
		}
		return err
	}, 1*time.Second, 100*time.Millisecond).ShouldNot(HaveOccurred(), "Failed to get APIServer CR")

	if exists {
		By("Deleting the default APIServer CR")
		Eventually(func() error {
			return c.Delete(ctx, instance)
		}, 1*time.Second, 100*time.Millisecond).ShouldNot(HaveOccurred(), "Failed to delete APIServer CR")
	}
}

func removeInstallation(ctx context.Context, c client.Client, name string) {
	// Delete any CRD that might have been created by the test.
	instance := &operator.Installation{
		TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}

	// Use Eventually to handle transient errors.
	exists := true
	EventuallyWithOffset(1, func() error {
		err := c.Get(ctx, client.ObjectKey{Name: name}, instance)
		if err != nil && kerror.IsNotFound(err) {
			exists = false
			return nil
		}
		return err
	}, 1*time.Second, 100*time.Millisecond).ShouldNot(HaveOccurred(), "Failed to get Installation CR")

	if exists {
		By("Deleting the Installation CRD")
		EventuallyWithOffset(1, func() error {
			return c.Delete(ctx, instance)
		}, 1*time.Second, 100*time.Millisecond).ShouldNot(HaveOccurred(), "Failed to delete Installation CR")
	}

	// Need to wait here for Installation resource to be fully deleted prior to cancelling the context
	// which will in turn terminate the operator. Race conditions can occur otherwise that will leave the
	// Installation resource intact while the operator is no longer running which will result in test failures
	// that try to create an Installation resource of their own
	By("Waiting for the Installation CR to be removed")
	EventuallyWithOffset(1, func() error {
		err := c.Get(ctx, client.ObjectKey{Name: name}, instance)
		if kerror.IsNotFound(err) {
			return nil
		} else if err != nil {
			return err
		}
		return fmt.Errorf("Installation still exists")
	}, 120*time.Second).ShouldNot(HaveOccurred(), func() string {
		// Collect debugging information for failure message
		var debugInfo strings.Builder
		debugInfo.WriteString("Installation instance still exists:\n")
		fmt.Fprintf(&debugInfo, "Instance: %+v\n", instance)

		// Get calico-system namespace
		ns := &corev1.Namespace{}
		if err := c.Get(ctx, client.ObjectKey{Name: "calico-system"}, ns); err != nil {
			fmt.Fprintf(&debugInfo, "Failed to get calico-system namespace: %v\n", err)
		} else {
			fmt.Fprintf(&debugInfo, "calico-system namespace: %+v\n", ns)
		}

		// Get all pods in calico-system namespace
		pods := &corev1.PodList{}
		if err := c.List(ctx, pods, client.InNamespace("calico-system")); err != nil {
			fmt.Fprintf(&debugInfo, "Failed to list pods in calico-system namespace: %v\n", err)
		} else {
			fmt.Fprintf(&debugInfo, "Pods in calico-system namespace (%d pods):\n", len(pods.Items))
			for i, pod := range pods.Items {
				fmt.Fprintf(&debugInfo, "  Pod %d: Name=%s, Phase=%s, Ready=%v\n", i+1, pod.Name, pod.Status.Phase, pod.Status.ContainerStatuses)
			}
		}

		return debugInfo.String()
	})
}

func cleanupIPPools(c client.Client) {
	By("Cleaning up IP pools")
	Eventually(func() error {
		ipPools := &v3.IPPoolList{}
		err := c.List(context.Background(), ipPools)
		if err != nil {
			return err
		}

		for _, p := range ipPools.Items {
			By(fmt.Sprintf("Deleting IP pool %s with CIDR %s (%s)", p.Name, p.Spec.CIDR, p.UID))
			err = c.Delete(context.Background(), &p)
			if err != nil {
				return err
			}
		}
		return nil
	}, 10*time.Second, 1*time.Second).ShouldNot(HaveOccurred())
}

func waitForProductTeardown(c client.Client) {
	By("Waiting for Calico resources to be torn down")
	Eventually(func() error {
		ns := &corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "calico-system"},
		}
		err := GetResource(c, ns)
		if err == nil {
			return fmt.Errorf("Calico namespace still exists")
		}
		if !kerror.IsNotFound(err) {
			return err
		}
		crb := &rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "calico-node"},
		}
		err = GetResource(c, crb)
		if err == nil {
			return fmt.Errorf("Node CRB still exists")
		}
		if !kerror.IsNotFound(err) {
			return err
		}
		defaultInstallation := &operator.Installation{
			TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		}
		err = GetResource(c, defaultInstallation)
		if err == nil {
			return fmt.Errorf("default Installation still exists")
		}
		if !kerror.IsNotFound(err) {
			return err
		}
		return nil
	}, 240*time.Second).ShouldNot(HaveOccurred(), "Calico resources were not torn down in time")
}

func NewNonCachingClient(config *rest.Config, options client.Options) (client.Client, error) {
	options.Cache = nil
	return client.New(config, options)
}
