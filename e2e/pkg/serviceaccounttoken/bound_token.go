// Copyright (c) 2022 Tigera, Inc. All rights reserved.
//
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

package serviceaccounttoken

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// CalicoDescribe annotates the test with the [calico] label.
func CalicoDescribe(text string, body func()) bool {
	return Describe("[calico] "+text, body)
}

// CalicoNamespace returns the namespace on the cluster that Calico is running in.
// Calico can either be in the calico-system namespace, or kube-system for legacy manifest installs.
func CalicoNamespace(ctx context.Context, f *framework.Framework) (string, error) {
	out, err := f.ClientSet.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", err
	}
	for _, ns := range out.Items {
		if ns.GetName() == "calico-system" {
			return "calico-system", nil
		}
	}
	return "kube-system", nil
}

var _ = CalicoDescribe("ServiceAccount token rotation [Disruptive] [LinuxOnly]", func() {
	var f = framework.NewDefaultFramework("calico-policy")
	var calicoNamespace string
	var err error

	BeforeEach(func() {
		if calicoNamespace == "" {
			calicoNamespace, err = CalicoNamespace(context.TODO(), f)
			Expect(err).NotTo(HaveOccurred())
		}
	})

	// This test forces a token rotation of the calico/node serviceaccount and then asserts that
	// pods can still be launched on the cluster, verifying that Calico properly propagates token
	// rotations to the CNI plugin.
	//
	// NOTE: This test is potentially disruptive as it deletes credentials that are actively in-use
	// by calico/node on the cluster. It is recommended to not run this test on production clusters. If this test fails,
	// it may have a domino effect on subsequent tests and impact the ability of the cluster to launch new pods.
	It("should handle a serviceaccount token rotation", func() {
		ctx := context.TODO()

		// Delete the serviceaccount token used for Calico. We expect the controller manager will provision a new one,
		// and that when it does Calico will detect it and start to use the new credentials.
		out, err := f.ClientSet.CoreV1().ServiceAccounts(calicoNamespace).Get(ctx, "calico-node", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		secrets := []string{}
		for _, sa := range out.Items {
			if sa.GetName() == "calico-node" {
				secrets = sa.Secrets
				break
			}
		}
		Expect(len(secrets)).To(BeNumerically(">=", 1))

		// Delete the secrets referenced by the serviceaccount. This will invalidate the secret currently in-use by calico/node,
		// and will also trigger recreattion of a new token.
		for _, s := range secrets {
			_, err := f.ClientSet.CoreV1().Secrets(calicoNamespace).Delete(ctx, s, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		}

		// Verify that pods can still be launched in the cluster.
	})
})
