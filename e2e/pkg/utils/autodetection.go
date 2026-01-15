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

package utils

import (
	"context"
	"time"

	"github.com/onsi/gomega"
	v1 "github.com/tigera/operator/api/v1"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/kubernetes/test/e2e/framework"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/utils/client"
)

func CalicoNamespace(f *framework.Framework) string {
	// Get calico-node pods.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	podList, err := f.ClientSet.CoreV1().Pods(metav1.NamespaceAll).List(
		ctx,
		metav1.ListOptions{
			LabelSelector: labels.SelectorFromSet(map[string]string{"k8s-app": "calico-node"}).String(),
		},
	)
	gomega.ExpectWithOffset(1, err).NotTo(gomega.HaveOccurred())
	gomega.ExpectWithOffset(1, len(podList.Items)).To(gomega.BeNumerically(">", 0))

	pod := podList.Items[0]
	return pod.Namespace
}

// ExpectedPodMTU returns the MTU that should be configured on pods, based on the Installation
// resource. If no MTU is configured, returns nil.
func ExpectedPodMTU(f *framework.Framework) *int32 {
	// Create a client to the API server.
	cli, err := client.New(f.ClientConfig())
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	installs := &v1.InstallationList{}
	err = cli.List(context.TODO(), installs)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	for _, inst := range installs.Items {
		if inst.Status.MTU > 0 {
			return &inst.Status.MTU
		}
	}
	return nil
}

func WhiskerInstalled(cli ctrlclient.Client) (bool, error) {
	k := ctrlclient.ObjectKey{Name: "whisker", Namespace: "calico-system"}
	err := cli.Get(context.TODO(), k, &appsv1.Deployment{})
	if errors.IsNotFound(err) {
		return false, nil
	}
	return true, err
}
