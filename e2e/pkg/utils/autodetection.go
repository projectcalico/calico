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

	"github.com/onsi/gomega"
	v1 "github.com/tigera/operator/api/v1"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/kubernetes/test/e2e/framework"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/utils/client"
)

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
