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

	. "github.com/onsi/gomega"
	v1 "github.com/tigera/operator/api/v1"
	"k8s.io/kubernetes/test/e2e/framework"

	"github.com/projectcalico/calico/e2e/pkg/utils/client"
)

func IsOpenShift(f *framework.Framework) bool {
	// Create a client to the API server.
	cli, err := client.New(f.ClientConfig())
	Expect(err).NotTo(HaveOccurred())

	// Query Installation object to check if we are running on OpenShift.
	installs := &v1.InstallationList{}
	err = cli.List(context.TODO(), installs)
	Expect(err).NotTo(HaveOccurred())

	for _, inst := range installs.Items {
		if inst.Spec.KubernetesProvider == v1.ProviderOpenShift {
			return true
		}
	}
	return false
}
