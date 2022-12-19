// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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

package utils

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

func RunDatastoreTest(t *testing.T, testFn func(t *testing.T, kdd bool, client clientv3.Interface)) {
	t.Run("etcd", func(t *testing.T) {
		RegisterTestingT(t)
		config := apiconfig.NewCalicoAPIConfig()
		config.Spec.DatastoreType = apiconfig.EtcdV3
		config.Spec.EtcdEndpoints = "http://127.0.0.1:2379"
		client, err := clientv3.New(*config)
		Expect(err).NotTo(HaveOccurred())
		defer func() {
			err := client.(interface {
				Backend() bapi.Client
			}).Backend().Clean()
			Expect(err).NotTo(HaveOccurred())
		}()
		testFn(t, false, client)
	})
	t.Run("kubernetes", func(t *testing.T) {
		RegisterTestingT(t)

		// When we run Calicoctl, it picks up our environment.
		unpatchEnv, err := PatchEnv("KUBECONFIG", "/go/src/github.com/projectcalico/calico/calicoctl/test-data/kubeconfig.yaml")
		Expect(err).NotTo(HaveOccurred())
		defer unpatchEnv()

		// Inline configuration for a local calico client.
		config := apiconfig.NewCalicoAPIConfig()
		config.Spec.DatastoreType = apiconfig.Kubernetes
		config.Spec.Kubeconfig = "/go/src/github.com/projectcalico/calico/calicoctl/test-data/kubeconfig.yaml"
		config.Spec.K8sInsecureSkipTLSVerify = true
		client, err := clientv3.New(*config)
		Expect(err).NotTo(HaveOccurred())
		defer func() {
			err := client.(interface {
				Backend() bapi.Client
			}).Backend().Clean()
			Expect(err).NotTo(HaveOccurred())
		}()
		testFn(t, true, client)
	})
}
