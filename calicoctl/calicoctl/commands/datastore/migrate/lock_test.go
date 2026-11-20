// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package migrate

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	v1scheme "github.com/projectcalico/calico/libcalico-go/lib/apis/crd.projectcalico.org/v1/scheme"
)

// clientConfigFor returns a calicoctl client config for the given datastore type
// and explicit Calico API group. Setting the API group stops UsingV3CRDs from
// trying to reach an API server.
func clientConfigFor(datastore apiconfig.DatastoreType, apiGroup string) *apiconfig.CalicoAPIConfig {
	cfg := apiconfig.NewCalicoAPIConfig()
	cfg.Spec.DatastoreType = datastore
	cfg.Spec.CalicoAPIGroup = apiGroup
	return cfg
}

var _ = Describe("checkLockSupported", func() {
	It("rejects lock and unlock with native v3 CRDs", func() {
		cfg := clientConfigFor(apiconfig.Kubernetes, apiv3.GroupVersionCurrent)

		err := checkLockSupported(cfg, "unlock")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("cannot unlock the datastore"))
		Expect(err.Error()).To(ContainSubstring("native projectcalico.org/v3 CRDs"))
	})

	It("allows lock and unlock in API server mode", func() {
		cfg := clientConfigFor(apiconfig.Kubernetes, v1scheme.GroupVersion)
		Expect(checkLockSupported(cfg, "lock")).To(Succeed())
	})

	It("allows lock and unlock on an etcd datastore", func() {
		// The API group only means something for the Kubernetes datastore.
		cfg := clientConfigFor(apiconfig.EtcdV3, apiv3.GroupVersionCurrent)
		Expect(checkLockSupported(cfg, "lock")).To(Succeed())
	})
})
