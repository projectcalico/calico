// Copyright (c) 2017-2024 Tigera, Inc. All rights reserved.

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
package testutils

import (
	"fmt"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
)

type DatastoreType int

const (
	DatastoreEtcdV3 DatastoreType = 1 << iota
	DatastoreK8s

	DatastoreAll = DatastoreEtcdV3 | DatastoreK8s

	// Mounted into the test container during test-setup.
	kubeconfig = "/kubeconfig.yaml"
)

// E2eDatastoreDescribe is a replacement for ginkgo.Describe which invokes Describe
// multiple times for one or more different datastore drivers - passing in the
// Calico API configuration as a parameter to the test function.  This allows
// easy construction of end-to-end tests covering multiple different datastore
// drivers.
//
// The *datastores* parameter is a bit-wise OR of the required datastore drivers
// that will be tested.
func E2eDatastoreDescribe(description string, datastores DatastoreType, body func(config apiconfig.CalicoAPIConfig)) bool {
	if datastores&DatastoreEtcdV3 != 0 {
		Describe(fmt.Sprintf("%s [Datastore] (etcdv3 backend)", description),
			func() {
				body(apiconfig.CalicoAPIConfig{
					Spec: apiconfig.CalicoAPIConfigSpec{
						DatastoreType: apiconfig.EtcdV3,
						EtcdConfig: apiconfig.EtcdConfig{
							EtcdEndpoints: "http://127.0.0.1:2379",
						},
					},
				})
			})
	}

	if datastores&DatastoreK8s != 0 {
		Describe(fmt.Sprintf("%s [Datastore] (kubernetes backend)", description),
			func() {
				body(apiconfig.CalicoAPIConfig{
					Spec: apiconfig.CalicoAPIConfigSpec{
						DatastoreType: apiconfig.Kubernetes,
						KubeConfig: apiconfig.KubeConfig{
							Kubeconfig:     kubeconfig,
							CalicoAPIGroup: os.Getenv("CALICO_API_GROUP"),
						},
					},
				})
			})
	}

	return true
}

// GetK8sInlineConfig returns a CalicoAPIConfig with the kubeconfig inline.
func GetK8sInlineConfig() apiconfig.CalicoAPIConfig {
	kc, err := os.ReadFile(kubeconfig)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return apiconfig.CalicoAPIConfig{
		Spec: apiconfig.CalicoAPIConfigSpec{
			DatastoreType: apiconfig.Kubernetes,
			KubeConfig: apiconfig.KubeConfig{
				KubeconfigInline: string(kc),
			},
		},
	}
}
