// Copyright (c) 2017,2020 Tigera, Inc. All rights reserved.

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
package testutils

import (
	"fmt"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"

	. "github.com/onsi/ginkgo"
)

type DatastoreType int

const (
	DatastoreEtcdV3 DatastoreType = 1 << iota
	DatastoreK8s
	DatastoreK8sInline

	DatastoreAll   = DatastoreEtcdV3 | DatastoreK8s
	k8sAPIEndpoint = "http://localhost:8080"
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
							K8sAPIEndpoint: k8sAPIEndpoint,
						},
					},
				})
			})
	}

	if datastores&DatastoreK8sInline != 0 {
		Describe(fmt.Sprintf("%s [Datastore] (kubernetes inline backend)", description),
			func() {
				body(apiconfig.CalicoAPIConfig{
					Spec: apiconfig.CalicoAPIConfigSpec{
						DatastoreType: apiconfig.Kubernetes,
						KubeConfig: apiconfig.KubeConfig{
							KubeconfigInline: fmt.Sprintf(`
apiVersion: v1
clusters:
- cluster:
    insecure-skip-tls-verify: true
    server: %s
  name: cluster-local
contexts:
- context:
    cluster: cluster-local
    user: ""
  name: cluster-local
current-context: cluster-local
kind: Config
preferences: {}
`,
								k8sAPIEndpoint,
							),
						},
					},
				})
			})
	}

	return true
}
