// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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
package infrastructure

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
)

type InfraFactory func() DatastoreInfra

// DatastoreDescribe is a replacement for ginkgo.Describe which invokes Describe
// multiple times for one or more different datastore drivers - passing in the
// function to retrieve the appropriate datastore infrastructure.  This allows
// easy construction of end-to-end tests covering multiple different datastore
// drivers.
//
// The *datastores* parameter is a slice of the DatastoreTypes to test.
func DatastoreDescribe(description string, datastores []apiconfig.DatastoreType, body func(InfraFactory)) bool {
	for _, ds := range datastores {
		switch ds {
		case apiconfig.EtcdV3:
			Describe(fmt.Sprintf("%s (etcdv3 backend)", description),
				func() {
					body(createEtcdDatastoreInfra)
				})
		case apiconfig.Kubernetes:
			Describe(fmt.Sprintf("%s (kubernetes backend)", description),
				func() {
					body(createK8sDatastoreInfra)
				})
		default:
			panic(fmt.Errorf("Unknown DatastoreType, %s", ds))
		}
	}

	return true
}
