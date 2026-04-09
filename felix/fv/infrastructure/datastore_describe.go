// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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
package infrastructure

import (
	"fmt"
	"os"
	"strings"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type InfraFactory func(...CreateOption) DatastoreInfra

// DatastoreDescribe is a replacement for ginkgo.Describe which invokes Describe
// multiple times for one or more different datastore drivers - passing in the
// function to retrieve the appropriate datastore infrastructure.  This allows
// easy construction of end-to-end tests covering multiple different datastore
// drivers.
//
// The *datastores* parameter is a slice of the DatastoreTypes to test.
func DatastoreDescribe(description string, datastores []apiconfig.DatastoreType, body func(InfraFactory)) bool {
	for _, ds := range datastores {

		ginkgo.Describe(fmt.Sprintf("%s (%s backend)", description, ds), func() {
			var coreFilesAtStart set.Set[string]
			ginkgo.BeforeEach(func() {
				coreFilesAtStart = readCoreFiles()
			})

			switch ds {
			case apiconfig.EtcdV3:
				body(createEtcdDatastoreInfra)
			case apiconfig.Kubernetes:
				body(createK8sDatastoreInfra)
			default:
				panic(fmt.Errorf("unknown DatastoreType, %s", ds))
			}

			ginkgo.AfterEach(func() {
				afterCoreFiles := readCoreFiles()
				coreFilesAtStart.Iter(func(item string) error {
					afterCoreFiles.Discard(item)
					return nil
				})
				if afterCoreFiles.Len() != 0 {
					if ginkgo.CurrentGinkgoTestDescription().Failed {
						ginkgo.Fail(fmt.Sprintf("Test FAILED and new core files were detected during tear-down: %v.  "+
							"Felix must have panicked during the test.", afterCoreFiles.Slice()))
						return
					}
					ginkgo.Fail(fmt.Sprintf("Test PASSED but new core files were detected during tear-down: %v.  "+
						"Felix must have panicked during the test.", afterCoreFiles.Slice()))
				}
			})
		})
	}

	return true
}

func readCoreFiles() set.Set[string] {
	tmpFiles, err := os.ReadDir("/tmp")
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	var coreFiles []string
	for _, f := range tmpFiles {
		if strings.HasPrefix(f.Name(), "core_felix-") {
			coreFiles = append(coreFiles, f.Name())
		}
	}
	return set.From(coreFiles...)
}
