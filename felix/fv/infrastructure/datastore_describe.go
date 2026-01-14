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
	"github.com/sirupsen/logrus"

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
			var currentInfra []DatastoreInfra
			ginkgo.BeforeEach(func() {
				coreFilesAtStart = readCoreFiles()
				currentInfra = nil
			})

			// Pick the base factory for this datastore, then wrap it to record the created infra.
			var baseFactory InfraFactory
			switch ds {
			case apiconfig.EtcdV3:
				baseFactory = createEtcdDatastoreInfra
			case apiconfig.Kubernetes:
				baseFactory = createK8sDatastoreInfra
			default:
				panic(fmt.Errorf("unknown DatastoreType, %s", ds))
			}
			wrappedFactory := func(opts ...CreateOption) DatastoreInfra {
				inf := baseFactory(opts...)
				currentInfra = append(currentInfra, inf)
				return inf
			}
			body(wrappedFactory)

			ginkgo.AfterEach(func() {
				// Always stop the infra after each test (collects diags on failure and cleans up).
				logrus.WithField("test", ginkgo.CurrentGinkgoTestDescription().FullTestText).Info("DatastoreDescribe AfterEach: stopping infrastructure.")
				if len(currentInfra) > 0 {
					for i := len(currentInfra) - 1; i >= 0; i-- {
						if currentInfra[i] != nil {
							currentInfra[i].Stop()
						}
					}
					currentInfra = nil
				}
			})

			ginkgo.AfterEach(func() {
				// Then, perform the core file check.
				logrus.WithField("test", ginkgo.CurrentGinkgoTestDescription().FullTestText).Info("DatastoreDescribe AfterEach: checking for core files.")
				afterCoreFiles := readCoreFiles()
				for item := range coreFilesAtStart.All() {
					afterCoreFiles.Discard(item)
				}
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
