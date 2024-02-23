// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

package wait

import (
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

var _ = Describe("k8s-wait", func() {

	Context("WaitForEndpointReady", func() {
		BeforeEach(func() {})
		AfterEach(func() {})

		It("should wait for the given timeout before returning if no file is found", func() {
			dummyEndpoint := &v3.WorkloadEndpoint{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "name-space",
				},
				Spec: v3.WorkloadEndpointSpec{
					Pod:          "podname",
					Orchestrator: "k8s",
					Node:         "node-1",
					Endpoint:     "eth0",
				},
			}

			exit := make(chan error)
			go func() {
				defer close(exit)
				err := ForEndpointReadyWithTimeout("/tmp", dummyEndpoint, 3*time.Second)
				if err != nil {
					exit <- err
				}
			}()

			Eventually(exit, "6s").Should(Receive(), "Expected an error to be returned after timeout elapsed.")
		})

		It("should return immediately after the right file is created", func() {
			dummyEndpoint := &v3.WorkloadEndpoint{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "name-space",
				},
				Spec: v3.WorkloadEndpointSpec{
					Pod:          "podname",
					Orchestrator: "k8s",
					Node:         "node-1",
					Endpoint:     "eth0",
				},
			}

			exit := make(chan error)
			go func() {
				defer close(exit)
				err := ForEndpointReadyWithTimeout("/tmp", dummyEndpoint, 10*time.Second)
				if err != nil {
					exit <- err
				}
			}()

			epKey := names.APIWorkloadEndpointToWorkloadEndpointKey(dummyEndpoint)
			Expect(epKey).NotTo(BeNil(), "Couldn't convert dummy endpoint to workload endpoint key.")

			epFilename := names.WorkloadEndpointKeyToStatusFilename(epKey)
			Expect(epFilename).NotTo(HaveLen(0), "Couldn't generate endpoint status filename from endpoint key.")

			fullFilePath := filepath.Join("/tmp", epFilename)
			_, err := os.Create(fullFilePath)
			defer func() {
				_ = os.Remove(fullFilePath)
			}()
			Expect(err).NotTo(HaveOccurred(), "Test failed to create a file in /tmp")

			Eventually(exit, "15s").Should(BeClosed(), "Expected return with no error when file created.")
		})
	})
})
