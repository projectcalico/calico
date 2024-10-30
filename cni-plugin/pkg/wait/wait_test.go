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

		pollAndReturn := func(exit chan error, dummyEndpoint *v3.WorkloadEndpoint, timeout time.Duration) {
			defer close(exit)
			err := ForEndpointReadyWithTimeout("/tmp", dummyEndpoint, timeout)
			exit <- err
		}

		It("should wait for the given timeout and return error when no file is found", func() {
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

			pollTimeout := 3 * time.Second
			exit := make(chan error)
			go pollAndReturn(exit, dummyEndpoint, pollTimeout)
			Consistently(exit, "1s").ShouldNot(Receive(), "Polling thread returned too soon.")

			var err error
			Eventually(exit, "6s").Should(Receive(&err), "Expected a return value from polling thread.")
			Expect(err).To(HaveOccurred(), "Expected an error from polling thread.")
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

			pollTimeout := 3 * time.Second
			exit := make(chan error)
			go pollAndReturn(exit, dummyEndpoint, pollTimeout)
			Consistently(exit, "1s").ShouldNot(Receive(), "Polling thread returned too soon.")

			epKey, err := names.V3WorkloadEndpointToWorkloadEndpointKey(dummyEndpoint)
			Expect(err).NotTo(HaveOccurred(), "Couldn't convert dummy endpoint to workload endpoint key.")
			Expect(epKey).NotTo(BeNil(), "Couldn't convert dummy endpoint to workload endpoint key.")

			epFilename := names.WorkloadEndpointKeyToStatusFilename(epKey)
			Expect(epFilename).NotTo(HaveLen(0), "Couldn't generate endpoint status filename from endpoint key.")

			fullFilePath := filepath.Join("/tmp", epFilename)
			_, err = os.Create(fullFilePath)
			defer func() {
				_ = os.Remove(fullFilePath)
			}()
			Expect(err).NotTo(HaveOccurred(), "Test failed to create a file in /tmp")

			Eventually(exit, "3s").Should(Receive(&err), "Expected a return value to be passed from polling thread.")
			Expect(err).NotTo(HaveOccurred(), "Polling thread returned an error.")
		})
	})
})
