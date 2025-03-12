// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package epstatusfile

import (
	"encoding/json"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/proto"
)

var _ = Describe("Workload endpoint status file writer test", func() {
	var itemJSONPod1, itemJSONPod2 string
	tmpPath := "/go/src/github.com/projectcalico/calico/ut-tmp-dir"
	statusDir := tmpPath + "/endpoint-status"

	writer := NewEndpointStatusFileWriter(tmpPath)

	// Assert directory will be created.
	_, _, err := writer.EnsureStatusDir(tmpPath)
	Expect(err).ShouldNot(HaveOccurred())

	_, err = os.ReadDir(statusDir)
	Expect(err).ShouldNot(HaveOccurred())

	BeforeEach(func() {
		endpoint := &proto.WorkloadEndpoint{
			State:        "active",
			Mac:          "01:02:03:04:05:06",
			Name:         "cali12345-ab",
			ProfileIds:   []string{},
			Ipv4Nets:     []string{"10.0.240.2/24"},
			Ipv6Nets:     []string{"2001:db8:2::2/128"},
			LocalBgpPeer: &proto.LocalBGPPeer{BgpPeerName: "global-peer"},
		}

		endpointStatus := WorkloadEndpointToWorkloadEndpointStatus(endpoint)

		itemJSON, err := json.Marshal(endpointStatus)
		itemJSONPod1 = string(itemJSON)
		Expect(err).ShouldNot(HaveOccurred())
		err = writer.WriteStatusFile("pod1", itemJSONPod1)
		Expect(err).ShouldNot(HaveOccurred())

		endpoint = &proto.WorkloadEndpoint{
			State:        "active",
			Mac:          "01:02:03:04:05:06",
			Name:         "cali12345-cd",
			ProfileIds:   []string{},
			Ipv4Nets:     []string{"10.0.240.2/24"},
			Ipv6Nets:     []string{"2001:db8:2::2/128"},
			LocalBgpPeer: &proto.LocalBGPPeer{BgpPeerName: "global-peer"},
		}

		endpointStatus = WorkloadEndpointToWorkloadEndpointStatus(endpoint)

		itemJSON, err = json.Marshal(endpointStatus)
		itemJSONPod2 = string(itemJSON)
		Expect(err).ShouldNot(HaveOccurred())
		err = writer.WriteStatusFile("pod2", itemJSONPod2)
		Expect(err).ShouldNot(HaveOccurred())
	})

	It("should read directory", func() {
		// Prepare a file with random content.
		err := writer.WriteStatusFile("random", "invalid")
		Expect(err).ShouldNot(HaveOccurred())

		entries, epStatuses, err := writer.EnsureStatusDir(tmpPath)
		Expect(err).ShouldNot(HaveOccurred())

		Expect(len(entries)).To(Equal(3))
		Expect(len(epStatuses)).To(Equal(3))

		statuses := map[string]WorkloadEndpointStatus{}
		for i, entry := range entries {
			statuses[entry.Name()] = epStatuses[i]
		}
		Expect(statuses["pod1"].IfaceName).To(Equal("cali12345-ab"))
		Expect(statuses["pod2"].IfaceName).To(Equal("cali12345-cd"))
		Expect(statuses["random"].IfaceName).To(Equal(""))
	})

	It("should read file", func() {
		status, err := GetWorkloadEndpointStatusFromFile(statusDir + "/pod1")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(status.IfaceName).To(Equal("cali12345-ab"))
	})
})
