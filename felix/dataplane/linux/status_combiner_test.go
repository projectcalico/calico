// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package intdataplane

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

var (
	epID = proto.WorkloadEndpointID{OrchestratorId: "orch", WorkloadId: "wl", EndpointId: "ep"}
)

var _ = Describe("StatusCombiner", func() {
	var (
		fromDataplane  chan interface{}
		statusCombiner *endpointStatusCombiner
	)

	endpoint := &proto.WorkloadEndpoint{
		State:      "active",
		Mac:        "01:02:03:04:05:06",
		Name:       "cali12345-ab",
		ProfileIds: []string{},
		Ipv4Nets:   []string{"10.0.240.2/24"},
		Ipv6Nets:   []string{"2001:db8:2::2/128"},
	}

	BeforeEach(func() {
		fromDataplane = make(chan interface{})
	})

	Describe("with IPv6 enabled", func() {
		BeforeEach(func() {
			statusCombiner = newEndpointStatusCombiner(fromDataplane, true)
		})

		DescribeTable("it should calculate correct status",
			func(v4Status, v6Status, expected string) {
				// Fire in the inputs from a background thread so we can use
				// Eventually to block on the channel.
				done := make(chan bool)
				go func() {
					statusCombiner.OnEndpointStatusUpdate(
						4, types.ProtoToWorkloadEndpointID(&epID), v4Status, endpoint,
					)
					statusCombiner.OnEndpointStatusUpdate(
						6, types.ProtoToWorkloadEndpointID(&epID), v6Status, endpoint,
					)
					statusCombiner.Apply()
					done <- true
				}()
				Eventually(fromDataplane).Should(Receive(Equal(
					&proto.WorkloadEndpointStatusUpdate{
						Id: &epID,
						Status: &proto.EndpointStatus{
							Status: expected,
						},
						Endpoint: endpoint,
					},
				)))
				// Need to wait for the first goroutine to finish because
				// statusCombiner could still be doing its post-send cleanup.
				Eventually(done).Should(Receive())

				// Then remove the status, should get cleaned up.
				go func() {
					statusCombiner.OnEndpointStatusUpdate(
						4, types.ProtoToWorkloadEndpointID(&epID), "", nil,
					)
					statusCombiner.OnEndpointStatusUpdate(
						6, types.ProtoToWorkloadEndpointID(&epID), "", nil,
					)
					statusCombiner.Apply()
				}()
				Eventually(fromDataplane).Should(Receive(Equal(
					&proto.WorkloadEndpointStatusRemove{
						Id: &epID,
					},
				)))
			},

			Entry("up, up == up", "up", "up", "up"),
			Entry("up, down == down", "up", "down", "down"),
			Entry("up, error == error", "up", "error", "error"),

			Entry("down, down == down", "down", "down", "down"),
			Entry("down, up == down", "down", "up", "down"),
			Entry("down, error == error", "down", "error", "error"),

			Entry("error, error == error", "error", "error", "error"),
			Entry("error, up == error", "error", "up", "error"),
			Entry("error, down == error", "error", "down", "error"),
		)
	})

	Describe("with IPv6 disabled", func() {
		BeforeEach(func() {
			statusCombiner = newEndpointStatusCombiner(fromDataplane, false)
		})

		DescribeTable("it should calculate correct status",
			func(v4Status string) {
				// Fire in the inputs from a background thread so we can use
				// Eventually to block on the channel.
				done := make(chan bool)
				go func() {
					statusCombiner.OnEndpointStatusUpdate(
						4, types.ProtoToWorkloadEndpointID(&epID), v4Status, endpoint,
					)
					statusCombiner.Apply()
					done <- true
				}()
				Eventually(fromDataplane).Should(Receive(Equal(
					&proto.WorkloadEndpointStatusUpdate{
						Id: &epID,
						Status: &proto.EndpointStatus{
							Status: v4Status,
						},
						Endpoint: endpoint,
					},
				)))
				// Need to wait for the first goroutine to finish because
				// statusCombiner could still be doing its post-send cleanup.
				Eventually(done).Should(Receive())

				// Then remove the status, should get cleaned up.
				go func() {
					statusCombiner.OnEndpointStatusUpdate(
						4, types.ProtoToWorkloadEndpointID(&epID), "", nil,
					)
					statusCombiner.Apply()
				}()
				Eventually(fromDataplane).Should(Receive(Equal(
					&proto.WorkloadEndpointStatusRemove{
						Id: &epID,
					},
				)))
			},

			Entry("up == up", "up"),
			Entry("down == down", "down"),
			Entry("error == error", "error"),
		)
	})
})
