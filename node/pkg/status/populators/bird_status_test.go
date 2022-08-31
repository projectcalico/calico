// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package populator

import (
	"bytes"
	"net"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Test BIRD status Scanner", func() {

	It("should be able to scan a BIRD status output", func() {

		output := `0001 BIRD v0.3.3+birdv1.6.8 ready.
1000-BIRD v0.3.3+birdv1.6.8
1011-Router ID is 172.17.0.3
 Current server time is 2021-09-19 20:48:43
 Last reboot on 2021-09-19 20:10:56
 Last reconfiguration on 2021-09-19 20:10:56
013 Daemon is up and running
`

		expectedStatus := &birdStatus{
			ready:            true,
			version:          "v0.3.3+birdv1.6.8",
			routerID:         "172.17.0.3",
			serverTime:       "2021-09-19 20:48:43",
			lastBootTime:     "2021-09-19 20:10:56",
			lastReconfigTime: "2021-09-19 20:10:56",
		}

		status, err := readBIRDStatus(getMockBirdConn(IPFamilyV4, output))
		Expect(err).ToNot(HaveOccurred())
		Expect(status).To(Equal(expectedStatus))
		Expect(err).NotTo(HaveOccurred())

		// Check we can print status.
		printStatus(status, GinkgoWriter)
	})

	DescribeTable("Convert to v3 object",
		func(b *birdStatus, v3Status v3.BGPDaemonStatus) {
			apiStatus := b.toNodeStatusAPI()
			Expect(apiStatus).To(Equal(v3Status))
		},
		Entry(
			"status ready",
			&birdStatus{
				ready:            true,
				version:          "v0.3.3+birdv1.6.8",
				routerID:         "172.17.0.3",
				serverTime:       "2021-09-19 20:48:43",
				lastBootTime:     "2021-09-19 20:48:56",
				lastReconfigTime: "2021-09-19 20:48:56",
			},
			v3.BGPDaemonStatus{
				State:                   v3.BGPDaemonStateReady,
				Version:                 "v0.3.3+birdv1.6.8",
				RouterID:                "172.17.0.3",
				LastBootTime:            "2021-09-19 20:48:56",
				LastReconfigurationTime: "2021-09-19 20:48:56",
			},
		),
		Entry(
			"status not ready",
			&birdStatus{
				ready:            false,
				version:          "v0.3.3+birdv1.6.8",
				routerID:         "172.17.0.3",
				serverTime:       "2021-09-19 20:48:43",
				lastBootTime:     "2021-09-19 20:48:56",
				lastReconfigTime: "2021-09-19 20:48:56",
			},
			v3.BGPDaemonStatus{
				State:                   v3.BGPDaemonStateNotReady,
				Version:                 "v0.3.3+birdv1.6.8",
				RouterID:                "172.17.0.3",
				LastBootTime:            "2021-09-19 20:48:56",
				LastReconfigurationTime: "2021-09-19 20:48:56",
			},
		),
	)
})

func getMockBirdConn(ipv IPFamily, output string) *birdConn {
	return &birdConn{
		ipv:  ipv,
		conn: mockConn{bytes.NewBufferString(output)},
	}
}

// Implement a Mock net.Conn interface, used to emulate reading data from a
// socket.
type mockConn struct {
	*bytes.Buffer
}

func (c mockConn) Close() error {
	panic("Should not be called")
}
func (c mockConn) LocalAddr() net.Addr {
	panic("Should not be called")
}
func (c mockConn) RemoteAddr() net.Addr {
	panic("Should not be called")
}
func (c mockConn) SetDeadline(t time.Time) error {
	panic("Should not be called")
}
func (c mockConn) SetReadDeadline(t time.Time) error {
	return nil
}
func (c mockConn) SetWriteDeadline(t time.Time) error {
	panic("Should not be called")
}
