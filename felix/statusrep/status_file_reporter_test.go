// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package statusrep

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/proto"
	epstatus "github.com/projectcalico/calico/libcalico-go/lib/epstatusfile"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

type mockBackoff struct {
	C            chan struct{}
	Closed       bool
	StepDuration time.Duration
}

func (b *mockBackoff) Step() time.Duration {
	if !b.Closed {
		close(b.C)
	}
	b.Closed = true
	return b.StepDuration
}

type mockFilesys struct {
	createCB  func(string)
	removeCB  func(string)
	mkdirCB   func(name string)
	readdirCB func(name string)
	writeCB   func(name string, data []byte, perm os.FileMode)
}

func (f *mockFilesys) Create(name string) (*os.File, error) {
	if f.createCB != nil {
		f.createCB(name)
	}
	return os.Create(name)
}

func (f *mockFilesys) Remove(name string) error {
	if f.removeCB != nil {
		f.removeCB(name)
	}
	return os.Remove(name)
}

func (f *mockFilesys) Mkdir(name string, perm os.FileMode) error {
	if f.mkdirCB != nil {
		f.mkdirCB(name)
	}
	return os.Mkdir(name, perm)
}

func (f *mockFilesys) ReadDir(name string) ([]os.DirEntry, error) {
	if f.readdirCB != nil {
		f.readdirCB(name)
	}
	return os.ReadDir(name)
}

func (f *mockFilesys) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func (f *mockFilesys) WriteFile(name string, data []byte, perm os.FileMode) error {
	if f.writeCB != nil {
		f.writeCB(name, data, perm)
	}
	return os.WriteFile(name, data, perm)
}

func clearDir(dirPath string) {
	entries, err := os.ReadDir(dirPath)
	Expect(err).ShouldNot(HaveOccurred())

	for _, entry := range entries {
		err := os.Remove(dirPath + "/" + entry.Name()) // Remove each file
		Expect(err).ShouldNot(HaveOccurred())
	}

	log.Infof("Directory %s cleared successfully!", dirPath)
}

var _ = Describe("Endpoint Policy Status Reports [file-reporting]", func() {
	logrus.SetLevel(logrus.DebugLevel)
	var endpointUpdatesC chan interface{}
	var ctx context.Context
	var cancel context.CancelFunc
	var doneC chan struct{}

	tmpPath := "/go/src/github.com/projectcalico/calico/ut-tmp-dir"
	statusDir := tmpPath + "/endpoint-status"
	err := os.MkdirAll(statusDir, 0755)
	Expect(err).ShouldNot(HaveOccurred())

	endpoint := &proto.WorkloadEndpoint{
		State:        "active",
		Mac:          "01:02:03:04:05:06",
		Name:         "cali12345-ab",
		ProfileIds:   []string{},
		Ipv4Nets:     []string{"10.0.240.2/24"},
		Ipv6Nets:     []string{"2001:db8:2::2/128"},
		LocalBgpPeer: &proto.LocalBGPPeer{BgpPeerName: "global-peer"},
	}

	endpointStatus := epstatus.WorkloadEndpointToWorkloadEndpointStatus(endpoint)

	wepID := &proto.WorkloadEndpointID{
		OrchestratorId: "abc",
		WorkloadId:     "default/pod1",
		EndpointId:     "eth0",
	}
	key := names.WorkloadEndpointIDToWorkloadEndpointKey(wepID, "host")
	mapKey := names.WorkloadEndpointKeyToStatusFilename(key)
	filename := filepath.Join(statusDir, mapKey)
	log.Infof("get filename %s", filename)

	BeforeEach(func() {
		endpointUpdatesC = make(chan interface{})
		ctx, cancel = context.WithCancel(context.Background())
		doneC = make(chan struct{})
	})

	AfterEach(func() {
		cancel()
		Eventually(doneC).Should(BeClosed(), "Didn't receive signal indicating fileReporter exited")
	})

	It("should create a new directory and retry if it fails", func() {
		var fileReporter *EndpointStatusFileReporter

		backoffCalledC := make(chan struct{})
		newMockBackoff := func() Backoff {
			return &mockBackoff{
				C:            backoffCalledC,
				StepDuration: 1 * time.Second,
			}
		}
		readdirC := make(chan string, 100)
		mockfs := mockFilesys{
			readdirCB: func(name string) {
				readdirC <- name
			},
		}

		// Use a path we think the reporter cannot write to.
		fileReporter = NewEndpointStatusFileReporter(endpointUpdatesC, "/root/", WithNewBackoffFunc(newMockBackoff), WithFilesys(&mockfs))

		By("Starting a fileReporter which cannot create the necessary directory")

		go func() {
			defer func() {
				close(doneC)
			}()
			fileReporter.SyncForever(ctx)
		}()

		Eventually(endpointUpdatesC, "10s").Should(BeSent(&proto.DataplaneInSync{}))

		Eventually(readdirC, "10s").Should(Receive(Equal("/root/endpoint-status")), "Expected reporter to try reading a forbidden directory")
		Eventually(backoffCalledC, "10s").Should(BeClosed(), "Backoff wasn't called by the reporter (is the file-reporting unexpectedly succeeding?).")
	})

	It("should only add a desired file to the delta-tracker when update has status up", func() {
		fileWriteC := make(chan string, 100)
		mockfs := mockFilesys{
			writeCB: func(name string, data []byte, perm os.FileMode) {
				fileWriteC <- name
			},
		}
		reporter := NewEndpointStatusFileReporter(endpointUpdatesC, tmpPath, WithHostname("host"), WithFilesys(&mockfs))
		defer clearDir(statusDir)

		go func() {
			defer close(doneC)
			reporter.SyncForever(ctx)
		}()

		By("Sending a status-down update to the reporter")
		Eventually(endpointUpdatesC, "10s").Should(BeSent(&proto.WorkloadEndpointStatusUpdate{
			Id: wepID,
			Status: &proto.EndpointStatus{
				Status: "down",
			},
			Endpoint: endpoint,
		}))
		Eventually(endpointUpdatesC, "10s").Should(BeSent(&proto.DataplaneInSync{}))

		Consistently(fileWriteC, "3s").ShouldNot(Receive(), "Tracker wrote a file for an endpoint before status was up")

		By("Sending a status-up update to the reporter")
		Eventually(endpointUpdatesC, "10s").Should(BeSent(&proto.WorkloadEndpointStatusUpdate{
			Id: wepID,
			Status: &proto.EndpointStatus{
				Status: "up",
			},
			Endpoint: endpoint,
		}))

		Eventually(fileWriteC, "10s").Should(Receive(Equal(filename)), "Tracker did not add desired file for endpoint with status up")

		epStatus, err := epstatus.GetWorkloadEndpointStatusFromFile(filename)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(reflect.DeepEqual(*epStatus, *endpointStatus)).To(BeTrue())
	})

	It("should add a desired file and remove old file", func() {
		// Write a file which contains an old endpoint without BGP peer info.
		endpointOld := &proto.WorkloadEndpoint{
			State:      "active",
			Mac:        "01:02:03:04:05:06",
			Name:       "cali12345-ab",
			ProfileIds: []string{},
			Ipv4Nets:   []string{"10.0.240.2/24"},
			Ipv6Nets:   []string{"2001:db8:2::2/128"},
		}

		endpointStatusOld := epstatus.WorkloadEndpointToWorkloadEndpointStatus(endpointOld)
		itemJSON, err := json.Marshal(endpointStatusOld)
		Expect(err).ShouldNot(HaveOccurred())
		err = os.WriteFile(filename, []byte(itemJSON), 0644)
		Expect(err).ShouldNot(HaveOccurred())

		fileWriteC := make(chan string, 100)
		mockfs := mockFilesys{
			writeCB: func(name string, data []byte, perm os.FileMode) {
				fileWriteC <- name
			},
		}
		reporter := NewEndpointStatusFileReporter(endpointUpdatesC, tmpPath, WithHostname("host"), WithFilesys(&mockfs))
		defer clearDir(statusDir)

		go func() {
			defer close(doneC)
			reporter.SyncForever(ctx)
		}()

		By("Sending a status-up update to the reporter")
		Eventually(endpointUpdatesC, "10s").Should(BeSent(&proto.WorkloadEndpointStatusUpdate{
			Id: wepID,
			Status: &proto.EndpointStatus{
				Status: "up",
			},
			Endpoint: endpoint,
		}))
		Eventually(endpointUpdatesC, "10s").Should(BeSent(&proto.DataplaneInSync{}))

		Eventually(fileWriteC, "10s").Should(Receive(Equal(filename)), "Tracker did not add desired file for endpoint with status up")

		epStatus, err := epstatus.GetWorkloadEndpointStatusFromFile(filename)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(reflect.DeepEqual(*epStatus, *endpointStatus)).To(BeTrue())
	})
})
