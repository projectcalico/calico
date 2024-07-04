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
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/proto"
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

var _ = Describe("Endpoint Policy Status Reports [file-reporting]", func() {
	logrus.SetLevel(logrus.DebugLevel)
	var endpointUpdatesC chan interface{}
	var ctx context.Context
	var cancel context.CancelFunc
	var doneC chan struct{}
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
		fileCreatedC := make(chan string, 100)
		mockfs := mockFilesys{
			createCB: func(name string) {
				fileCreatedC <- name
			},
		}
		reporter := NewEndpointStatusFileReporter(endpointUpdatesC, "/tmp", WithHostname("host"), WithFilesys(&mockfs))

		go func() {
			defer close(doneC)
			reporter.SyncForever(ctx)
		}()

		By("Sending a status-down update to the reporter")

		wepID := &proto.WorkloadEndpointID{
			OrchestratorId: "abc",
			WorkloadId:     "default/pod1",
			EndpointId:     "eth0",
		}
		key := names.WorkloadEndpointIDToWorkloadEndpointKey(wepID, "host")
		mapKey := names.WorkloadEndpointKeyToStatusFilename(key)
		filename := filepath.Join("/tmp/endpoint-status", mapKey)

		Eventually(endpointUpdatesC, "10s").Should(BeSent(&proto.WorkloadEndpointStatusUpdate{
			Id: wepID,
			Status: &proto.EndpointStatus{
				Status: "down",
			},
		}))
		Eventually(endpointUpdatesC, "10s").Should(BeSent(&proto.DataplaneInSync{}))

		Consistently(fileCreatedC, "3s").ShouldNot(Receive(), "Tracker wrote a file for an endpoint before status was up")

		By("Sending a status-up update to the reporter")
		Eventually(endpointUpdatesC, "10s").Should(BeSent(&proto.WorkloadEndpointStatusUpdate{
			Id: wepID,
			Status: &proto.EndpointStatus{
				Status: "up",
			},
		}))

		Eventually(fileCreatedC, "10s").Should(Receive(Equal(filename)), "Tracker did not add desired file for endpoint with status up")
	})
})
