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

package policysync_test

import (
	"errors"
	"time"

	"github.com/projectcalico/calico/felix/policysync"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/pod2daemon/binder"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/net/context"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

var _ = Describe("Server", func() {
	var uut *policysync.Server
	var joins chan interface{}

	BeforeEach(func() {
		joins = make(chan interface{})
		uut = policysync.NewServer(joins, policysync.NewUIDAllocator().NextUID)
	})

	Describe("Sync tests", func() {

		Context("after calling Sync and joining", func() {
			var stream *testSyncStream
			var updates chan<- proto.ToDataplane
			var output chan *proto.ToDataplane
			syncDone := make(chan bool)

			BeforeEach(withTimeout("1s", func() {
				output = make(chan *proto.ToDataplane)
				stream = &testSyncStream{output: output}
				go func() {
					_ = uut.Sync(&proto.SyncRequest{}, stream)
					syncDone <- true
				}()
				j := <-joins
				jr := j.(policysync.JoinRequest)
				Expect(jr.EndpointID.GetWorkloadId()).To(Equal(WorkloadID))
				updates = jr.C
			}))

			It("should stream messages", withTimeout("1s", func() {
				msgs := []proto.ToDataplane{
					{Payload: &proto.ToDataplane_WorkloadEndpointUpdate{}},
					{Payload: &proto.ToDataplane_InSync{}},
				}
				for _, msg := range msgs {
					updates <- msg
					g := <-output
					Expect(g).To(Equal(&msg))
				}
			}))

			Context("with unstreamed updates", func() {
				BeforeEach(withTimeout("1s", func() {
					// Queue up 10 messages. This should not block because the updates channel should be buffered.
					for i := 0; i < 10; i++ {
						updates <- proto.ToDataplane{}
					}
				}))

				Context("after error on stream", func() {
					BeforeEach(withTimeout("1s", func() {
						stream.sendErr = true
						<-output
					}))

					It("should drain updates channel, send leave request and end Sync", withTimeout("1s", func() {
						for i := 0; i < 10; i++ {
							updates <- proto.ToDataplane{}
						}
						j := <-joins
						lr := j.(policysync.LeaveRequest)
						Expect(lr.EndpointID.GetWorkloadId()).To(Equal(WorkloadID))
						close(updates)
						<-syncDone
					}))

				})

				Context("after updates closed", func() {
					BeforeEach(func() {
						close(updates)
					})

					It("send pending updates, leave request and end Sync", withTimeout("1s", func() {
						for i := 0; i < 10; i++ {
							<-output
						}
						j := <-joins
						lr := j.(policysync.LeaveRequest)
						Expect(lr.EndpointID.GetWorkloadId()).To(Equal(WorkloadID))
						<-syncDone
					}))
				})
			})
		})
	})
})

type testSyncStream struct {
	output  chan<- *proto.ToDataplane
	sendErr bool
}

func (s *testSyncStream) Send(m *proto.ToDataplane) error {
	s.output <- m
	if s.sendErr {
		return errors.New("test error")
	}
	return nil
}

func (*testSyncStream) SetHeader(metadata.MD) error {
	panic("not implemented")
}

func (*testSyncStream) SendHeader(metadata.MD) error {
	panic("not implemented")
}

func (*testSyncStream) SetTrailer(metadata.MD) {
	panic("not implemented")
}

func (*testSyncStream) Context() context.Context {
	return &testContext{}
}

func (*testSyncStream) SendMsg(m interface{}) error {
	panic("not implemented")
}

func (*testSyncStream) RecvMsg(m interface{}) error {
	panic("not implemented")
}

type testContext struct{}

func (*testContext) Deadline() (deadline time.Time, ok bool) {
	panic("not implemented")
}

func (*testContext) Done() <-chan struct{} {
	panic("not implemented")
}

func (*testContext) Err() error {
	panic("not implemented")
}

const WorkloadName = "servertest"
const Namespace = "default"
const WorkloadID = "default/servertest"

func (*testContext) Value(key interface{}) interface{} {
	// Server accesses the peer value only.
	peer := &peer.Peer{AuthInfo: binder.Credentials{
		Uid:            "test",
		Workload:       WorkloadName,
		Namespace:      Namespace,
		ServiceAccount: "default",
	}}
	return peer
}
