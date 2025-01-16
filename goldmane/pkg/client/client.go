// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package client

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

func NewFlowClient(server string) *FlowClient {
	cc, err := grpc.NewClient(server, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		logrus.WithError(err).Fatal("Failed to dial server")
	}

	// Create a cache to store flows that we've seen, and start the background task
	// to expire old flows.
	cache := newFlowTimedCache()
	go cache.gcRoutine()

	return &FlowClient{
		grpcClient: cc,
		inChan:     make(chan *proto.Flow, 5000),
		cache:      cache,
	}
}

// flowKey wraps the canonical FlowKey type with a start and end time, since this cache
// stores flows across multiple aggregation intervals.
type flowKey struct {
	StartTime int64
	EndTime   int64
	types.FlowKey
}

type flowEntry struct {
	Flow     *proto.Flow
	ExpireAt time.Time
}

type flowTimedCache struct {
	sync.Mutex
	flows map[flowKey]*flowEntry
}

func newFlowTimedCache() *flowTimedCache {
	return &flowTimedCache{
		flows: make(map[flowKey]*flowEntry),
	}
}

func (c *flowTimedCache) Add(f *proto.Flow) {
	key := flowKey{
		StartTime: f.StartTime,
		EndTime:   f.EndTime,
		FlowKey:   *types.ProtoToFlowKey(f.Key),
	}
	c.Lock()
	defer c.Unlock()
	c.flows[key] = &flowEntry{
		Flow:     f,
		ExpireAt: time.Now().Add(5 * time.Minute),
	}
}

func (c *flowTimedCache) Iter(f func(f *proto.Flow) error) {
	c.Lock()
	defer c.Unlock()
	for _, v := range c.flows {
		if err := f(v.Flow); err != nil {
			return
		}
	}
}

func (c *flowTimedCache) gcRoutine() {
	for {
		<-time.After(15 * time.Second)
		c.DeleteExpired()
	}
}

func (c *flowTimedCache) DeleteExpired() {
	c.Lock()
	defer c.Unlock()

	now := time.Now()
	for k, v := range c.flows {
		if v.ExpireAt.Before(now) {
			delete(c.flows, k)
		}
	}
}

// FlowClient pushes flow updates to the flow server.
type FlowClient struct {
	grpcClient *grpc.ClientConn
	inChan     chan *proto.Flow
	cache      *flowTimedCache
}

func (c *FlowClient) Run(ctx context.Context) {
	logrus.Info("Starting flow client")
	defer func() {
		logrus.Info("Stopping flow client")
	}()

	// Create a new client to push flows to the server.
	cli := proto.NewFlowCollectorClient(c.grpcClient)

	for {
		// Check if the parent context has been canceled.
		if err := ctx.Err(); err != nil {
			logrus.WithError(err).Warn("Parent context canceled")
			return
		}

		// Connect to the flow server. This establishes a streaming connection over which
		// we can send flow updates.
		rc, err := cli.Connect(ctx)
		if err != nil {
			logrus.WithError(err).Warn("Failed to connect to flow server")
			time.Sleep(5 * time.Second)
			continue
		}
		logrus.Info("Connected to flow server")

		// On a new connection, send all of the flows that we have cached. We're assuming
		// this indicates a restart of the flow server. The flow server will handle deuplication
		// if we happen to send the same flow twice.
		c.cache.Iter(func(f *proto.Flow) error {
			// Send.
			if err := rc.Send(&proto.FlowUpdate{Flow: f}); err != nil {
				logrus.WithError(err).Warn("Failed to send flow")
				return err
			}
			// Get receipt.
			if _, err := rc.Recv(); err != nil {
				logrus.WithError(err).Warn("Failed to receive receipt")
				return err
			}
		})

		// Send new Flows as they are received.
		for flog := range c.inChan {
			// Add the flow to our cache. It will automatically be expired in the background.
			c.cache.Add(flog)

			// Send the flow.
			if err := rc.Send(&proto.FlowUpdate{Flow: flog}); err != nil {
				logrus.WithError(err).Warn("Failed to send flow")
				break
			}

			// Receive a receipt.
			if _, err := rc.Recv(); err != nil {
				logrus.WithError(err).Warn("Failed to receive receipt")
				break
			}
		}

		if err := rc.CloseSend(); err != nil {
			logrus.WithError(err).Warn("Failed to close connection")
		}

		// TODO: Exponential backoff.
		time.Sleep(1 * time.Second)
	}
}

func (c *FlowClient) Push(f *proto.Flow) {
	// Make a copy of the flow to decouple the caller from the client.
	cp := f
	select {
	case c.inChan <- cp:
	default:
		logrus.Warn("Flow client buffer full, dropping flow")
	}
}
