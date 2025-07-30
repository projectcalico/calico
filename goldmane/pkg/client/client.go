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

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/projectcalico/calico/goldmane/pkg/internal/flowcache"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
)

const (
	FlowCacheExpiry  = 5 * time.Minute
	FlowCacheCleanup = 30 * time.Second
)

// NewFlowClient creates a new client to the goldmane grpc API. It creates the initial grpcClient connection to verify
// that an initial connection can be created when connect is called (grpc.NewClient doesn't establish an initial connection,
// just validates that it should be able to with the given parameters).
//
// If an error is returned, it means that no amount of retrying will create the client with the same parameters.
func NewFlowClient(server, cert, key, caFile string) (*FlowClient, error) {
	// Get credentials.
	opts := []grpc.DialOption{}
	if caFile != "" || cert != "" || key != "" {
		creds, err := ClientCredentials(cert, key, caFile)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		// TODO: We only need this for Felix FVs right now. Remove this once
		// we update the FVs to use TLS.
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	grpcClient, err := grpc.NewClient(server, opts...)
	if err != nil {
		return nil, err
	}

	return &FlowClient{
		inChan:      make(chan *types.Flow, 5000),
		cache:       flowcache.NewExpiringFlowCache(FlowCacheExpiry),
		grpcCliConn: grpcClient,
	}, nil
}

// FlowClient pushes flow updates to the flow server.
type FlowClient struct {
	cancel      context.CancelFunc
	inChan      chan *types.Flow
	cache       *flowcache.ExpiringFlowCache
	grpcCliConn *grpc.ClientConn
}

// Connect starts the grpc connection to stream flows to goldmane. It returns a channel that closes once the initial
// connection has been established which gives callers the option to wait for an initial connection before proceeding
// to use the client.
func (c *FlowClient) Connect(ctx context.Context) <-chan struct{} {
	logrus.Info("Starting flow client")

	// Wrap the given context to make it cancelable.
	ctx, c.cancel = context.WithCancel(ctx)

	// Start the cache cleanup task.
	go c.cache.Run(FlowCacheCleanup)

	startUp := make(chan struct{})
	go func() {
		defer func() {
			logrus.Info("Stopping flow client")
			if err := c.grpcCliConn.Close(); err != nil {
				logrus.WithError(err).Warn("Failed to close grpc client")
			}
		}()

		rc, err := c.connect(ctx)
		// Close this regardless of the error since we don't want the other side of the channel to hang forever.
		close(startUp)
		if err != nil {
			logrus.WithError(err).Warn("Unable to connect to flow server, will not retry (fatal error).")
			return
		}

		// Loop is to handle reconnecting when disruptions happen to the connection. When the inner loop fails and breaks
		// reconnection happens before the out loop runs again.
		upd := proto.FlowUpdate{Flow: proto.NewFlow()}
		for {
			// Send new Flows as they are received.
			for flog := range c.inChan {
				logrus.WithField("flow", flog).Debug("Sending flow")
				// Add the flow to our cache. It will automatically be expired in the background.
				// We don't need to pass in a value for scope, since the client is intrinsically scoped
				// to a particular node.
				c.cache.Add(flog, "")

				// Unpack the minified flow into a full flow and send it.
				types.FlowIntoProto(flog, upd.Flow)

				// Send the flow.
				if err := rc.Send(&upd); err != nil {
					logrus.WithError(err).Warn("Failed to send flow")
					break
				}

				// Receive a receipt.
				if _, err := rc.Recv(); err != nil {
					logrus.WithError(err).Warn("Failed to receive receipt")
					break
				}
			}

			if ctx.Err() != nil {
				// Context was canceled - client is shutting down.
				return
			}

			if err := rc.CloseSend(); err != nil {
				logrus.WithError(err).Warn("Failed to close connection")
			}

			rc, err = c.connect(ctx)
			if err != nil {
				logrus.WithError(err).Warn("Failed to reconnect to flow server, will not retry (fatal error).")
				return
			}
		}
	}()

	return startUp
}

// connect establishes a new connection to the server and sends any cached logs. Note that non-fatal errors are retried
// indefinitely.
// Any returned error is deemed unrecoverable and demands establishment of a new underlying gRPC connection.
func (c *FlowClient) connect(ctx context.Context) (grpc.BidiStreamingClient[proto.FlowUpdate, proto.FlowReceipt], error) {
	// Create a new client to push flows to the server.
	cli := proto.NewFlowCollectorClient(c.grpcCliConn)

	// Create a backoff helper.
	b := newBackoff(1*time.Second, 10*time.Second)

	for {
		// Check if the parent context has been canceled.
		if err := ctx.Err(); err != nil {
			logrus.WithError(err).Warn("Parent context canceled")
			return nil, err
		}

		// Connect to the flow server. This establishes a streaming connection over which
		// we can send flow updates.

		var err error
		rc, err := cli.Connect(ctx)
		if err != nil {
			logrus.WithError(err).WithField("target", c.grpcCliConn.CanonicalTarget()).
				Warn("Failed to connect to flow server")
			b.Wait()
			continue
		}

		logrus.WithField("target", c.grpcCliConn.CanonicalTarget()).Info("Connected to flow server")
		b.Reset()

		// On a new connection, send all of the flows that we have cached. We're assuming
		// this indicates a restart of the flow server. The flow server will handle deuplication
		// if we happen to send the same flow twice.
		upd := proto.FlowUpdate{Flow: proto.NewFlow()}
		err = c.cache.Iter(func(f *types.Flow) error {
			// Unpack the minified flow into a full flow and send it.
			types.FlowIntoProto(f, upd.Flow)
			if err := rc.Send(&upd); err != nil {
				logrus.WithError(err).Warn("Failed to send flow")
				return err
			}

			// Get receipt.
			if _, err := rc.Recv(); err != nil {
				logrus.WithError(err).Warn("Failed to receive receipt")
				return err
			}
			return nil
		})
		if err != nil {
			b.Wait()
			continue
		}
		return rc, nil
	}
}

func (c *FlowClient) PushWait(f *types.Flow) {
	select {
	case c.inChan <- f:
	default:
		logrus.Warn("Flow client buffer full, waiting")
		c.inChan <- f
	}
}

func (c *FlowClient) Push(f *types.Flow) {
	logrus.Debug("Pushing flow to client")
	select {
	case c.inChan <- f:
	default:
		logrus.Warn("Flow client buffer full, dropping flow")
	}
}

// Close closes the flow client's input channel. This must be called from the same goroutine
// that is pushing flows to the client when the client is no longer needed.
func (c *FlowClient) Close() {
	c.cancel()
	close(c.inChan)
}

// backoff is a small helper to implement exponential backoff.
func newBackoff(base, maxBackoff time.Duration) *backoff {
	return &backoff{
		base:       base,
		interval:   base,
		maxBackoff: maxBackoff,
	}
}

type backoff struct {
	base       time.Duration
	interval   time.Duration
	maxBackoff time.Duration
}

func (b *backoff) Wait() {
	logrus.WithField("duration", b.interval).Info("Waiting before next connection attempt")
	time.Sleep(b.interval)
	b.interval *= 2
	if b.interval > b.maxBackoff {
		b.interval = b.maxBackoff
	}
}

func (b *backoff) Reset() {
	b.interval = b.base
}
