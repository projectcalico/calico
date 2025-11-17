// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.

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

package syncher

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/proto"
)

const (
	// The stats reporting and flush interval. Currently set to half the hardcoded expiration time of cache entries in
	// the Felix stats collector component.
	DefaultSubscriptionType   = "per-pod-policies"
	DefaultStatsFlushInterval = 5 * time.Second
	PolicySyncRetryTime       = 1000 * time.Millisecond
)

type SyncClient struct {
	target           string
	dialOpts         []grpc.DialOption
	subscriptionType string
	inSync           bool
	storeManager     policystore.PolicyStoreManager
}

type ClientOptions func(*SyncClient)

func WithSubscriptionType(subscriptionType string) ClientOptions {
	return func(s *SyncClient) {
		switch subscriptionType {
		case "":
			s.subscriptionType = "per-pod-policies"
		case "per-pod-policies", "per-host-policies":
			s.subscriptionType = subscriptionType
		default:
			log.Panicf("invalid subscription type: '%s'", subscriptionType)
		}
	}
}

// NewClient creates a new syncClient.
func NewClient(
	target string,
	policyStoreManager policystore.PolicyStoreManager,
	dialOpts []grpc.DialOption,
	clientOpts ...ClientOptions,
) *SyncClient {
	syncClient := &SyncClient{
		target:           target,
		storeManager:     policyStoreManager,
		dialOpts:         dialOpts,
		subscriptionType: DefaultSubscriptionType,
	}
	for _, opt := range clientOpts {
		opt(syncClient)
	}
	return syncClient
}

func (s *SyncClient) Sync(cxt context.Context) {
	for {
		select {
		case <-cxt.Done():
			s.inSync = false
			return
		default:
			inSync := make(chan struct{})
			done := make(chan struct{})
			go s.syncStore(cxt, inSync, done)

			// Block until we receive InSync message, or cancelled.
			select {
			case <-inSync:
				s.inSync = true
			// Also catch the case where syncStore ends before it gets an InSync message.
			case <-done:
				// pass
			case <-cxt.Done():
				s.inSync = false
				return
			}

			// Block until syncStore() ends (e.g. disconnected), or cancelled.
			select {
			case <-done:
				s.inSync = false
				// pass
			case <-cxt.Done():
				return
			}

			time.Sleep(PolicySyncRetryTime)
		}
	}
}

func (s *SyncClient) syncStore(cxt context.Context, inSync chan<- struct{}, done chan<- struct{}) {
	defer close(done)
	conn, err := grpc.NewClient(s.target, s.dialOpts...)
	if err != nil {
		log.Warnf("fail to dial Policy Sync server: %v", err)
		return
	}
	log.Info("Successfully connected to Policy Sync server")
	defer func() { _ = conn.Close() }()
	client := proto.NewPolicySyncClient(conn)
	stream, err := client.Sync(cxt, &proto.SyncRequest{})
	if err != nil {
		log.Warnf("failed to synchronize with Policy Sync server: %v", err)
		s.inSync = false
		return
	}
	log.Info("Starting synchronization with Policy Sync server")
	for {
		update, err := stream.Recv()
		if err != nil {
			log.Warnf("connection to Policy Sync server broken: %v", err)
			return
		}
		log.WithFields(log.Fields{"proto": update}).Debug("Received sync API Update")
		switch update.Payload.(type) {
		case *proto.ToDataplane_InSync:
			s.inSync = true
			s.storeManager.OnInSync()
		default:
			s.storeManager.DoWithLock(func(ps *policystore.PolicyStore) {
				ps.ProcessUpdate(s.subscriptionType, update, false)
			})
		}
	}
}

// Readiness returns whether the SyncClient is InSync.
func (s *SyncClient) Readiness() bool {
	return s.inSync
}
