// Copyright (c) 2018-2024 Tigera, Inc. All rights reserved.

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
	"log"
	"time"

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
		target:       target,
		storeManager: policyStoreManager,
		dialOpts:     dialOpts,
	}
	for _, opt := range clientOpts {
		opt(syncClient)
	}
	return syncClient
}

func (s *SyncClient) Start(ctx context.Context) error {
	// Create the connection with policySync
	cc, err := grpc.NewClient(s.target, s.dialOpts...)
	if err != nil {
		return err
	}
	// go routine to close the connection when the context is Done
	go func() {
		<-ctx.Done()
		cc.Close()
	}()

	go s.sync(ctx)

	return nil
}

func (s *SyncClient) sync(ctx context.Context) {
	updateC := make(chan *proto.ToDataplane)

	for {
		select {
		case <-ctx.Done():
			s.inSync = false
			return
		case update := <-updateC:
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
}

// Readiness returns whether the SyncClient is InSync.
func (s *SyncClient) Readiness() bool {
	return s.inSync
}
