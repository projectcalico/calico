// Copyright (c) 2015-2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package utils

import (
	"context"
	"testing"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

type messageTestClient struct{ client.Interface }

func (messageTestClient) IPPools() client.IPPoolInterface { return messageTestPools{} }

type messageTestPools struct{ client.IPPoolInterface }

func (messageTestPools) List(context.Context, options.ListOptions) (*api.IPPoolList, error) {
	return &api.IPPoolList{}, nil
}
func TestPoolFamilyMismatchMessages(t *testing.T) {
	for _, tc := range []struct {
		cidr    string
		ipv4    bool
		message string
	}{
		{"2001:db8::/64", true, "\"2001:db8::\" isn't an IPv4 address"},
		{"192.0.2.0/24", false, "\"192.0.2.0\" isn't an IPv6 address"},
	} {
		_, err := ResolvePools(context.Background(), messageTestClient{}, []string{tc.cidr}, tc.ipv4)
		if err == nil || err.Error() != tc.message {
			t.Fatalf("unexpected pool error: %v", err)
		}
	}
}
