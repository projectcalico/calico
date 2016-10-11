// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package testutils

import (
	"log"
	"net"
	"os"

	"github.com/tigera/libcalico-go/lib/api"
	"github.com/tigera/libcalico-go/lib/api/unversioned"
	"github.com/tigera/libcalico-go/lib/client"
	cnet "github.com/tigera/libcalico-go/lib/net"
)

// NewClient is a util function to create a new default client.
// When passed empty string, it loads the default config instead from a config file.
func NewClient(cf string) (*client.Client, error) {
	if _, err := os.Stat(cf); err != nil {
		cf = ""
	}

	cfg, err := client.LoadClientConfig(cf)
	if err != nil {
		return nil, err
	}

	c, err := client.New(*cfg)
	if err != nil {
		return nil, err
	}

	return c, err
}

func CreateNewPool(c client.Client, poolSubnet string, ipip, natOut, ipam bool) {

	_, cidr, err := net.ParseCIDR(poolSubnet)
	if err != nil {
		log.Printf("Error parsing CIDR: %s\n", err)
	}

	pool := api.Pool{
		TypeMetadata: unversioned.TypeMetadata{
			Kind:       "pool",
			APIVersion: "v1",
		},
		Metadata: api.PoolMetadata{
			ObjectMetadata: unversioned.ObjectMetadata{},
			CIDR:           cnet.IPNet{*cidr},
		},
		Spec: api.PoolSpec{
			IPIP: &api.IPIPConfiguration{
				Enabled: ipip,
			},
			NATOutgoing: natOut,
			Disabled:    !ipam,
		},
	}

	_, err = c.Pools().Create(&pool)

	if err != nil {
		log.Printf("Error creating pool: %s\n", err)
	}

}
